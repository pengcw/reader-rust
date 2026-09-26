use crate::crawler::{
    analyze_url_with_headers, decode_body, execute_request_spec, HttpClient,
};
use crate::model::book_source::BookSource;
use crate::parser::html;
use crate::parser::jsonpath;
use crate::parser::rule_analyzer;
use crate::parser::rule_engine;
use crate::util::hash::md5_hex;
use crate::util::text::{apply_regex_replace, strip_whitespace};
use aes::Aes128;
use base64::Engine;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use chrono::{FixedOffset, Local, TimeZone};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use once_cell::sync::Lazy;
use ring::hmac;
use rquickjs::function::Func;
use rquickjs::{Context, Object, Runtime, Value};
use serde_json::Value as JsonValue;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};
use ureq::http::Method;
use uuid::Uuid;

static JS_KV: Lazy<Mutex<HashMap<String, String>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static JS_CACHE: Lazy<Mutex<HashMap<String, JsCacheEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static JS_LIB_CACHE: Lazy<Mutex<HashMap<String, String>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Clone)]
struct JsCacheEntry {
    value: String,
    expires_at: Option<Instant>,
}
static JS_HTTP_CLIENT: Lazy<HttpClient> = Lazy::new(HttpClient::standalone);
static JS_DEVICE_ID: Lazy<String> = Lazy::new(|| {
    let mut map = JS_KV.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(existing) = map.get("__device_id") {
        return existing.clone();
    }
    let generated = Uuid::new_v4().to_string();
    map.insert("__device_id".to_string(), generated.clone());
    generated
});
type Aes128CbcDecryptor = cbc::Decryptor<Aes128>;
type Aes128CbcEncryptor = cbc::Encryptor<Aes128>;

struct TimerGuard(Arc<AtomicU64>);
impl Drop for TimerGuard {
    fn drop(&mut self) {
        self.0.store(0, Ordering::Relaxed);
    }
}

thread_local! {
    static ACTIVE_JS_LIB: RefCell<Option<String>> = const { RefCell::new(None) };
    // reader_execute installs its source-bound HTTP session here so JavaScript
    // java.ajax/get/post shares the same cookies and request policy as Rust HTTP.
    static ACTIVE_JS_HTTP_CLIENT: RefCell<Option<HttpClient>> = const { RefCell::new(None) };
    static ACTIVE_JS_BOOK_SOURCE: RefCell<Option<BookSource>> = const { RefCell::new(None) };
    // Native JS callbacks may need AnalyzeUrl to evaluate nested header/URL JavaScript.
    // Reuse the currently borrowed QuickJS context instead of entering Context::with again.
    static ACTIVE_JS_REENTRANT_CTX: RefCell<Option<NonNull<rquickjs::qjs::JSContext>>> =
        const { RefCell::new(None) };

    static JS_ENV: (Runtime, Context, Arc<AtomicU64>) = {
        let rt = Runtime::new().expect("Failed to create JS Runtime");
        rt.set_max_stack_size(512 * 1024);
        rt.set_memory_limit(30 * 1024 * 1024);

        let start_time = Arc::new(AtomicU64::new(0));
        let st_clone = start_time.clone();

        rt.set_interrupt_handler(Some(Box::new(move || {
            let st = st_clone.load(Ordering::Relaxed);
            if st == 0 {
                return false;
            }
            if let Ok(elapsed) = SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                if elapsed.as_secs() > st + 4 {
                    return true;
                }
            }
            false
        })));

        let ctx = Context::full(&rt).expect("Failed to create JS Context");
        (rt, ctx, start_time)
    };
}

pub fn with_js_lib<T>(js_lib: Option<&str>, f: impl FnOnce() -> T) -> T {
    ACTIVE_JS_LIB.with(|cell| {
        let previous = cell.replace(js_lib.map(|value| value.to_string()));
        let result = f();
        cell.replace(previous);
        result
    })
}

/// Bind a source-specific synchronous HTTP client for the duration of a rule
/// execution. Nested calls restore the prior client, so reader_eval keeps its
/// legacy fallback client.
pub(crate) fn with_js_http_client<T>(client: &HttpClient, f: impl FnOnce() -> T) -> T {
    ACTIVE_JS_HTTP_CLIENT.with(|cell| {
        let previous = cell.replace(Some(client.clone()));
        let result = f();
        cell.replace(previous);
        result
    })
}

pub(crate) fn with_js_http_context<T>(
    client: &HttpClient,
    source: &BookSource,
    f: impl FnOnce() -> T,
) -> T {
    let previous_source = ACTIVE_JS_BOOK_SOURCE.with(|cell| cell.replace(Some(source.clone())));
    let result = with_js_http_client(client, f);
    ACTIVE_JS_BOOK_SOURCE.with(|cell| cell.replace(previous_source));
    result
}

fn active_js_http_client() -> HttpClient {
    ACTIVE_JS_HTTP_CLIENT
        .with(|cell| cell.borrow().clone())
        .unwrap_or_else(|| JS_HTTP_CLIENT.clone())
}

fn with_js_reentrant_ctx<T>(
    ctx: &rquickjs::Ctx<'_>,
    f: impl FnOnce() -> T,
) -> T {
    ACTIVE_JS_REENTRANT_CTX.with(|cell| {
        let previous = cell.replace(Some(ctx.as_raw()));
        let result = f();
        cell.replace(previous);
        result
    })
}

pub fn eval_js(script: &str, input: &str, base_url: &str) -> anyhow::Result<String> {
    eval_js_inner(script, Some(input), Some(base_url), None, None, None)
}

pub fn eval_js_with_bindings(
    script: &str,
    input: &str,
    base_url: &str,
    bindings: &HashMap<String, JsonValue>,
) -> anyhow::Result<String> {
    eval_js_inner(
        script,
        Some(input),
        Some(base_url),
        None,
        None,
        Some(bindings),
    )
}

pub fn eval_js_search_with_source(
    script: &str,
    key: &str,
    page: i32,
    source_key: &str,
) -> anyhow::Result<String> {
    eval_js_inner_with_source(
        script,
        None,
        None,
        Some(key),
        Some(page),
        Some(source_key),
        None,
        false,
    )
}

pub fn eval_js_url(
    script: &str,
    result: &str,
    key: &str,
    page: i32,
    source_key: &str,
    base_url: &str,
) -> anyhow::Result<String> {
    eval_js_url_with_bindings(script, result, key, page, source_key, base_url, None)
}

pub fn eval_js_url_with_bindings(
    script: &str,
    result: &str,
    key: &str,
    page: i32,
    source_key: &str,
    base_url: &str,
    bindings: Option<&HashMap<String, JsonValue>>,
) -> anyhow::Result<String> {
    eval_js_inner_with_source(
        script,
        Some(result),
        Some(base_url),
        Some(key),
        Some(page),
        Some(source_key),
        bindings,
        false,
    )
}

pub fn eval_js_url_template(
    script: &str,
    result: &str,
    key: &str,
    page: i32,
    source_key: &str,
    base_url: &str,
) -> anyhow::Result<String> {
    eval_js_url_template_with_bindings(script, result, key, page, source_key, base_url, None)
}

pub fn eval_js_url_template_with_bindings(
    script: &str,
    result: &str,
    key: &str,
    page: i32,
    source_key: &str,
    base_url: &str,
    bindings: Option<&HashMap<String, JsonValue>>,
) -> anyhow::Result<String> {
    eval_js_inner_with_source(
        script,
        Some(result),
        Some(base_url),
        Some(key),
        Some(page),
        Some(source_key),
        bindings,
        true,
    )
}

pub fn eval_js_template(script: &str, input: &str, base_url: &str) -> anyhow::Result<String> {
    eval_js_inner_with_source(
        script,
        Some(input),
        Some(base_url),
        None,
        None,
        None,
        None,
        true,
    )
}

pub fn eval_js_template_with_bindings(
    script: &str,
    input: &str,
    base_url: &str,
    bindings: &HashMap<String, JsonValue>,
) -> anyhow::Result<String> {
    eval_js_inner_with_source(
        script,
        Some(input),
        Some(base_url),
        None,
        None,
        None,
        Some(bindings),
        true,
    )
}

fn eval_js_inner(
    script: &str,
    input: Option<&str>,
    base_url: Option<&str>,
    key: Option<&str>,
    page: Option<i32>,
    bindings: Option<&HashMap<String, JsonValue>>,
) -> anyhow::Result<String> {
    eval_js_inner_with_source(script, input, base_url, key, page, None, bindings, false)
}

fn eval_js_inner_with_source(
    script: &str,
    input: Option<&str>,
    base_url: Option<&str>,
    key: Option<&str>,
    page: Option<i32>,
    source_key: Option<&str>,
    bindings: Option<&HashMap<String, JsonValue>>,
    template_result: bool,
) -> anyhow::Result<String> {
    if let Some(raw_ctx) = ACTIVE_JS_REENTRANT_CTX.with(|cell| *cell.borrow()) {
        // SAFETY: the pointer is installed only for the duration of a native
        // callback invoked by this same QuickJS context and thread.
        let ctx = unsafe { rquickjs::Ctx::from_raw(raw_ctx) };
        return eval_js_reentrant(
            ctx,
            script,
            input,
            base_url,
            key,
            page,
            source_key,
            bindings,
            template_result,
        );
    }

    JS_ENV.with(|(_, ctx, start_time)| {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        start_time.store(now, Ordering::Relaxed);
        let _guard = TimerGuard(start_time.clone());

        ctx.with(|ctx| {
            let globals = ctx.globals();
            let input_value = input.unwrap_or("");
            let content_state = Arc::new(Mutex::new(input_value.to_string()));
            let base_url_value = base_url.unwrap_or("");
            let shared_js = active_js_lib_script()?;

            globals.set("input", input_value)?;
            globals.set("result", input_value)?;
            globals.set("src", input_value)?;
            globals.set("loginInfo", ctx.json_parse("{}")?)?;
            globals.set("base_url", base_url_value)?;
            globals.set("baseUrl", base_url_value)?;
            if let Some(key) = key {
                globals.set("key", key)?;
            }
            if let Some(page) = page {
                globals.set("page", page)?;
            }

            // Default url variable for Legado compatibility
            globals.set("url", base_url_value)?;

            // Stubs for Legado compatibility
            let source_key_val = source_key.unwrap_or("").to_string();
            let source_obj = Object::new(ctx.clone())?;
            let sk_clone = source_key_val.clone();
            source_obj.set("key", source_key_val.clone())?;
            source_obj.set("getKey", Func::new(move || sk_clone.clone()))?;

            source_obj.set(
                "getVariable",
                Func::new(|key: rquickjs::function::Opt<String>| -> String {
                    let key_str = key.0.unwrap_or_default();
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        if let Some(val) = active.get_variable(&key_str) {
                            return match val {
                                serde_json::Value::String(s) => s,
                                other => other.to_string(),
                            };
                        }
                    }
                    "".to_string()
                }),
            )?;

            source_obj.set(
                "setVariable",
                Func::new(
                    |first: String, second: rquickjs::function::Opt<String>| -> String {
                        if let Some(active) = crate::crawler::session::current_active_session() {
                            if let Some(sec) = second.0 {
                                active.set_variable(&first, serde_json::Value::String(sec.clone()));
                                sec
                            } else {
                                active.set_variable("", serde_json::Value::String(first.clone()));
                                first
                            }
                        } else {
                            "".to_string()
                        }
                    },
                ),
            )?;

            source_obj.set(
                "getLoginHeader",
                Func::new(|| -> String {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        if let Some(val) = active.get_login_header() {
                            return match val {
                                serde_json::Value::String(s) => s,
                                other => other.to_string(),
                            };
                        }
                    }
                    "".to_string()
                }),
            )?;

            source_obj.set(
                "putLoginHeader",
                Func::new(|val: String| -> String {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        let json_val = serde_json::from_str::<serde_json::Value>(&val)
                            .unwrap_or_else(|_| serde_json::Value::String(val.clone()));
                        active.put_login_header(json_val);
                    }
                    val
                }),
            )?;

            source_obj.set(
                "removeLoginHeader",
                Func::new(|| -> String {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.remove_login_header();
                    }
                    "".to_string()
                }),
            )?;

            globals.set("source", source_obj)?;

            let cookie_obj = Object::new(ctx.clone())?;
            cookie_obj.set(
                "getCookie",
                Func::new(|url: String| -> String {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.get_cookie(&url).unwrap_or_default()
                    } else {
                        "".to_string()
                    }
                }),
            )?;
            cookie_obj.set(
                "getKey",
                Func::new(|url: String, key: String| -> String {
                    crate::crawler::session::current_active_session()
                        .and_then(|active| active.get_cookie_key(&url, &key))
                        .unwrap_or_default()
                }),
            )?;
            cookie_obj.set(
                "get",
                Func::new(|url: String| -> String {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.get_cookie(&url).unwrap_or_default()
                    } else {
                        "".to_string()
                    }
                }),
            )?;
            cookie_obj.set(
                "setCookie",
                Func::new(|url: String, cookie: String| -> String {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.set_cookie(&url, &cookie);
                    }
                    cookie
                }),
            )?;
            cookie_obj.set(
                "set",
                Func::new(|url: String, cookie: String| -> String {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.set_cookie(&url, &cookie);
                    }
                    cookie
                }),
            )?;
            cookie_obj.set(
                "removeCookie",
                Func::new(|url: String| -> String {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.remove_cookie(&url);
                    }
                    "".to_string()
                }),
            )?;
            cookie_obj.set(
                "remove",
                Func::new(|url: String| -> String {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.remove_cookie(&url);
                    }
                    "".to_string()
                }),
            )?;
            globals.set("cookie", cookie_obj)?;

            let cache_obj = Object::new(ctx.clone())?;
            cache_obj.set(
                "get",
                Func::new(|key: String| -> Option<String> { js_cache_get(&key) }),
            )?;
            cache_obj.set(
                "put",
                Func::new(
                    |key: String, val: String, save_time: rquickjs::function::Opt<i64>| -> bool {
                        js_cache_put(&key, val, save_time.0)
                    },
                ),
            )?;
            cache_obj.set(
                "delete",
                Func::new(|key: String| -> bool { js_cache_delete(&key) }),
            )?;
            globals.set("cache", cache_obj)?;

            let java_obj = Object::new(ctx.clone())?;
            let content_for_set = content_state.clone();
            java_obj.set(
                "setContent",
                Func::new(move |content: String| -> String {
                    *content_for_set.lock().unwrap_or_else(|e| e.into_inner()) = content.clone();
                    content
                }),
            )?;
            java_obj.set(
                "ajax",
                Func::new(|spec: String| -> String { java_ajax(&spec).unwrap_or_default() }),
            )?;
            java_obj.set(
                "md5Encode",
                Func::new(|input: String| -> String { md5_hex(&input) }),
            )?;
            let md5_to_16 = |input: String| -> String {
                let md5 = md5_hex(&input);
                if md5.len() >= 16 {
                    md5[8..24].to_string()
                } else {
                    md5
                }
            };
            java_obj.set("md5To16", Func::new(md5_to_16))?;
            java_obj.set("md5Encode16", Func::new(md5_to_16))?;
            java_obj.set(
                "timeFormat",
                Func::new(|timestamp: i64| -> String { java_time_format(timestamp) }),
            )?;
            java_obj.set(
                "timeFormatUTC",
                Func::new(|timestamp: i64, format: String, offset_ms: i64| -> String {
                    java_time_format_utc(timestamp, &format, offset_ms)
                }),
            )?;
            java_obj.set(
                "androidId",
                Func::new(|| -> String { JS_DEVICE_ID.clone() }),
            )?;
            java_obj.set("deviceID", Func::new(|| -> String { JS_DEVICE_ID.clone() }))?;
            java_obj.set("randomUUID", Func::new(|| -> String { Uuid::new_v4().to_string() }))?;
            java_obj.set(
                "__nativeConnect",
                Func::new(
                    |ctx: rquickjs::Ctx<'_>, url: String, headers_json: String| -> String {
                        with_js_reentrant_ctx(&ctx, || {
                            java_analyzed_request_response(&url, &headers_json)
                        })
                    },
                ),
            )?;
            java_obj.set(
                "__nativeAjaxAllItem",
                Func::new(|ctx: rquickjs::Ctx<'_>, url: String| -> String {
                    with_js_reentrant_ctx(&ctx, || java_analyzed_request_response(&url, ""))
                }),
            )?;
            java_obj.set(
                "__nativeGet",
                Func::new(|url: String, headers_json: String| -> String {
                    java_request_simple_response("GET", &url, None, &headers_json)
                }),
            )?;
            java_obj.set(
                "__nativePost",
                Func::new(|url: String, body: String, headers_json: String| -> String {
                    java_request_simple_response("POST", &url, Some(body), &headers_json)
                }),
            )?;
            java_obj.set(
                "__nativeHead",
                Func::new(|url: String, headers_json: String| -> String {
                    java_request_simple_response("HEAD", &url, None, &headers_json)
                }),
            )?;
            java_obj.set(
                "put",
                Func::new(|url: String, body: String| -> String {
                    java_request_simple("PUT", &url, Some(body), "{}").unwrap_or_default()
                }),
            )?;
            java_obj.set(
                "base64Encode",
                Func::new(|input: String| -> String {
                    base64::engine::general_purpose::STANDARD.encode(input)
                }),
            )?;
            java_obj.set(
                "base64Decode",
                Func::new(
                    |input: String, charset: rquickjs::function::Opt<String>| -> String {
                        java_base64_decode(&input, charset.0.as_deref())
                    },
                ),
            )?;
            java_obj.set(
                "base64DecodeBytes",
                Func::new(|input: String| -> String {
                    java_base64_decode_bytes(&input, 0)
                }),
            )?;
            java_obj.set(
                "__base64EncodeBytes",
                Func::new(|bytes_json: String, flags: i32| -> String {
                    java_base64_encode_bytes(&bytes_json, flags)
                }),
            )?;
            java_obj.set(
                "__base64DecodeBytes",
                Func::new(|input: String, flags: i32| -> String {
                    java_base64_decode_bytes(&input, flags)
                }),
            )?;
            java_obj.set(
                "__hmacBytes",
                Func::new(|algorithm: String, key_json: String, data_json: String| -> String {
                    java_hmac_bytes(&algorithm, &key_json, &data_json)
                }),
            )?;
            java_obj.set(
                "__strToBytes",
                Func::new(
                    |input: String, charset: rquickjs::function::Opt<String>| -> String {
                        serde_json::to_string(&java_str_to_bytes(
                            &input,
                            charset.0.as_deref(),
                        ))
                        .unwrap_or_else(|_| "[]".to_string())
                    },
                ),
            )?;
            java_obj.set(
                "__bytesToStr",
                Func::new(|bytes_json: String, charset: String| -> String {
                    let bytes = serde_json::from_str::<Vec<i64>>(&bytes_json)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|byte| byte.rem_euclid(256) as u8)
                        .collect::<Vec<_>>();
                    java_bytes_to_str(&bytes, Some(&charset))
                }),
            )?;
            java_obj.set(
                "__hexDecodeBytes",
                Func::new(|input: String| -> String {
                    serde_json::to_string(&hex::decode(input.trim()).unwrap_or_default())
                        .unwrap_or_else(|_| "[]".to_string())
                }),
            )?;
            java_obj.set(
                "hexDecodeToString",
                Func::new(|input: String| -> String {
                    String::from_utf8_lossy(&hex::decode(input.trim()).unwrap_or_default())
                        .into_owned()
                }),
            )?;
            java_obj.set(
                "hexEncodeToString",
                Func::new(|input: String| -> String { hex::encode(input.as_bytes()) }),
            )?;
            java_obj.set(
                "aesBase64DecodeToString",
                Func::new(
                    |input: String, key: String, algorithm: String, iv: String| -> String {
                        java_aes_base64_decode_to_string(&input, &key, &algorithm, &iv)
                    },
                ),
            )?;
            java_obj.set(
                "aesDecryptBytes",
                Func::new(|input: String| -> String { java_aes_decrypt_bytes(&input) }),
            )?;
            java_obj.set(
                "__aesDecryptByteArray",
                Func::new(|input: String| -> String {
                    serde_json::to_string(&java_aes_decrypt_byte_array(&input))
                        .unwrap_or_else(|_| "[]".to_string())
                }),
            )?;
            java_obj.set(
                "aesBase64Encode",
                Func::new(
                    |input: String, key: String, algorithm: String, iv: String| -> String {
                        java_aes_base64_encode(&input, &key, &algorithm, &iv)
                    },
                ),
            )?;
            java_obj.set(
                "aesEncode",
                Func::new(
                    |input: String, key: String, algorithm: String, iv: String| -> String {
                        java_aes_encode(&input, &key, &algorithm, &iv)
                    },
                ),
            )?;
            java_obj.set(
                "escape",
                Func::new(|input: String| -> String {
                    input
                        .chars()
                        .map(|c| {
                            if c.is_ascii_alphanumeric()
                                || c == '*'
                                || c == '+'
                                || c == '-'
                                || c == '.'
                                || c == '/'
                                || c == '@'
                                || c == '_'
                            {
                                c.to_string()
                            } else if (c as u32) < 256 {
                                format!("%{:02X}", c as u32)
                            } else {
                                format!("%u{:04X}", c as u32)
                            }
                        })
                        .collect()
                }),
            )?;
            java_obj.set(
                "unescape",
                Func::new(|input: String| -> String {
                    // simple unescape implementation
                    let mut res = String::new();
                    let mut chars = input.chars().peekable();
                    while let Some(c) = chars.next() {
                        if c == '%' {
                            if let Some('u') = chars.peek() {
                                chars.next();
                                let mut hex = String::new();
                                for _ in 0..4 {
                                    if let Some(hc) = chars.next() {
                                        hex.push(hc);
                                    }
                                }
                                if let Ok(val) = u32::from_str_radix(&hex, 16) {
                                    if let Some(char_val) = char::from_u32(val) {
                                        res.push(char_val);
                                        continue;
                                    }
                                }
                                res.push_str("%u");
                                res.push_str(&hex);
                            } else {
                                let mut hex = String::new();
                                for _ in 0..2 {
                                    if let Some(hc) = chars.next() {
                                        hex.push(hc);
                                    }
                                }
                                if let Ok(val) = u8::from_str_radix(&hex, 16) {
                                    res.push(val as char);
                                    continue;
                                }
                                res.push('%');
                                res.push_str(&hex);
                            }
                        } else {
                            res.push(c);
                        }
                    }
                    res
                }),
            )?;
            java_obj.set(
                "gzip",
                Func::new(|input: String| -> String {
                    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                    let _ = encoder.write_all(input.as_bytes());
                    if let Ok(compressed) = encoder.finish() {
                        base64::engine::general_purpose::STANDARD.encode(compressed)
                    } else {
                        String::new()
                    }
                }),
            )?;
            java_obj.set(
                "ungzip",
                Func::new(|input: String| -> String {
                    if let Ok(compressed) =
                        base64::engine::general_purpose::STANDARD.decode(input.trim())
                    {
                        let mut decoder = GzDecoder::new(&compressed[..]);
                        let mut s = String::new();
                        if decoder.read_to_string(&mut s).is_ok() {
                            return s;
                        }
                    }
                    String::new()
                }),
            )?;
            java_obj.set(
                "encodeURIComponent",
                Func::new(|input: String| -> String { urlencoding::encode(&input).into_owned() }),
            )?;
            java_obj.set(
                "decodeURIComponent",
                Func::new(|input: String| -> String {
                    urlencoding::decode(&input)
                        .map(|s| s.into_owned())
                        .unwrap_or_default()
                }),
            )?;
            java_obj.set(
                "encodeURI",
                Func::new(
                    |input: String, charset: rquickjs::function::Opt<String>| -> String {
                        java_encode_uri(&input, charset.0.as_deref())
                    },
                ),
            )?;
            java_obj.set(
                "decodeURI",
                Func::new(|input: String| -> String {
                    urlencoding::decode(&input)
                        .map(|s| s.into_owned())
                        .unwrap_or_default()
                }),
            )?;
            java_obj.set(
                "now",
                Func::new(|| -> i64 { chrono::Utc::now().timestamp_millis() }),
            )?;
            java_obj.set(
                "uuid",
                Func::new(|| -> String { Uuid::new_v4().to_string() }),
            )?;

            let default_content_for_get_string = content_state.clone();
            let base_url_for_get_string = base_url_value.to_string();
            java_obj.set(
                "getString",
                Func::new(
                    move |rule: Option<String>,
                          content: Option<String>,
                          is_url: Option<bool>,
                          unescape: Option<bool>|
                          -> String {
                        let default_content = default_content_for_get_string
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .clone();
                        java_get_string(
                            rule.as_deref(),
                            content.as_deref(),
                            &default_content,
                            &base_url_for_get_string,
                            is_url.unwrap_or(false),
                            unescape.unwrap_or(true),
                        )
                    },
                ),
            )?;

            let default_content_for_get_string_list = content_state.clone();
            let base_url_for_get_string_list = base_url_value.to_string();
            java_obj.set(
                "getStringList",
                Func::new(
                    move |rule: Option<String>,
                          content: Option<String>,
                          is_url: Option<bool>|
                          -> Vec<String> {
                        let default_content = default_content_for_get_string_list
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .clone();
                        java_get_string_list(
                            rule.as_deref(),
                            content.as_deref(),
                            &default_content,
                            &base_url_for_get_string_list,
                            is_url.unwrap_or(false),
                        )
                    },
                ),
            )?;

            let content_for_elements = content_state.clone();
            let base_url_for_elements = base_url_value.to_string();
            java_obj.set(
                "getElements",
                Func::new(
                    move |rule: String, content: Option<String>, raw_css: Option<bool>| -> String {
                        let default_content = content_for_elements
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .clone();
                        java_get_elements_json_with_mode(
                            &rule,
                            content.as_deref().unwrap_or(&default_content),
                            &base_url_for_elements,
                            raw_css.unwrap_or(false),
                        )
                    },
                ),
            )?;
            let content_for_element = content_state.clone();
            let base_url_for_element = base_url_value.to_string();
            java_obj.set(
                "getElement",
                Func::new(move |rule: String, content: Option<String>| -> String {
                    let default_content = content_for_element
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    java_get_elements_json(
                        &rule,
                        content.as_deref().unwrap_or(&default_content),
                        &base_url_for_element,
                    )
                }),
            )?;

            java_obj.set(
                "put",
                Func::new(|key: String, val: String| -> bool {
                    let mut map = JS_KV.lock().unwrap_or_else(|e| e.into_inner());
                    map.insert(key, val);
                    true
                }),
            )?;
            let rule_bindings = bindings.cloned().unwrap_or_default();
            java_obj.set(
                "__nativeVariableGet",
                Func::new(move |key: String| -> String {
                    scoped_java_variable(&rule_bindings, &key)
                        .or_else(|| {
                            crate::crawler::session::current_active_session()
                                .and_then(|session| session.get_variable(&key))
                                .map(|value| json_value_to_string(&value))
                                .filter(|value| !value.is_empty())
                        })
                        .or_else(|| {
                            JS_KV
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .get(&key)
                                .cloned()
                        })
                        .unwrap_or_default()
                }),
            )?;
            java_obj.set(
                "log",
                Func::new(|msg: rquickjs::function::Opt<String>| {
                    if let Some(m) = msg.0 {
                        eprintln!("[legado::js] {}", m);
                    }
                }),
            )?;
            java_obj.set(
                "toast",
                Func::new(|_msg: rquickjs::function::Opt<String>| {}),
            )?;
            java_obj.set(
                "longToast",
                Func::new(|_msg: rquickjs::function::Opt<String>| {}),
            )?;
            let base_url_for_html_format = base_url_value.to_string();
            java_obj.set(
                "htmlFormat",
                Func::new(move |html: String| -> String {
                    crate::parser::html::format_keep_img(&html, &base_url_for_html_format)
                }),
            )?;

            globals.set("java", java_obj)?;
            eval_script(
                ctx.clone(),
                r#"(function() {
                    const java = globalThis.java;
                    const headersJson = headers => {
                        if (headers == null) return '{}';
                        if (typeof headers === 'string') {
                            try {
                                const parsed = JSON.parse(headers);
                                return JSON.stringify(parsed && typeof parsed === 'object' ? parsed : {});
                            } catch (_) { return '{}'; }
                        }
                        return typeof headers === 'object' ? JSON.stringify(headers) : '{}';
                    };
                    const responseFromJson = value => {
                        let raw;
                        try { raw = JSON.parse(String(value || '{}')); } catch (_) { raw = {}; }
                        const body = String(raw.body == null ? '' : raw.body);
                        const headers = Object.assign({}, raw.headers || {});
                        const status = Number(raw.code || raw.status || 0);
                        const header = name => {
                            const key = Object.keys(headers).find(k => k.toLowerCase() === String(name).toLowerCase());
                            return key === undefined ? null : headers[key];
                        };
                        const responseHeaders = Object.assign({}, headers, {
                            get: name => header(name),
                            names: () => Object.keys(headers),
                            toMultimap: () => Object.assign({}, headers)
                        });
                        return {
                            body: () => body,
                            statusCode: () => status,
                            code: () => status,
                            url: () => String(raw.url || ''),
                            headers: () => responseHeaders,
                            header,
                            hasHeader: name => header(name) !== null,
                            contentType: () => header('content-type') || '',
                            charset: () => {
                                const match = /charset\s*=\s*([^;\s]+)/i.exec(header('content-type') || '');
                                return match ? match[1] : 'UTF-8';
                            },
                            isSuccessful: () => status >= 200 && status < 300,
                            toString: () => body,
                            toJSON: () => raw
                        };
                    };
                    const nativeVariableGet = java.__nativeVariableGet;
                    java.get = function(url, headers) {
                        const target = String(url == null ? '' : url);
                        if (arguments.length < 2 && !/^https?:\/\//i.test(target)) {
                            return nativeVariableGet(target);
                        }
                        return responseFromJson(java.__nativeGet(target, headersJson(headers)));
                    };
                    java.post = (url, body, headers) => responseFromJson(java.__nativePost(
                        String(url), String(body == null ? '' : body), headersJson(headers)));
                    java.head = (url, headers) => responseFromJson(java.__nativeHead(
                        String(url), headersJson(headers)));
                    const strResponseFromJson = value => {
                        let raw;
                        try { raw = typeof value === 'string' ? JSON.parse(value) : value || {}; }
                        catch (_) { raw = {}; }
                        const bodyText = String(raw.body == null ? '' : raw.body);
                        const url = String(raw.url || '');
                        const code = Number(raw.code ?? raw.status ?? 200);
                        const message = String(raw.message == null ? 'OK' : raw.message);
                        const headers = Object.assign({}, raw.headers || {});
                        const responseHeaders = Object.assign({}, headers, {
                            get(name) {
                                const key = Object.keys(headers).find(k => k.toLowerCase() === String(name).toLowerCase());
                                return key === undefined ? null : headers[key];
                            },
                            names: () => Object.keys(headers),
                            toMultimap: () => Object.assign({}, headers)
                        });
                        const isSuccessful = raw.isSuccessful == null
                            ? code >= 200 && code < 300 : !!raw.isSuccessful;
                        const rawResponseBody = () => {
                            const value = new String(bodyText);
                            value.string = () => bodyText;
                            value.close = () => {};
                            return value;
                        };
                        const rawResponse = {
                            body: rawResponseBody,
                            url: () => url,
                            code: () => code,
                            message: () => message,
                            headers: () => responseHeaders,
                            isSuccessful: () => isSuccessful,
                            toString: () => `Response{code=${code}, message=${message}, url=${url}}`
                        };
                        return {
                            __ffiStrResponse: true,
                            body: () => bodyText,
                            url: () => url,
                            code: () => code,
                            message: () => message,
                            headers: () => responseHeaders,
                            raw: () => rawResponse,
                            isSuccessful: () => isSuccessful,
                            toString: () => rawResponse.toString(),
                            toJSON: () => ({
                                __ffiStrResponse: true,
                                body: bodyText,
                                url,
                                code,
                                message,
                                headers,
                                isSuccessful
                            })
                        };
                    };
                    globalThis.__readerMakeStrResponse = strResponseFromJson;
                    java.connect = (url, headers) => strResponseFromJson(
                        java.__nativeConnect(
                            String(url), headers == null ? '' : headersJson(headers)));
                    java.ajaxAll = urls => Array.from(urls || [], url =>
                        strResponseFromJson(java.__nativeAjaxAllItem(String(url))));
                    java.strToBytes = (value, charset) => JSON.parse(
                        java.__strToBytes(String(value), charset == null ? '' : String(charset)));
                    java.bytesToStr = (bytes, charset) => java.__bytesToStr(
                        JSON.stringify(Array.from(bytes == null ? [] : bytes)),
                        charset == null ? '' : String(charset));
                    java.hexDecodeToByteArray = value => JSON.parse(
                        java.__hexDecodeBytes(String(value)));
                    const nativeCacheGet = globalThis.cache.get;
                    globalThis.cache.get = key => {
                        const value = nativeCacheGet(String(key));
                        return value == null ? null : value;
                    };
                })();"#,
            )?;

            globals.set(
                "kv_get",
                Func::new(|key: String| -> Option<String> {
                    let map = JS_KV.lock().unwrap_or_else(|e| e.into_inner());
                    map.get(&key).cloned()
                }),
            )?;
            globals.set(
                "kv_put",
                Func::new(|key: String, val: String| -> bool {
                    let mut map = JS_KV.lock().unwrap_or_else(|e| e.into_inner());
                    map.insert(key, val);
                    true
                }),
            )?;
            globals.set(
                "regex_replace",
                Func::new(
                    |input: String, pattern: String, replace: String| -> String {
                        apply_regex_replace(&input, &pattern, &replace)
                    },
                ),
            )?;
            globals.set(
                "strip_ws",
                Func::new(|input: String| -> String { strip_whitespace(&input) }),
            )?;

            globals.set("book", Object::new(ctx.clone())?)?;
            globals.set("chapter", Object::new(ctx.clone())?)?;
            globals.set("title", "")?;
            globals.set("nextChapterUrl", "")?;
            globals.set("rssArticle", Object::new(ctx.clone())?)?;
            globals.set("__allowTocRefresh", false)?;

            if let Some(bindings) = bindings {
                for (key, value) in bindings {
                    let js_value = ctx.json_parse(value.to_string())?;
                    globals.set(key.as_str(), js_value)?;
                }
            }
            eval_script(
                ctx.clone(),
                "source.getLoginInfo = function() { return globalThis.loginInfo || {}; }; source.getLoginInfoMap = function() { return new Map(Object.entries(globalThis.loginInfo || {}).map(([key, value]) => [key, String(value)])); }; java.reGetBook = function() { if (globalThis.__allowTocRefresh !== true) throw new Error('java.reGetBook is only available in preUpdateJs'); return false; }; java.refreshTocUrl = function() { if (globalThis.__allowTocRefresh !== true) throw new Error('java.refreshTocUrl is only available in preUpdateJs'); return false; };",
            )?;

            eval_script(
                ctx.clone(),
                r#"if (globalThis.java && globalThis.java.getString) {
                    const _orig_getString = globalThis.java.getString;
                    globalThis.java.getString = function(rule, content, isUrl, unescape) {
                        if (typeof content === 'object' && content !== null) {
                            try { content = JSON.stringify(content); } catch (e) {}
                        }
                        const r = (rule !== undefined && rule !== null) ? String(rule) : undefined;
                        const c = (content !== undefined && content !== null) ? String(content) : undefined;
                        return _orig_getString(r, c, isUrl, unescape);
                    };
                    const _orig_getStringList = globalThis.java.getStringList;
                    globalThis.java.getStringList = function(rule, content, isUrl) {
                        if (typeof content === 'object' && content !== null) {
                            try { content = JSON.stringify(content); } catch (e) {}
                        }
                        const r = (rule !== undefined && rule !== null) ? String(rule) : undefined;
                        const c = (content !== undefined && content !== null) ? String(content) : undefined;
                        return _orig_getStringList(r, c, isUrl);
                    };
                    const _origSetContent = globalThis.java.setContent;
                    globalThis.java.setContent = function(content) {
                        if (typeof content === 'object' && content !== null) {
                            try { content = JSON.stringify(content); } catch (e) {}
                        }
                        return _origSetContent(String(content == null ? '' : content));
                    };
                    const _nativeGetElements = globalThis.java.getElements;
                    const _decorateItems = (values, rawCss = false) => {
                        if (!Array.isArray(values)) values = [];
                        const items = values.map(item => {
                            if (!item || item.__readerHtmlElement !== true) return item;
                            const attrs = item.attrs || {};
                            return {
                                __readerIndex: item.__readerIndex,
                                attr(name) { return attrs[String(name)] || ''; },
                                hasClass(name) {
                                    return String(attrs.class || '').split(/\s+/).includes(String(name));
                                },
                                html() { return item.html || ''; },
                                text() { return item.text || ''; },
                                outerHtml() { return item.outerHtml || ''; },
                                select(selector) {
                                    const rule = String(selector);
                                    const xpath = /^\s*(?:@xpath:|\/|\.\/|id\()/i.test(rule);
                                    return _wrapElements(rule, item.outerHtml || '', xpath ? false : true);
                                },
                                toString() { return item.outerHtml || ''; }
                            };
                        });
                        items.first = function() { return this.length ? this[0] : null; };
                        items.get = function(index) {
                            const position = Number(index);
                            return Number.isInteger(position) && position >= 0 && position < this.length
                                ? this[position] : null;
                        };
                        items.size = function() { return this.length; };
                        items.toArray = function() { return Array.from(this); };
                        return items;
                    };
                    const _wrapElements = (rule, content, rawCss = false) => {
                        const raw = _nativeGetElements(rule, content, rawCss);
                        let values;
                        try { values = JSON.parse(raw); } catch (e) { values = []; }
                        return _decorateItems(values, rawCss);
                    };
                    globalThis.__wrapReaderElements = values => _decorateItems(values, false);
                    if (Array.isArray(globalThis.result)) {
                        globalThis.result = _decorateItems(globalThis.result, false);
                    }
                    const _attachVariableMap = value => {
                        if (!value || typeof value !== 'object') return;
                        if (typeof value.getVariable !== 'function') {
                            value.getVariable = function(key) {
                                const variables = this.variableMap || {};
                                const found = variables[String(key)];
                                return found == null ? '' : String(found);
                            };
                        }
                    };
                    _attachVariableMap(globalThis.book);
                    _attachVariableMap(globalThis.chapter);
                    globalThis.java.getElements = _wrapElements;
                    globalThis.java.getElement = function(rule, content) {
                        const items = _wrapElements(rule, content);
                        return items.length > 0 ? items[0] : null;
                    };
                }"#,
            )?;

            eval_script(
                ctx.clone(),
                r#"(function() {
                    const asObject = value => value && (typeof value === 'object' || typeof value === 'function')
                        ? value : {};
                    globalThis.org = asObject(globalThis.org);
                    globalThis.org.jsoup = asObject(globalThis.org.jsoup);
                    globalThis.org.jsoup.Jsoup = asObject(globalThis.org.jsoup.Jsoup);
                    if (typeof globalThis.org.jsoup.Jsoup.parse !== 'function') {
                        globalThis.org.jsoup.Jsoup.parse = function(html) {
                            const source = String(html == null ? '' : html);
                            return {
                                select(selector) {
                                    return globalThis.java.getElements(String(selector), source, true);
                                }
                            };
                        };
                    }
                })();"#,
            )?;

            eval_script(
                ctx.clone(),
                r#"(function() {
                    const preferenceKey = (name, key) => `__prefs:${String(name)}:${String(key)}`;
                    const sharedPreferences = name => ({
                        getString(key, defaultValue) {
                            const value = source.getVariable(preferenceKey(name, key));
                            return value === '' ? String(defaultValue == null ? '' : defaultValue) : value;
                        },
                        edit() {
                            const changes = {};
                            const editor = {
                                putString(key, value) { changes[String(key)] = String(value); return editor; },
                                remove(key) { changes[String(key)] = null; return editor; },
                                commit() {
                                    for (const [key, value] of Object.entries(changes)) {
                                        source.setVariable(preferenceKey(name, key), value == null ? '' : value);
                                    }
                                    return true;
                                },
                                apply() { editor.commit(); }
                            };
                            return editor;
                        }
                    });
                    const hostContext = {
                        MODE_PRIVATE: 0,
                        getSharedPreferences(name) { return sharedPreferences(name); }
                    };
                    const log = {
                        d(tag, message) { java.log(`[D] ${String(tag)}: ${String(message)}`); return 0; },
                        e(tag, message) { java.log(`[E] ${String(tag)}: ${String(message)}`); return 0; }
                    };
                    const toBytes = value => {
                        if (Array.isArray(value)) return value.map(byte => Number(byte) & 0xff);
                        if (value instanceof Uint8Array) return Array.from(value);
                        return java.strToBytes(String(value == null ? '' : value), 'UTF-8');
                    };
                    const base64 = {
                        DEFAULT: 0, NO_PADDING: 1, NO_WRAP: 2, URL_SAFE: 8,
                        encodeToString(value, flags) {
                            return java.__base64EncodeBytes(
                                JSON.stringify(toBytes(value)), Number(flags || 0));
                        },
                        decode(value, flags) {
                            const input = Array.isArray(value) || value instanceof Uint8Array
                                ? String.fromCharCode(...toBytes(value))
                                : String(value == null ? '' : value);
                            return JSON.parse(java.__base64DecodeBytes(
                                input, Number(flags || 0)));
                        }
                    };
                    const javaBase64Encoder = flags => ({
                        encodeToString(value) { return base64.encodeToString(value, flags); },
                        withoutPadding() { return javaBase64Encoder(flags | base64.NO_PADDING); }
                    });
                    const javaBase64 = {
                        getEncoder() { return javaBase64Encoder(0); },
                        getDecoder() { return { decode: value => base64.decode(value, 0) }; },
                        getUrlEncoder() { return javaBase64Encoder(base64.URL_SAFE); },
                        getUrlDecoder() { return { decode: value => base64.decode(value, base64.URL_SAFE) }; }
                    };
                    globalThis.System = Object.assign(globalThis.System || {}, {
                        currentTimeMillis: () => java.now()
                    });
                    const randomUuid = () => {
                        const value = java.randomUUID();
                        return { toString: () => value };
                    };
                    globalThis.UUID = { randomUUID: randomUuid };
                    java.util = java.util || {};
                    java.util.UUID = { randomUUID: randomUuid };
                    java.util.Base64 = javaBase64;

                    if (!String.prototype.getBytes) {
                        Object.defineProperty(String.prototype, 'getBytes', {
                            value(charset) {
                                return java.strToBytes(
                                    String(this), charset == null ? 'UTF-8' : String(charset));
                            }
                        });
                    }

                    const JsString = globalThis.String;
                    function JavaString(value, charset) {
                        const text = Array.isArray(value) || value instanceof Uint8Array
                            ? java.bytesToStr(
                                value, charset == null ? 'UTF-8' : JsString(charset))
                            : JsString(value == null ? '' : value);
                        return new.target ? new JsString(text) : text;
                    }
                    function SecretKeySpec(key, algorithm) {
                        return { key: toBytes(key), algorithm: JsString(algorithm) };
                    }
                    function IvParameterSpec(iv) {
                        return { iv: toBytes(iv) };
                    }
                    const Arrays = {
                        copyOfRange(value, start, end) {
                            const bytes = Array.from(value == null ? [] : value).slice(start, end);
                            while (bytes.length < end - start) bytes.push(0);
                            return bytes;
                        }
                    };
                    const Cipher = {
                        DECRYPT_MODE: 2,
                        getInstance: algorithm => ({
                            init(mode, key, iv) { this.mode = mode; this.key = key; this.iv = iv; },
                            doFinal(data) {
                                return JSON.parse(java.__aesDecryptByteArray(JSON.stringify({
                                    algorithm, mode: this.mode, key: this.key.key,
                                    iv: this.iv.iv, data: toBytes(data)
                                })));
                            }
                        })
                    };
                    const Mac = {
                        getInstance: algorithm => ({
                            init(key) { this.key = key; },
                            doFinal(data) {
                                return JSON.parse(java.__hmacBytes(
                                    String(algorithm),
                                    JSON.stringify(this.key ? this.key.key : []),
                                    JSON.stringify(toBytes(data))));
                            }
                        })
                    };
                    const URLEncoder = {
                        encode(value, charset) {
                            return java.encodeURI(
                                String(value), charset == null ? 'UTF-8' : String(charset))
                                .replace(/%20/g, '+')
                                .replace(/%2A/gi, '*')
                                .replace(/~/g, '%7E');
                        }
                    };
                    const URLDecoder = {
                        decode(value) {
                            return decodeURIComponent(String(value).replace(/\+/g, ' '));
                        }
                    };
                    const DatatypeConverter = {
                        printHexBinary(value) {
                            return toBytes(value)
                                .map(byte => byte.toString(16).padStart(2, '0'))
                                .join('')
                                .toUpperCase();
                        },
                        parseHexBinary(value) {
                            return JSON.parse(java.__hexDecodeBytes(String(value)));
                        }
                    };
                    const markClass = (name, value) => {
                        try {
                            Object.defineProperty(value, '__javaName', {
                                value: name, configurable: true
                            });
                        } catch (_) {}
                        return value;
                    };

                    globalThis.Packages = globalThis.Packages || {};
                    Packages.java = Packages.java || {};
                    Packages.java.lang = Packages.java.lang || {};
                    Packages.java.net = Packages.java.net || {};
                    Packages.java.util = Packages.java.util || {};
                    Packages.javax = Packages.javax || {};
                    Packages.javax.crypto = Packages.javax.crypto || {};
                    Packages.javax.crypto.spec = Packages.javax.crypto.spec || {};
                    Packages.javax.xml = Packages.javax.xml || {};
                    Packages.javax.xml.bind = Packages.javax.xml.bind || {};
                    Packages.android = Packages.android || {};
                    Packages.android.util = Packages.android.util || {};

                    Packages.java.lang.String = markClass('String', JavaString);
                    Packages.java.net.URLEncoder = markClass('URLEncoder', URLEncoder);
                    Packages.java.net.URLDecoder = markClass('URLDecoder', URLDecoder);
                    Packages.java.util.Arrays = markClass('Arrays', Arrays);
                    Packages.java.util.Base64 = markClass('Base64', javaBase64);
                    Packages.java.util.UUID = markClass('UUID', java.util.UUID);
                    Packages.javax.crypto.Mac = markClass('Mac', Mac);
                    Packages.javax.crypto.Cipher = markClass('Cipher', Cipher);
                    Packages.javax.crypto.spec.SecretKeySpec =
                        markClass('SecretKeySpec', SecretKeySpec);
                    Packages.javax.crypto.spec.IvParameterSpec =
                        markClass('IvParameterSpec', IvParameterSpec);
                    Packages.javax.xml.bind.DatatypeConverter =
                        markClass('DatatypeConverter', DatatypeConverter);
                    Packages.android.util.Base64 = markClass('Base64', base64);

                    const exposeJavaValue = (target, value) => {
                        if (!value) return;
                        if (value.__javaName) {
                            target[value.__javaName] = value;
                            return;
                        }
                        if (typeof value === 'object') {
                            for (const candidate of Object.values(value)) {
                                if (candidate && candidate.__javaName) {
                                    target[candidate.__javaName] = candidate;
                                }
                            }
                        }
                    };
                    globalThis.JavaImporter = function(...values) {
                        values.forEach(value => exposeJavaValue(this, value));
                        this.importPackage = (...packages) => {
                            packages.forEach(pkg => exposeJavaValue(this, pkg));
                            return this;
                        };
                    };
                    globalThis.URLEncoder = URLEncoder;
                    globalThis.URLDecoder = URLDecoder;
                    globalThis.Log = log;
                    globalThis.android = globalThis.android || {};
                    globalThis.android.util = globalThis.android.util || {};
                    globalThis.android.util.Log = log;
                    globalThis.android.util.Base64 = base64;
                    globalThis.application = hostContext;
                    globalThis.context = hostContext;
                    globalThis.activity = Object.assign({}, hostContext);
                    globalThis.app = hostContext;
                })();"#,
            )?;

            if !shared_js.trim().is_empty() {
                eval_script(ctx.clone(), &shared_js)?;
            }

            eval_script(
                ctx.clone(),
                r#"if (globalThis.result && globalThis.result.__ffiStrResponse === true) {
                    globalThis.result = globalThis.__readerMakeStrResponse(globalThis.result);
                }"#,
            )?;

            // Rule scripts may run once per chapter while JS_ENV is reused. Keep
            // let/const declarations local to this evaluation to avoid a later
            // chapter failing with a global lexical redeclaration SyntaxError.
            let scoped_script = format!("{{\n{script}\n}}");
            let v = eval_script(ctx.clone(), &scoped_script)?;

            let result = if v.is_null() || v.is_undefined() {
                if !template_result {
                    if let Ok(res_val) = globals.get::<_, rquickjs::Value<'_>>("result") {
                        if !res_val.is_null() && !res_val.is_undefined() {
                            if let Some(s) = res_val.clone().into_string() {
                                let s: rquickjs::String<'_> = s;
                                s.to_string()
                                    .map(|value| value.to_string())
                                    .unwrap_or_default()
                            } else {
                                match ctx.json_stringify(res_val) {
                                    Ok(Some(json)) => json.to_string().unwrap_or_default(),
                                    _ => String::new(),
                                }
                            }
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                }
            } else if template_result {
                let value: rquickjs::Coerced<std::string::String> =
                    rquickjs::FromJs::from_js(&ctx, v)?;
                value.0
            } else if let Some(s) = v.clone().into_string() {
                let s: rquickjs::String<'_> = s;
                s.to_string()
                    .map(|value| value.to_string())
                    .unwrap_or_default()
            } else {
                match ctx.json_stringify(v) {
                    Ok(Some(json)) => json.to_string().unwrap_or_default(),
                    _ => String::new(),
                }
            };

            Ok(result)
        }) // closes ctx.with
    }) // closes JS_ENV.with
}

fn eval_js_reentrant<'js>(
    ctx: rquickjs::Ctx<'js>,
    script: &str,
    input: Option<&str>,
    base_url: Option<&str>,
    key: Option<&str>,
    page: Option<i32>,
    _source_key: Option<&str>,
    bindings: Option<&HashMap<String, JsonValue>>,
    template_result: bool,
) -> anyhow::Result<String> {
    let globals = ctx.globals();
    let mut saved = Vec::<(String, Option<Value<'js>>)>::new();

    let mut save_global = |name: &str| -> anyhow::Result<()> {
        if saved.iter().any(|(saved_name, _)| saved_name == name) {
            return Ok(());
        }
        let value = if globals.contains_key(name)? {
            Some(globals.get::<_, Value<'js>>(name)?)
        } else {
            None
        };
        saved.push((name.to_string(), value));
        Ok(())
    };

    for name in ["input", "result", "src", "base_url", "baseUrl", "url", "key", "page"] {
        save_global(name)?;
    }
    if let Some(bindings) = bindings {
        for name in bindings.keys() {
            save_global(name)?;
        }
    }

    let result = (|| -> anyhow::Result<String> {
        let input_value = input.unwrap_or("");
        let base_url_value = base_url.unwrap_or("");
        globals.set("input", input_value)?;
        globals.set("result", input_value)?;
        globals.set("src", input_value)?;
        globals.set("base_url", base_url_value)?;
        globals.set("baseUrl", base_url_value)?;
        globals.set("url", base_url_value)?;
        if let Some(key) = key {
            globals.set("key", key)?;
        }
        if let Some(page) = page {
            globals.set("page", page)?;
        }
        if let Some(bindings) = bindings {
            for (name, value) in bindings {
                globals.set(name.as_str(), ctx.json_parse(value.to_string())?)?;
            }
        }

        let scoped_script = format!("{{\n{script}\n}}");
        let value = eval_script(ctx.clone(), &scoped_script)?;
        if value.is_null() || value.is_undefined() {
            if template_result {
                return Ok(String::new());
            }
            let result_value = globals.get::<_, Value<'js>>("result")?;
            if result_value.is_null() || result_value.is_undefined() {
                return Ok(String::new());
            }
            if let Some(string) = result_value.clone().into_string() {
                return Ok(string.to_string().unwrap_or_default());
            }
            return Ok(ctx
                .json_stringify(result_value)?
                .and_then(|json| json.to_string().ok())
                .unwrap_or_default());
        }
        if template_result {
            let value: rquickjs::Coerced<String> = rquickjs::FromJs::from_js(&ctx, value)?;
            return Ok(value.0);
        }
        if let Some(string) = value.clone().into_string() {
            return Ok(string.to_string().unwrap_or_default());
        }
        Ok(ctx
            .json_stringify(value)?
            .and_then(|json| json.to_string().ok())
            .unwrap_or_default())
    })();

    for (name, value) in saved.into_iter().rev() {
        match value {
            Some(value) => {
                let _ = globals.set(name.as_str(), value);
            }
            None => {
                let _ = globals.remove(name.as_str());
            }
        }
    }
    result
}

pub(crate) fn java_get_string(
    rule: Option<&str>,
    content: Option<&str>,
    default_content: &str,
    base_url: &str,
    is_url: bool,
    unescape: bool,
) -> String {
    let Some(rule) = rule.map(str::trim).filter(|s| !s.is_empty()) else {
        return String::new();
    };

    let target_content = content.unwrap_or(default_content).trim();
    if target_content.is_empty() {
        return String::new();
    }

    // 支持 || 与 && 组合符 (规范 6.8 & 8.2)
    let split = rule_analyzer::split_top_level(rule, &["||", "&&"]);
    if let Some(delim) = split.delimiter.as_deref() {
        if delim == "||" {
            for part in split.parts {
                let res = java_get_string(
                    Some(&part),
                    content,
                    default_content,
                    base_url,
                    is_url,
                    unescape,
                );
                if !res.is_empty() {
                    return res;
                }
            }
            return String::new();
        } else if delim == "&&" {
            let mut results = Vec::new();
            for part in split.parts {
                let res = java_get_string(
                    Some(&part),
                    content,
                    default_content,
                    base_url,
                    is_url,
                    unescape,
                );
                if !res.is_empty() {
                    results.push(res);
                }
            }
            return results.join("\n");
        }
    }

    // 分离 ## 替换正则 (规范 6.7)
    let (main_rule, regex_part) = rule_engine::split_legado_regex(rule);
    let main_rule = main_rule.trim();

    let mut res = if main_rule.is_empty() {
        target_content.to_string()
    } else if main_rule.starts_with("<js>")
        || main_rule.starts_with("@js:")
        || main_rule.starts_with("js:")
    {
        let script = rule_engine::strip_js_rule(main_rule);
        eval_js(script, target_content, base_url).unwrap_or_default()
    } else if let Some(pure) = html::xpath_rule(main_rule) {
        html::select_xpath(target_content, pure)
            .into_iter()
            .next()
            .unwrap_or_default()
    } else if main_rule.starts_with("@json:")
        || main_rule.starts_with("@Json:")
        || main_rule.starts_with("@JSON:")
        || main_rule.starts_with("$.")
        || main_rule.starts_with("$[")
        || (target_content.starts_with('{') || target_content.starts_with('['))
    {
        // JSON 模式
        let pure = if let Some(stripped) = main_rule
            .strip_prefix("@json:")
            .or_else(|| main_rule.strip_prefix("@Json:"))
            .or_else(|| main_rule.strip_prefix("@JSON:"))
        {
            stripped.trim()
        } else {
            main_rule
        };

        if let Ok(v) = serde_json::from_str::<serde_json::Value>(target_content) {
            if pure.is_empty() {
                jsonpath::value_to_string(&v).unwrap_or_default()
            } else if pure.starts_with('$') {
                jsonpath::jsonpath_first_string(&v, pure).unwrap_or_default()
            } else if let Some(val) = v.get(pure) {
                jsonpath::value_to_string(val).unwrap_or_default()
            } else {
                jsonpath::jsonpath_first_string(&v, &format!("$.{}", pure)).unwrap_or_default()
            }
        } else {
            String::new()
        }
    } else if main_rule.starts_with("@regex:") || main_rule.starts_with(':') {
        // Regex 模式
        let pure = if let Some(stripped) = main_rule.strip_prefix("@regex:") {
            stripped.trim()
        } else {
            &main_rule[1..]
        };
        if let Ok(re) = regex::Regex::new(pure) {
            if let Some(caps) = re.captures(target_content) {
                if let Some(m) = caps.get(1).or_else(|| caps.get(0)) {
                    m.as_str().to_string()
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        } else {
            String::new()
        }
    } else {
        // 默认 CSS / HTML 模式
        let pure = if let Some(stripped) = main_rule
            .strip_prefix("@css:")
            .or_else(|| main_rule.strip_prefix("@CSS:"))
        {
            stripped.trim()
        } else {
            main_rule
        };
        let doc = html::parse_document(target_content);
        html::select_all_text(&doc, pure)
            .or_else(|| html::select_text(&doc, pure))
            .unwrap_or_default()
    };

    if let Some(regex) = regex_part {
        res = rule_engine::apply_legado_regex(&res, regex);
    }

    if unescape && res.contains('&') {
        res = html::html_unescape(&res);
    }

    if is_url && !res.is_empty() {
        res = rule_engine::resolve_url(base_url, &res);
    }

    res
}

pub(crate) fn java_get_string_list(
    rule: Option<&str>,
    content: Option<&str>,
    default_content: &str,
    base_url: &str,
    is_url: bool,
) -> Vec<String> {
    let Some(rule) = rule.map(str::trim).filter(|s| !s.is_empty()) else {
        return Vec::new();
    };

    let target_content = content.unwrap_or(default_content).trim();
    if target_content.is_empty() {
        return Vec::new();
    }

    // 支持 || 与 && / %% 组合符 (规范 6.9 & 8.2)
    let split = rule_analyzer::split_top_level(rule, &["||", "&&", "%%"]);
    if let Some(delim) = split.delimiter.as_deref() {
        if delim == "||" {
            for part in split.parts {
                let res =
                    java_get_string_list(Some(&part), content, default_content, base_url, is_url);
                if !res.is_empty() {
                    return res;
                }
            }
            return Vec::new();
        } else if delim == "&&" || delim == "%%" {
            let mut results = Vec::new();
            for part in split.parts {
                let res =
                    java_get_string_list(Some(&part), content, default_content, base_url, is_url);
                results.extend(res);
            }
            return results;
        }
    }

    // 分离 ## 替换正则 (规范 6.7)
    let (main_rule, regex_part) = rule_engine::split_legado_regex(rule);
    let main_rule = main_rule.trim();

    let mut list = if main_rule.is_empty() {
        vec![target_content.to_string()]
    } else if main_rule.starts_with("<js>")
        || main_rule.starts_with("@js:")
        || main_rule.starts_with("js:")
    {
        let script = rule_engine::strip_js_rule(main_rule);
        if let Ok(js_res) = eval_js(script, target_content, base_url) {
            js_res
                .lines()
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            Vec::new()
        }
    } else if let Some(pure) = html::xpath_rule(main_rule) {
        html::select_xpath(target_content, pure)
    } else if main_rule.starts_with("@json:")
        || main_rule.starts_with("@Json:")
        || main_rule.starts_with("@JSON:")
        || main_rule.starts_with("$.")
        || main_rule.starts_with("$[")
        || (target_content.starts_with('{') || target_content.starts_with('['))
    {
        let pure = if let Some(stripped) = main_rule
            .strip_prefix("@json:")
            .or_else(|| main_rule.strip_prefix("@Json:"))
            .or_else(|| main_rule.strip_prefix("@JSON:"))
        {
            stripped.trim()
        } else {
            main_rule
        };

        if let Ok(v) = serde_json::from_str::<serde_json::Value>(target_content) {
            if pure.starts_with('$') {
                jsonpath::jsonpath_query(&v, pure)
                    .iter()
                    .filter_map(jsonpath::value_to_string)
                    .collect()
            } else if let Some(val) = v.get(pure) {
                match val {
                    serde_json::Value::Array(arr) => {
                        arr.iter().filter_map(jsonpath::value_to_string).collect()
                    }
                    other => jsonpath::value_to_string(other).into_iter().collect(),
                }
            } else {
                jsonpath::jsonpath_query(&v, &format!("$.{}", pure))
                    .iter()
                    .filter_map(jsonpath::value_to_string)
                    .collect()
            }
        } else {
            Vec::new()
        }
    } else if main_rule.starts_with("@regex:") || main_rule.starts_with(':') {
        let pure = if let Some(stripped) = main_rule.strip_prefix("@regex:") {
            stripped.trim()
        } else {
            &main_rule[1..]
        };
        if let Ok(re) = regex::Regex::new(pure) {
            re.captures_iter(target_content)
                .filter_map(|caps| {
                    caps.get(1)
                        .or_else(|| caps.get(0))
                        .map(|m| m.as_str().to_string())
                })
                .collect()
        } else {
            Vec::new()
        }
    } else {
        let pure = if let Some(stripped) = main_rule
            .strip_prefix("@css:")
            .or_else(|| main_rule.strip_prefix("@CSS:"))
        {
            stripped.trim()
        } else {
            main_rule
        };
        let doc = html::parse_document(target_content);
        html::select_text_list(&doc, pure)
    };

    if let Some(regex) = regex_part {
        list = list
            .into_iter()
            .map(|item| rule_engine::apply_legado_regex(&item, regex))
            .collect();
    }

    if is_url {
        list = list
            .into_iter()
            .filter(|item| !item.is_empty())
            .map(|item| rule_engine::resolve_url(base_url, &item))
            .collect();
    }

    list
}

fn java_get_elements_json(rule: &str, content: &str, base_url: &str) -> String {
    java_get_elements_json_with_mode(rule, content, base_url, false)
}

fn java_get_elements_json_with_mode(
    rule: &str,
    content: &str,
    base_url: &str,
    raw_css: bool,
) -> String {
    let rule = rule.trim();
    let content = content.trim();
    if rule.is_empty() || content.is_empty() {
        return "[]".to_string();
    }

    let lower_rule = rule.to_ascii_lowercase();
    let explicit_css = rule.starts_with("@@") || lower_rule.starts_with("@css:");
    let explicit_other_mode = html::xpath_rule(rule).is_some()
        || lower_rule.starts_with("@regex:")
        || lower_rule.starts_with("@js:")
        || lower_rule.starts_with("js:")
        || rule.starts_with(':');
    let json_content = serde_json::from_str::<JsonValue>(content).ok();
    let json_rule = rule.starts_with('$') || lower_rule.starts_with("@json:");
    if !raw_css && !explicit_css && !explicit_other_mode && (json_rule || json_content.is_some()) {
        let Some(value) = json_content else {
            return "[]".to_string();
        };
        let pure = if lower_rule.starts_with("@json:") {
            &rule[6..]
        } else {
            rule
        }
        .trim();
        let values = if pure.starts_with('$') {
            jsonpath::jsonpath_query(&value, pure)
        } else if let Some(found) = value.get(pure) {
            match found {
                JsonValue::Array(items) => items.clone(),
                other => vec![other.clone()],
            }
        } else {
            jsonpath::jsonpath_query(&value, &format!("$.{pure}"))
        };
        return serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string());
    }

    if !raw_css {
        if let Some(pure) = html::xpath_rule(rule) {
            return html::select_xpath_elements_json(content, pure);
        }
    }

    if !raw_css
        && (rule.starts_with("@regex:")
            || rule.starts_with(':')
            || rule.starts_with("@js:")
            || rule.starts_with("js:"))
    {
        let values = java_get_string_list(Some(rule), Some(content), "", base_url, false)
            .into_iter()
            .map(JsonValue::String)
            .collect::<Vec<_>>();
        return serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string());
    }

    let selector = if raw_css {
        rule
    } else if rule.starts_with("@@") {
        &rule[2..]
    } else if lower_rule.starts_with("@css:") {
        &rule[5..]
    } else {
        rule
    }
    .trim();
    let document = html::parse_document(content);
    let elements = if raw_css {
        html::select_css_list(&document, selector)
    } else {
        html::select_list(&document, selector)
    };
    let values = elements
        .into_iter()
        .map(|element| {
            let attrs = element
                .value()
                .attrs()
                .map(|(name, value)| (name.to_string(), JsonValue::String(value.to_string())))
                .collect::<serde_json::Map<_, _>>();
            serde_json::json!({
                "__readerHtmlElement": true,
                "attrs": attrs,
                "html": element.inner_html(),
                "outerHtml": element.html(),
                "text": element.text().collect::<Vec<_>>().join(" ").trim(),
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string())
}

fn java_aes_base64_decode_to_string(input: &str, key: &str, algorithm: &str, iv: &str) -> String {
    let algorithm = algorithm.to_ascii_uppercase();
    if algorithm != "AES/CBC/PKCS5PADDING" && algorithm != "AES/CBC/PKCS7PADDING" {
        return String::new();
    }

    let Ok(mut encrypted) = base64::engine::general_purpose::STANDARD.decode(input.trim()) else {
        return String::new();
    };

    let Ok(cipher) = Aes128CbcDecryptor::new_from_slices(key.as_bytes(), iv.as_bytes()) else {
        return String::new();
    };

    cipher
        .decrypt_padded_mut::<Pkcs7>(&mut encrypted)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok())
        .unwrap_or_default()
}

fn java_aes_decrypt_byte_array(input: &str) -> Vec<u8> {
    let Ok(value) = serde_json::from_str::<JsonValue>(input) else {
        return Vec::new();
    };
    let bytes = |key: &str| -> Option<Vec<u8>> {
        value
            .get(key)?
            .as_array()?
            .iter()
            .map(|byte| u8::try_from(byte.as_u64()?).ok())
            .collect()
    };
    if value.get("mode").and_then(JsonValue::as_i64) != Some(2)
        || !matches!(
            value
                .get("algorithm")
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_ascii_uppercase()
                .as_str(),
            "AES/CBC/PKCS5PADDING" | "AES/CBC/PKCS7PADDING"
        )
    {
        return Vec::new();
    }
    let (Some(key), Some(iv), Some(mut encrypted)) = (bytes("key"), bytes("iv"), bytes("data"))
    else {
        return Vec::new();
    };
    let Ok(cipher) = Aes128CbcDecryptor::new_from_slices(&key, &iv) else {
        return Vec::new();
    };
    cipher
        .decrypt_padded_mut::<Pkcs7>(&mut encrypted)
        .map(|plaintext| plaintext.to_vec())
        .unwrap_or_default()
}

fn java_aes_decrypt_bytes(input: &str) -> String {
    String::from_utf8(java_aes_decrypt_byte_array(input)).unwrap_or_default()
}

fn java_aes_base64_encode(input: &str, key: &str, algorithm: &str, iv: &str) -> String {
    let algorithm = algorithm.to_ascii_uppercase();
    if algorithm != "AES/CBC/PKCS5PADDING" && algorithm != "AES/CBC/PKCS7PADDING" {
        return String::new();
    }
    let Ok(cipher) = Aes128CbcEncryptor::new_from_slices(key.as_bytes(), iv.as_bytes()) else {
        return String::new();
    };
    let mut buf = vec![0u8; input.len() + 16];
    buf[..input.len()].copy_from_slice(input.as_bytes());
    if let Ok(encrypted) = cipher.encrypt_padded_mut::<Pkcs7>(&mut buf, input.len()) {
        base64::engine::general_purpose::STANDARD.encode(encrypted)
    } else {
        String::new()
    }
}

fn java_aes_encode(input: &str, key: &str, algorithm: &str, iv: &str) -> String {
    let algorithm = algorithm.to_ascii_uppercase();
    if algorithm != "AES/CBC/PKCS5PADDING" && algorithm != "AES/CBC/PKCS7PADDING" {
        return String::new();
    }
    let Ok(cipher) = Aes128CbcEncryptor::new_from_slices(key.as_bytes(), iv.as_bytes()) else {
        return String::new();
    };
    let mut buf = vec![0u8; input.len() + 16];
    buf[..input.len()].copy_from_slice(input.as_bytes());
    if let Ok(encrypted) = cipher.encrypt_padded_mut::<Pkcs7>(&mut buf, input.len()) {
        hex::encode(encrypted)
    } else {
        String::new()
    }
}

// 修复：sloppy 全局模式（见下）
fn eval_script<'js>(ctx: rquickjs::Ctx<'js>, script: &str) -> anyhow::Result<Value<'js>> {
    use std::ffi::CString;
    // Legado 规则普遍使用隐式全局变量（如 `time=...;t=...` 不带 var 声明），
    // 必须用 sloppy（JS_EVAL_TYPE_GLOBAL=0）模式求值；module/strict 模式会抛
    // ReferenceError，导致规则走 catch 降级分支（如 qmbook 目录 URL 退化为
    // 无签名 COS 地址而 403）。
    // 注：rquickjs 的 EvalOptions 为 #[non_exhaustive] 且 Ctx::eval 默认 Module
    // （strict）模式，无法在外部构造/修改，故直接调用 qjs::JS_Eval 显式指定
    // JS_EVAL_TYPE_GLOBAL。
    let src = CString::new(script)?;
    let file_name = c"eval_script";
    let val = unsafe {
        rquickjs::qjs::JS_Eval(
            ctx.as_raw().as_ptr(),
            src.as_ptr(),
            src.as_bytes().len() as _,
            file_name.as_ptr(),
            rquickjs::qjs::JS_EVAL_TYPE_GLOBAL as i32,
        )
    };
    // 与 rquickjs Ctx::handle_exception 等价：JS_TAG_EXCEPTION 时取异常信息
    unsafe {
        if rquickjs::qjs::JS_VALUE_GET_NORM_TAG(val) != rquickjs::qjs::JS_TAG_EXCEPTION {
            let v = Value::from_raw(ctx.clone(), val);
            return Ok(v);
        }
    }
    if let Some(exception) = ctx.catch().into_exception() {
        return Err(anyhow::anyhow!("JS Exception: {:?}", exception));
    }
    Err(anyhow::anyhow!("JS Exception"))
}

fn active_js_lib_script() -> anyhow::Result<String> {
    let js_lib = ACTIVE_JS_LIB.with(|cell| cell.borrow().clone());
    let Some(js_lib) = js_lib.filter(|value| !value.trim().is_empty()) else {
        return Ok(String::new());
    };
    let cache_key = md5_hex(&js_lib);
    if let Some(cached) = JS_LIB_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&cache_key)
        .cloned()
    {
        return Ok(cached);
    }

    let compiled = compile_js_lib(&js_lib)?;
    JS_LIB_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(cache_key, compiled.clone());
    Ok(compiled)
}

fn compile_js_lib(js_lib: &str) -> anyhow::Result<String> {
    let trimmed = js_lib.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.starts_with('{') {
        if let Ok(value) = serde_json::from_str::<JsonValue>(trimmed) {
            if let Some(map) = value.as_object() {
                let mut scripts = Vec::new();
                for entry in map.values().filter_map(JsonValue::as_str) {
                    if is_absolute_http_url(entry) {
                        scripts.push(resolve_js_lib_entry(entry)?);
                    }
                }
                return Ok(scripts.join("\n"));
            }
        }
    }
    Ok(trimmed.to_string())
}

fn is_absolute_http_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| matches!(url.scheme(), "http" | "https"))
}

fn resolve_js_lib_entry(entry: &str) -> anyhow::Result<String> {
    let value = entry.trim();
    if is_absolute_http_url(value) {
        return Ok(active_js_http_client().request_text(Method::GET, value, &[], None)?);
    }
    Ok(value.to_string())
}

fn java_time_format(timestamp: i64) -> String {
    let secs = if timestamp > 1_000_000_000_000 {
        timestamp / 1000
    } else {
        timestamp
    };
    match Local.timestamp_opt(secs, 0).single() {
        Some(dt) => dt.format("%Y-%m-%d %H:%M").to_string(),
        None => String::new(),
    }
}

fn java_time_format_utc(timestamp_ms: i64, format: &str, offset_ms: i64) -> String {
    let Ok(offset_seconds) = i32::try_from(offset_ms / 1000) else {
        return String::new();
    };
    let Some(offset) = FixedOffset::east_opt(offset_seconds) else {
        return String::new();
    };
    let Some(utc) = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(timestamp_ms) else {
        return String::new();
    };
    let datetime = utc.with_timezone(&offset);
    datetime
        .format(&java_date_pattern_to_chrono(format))
        .to_string()
}

fn java_date_pattern_to_chrono(pattern: &str) -> String {
    let chars = pattern.chars().collect::<Vec<_>>();
    let mut output = String::new();
    let mut index = 0;
    let mut quoted = false;

    while index < chars.len() {
        let ch = chars[index];
        if ch == '\'' {
            if chars.get(index + 1) == Some(&'\'') {
                output.push('\'');
                index += 2;
                continue;
            }
            quoted = !quoted;
            index += 1;
            continue;
        }
        if quoted || !ch.is_ascii_alphabetic() {
            if ch == '%' {
                output.push_str("%%");
            } else {
                output.push(ch);
            }
            index += 1;
            continue;
        }

        let mut end = index + 1;
        while end < chars.len() && chars[end] == ch {
            end += 1;
        }
        let width = end - index;
        let directive = match ch {
            'y' => Some(if width == 2 { "%y" } else { "%Y" }),
            'M' => Some(match width {
                1 => "%-m",
                2 => "%m",
                3 => "%b",
                _ => "%B",
            }),
            'd' => Some(if width == 1 { "%-d" } else { "%d" }),
            'H' => Some(if width == 1 { "%-H" } else { "%H" }),
            'h' => Some(if width == 1 { "%-I" } else { "%I" }),
            'm' => Some(if width == 1 { "%-M" } else { "%M" }),
            's' => Some(if width == 1 { "%-S" } else { "%S" }),
            'S' => Some(match width {
                1 => "%1f",
                2 => "%2f",
                _ => "%3f",
            }),
            'a' => Some("%p"),
            'E' => Some(if width <= 3 { "%a" } else { "%A" }),
            'u' => Some("%u"),
            'Z' => Some("%z"),
            'X' => Some(if width >= 3 { "%:z" } else { "%z" }),
            _ => None,
        };
        if let Some(directive) = directive {
            output.push_str(directive);
        } else {
            for _ in 0..width {
                output.push(ch);
            }
        }
        index = end;
    }

    output
}

fn charset_encoding(charset: Option<&str>) -> &'static encoding_rs::Encoding {
    charset
        .and_then(|label| encoding_rs::Encoding::for_label(label.trim().as_bytes()))
        .unwrap_or(encoding_rs::UTF_8)
}

fn java_str_to_bytes(input: &str, charset: Option<&str>) -> Vec<u8> {
    charset_encoding(charset).encode(input).0.into_owned()
}

fn java_bytes_to_str(bytes: &[u8], charset: Option<&str>) -> String {
    charset_encoding(charset).decode(bytes).0.into_owned()
}

fn java_base64_decode(input: &str, charset: Option<&str>) -> String {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(input.trim()));
    bytes
        .map(|bytes| java_bytes_to_str(&bytes, charset))
        .unwrap_or_default()
}

fn json_byte_array(input: &str) -> Vec<u8> {
    serde_json::from_str::<Vec<i64>>(input)
        .unwrap_or_default()
        .into_iter()
        .map(|byte| byte.rem_euclid(256) as u8)
        .collect()
}

fn java_base64_encode_bytes(input_json: &str, flags: i32) -> String {
    let bytes = json_byte_array(input_json);
    let url_safe = flags & 8 != 0;
    let no_padding = flags & 1 != 0;
    match (url_safe, no_padding) {
        (true, true) => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
        (true, false) => base64::engine::general_purpose::URL_SAFE.encode(bytes),
        (false, true) => base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes),
        (false, false) => base64::engine::general_purpose::STANDARD.encode(bytes),
    }
}

fn java_base64_decode_bytes(input: &str, flags: i32) -> String {
    let input = input.chars().filter(|ch| !ch.is_whitespace()).collect::<String>();
    let url_safe = flags & 8 != 0;
    let decoded = if url_safe {
        base64::engine::general_purpose::URL_SAFE
            .decode(&input)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&input))
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(&input)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&input))
    }
    .unwrap_or_default();
    serde_json::to_string(&decoded).unwrap_or_else(|_| "[]".to_string())
}

fn java_hmac_bytes(algorithm: &str, key_json: &str, data_json: &str) -> String {
    let algorithm = match algorithm.to_ascii_uppercase().as_str() {
        "HMACSHA1" => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        "HMACSHA256" => hmac::HMAC_SHA256,
        "HMACSHA384" => hmac::HMAC_SHA384,
        "HMACSHA512" => hmac::HMAC_SHA512,
        _ => return "[]".to_string(),
    };
    let key = hmac::Key::new(algorithm, &json_byte_array(key_json));
    let tag = hmac::sign(&key, &json_byte_array(data_json));
    serde_json::to_string(tag.as_ref()).unwrap_or_else(|_| "[]".to_string())
}

fn java_encode_uri(input: &str, charset: Option<&str>) -> String {
    let bytes = java_str_to_bytes(input, charset);
    urlencoding::encode_binary(&bytes).into_owned()
}

fn js_cache_get(key: &str) -> Option<String> {
    let mut cache = JS_CACHE.lock().unwrap_or_else(|error| error.into_inner());
    let expired = cache
        .get(key)
        .and_then(|entry| entry.expires_at)
        .is_some_and(|expires_at| Instant::now() >= expires_at);
    if expired {
        cache.remove(key);
        None
    } else {
        cache.get(key).map(|entry| entry.value.clone())
    }
}

fn js_cache_put(key: &str, value: String, save_time_secs: Option<i64>) -> bool {
    let expires_at = save_time_secs
        .filter(|seconds| *seconds > 0)
        .and_then(|seconds| Instant::now().checked_add(Duration::from_secs(seconds as u64)));
    let mut cache = JS_CACHE.lock().unwrap_or_else(|error| error.into_inner());
    cache.insert(key.to_string(), JsCacheEntry { value, expires_at });
    true
}

fn js_cache_delete(key: &str) -> bool {
    JS_CACHE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(key)
        .is_some()
}

fn java_ajax(spec: &str) -> anyhow::Result<String> {
    let (url, options) = split_ajax_spec(spec);
    if url.trim().is_empty() {
        return Ok(String::new());
    }

    let options_json = options
        .and_then(|raw| serde_json::from_str::<JsonValue>(raw).ok())
        .unwrap_or(JsonValue::Null);

    let method = options_json
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .to_uppercase();
    let method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);

    let headers = options_json
        .get("headers")
        .and_then(|value| value.as_object())
        .map(|headers| {
            headers
                .iter()
                .filter_map(|(key, value)| {
                    if let Some(value) = value.as_str() {
                        Some((key.clone(), value.to_string()))
                    } else if !value.is_null() {
                        Some((key.clone(), value.to_string()))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let body = options_json.get("body").and_then(|value| {
        if let Some(value) = value.as_str() {
            Some(value.to_string())
        } else if !value.is_null() {
            Some(value.to_string())
        } else {
            None
        }
    });

    Ok(active_js_http_client().request_text(method, url.trim(), &headers, body.as_deref())?)
}

fn java_request_simple(
    method: &str,
    url: &str,
    body: Option<String>,
    headers_json: &str,
) -> anyhow::Result<String> {
    let method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    Ok(active_js_http_client().request_text(
        method,
        url.trim(),
        &java_request_headers(headers_json),
        body.as_deref(),
    )?)
}

fn java_request_simple_response(
    method: &str,
    url: &str,
    body: Option<String>,
    headers_json: &str,
) -> String {
    java_request_simple_response_with_client(
        method,
        url,
        body,
        headers_json,
        &active_js_http_client(),
    )
}

fn java_request_simple_response_with_client(
    method: &str,
    url: &str,
    body: Option<String>,
    headers_json: &str,
    client: &HttpClient,
) -> String {
    let method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    let response = client.execute(
        method,
        url.trim(),
        &java_request_headers(headers_json),
        body.as_deref(),
        None,
    );
    let payload = match response {
        Ok(response) => {
            let headers = response
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    value.to_str().ok().map(|value| {
                        (
                            name.as_str().to_string(),
                            JsonValue::String(value.to_string()),
                        )
                    })
                })
                .collect::<serde_json::Map<String, JsonValue>>();
            let status = response.status;
            serde_json::json!({
                "__ffiStrResponse": true,
                "body": String::from_utf8_lossy(&response.body).into_owned(),
                "url": response.url,
                "code": status,
                "message": http_status_message(status),
                "headers": headers,
                "isSuccessful": (200..300).contains(&status),
            })
        }
        Err(error) => serde_json::json!({
            "__ffiStrResponse": true,
            "body": error.to_string(),
            "url": url.trim(),
            "code": 0,
            "message": "",
            "headers": {},
            "isSuccessful": false,
        })
    };
    payload.to_string()
}

fn java_analyzed_request_response(url: &str, headers_json: &str) -> String {
    let client = active_js_http_client();
    let source = ACTIVE_JS_BOOK_SOURCE.with(|cell| cell.borrow().clone());
    let Some(source) = source else {
        let payload =
            java_request_simple_response_with_client("GET", url, None, headers_json, &client);
        if let Ok(value) = serde_json::from_str::<JsonValue>(&payload) {
            if value.get("code").and_then(JsonValue::as_u64) == Some(0) {
                let error = value
                    .get("body")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("request failed");
                return java_error_response(url, error);
            }
        }
        return payload;
    };
    let explicit_headers =
        (!headers_json.is_empty()).then(|| java_request_headers(headers_json));
    let spec = match analyze_url_with_headers(
        url,
        "",
        0,
        &source.book_source_url,
        &source,
        explicit_headers,
    ) {
        Ok(spec) => spec,
        Err(error) => return java_error_response(url, &error),
    };

    let response = match execute_request_spec(&client, &spec) {
        Ok(response) => response,
        Err(error) => return java_error_response(&spec.url, &error.to_string()),
    };

    let headers = response
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|value| {
                (
                    name.as_str().to_string(),
                    JsonValue::String(value.to_string()),
                )
            })
        })
        .collect::<serde_json::Map<String, JsonValue>>();
    let content_type = response
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok());
    let decoded_body = decode_body(&response.body, spec.charset.as_deref(), content_type);
    let body = if spec
        .response_type
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        response
            .body
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    } else {
        decoded_body
    };
    serde_json::json!({
        "__ffiStrResponse": true,
        "body": body,
        "url": response.url,
        "code": response.status,
        "message": http_status_message(response.status),
        "headers": headers,
        "isSuccessful": (200..300).contains(&response.status),
    })
    .to_string()
}

fn http_status_message(status: u16) -> String {
    ureq::http::StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .unwrap_or("")
        .to_string()
}

fn java_error_response(url: &str, error: &str) -> String {
    let raw_url = split_ajax_spec(url).0.trim();
    let response_url = url::Url::parse(raw_url)
        .ok()
        .filter(|parsed| matches!(parsed.scheme(), "http" | "https"))
        .map(|parsed| parsed.to_string())
        .unwrap_or_else(|| "http://localhost/".to_string());
    serde_json::json!({
        "__ffiStrResponse": true,
        "body": error,
        "url": response_url,
        "code": 200,
        "message": "OK",
        "headers": {},
        "isSuccessful": true,
    })
    .to_string()
}

fn java_request_headers(headers_json: &str) -> Vec<(String, String)> {
    serde_json::from_str::<JsonValue>(headers_json)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .map(|headers| {
            headers
                .into_iter()
                .filter_map(|(key, value)| {
                    (!value.is_null()).then(|| (key, json_value_to_string(&value)))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn scoped_java_variable(bindings: &HashMap<String, JsonValue>, key: &str) -> Option<String> {
    if key == "bookName" {
        return binding_object_value(bindings.get("book"), "bookName")
            .or_else(|| binding_object_value(bindings.get("book"), "name"));
    }
    if key == "title" {
        return binding_object_value(bindings.get("chapter"), "title")
            .or_else(|| bindings.get("title").map(json_value_to_string))
            .filter(|value| !value.is_empty());
    }

    ["chapter", "book", "ruleData", "rule_data"]
        .iter()
        .filter_map(|scope| bindings.get(*scope))
        .find_map(|scope| {
            let object = scope.as_object()?;
            object
                .get("variableMap")
                .and_then(|variables| variables.get(key))
                .or_else(|| object.get(key))
                .map(json_value_to_string)
                .filter(|value| !value.is_empty())
        })
}

fn binding_object_value(value: Option<&JsonValue>, key: &str) -> Option<String> {
    value
        .and_then(JsonValue::as_object)
        .and_then(|object| object.get(key))
        .map(json_value_to_string)
        .filter(|value| !value.is_empty())
}

fn json_value_to_string(value: &JsonValue) -> String {
    match value {
        JsonValue::String(value) => value.clone(),
        JsonValue::Null => String::new(),
        value => value.to_string(),
    }
}

fn split_ajax_spec(spec: &str) -> (&str, Option<&str>) {
    let mut depth = 0i32;
    let mut in_string = false;
    let mut quote = '\0';
    let mut escaped = false;

    for (idx, ch) in spec.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        match ch {
            '\\' if in_string => {
                escaped = true;
            }
            '"' | '\'' if in_string && ch == quote => {
                in_string = false;
                quote = '\0';
            }
            '"' | '\'' if !in_string => {
                in_string = true;
                quote = ch;
            }
            '{' | '[' if !in_string => depth += 1,
            '}' | ']' if !in_string => depth -= 1,
            ',' if !in_string && depth == 0 => {
                let left = &spec[..idx];
                let right = &spec[idx + ch.len_utf8()..];
                return (left, Some(right.trim()));
            }
            _ => {}
        }
    }

    (spec, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawler::session::{with_active_session, ExecuteSession};
    use serde_json::json;
    use std::io::BufRead;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::thread;

    fn accept_with_timeout(listener: &TcpListener) -> (TcpStream, SocketAddr) {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, address)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    return (stream, address);
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("test HTTP server did not receive request: {error}"),
            }
        }
    }

    #[test]
    fn js_lib_json_object_loads_only_absolute_urls_and_uses_cache() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/shared.js");
        let marker = format!("shared_lib_{}", address.port());
        let script = format!("globalThis.{marker}=41;");
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{script}",
                script.len()
            )
            .unwrap();
        });
        let js_lib = serde_json::json!({
            "remote": url,
            "inline": "throw new Error('inline value must be ignored')",
            "relative": "/not-a-script.js"
        })
        .to_string();

        with_js_lib(Some(&js_lib), || {
            let expression = format!("{marker} + 1");
            assert_eq!(eval_js(&expression, "", &url).unwrap(), "42");
            assert_eq!(eval_js(&expression, "", &url).unwrap(), "42");
        });
        server.join().unwrap();
        assert_eq!(
            compile_js_lib(r#"{"inline":"var notLoaded=1"}"#).unwrap(),
            ""
        );
    }

    #[test]
    fn low_risk_compat_apis_cover_headers_encodings_cache_and_utc_time() {
        let cache_key = format!("js-compat-{}", Uuid::new_v4());
        let script = format!(
            r#"
                const bytes = java.strToBytes('中文', 'GBK');
                const decoded = java.bytesToStr(bytes, 'GBK');
                const encoded = java.encodeURI('中文', 'GBK');
                const b64 = java.base64Decode('5Lit5paH', 'UTF-8');
                const hex = java.hexEncodeToString('reader');
                const hexBytes = java.hexDecodeToByteArray(hex).join(',');
                const hexText = java.hexDecodeToString(hex);
                const digestAlias = java.md5Encode16('reader') === java.md5To16('reader');
                const utc = java.timeFormatUTC(0, "yyyy-MM-dd HH:mm:ss.SSS", 28800000);
                cache.put('{cache_key}', 'cached', 60);
                const cached = cache.get('{cache_key}');
                const removed = cache.delete('{cache_key}');
                [decoded, encoded, b64, hex, hexBytes, hexText, digestAlias, utc,
                 cached, removed, cache.get('{cache_key}') === null].join('|');
            "#
        );
        let output = eval_js(&script, "", "https://example.com").unwrap();
        assert_eq!(
            output,
            "中文|%D6%D0%CE%C4|中文|726561646572|114,101,97,100,101,114|reader|true|1970-01-01 08:00:00.000|cached|true|true"
        );

        let expired_key = format!("js-expired-{}", Uuid::new_v4());
        JS_CACHE
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(
                expired_key.clone(),
                JsCacheEntry {
                    value: "stale".to_string(),
                    expires_at: Some(Instant::now() - Duration::from_secs(1)),
                },
            );
        let expired = eval_js(
            &format!("cache.get('{expired_key}') === null"),
            "",
            "https://example.com",
        )
        .unwrap();
        assert_eq!(expired, "true");
    }

    #[test]
    fn java_connect_returns_str_response_for_http_and_transport_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                request.push_str(&line);
            }
            write!(
                stream,
                "HTTP/1.1 418 I'm a teapot\r\nContent-Type: application/json\r\nX-Connect: yes\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied"
            )
            .unwrap();
            request.to_ascii_lowercase()
        });

        let url = format!("http://{address}/connect");
        let source = BookSource {
            book_source_url: url.clone(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let script = format!(
            r#"
                const response = java.connect('{url}', {{'X-Request':'connect'}});
                [response.__ffiStrResponse, response.code(), response.message(),
                 response.url(), response.body(), response.isSuccessful(),
                 response.headers().get('x-connect'), response.raw().code(),
                 String(response).includes('code=418')].join('|');
            "#
        );
        let result = with_js_http_context(&client, &source, || {
            eval_js(&script, "", &url).unwrap()
        });
        assert_eq!(
            result,
            format!("true|418|I'm a teapot|{url}|denied|false|yes|418|true")
        );
        assert!(server.join().unwrap().contains("x-request: connect"));

        let invalid = with_js_http_context(&client, &source, || {
            eval_js(
                "(() => { const response = java.connect('ftp://invalid'); return [response.code(), response.message(), response.isSuccessful(), response.url(), response.body().length > 0, response.raw().code()].join('|'); })()",
                "",
                &url,
            )
            .unwrap()
        });
        assert_eq!(invalid, "200|OK|true|http://localhost/|true|200");
    }

    #[test]
    fn java_ajax_all_runs_sequentially_preserves_order_and_isolates_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, cookie, body) in [(201, true, "first"), (502, false, "last")] {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    request.push_str(&line);
                }
                requests.push(request.to_ascii_lowercase());
                if cookie {
                    write!(
                        stream,
                        "HTTP/1.1 {status} Created\r\nSet-Cookie: sid=ordered; Path=/\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                } else {
                    write!(
                        stream,
                        "HTTP/1.1 {status} Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                }
            }
            requests
        });

        let first = format!("http://{address}/first");
        let last = format!("http://{address}/last");
        let source = BookSource {
            book_source_url: first.clone(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let result = with_js_http_context(&client, &source, || {
            eval_js(
                &format!(
                    r#"(() => {{
                        const responses = java.ajaxAll(['{first}', 'ftp://invalid', '{last}']);
                        return [responses.length, responses[0].code(), responses[0].body(),
                            responses[1].code(), responses[1].isSuccessful(), responses[1].body().length > 0,
                            responses[2].code(), responses[2].body()].join('|');
                    }})()"#
                ),
                "",
                &first,
            )
            .unwrap()
        });
        assert_eq!(result, "3|201|first|200|true|true|502|last");

        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("get /first "));
        assert!(requests[1].starts_with("get /last "));
        assert!(requests[1].contains("cookie: sid=ordered"));
    }

    #[test]
    fn java_connect_and_ajax_all_follow_analyze_url_header_precedence() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..3 {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some(value) = line
                        .strip_prefix("Content-Length: ")
                        .or_else(|| line.strip_prefix("content-length: "))
                    {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                    request.push_str(&line);
                }
                let mut body = vec![0; content_length];
                reader.read_exact(&mut body).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 201 Created\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )
                .unwrap();
                requests.push((
                    request.to_ascii_lowercase(),
                    String::from_utf8(body).unwrap(),
                ));
            }
            requests
        });

        let url =
            r#"/ajax,{"method":"POST","headers":{"X-Url":"configured","X-Order":"url"},"body":"payload","js":"result"}"#
                .to_string();
        let script = format!(
            "(() => {{ globalThis.__sourceHeaderCounter = 0; const all = java.ajaxAll([{}, {}]); const one = java.connect({}, {{'X-Order':'connect','X-Connect':'configured'}}); return [all[0].code(), all[1].code(), one.code(), all[0].body(), all[1].body(), one.body()].join('|'); }})()",
            serde_json::to_string(&url).unwrap(),
            serde_json::to_string(&url).unwrap(),
            serde_json::to_string(&url).unwrap()
        );
        let source = BookSource {
            book_source_url: format!("http://{address}/source"),
            header: Some(
                r#"js:globalThis.__sourceHeaderCounter=(globalThis.__sourceHeaderCounter||0)+1;JSON.stringify({"X-Source":String(globalThis.__sourceHeaderCounter),"X-Order":"source"})"#
                    .to_string(),
            ),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let result = with_js_http_context(&client, &source, || {
            eval_js(&script, "", &source.book_source_url).unwrap()
        });
        assert_eq!(result, "201|201|201|ok|ok|ok");

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 3);
        for (index, (request, body)) in requests[..2].iter().enumerate() {
            assert!(request.starts_with("post /ajax "));
            assert!(request.contains(&format!("x-source: {}", index + 1)));
            assert!(request.contains("x-url: configured"));
            assert!(request.contains("x-order: url"));
            assert_eq!(body, "payload");
        }

        assert!(requests[2].0.starts_with("post /ajax "));
        assert!(!requests[2].0.contains("x-source:"));
        assert!(requests[2].0.contains("x-connect: configured"));
        assert!(requests[2].0.contains("x-url: configured"));
        assert!(requests[2].0.contains("x-order: url"));
        assert_eq!(requests[2].1, "payload");
    }

    #[test]
    fn simple_http_methods_forward_optional_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..3 {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    request.push_str(&line);
                }
                requests.push(request.to_ascii_lowercase());
                let request = &requests[requests.len() - 1];
                let is_head = request.starts_with("head ");
                let response_body = if is_head { "" } else { "ok" };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                )
                .unwrap();
            }
            requests
        });

        let url = format!("http://{address}/api");
        let client = HttpClient::standalone();
        let result = with_js_http_client(&client, || {
            eval_js(
                &format!(
                    "(() => {{ const get = java.get('{url}', {{'X-Test':'get'}}); const post = java.post('{url}', 'body', {{'X-Test':'post'}}); const head = java.head('{url}', {{'X-Test':'head'}}); return [get.body(), get.statusCode(), post.body(), head.statusCode(), String(get), head.body(), get.headers().get('content-length')].join('|'); }})()"
                ),
                "",
                &url,
            )
            .unwrap()
        });
        assert_eq!(result, "ok|200|ok|200|ok||2");

        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("get /api "));
        assert!(requests[0].contains("x-test: get"));
        assert!(requests[1].starts_with("post /api "));
        assert!(requests[1].contains("x-test: post"));
        assert!(requests[2].starts_with("head /api "));
        assert!(requests[2].contains("x-test: head"));
    }

    #[test]
    fn nashorn_java_importer_decrypts_aes_payload() {
        let key = "242ccb8230d709e1";
        let iv = "0123456789abcdef";
        let plaintext = "本地解析正文测试";
        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(java_aes_base64_encode(
                plaintext,
                key,
                "AES/CBC/PKCS5Padding",
                iv,
            ))
            .unwrap();
        let mut payload = iv.as_bytes().to_vec();
        payload.extend(encrypted);
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
        let script = format!(
            r#"
                var javaImport = new JavaImporter();
                javaImport.importPackage(Packages.java.lang, Packages.javax.crypto.spec,
                    Packages.javax.crypto, Packages.java.util);
                with (javaImport) {{
                    function decode(content) {{
                        var ivEncData = Base64.getDecoder().decode(String(content));
                        var key = SecretKeySpec(String("{key}").getBytes(), "AES");
                        var iv = IvParameterSpec(Arrays.copyOfRange(ivEncData, 0, 16));
                        var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipher.init(2, key, iv);
                        return String(cipher.doFinal(Arrays.copyOfRange(ivEncData, 16, ivEncData.length)));
                    }}
                }}
                decode("{encoded}");
            "#
        );
        assert_eq!(
            eval_js(&script, "", "https://example.com").unwrap(),
            plaintext
        );
    }

    #[test]
    fn java_importer_supports_legado_hmac_sha1_fixture() {
        let script = r#"
            var aly = new JavaImporter(
                Packages.javax.crypto.Mac,
                Packages.javax.crypto.spec.SecretKeySpec,
                Packages.javax.xml.bind.DatatypeConverter,
                Packages.java.net.URLEncoder,
                Packages.java.lang.String,
                Packages.android.util.Base64
            );
            with (aly) {
                function percentEncode(value) {
                    return URLEncoder.encode(value, "UTF-8")
                        .replace("+", "%20")
                        .replace("*", "%2A")
                        .replace("%7E", "~");
                }
                function sign(stringToSign, accessKeySecret) {
                    var mac = Mac.getInstance("HmacSHA1");
                    mac.init(new SecretKeySpec(
                        String(accessKeySecret + "&").getBytes("UTF-8"), "HmacSHA1"));
                    var signData = mac.doFinal(String(stringToSign).getBytes("UTF-8"));
                    var signBase64 = Base64.encodeToString(signData, Base64.NO_WRAP);
                    return percentEncode(signBase64);
                }
            }
            sign("reader", "secret");
        "#;
        assert_eq!(
            eval_js(script, "", "https://example.com").unwrap(),
            "%2BziHIM45rqfvezm%2F4BidN45XHvo%3D"
        );
    }

    #[test]
    fn base64_shims_preserve_byte_array_semantics() {
        let script = r#"
            const bytes = [97, 98, 99];
            const standard = android.util.Base64.encodeToString(
                bytes, android.util.Base64.NO_WRAP);
            const decoded = java.util.Base64.getDecoder().decode(standard).join(',');
            const urlSafe = java.util.Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString([251, 255]);
            [standard, decoded, urlSafe].join('|');
        "#;
        assert_eq!(
            eval_js(script, "", "https://example.com").unwrap(),
            "YWJj|97,98,99|-_8"
        );
    }

    #[test]
    fn legado_android_compat_shims_use_session_and_safe_host_objects() {
        let initial = ExecuteSession::default();
        let script = r#"
            const preferences = context.getSharedPreferences('reader', context.MODE_PRIVATE);
            preferences.edit().putString('token', 'saved').apply();
            preferences.edit().putString('temporary', 'remove').commit();
            preferences.edit().remove('temporary').apply();
            const encoded = URLEncoder.encode('reader rust');
            const decoded = URLDecoder.decode(encoded);
            const base64 = java.util.Base64.getEncoder().encodeToString('reader');
            const decodedBase64 = java.bytesToStr(
                android.util.Base64.decode(base64, android.util.Base64.DEFAULT), 'UTF-8');
            const uuid = UUID.randomUUID().toString();
            const javaUuid = java.util.UUID.randomUUID().toString();
            const helperUuid = java.randomUUID();
            if (preferences.getString('token', '') !== 'saved' ||
                preferences.getString('temporary', 'fallback') !== 'fallback' ||
                decoded !== 'reader rust' || decodedBase64 !== 'reader' ||
                uuid.length !== 36 || javaUuid.length !== 36 || helperUuid.length !== 36 ||
                System.currentTimeMillis() <= 0 ||
                !application || !context || !activity || !app ||
                !android.util.Log || Log.d('compat', 'ok') !== 0) {
                throw new Error('compatibility shim failed');
            }
            'OK'
        "#;
        let (result, delta) = with_active_session(Some(&initial), "https://example.com", |_| {
            eval_js(script, "", "https://example.com").unwrap()
        });
        assert_eq!(result, "OK");
        assert_eq!(
            delta.unwrap().variables.unwrap()["__prefs:reader:token"],
            JsonValue::String("saved".to_string())
        );
    }

    #[test]
    fn compat_jsoup_subset_supports_select_collection_and_element_methods() {
        let script = r#"
            var doc = org.jsoup.Jsoup.parse(result);
            var items = doc.select('ul.volume-chapters li.chapter-li:not(.volume-cover)');
            var output = [];
            for (var i = 0; i < items.size(); i++) {
                var item = items.get(i);
                var link = item.select('a').first();
                output.push({
                    title: link ? link.text() : '',
                    url: link ? link.attr('href') : '',
                    isVolume: item.hasClass('chapter-bar')
                });
            }
            JSON.stringify(output);
        "#;
        let body = r#"<ul class="volume-chapters">
            <li class="chapter-li"><a href="/chapter/1">Chapter 1</a></li>
            <li class="chapter-li chapter-bar"><a href="/volume/1">Volume 1</a></li>
            <li class="chapter-li volume-cover"><a href="/cover">Cover</a></li>
        </ul>"#;

        let output = eval_js(script, body, "https://source.example").unwrap();
        let items = serde_json::from_str::<Vec<JsonValue>>(&output).unwrap();

        assert_eq!(items.len(), 2, "Jsoup output: {output}");
        assert_eq!(items[0]["title"], "Chapter 1");
        assert_eq!(items[0]["url"], "/chapter/1");
        assert_eq!(items[0]["isVolume"], false);
        assert_eq!(items[1]["isVolume"], true);
    }

    #[test]
    fn toc_refresh_shims_are_rejected_outside_pre_update_context() {
        assert!(eval_js("java.reGetBook()", "", "https://example.com").is_err());
        assert!(eval_js("java.refreshTocUrl()", "", "https://example.com").is_err());
    }

    #[test]
    fn compat_cookie_get_key_reads_session_cookie_values() {
        let initial = ExecuteSession {
            cookies: Some("sid=initial_token; token=a=b=c".to_string()),
            ..Default::default()
        };
        let result = with_active_session(Some(&initial), "https://example.com", |_| {
            eval_js(
                "[cookie.getKey('example.com', 'sid'), cookie.getKey('https://example.com/path', 'token'), cookie.getKey('example.com', 'missing')].join('|')",
                "",
                "https://example.com",
            )
            .unwrap()
        })
        .0;

        assert_eq!(result, "initial_token|a=b=c|");
    }

    #[test]
    fn compat_java_set_content_and_get_elements_support_json_and_html() {
        let script = r#"
            java.setContent(JSON.stringify({data:{list:[{name:'first'},{name:'last'}]}}));
            const list = java.getElements('$.data.list[*]').toArray();
            const last = java.getElement('$.data.list[-1]');
            const firstName = java.getString('$.data.list[0].name');
            java.setContent('<div><p id="p1"><b>one</b></p><p id="p2">two</p></div>');
            const paragraphs = java.getElements('@@tag.p').toArray();
            [list[0].name, last.name, firstName, paragraphs[0].attr('id'),
             paragraphs[0].html(), paragraphs[0].text()].join('|')
        "#;
        let result = eval_js(script, "", "https://example.com").unwrap();
        assert_eq!(result, "first|last|first|p1|<b>one</b>|one");
    }

    #[test]
    fn java_get_reads_legado_book_and_chapter_variable_scopes() {
        let bindings = HashMap::from([
            (
                "book".to_string(),
                json!({
                    "name": "Book",
                    "variableMap": {
                        "bookOnly": "book-value",
                        "shadowed": "book-value",
                        "headers": r#"{"headers":{"X-Test":"ok"}}"#
                    }
                }),
            ),
            (
                "chapter".to_string(),
                json!({
                    "title": "Chapter",
                    "variableMap": {
                        "chapterOnly": "chapter-value",
                        "shadowed": "chapter-value"
                    }
                }),
            ),
            ("title".to_string(), json!("Chapter")),
        ]);

        let result = eval_js_with_bindings(
            "[java.get('bookOnly'), java.get('chapterOnly'), java.get('shadowed'), java.get('headers'), java.get('bookName'), java.get('title')].join('|')",
            "",
            "https://example.com",
            &bindings,
        )
        .unwrap();
        assert_eq!(
            result,
            r#"book-value|chapter-value|chapter-value|{"headers":{"X-Test":"ok"}}|Book|Chapter"#
        );
    }

    #[test]
    fn test_js_session_bindings() {
        let initial = ExecuteSession {
            cookies: Some("sid=initial_token".to_string()),
            header: Some(json!({"Authorization": "Bearer init_auth"})),
            variables: Some(
                [("myVar".to_string(), json!("initial_val"))]
                    .into_iter()
                    .collect(),
            ),
        };

        let (_, delta) =
            with_active_session(Some(&initial), "https://example.com/books", |_session| {
                // Read initial variable
                let res =
                    eval_js("source.getVariable('myVar')", "", "https://example.com").unwrap();
                assert_eq!(res, "initial_val");

                // Write new variable
                let res = eval_js(
                    "source.setVariable('myVar', 'updated_val')",
                    "",
                    "https://example.com",
                )
                .unwrap();
                assert_eq!(res, "updated_val");

                // Read login header
                let h = eval_js("source.getLoginHeader()", "", "https://example.com").unwrap();
                assert!(h.contains("init_auth"));

                // Put new login header with Cookie
                eval_js(
                    r#"source.putLoginHeader(JSON.stringify({Cookie: "sid=refreshed_token"}))"#,
                    "",
                    "https://example.com",
                )
                .unwrap();

                // Cookie get
                let c = eval_js(
                    "cookie.getCookie('https://example.com')",
                    "",
                    "https://example.com",
                )
                .unwrap();
                assert!(c.contains("sid=refreshed_token"));
            });

        assert!(delta.is_some());
        let delta = delta.unwrap();
        assert_eq!(delta.cookies, Some("sid=refreshed_token".to_string()));
        assert_eq!(
            delta
                .variables
                .as_ref()
                .unwrap()
                .get("myVar")
                .and_then(JsonValue::as_str),
            Some("updated_val")
        );
    }

    #[test]
    fn compat_java_get_elements_supports_xpath_element_chaining() {
        let body = r#"<div id="catalog"><a href="/ch1" class="c-link">Chapter One</a><a href="/ch2" class="c-link">Chapter Two</a></div>"#;
        let script = r#"
            const items = java.getElements('//div[@id="catalog"]//a', result);
            const first = items.first();
            const last = items.get(1);
            [items.size(), first.attr('href'), first.text(), first.hasClass('c-link'), last.attr('href'), last.text()].join('|')
        "#;
        let output = eval_js(script, body, "https://example.com").unwrap();
        assert_eq!(output, "2|/ch1|Chapter One|true|/ch2|Chapter Two");
    }

    #[test]
    fn compat_java_get_elements_advanced_xpath_chaining() {
        let body = r#"
            <div id="catalog">
                <div class="header">
                    <img src="/cover.jpg" alt="Cover Image" />
                    <span class="count">Total: 2</span>
                </div>
                <ul class="chapters">
                    <li><a href="/ch1" class="c-link">Chapter One</a></li>
                    <li><a href="/ch2" class="c-link">Chapter Two</a></li>
                </ul>
            </div>
            <div id="footer">The End</div>
        "#;

        // 1. Test getElement singular, id() function, select() chaining with XPath
        let script = r#"
            const root = java.getElement('id("catalog")', result);
            const img = root.select('.//img').first();
            const links = root.select('.//ul/li/a');
            const footer = java.getElement('id("footer")', result);
            const missing = java.getElement('id("nonexistent")', result);

            [
                root.attr('id'),
                img.attr('src'),
                img.attr('alt'),
                links.size(),
                links.get(0).attr('href'),
                links.get(0).text(),
                links.get(1).attr('href'),
                links.get(1).text(),
                footer.text(),
                missing === null
            ].join('|')
        "#;
        let output = eval_js(script, body, "https://example.com").unwrap();
        assert_eq!(
            output,
            "catalog|/cover.jpg|Cover Image|2|/ch1|Chapter One|/ch2|Chapter Two|The End|true"
        );

        // 2. Test XPath direct attribute query and text node query in java.getElements
        let script_attrs = r#"
            const hrefs = java.getElements('//ul[@class="chapters"]//a/@href', result);
            const texts = java.getElements('//ul[@class="chapters"]//a/text()', result);
            [hrefs.size(), hrefs.get(0), hrefs.get(1), texts.size(), texts.get(0), texts.get(1)].join('|')
        "#;
        let output_attrs = eval_js(script_attrs, body, "https://example.com").unwrap();
        assert_eq!(output_attrs, "2|/ch1|/ch2|2|Chapter One|Chapter Two");

        // 3. Test mixed XPath and CSS chaining: select XPath root then select CSS
        let script_mixed = r#"
            const catalog = java.getElement('//div[@id="catalog"]', result);
            const span = catalog.select('span.count').first();
            const link = catalog.select('ul li a').first();
            [span.text(), span.attr('class'), link.attr('href')].join('|')
        "#;
        let output_mixed = eval_js(script_mixed, body, "https://example.com").unwrap();
        assert_eq!(output_mixed, "Total: 2|count|/ch1");

        // 4. All java string APIs share the same XPath mode detection, including id().
        let script_strings = r#"
            const footer = java.getString('id("footer")/text()', result);
            const hrefs = java.getStringList('id("catalog")//a/@href', result);
            [footer, hrefs.join(',')].join('|')
        "#;
        let output_strings = eval_js(script_strings, body, "https://example.com").unwrap();
        assert_eq!(output_strings, "The End|/ch1,/ch2");
    }
}
