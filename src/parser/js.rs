use crate::crawler::HttpClient;
use crate::parser::html;
use crate::parser::jsonpath;
use crate::parser::rule_analyzer;
use crate::parser::rule_engine;
use crate::util::hash::md5_hex;
use crate::util::text::{apply_regex_replace, strip_whitespace};
use aes::Aes128;
use base64::Engine;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use chrono::{Local, TimeZone};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use once_cell::sync::Lazy;
use rquickjs::function::Func;
use rquickjs::{Context, Object, Runtime, Value};
use serde_json::Value as JsonValue;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;
use ureq::http::Method;
use uuid::Uuid;

static JS_KV: Lazy<Mutex<HashMap<String, String>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static JS_LIB_CACHE: Lazy<Mutex<HashMap<String, String>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
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

fn active_js_http_client() -> HttpClient {
    ACTIVE_JS_HTTP_CLIENT
        .with(|cell| cell.borrow().clone())
        .unwrap_or_else(|| JS_HTTP_CLIENT.clone())
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
                Func::new(|key: String| -> Option<String> {
                    let map = JS_KV.lock().unwrap_or_else(|e| e.into_inner());
                    map.get(&key).cloned()
                }),
            )?;
            cache_obj.set(
                "put",
                Func::new(|key: String, val: String| -> bool {
                    let mut map = JS_KV.lock().unwrap_or_else(|e| e.into_inner());
                    map.insert(key, val);
                    true
                }),
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
            java_obj.set(
                "md5To16",
                Func::new(|input: String| -> String {
                    let md5 = md5_hex(&input);
                    if md5.len() >= 16 {
                        md5[8..24].to_string()
                    } else {
                        md5
                    }
                }),
            )?;
            java_obj.set(
                "timeFormat",
                Func::new(|timestamp: i64| -> String { java_time_format(timestamp) }),
            )?;
            java_obj.set(
                "androidId",
                Func::new(|| -> String { JS_DEVICE_ID.clone() }),
            )?;
            java_obj.set("deviceID", Func::new(|| -> String { JS_DEVICE_ID.clone() }))?;
            java_obj.set(
                "get",
                Func::new(|url: String| -> String {
                    java_request_simple("GET", &url, None).unwrap_or_default()
                }),
            )?;
            java_obj.set(
                "post",
                Func::new(|url: String, body: String| -> String {
                    java_request_simple("POST", &url, Some(body)).unwrap_or_default()
                }),
            )?;
            java_obj.set(
                "put",
                Func::new(|url: String, body: String| -> String {
                    java_request_simple("PUT", &url, Some(body)).unwrap_or_default()
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
                Func::new(|input: String| -> String {
                    base64::engine::general_purpose::STANDARD
                        .decode(input)
                        .ok()
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                        .unwrap_or_default()
                }),
            )?;
            java_obj.set(
                "base64DecodeBytes",
                Func::new(|input: String| -> String {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(input.trim())
                        .or_else(|_| {
                            base64::engine::general_purpose::STANDARD_NO_PAD.decode(input.trim())
                        })
                        .unwrap_or_default();
                    serde_json::to_string(&bytes).unwrap_or_else(|_| "[]".to_string())
                }),
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
                Func::new(|input: String| -> String { urlencoding::encode(&input).into_owned() }),
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
                "get",
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
                    const base64 = {
                        DEFAULT: 0, NO_WRAP: 2, URL_SAFE: 8, NO_PADDING: 1,
                        encodeToString(value) { return java.base64Encode(String(value)); },
                        decode(value) { return java.base64Decode(String(value).replace(/\s/g, '')); }
                    };
                    globalThis.System = Object.assign(globalThis.System || {}, {
                        currentTimeMillis: () => java.now()
                    });
                    const randomUuid = () => {
                        const value = java.uuid();
                        return { toString: () => value };
                    };
                    globalThis.UUID = { randomUUID: randomUuid };
                    java.util = java.util || {};
                    java.util.UUID = { randomUUID: randomUuid };
                    java.util.Base64 = {
                        getEncoder() { return { encodeToString: base64.encodeToString, withoutPadding() { return this; } }; },
                        getDecoder() { return { decode: base64.decode }; },
                        getUrlEncoder() { return { encodeToString: value => java.base64Encode(String(value)).replace(/\+/g, '-').replace(/\//g, '_') }; }
                    };
                    globalThis.Packages = globalThis.Packages || {};
                    Packages.java = Packages.java || {};
                    Packages.java.lang = Packages.java.lang || {};
                    Packages.java.util = Packages.java.util || {};
                    Packages.javax = Packages.javax || {};
                    Packages.javax.crypto = Packages.javax.crypto || {};
                    Packages.javax.crypto.spec = Packages.javax.crypto.spec || {};
                    const utf8Bytes = value => {
                        const encoded = encodeURIComponent(String(value));
                        const bytes = [];
                        for (let i = 0; i < encoded.length;) {
                            if (encoded[i] === '%') {
                                bytes.push(parseInt(encoded.slice(i + 1, i + 3), 16));
                                i += 3;
                            } else {
                                bytes.push(encoded.charCodeAt(i++));
                            }
                        }
                        return bytes;
                    };
                    if (!String.prototype.getBytes) {
                        Object.defineProperty(String.prototype, 'getBytes', {
                            value() { return utf8Bytes(String(this)); }
                        });
                    }
                    globalThis.JavaImporter = function() {
                        this.importPackage = function() {};
                        this.Base64 = { getDecoder() { return { decode: value => JSON.parse(java.base64DecodeBytes(String(value))) }; } };
                        this.SecretKeySpec = (key, algorithm) => ({ key: Array.from(key), algorithm: String(algorithm) });
                        this.IvParameterSpec = iv => ({ iv: Array.from(iv) });
                        this.Arrays = { copyOfRange(value, start, end) {
                            const bytes = Array.from(value).slice(start, end);
                            while (bytes.length < end - start) bytes.push(0);
                            return bytes;
                        } };
                        this.Cipher = {
                            DECRYPT_MODE: 2,
                            getInstance: algorithm => ({
                                init(mode, key, iv) { this.mode = mode; this.key = key; this.iv = iv; },
                                doFinal(data) {
                                    return java.aesDecryptBytes(JSON.stringify({
                                        algorithm, mode: this.mode, key: this.key.key,
                                        iv: this.iv.iv, data: Array.from(data)
                                    }));
                                }
                            })
                        };
                    };
                    globalThis.URLEncoder = {
                        encode(value) { return encodeURIComponent(String(value)).replace(/%20/g, '+').replace(/[!'()*]/g, char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`); }
                    };
                    globalThis.URLDecoder = {
                        decode(value) { return decodeURIComponent(String(value).replace(/\+/g, ' ')); }
                    };
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
                    const raw = globalThis.result;
                    const responseHeaders = Object.assign({}, raw.headers || {});
                    responseHeaders.get = function(name) {
                        const key = Object.keys(raw.headers || {}).find(k => k.toLowerCase() === String(name).toLowerCase());
                        return key === undefined ? null : raw.headers[key];
                    };
                    responseHeaders.names = function() { return Object.keys(raw.headers || {}); };
                    responseHeaders.toMultimap = function() { return Object.assign({}, raw.headers || {}); };
                    const bodyText = String(raw.body == null ? "" : raw.body);
                    const statusCode = Number(raw.code || raw.status || 0);
                    const strResponse = {
                        __ffiStrResponse: true,
                        raw: raw.raw || null,
                        body: function() { return { string: function() { return bodyText; }, toString: function() { return bodyText; } }; },
                        url: function() { return String(raw.url || ""); },
                        code: function() { return statusCode; },
                        headers: function() { return responseHeaders; },
                        isSuccessful: function() { return raw.isSuccessful == null ? statusCode >= 200 && statusCode < 300 : !!raw.isSuccessful; },
                        toJSON: function() { return {
                            __ffiStrResponse: true,
                            raw: raw.raw || null,
                            body: bodyText,
                            url: String(raw.url || ""),
                            code: statusCode,
                            headers: raw.headers || {},
                            isSuccessful: raw.isSuccessful == null ? statusCode >= 200 && statusCode < 300 : !!raw.isSuccessful
                        }; }
                    };
                    globalThis.result = strResponse;
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

fn java_aes_decrypt_bytes(input: &str) -> String {
    let Ok(value) = serde_json::from_str::<JsonValue>(input) else {
        return String::new();
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
        return String::new();
    }
    let (Some(key), Some(iv), Some(mut encrypted)) = (bytes("key"), bytes("iv"), bytes("data"))
    else {
        return String::new();
    };
    let Ok(cipher) = Aes128CbcDecryptor::new_from_slices(&key, &iv) else {
        return String::new();
    };
    cipher
        .decrypt_padded_mut::<Pkcs7>(&mut encrypted)
        .ok()
        .and_then(|plaintext| String::from_utf8(plaintext.to_vec()).ok())
        .unwrap_or_default()
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

fn java_request_simple(method: &str, url: &str, body: Option<String>) -> anyhow::Result<String> {
    let method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    Ok(active_js_http_client().request_text(method, url.trim(), &[], body.as_deref())?)
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
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn js_lib_json_object_loads_only_absolute_urls_and_uses_cache() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/shared.js");
        let marker = format!("shared_lib_{}", address.port());
        let script = format!("globalThis.{marker}=41;");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
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
            const decodedBase64 = android.util.Base64.decode(base64, android.util.Base64.DEFAULT);
            const uuid = UUID.randomUUID().toString();
            const javaUuid = java.util.UUID.randomUUID().toString();
            if (preferences.getString('token', '') !== 'saved' ||
                preferences.getString('temporary', 'fallback') !== 'fallback' ||
                decoded !== 'reader rust' || decodedBase64 !== 'reader' ||
                uuid.length !== 36 || javaUuid.length !== 36 ||
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
        assert_eq!(
            output_attrs,
            "2|/ch1|/ch2|2|Chapter One|Chapter Two"
        );

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

