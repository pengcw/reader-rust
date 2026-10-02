use crate::crawler::{
    analyze_url_with_headers, decode_body, execute_request_spec, execute_request_spec_limited,
    format_analyzed_body, HttpClient,
};
use crate::model::book_source::BookSource;
use crate::parser::html;
use crate::parser::jsonpath;
use crate::parser::rule_analyzer;
use crate::parser::rule_engine;
use crate::parser::source_regex;
use crate::util::hash::md5_hex;
use crate::util::text::strip_whitespace;
use aes::Aes128;
use base64::Engine;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use chrono::{FixedOffset, Local, TimeZone};
use once_cell::sync::Lazy;
use ring::{digest, hmac};
use rquickjs::function::Func;
use rquickjs::{Context, Object, Runtime, Value};
use serde_json::Value as JsonValue;
use std::cell::RefCell;
use std::collections::HashMap;
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

    static JS_ENV: (Runtime, Arc<AtomicU64>) = {
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

        (rt, start_time)
    };
}

pub fn with_js_lib<T>(js_lib: Option<&str>, f: impl FnOnce() -> T) -> T {
    ACTIVE_JS_LIB
        .with(|cell| crate::util::scoped::with_scoped_value(cell, js_lib.map(str::to_string), f))
}

/// Bind a source-specific synchronous HTTP client for the duration of a rule
/// execution. Nested calls restore the prior client, so reader_eval keeps its
/// legacy fallback client.
pub(crate) fn with_js_http_client<T>(client: &HttpClient, f: impl FnOnce() -> T) -> T {
    ACTIVE_JS_HTTP_CLIENT
        .with(|cell| crate::util::scoped::with_scoped_value(cell, Some(client.clone()), f))
}

pub(crate) fn with_js_http_context<T>(
    client: &HttpClient,
    source: &BookSource,
    f: impl FnOnce() -> T,
) -> T {
    ACTIVE_JS_BOOK_SOURCE.with(|cell| {
        crate::util::scoped::with_scoped_value(cell, Some(source.clone()), || {
            with_js_http_client(client, f)
        })
    })
}

fn active_js_http_client() -> HttpClient {
    ACTIVE_JS_HTTP_CLIENT
        .with(|cell| cell.borrow().clone())
        .unwrap_or_else(|| JS_HTTP_CLIENT.clone())
}

fn with_js_reentrant_ctx<T>(ctx: &rquickjs::Ctx<'_>, f: impl FnOnce() -> T) -> T {
    ACTIVE_JS_REENTRANT_CTX
        .with(|cell| crate::util::scoped::with_scoped_value(cell, Some(ctx.as_raw()), f))
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
        None,
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
        None,
    )
}

/// Evaluate an AnalyzeUrl option script with its mutable, request-local headerMap.
pub fn eval_js_url_with_headers(
    script: &str,
    result: &str,
    key: &str,
    page: i32,
    source_key: &str,
    base_url: &str,
    bindings: Option<&HashMap<String, JsonValue>>,
    headers: &mut Vec<(String, String)>,
) -> anyhow::Result<String> {
    eval_js_url_with_headers_inner(
        script, result, key, page, source_key, base_url, bindings, headers, false,
    )
}

pub fn eval_js_url_template_with_headers(
    script: &str,
    result: &str,
    key: &str,
    page: i32,
    source_key: &str,
    base_url: &str,
    bindings: Option<&HashMap<String, JsonValue>>,
    headers: &mut Vec<(String, String)>,
) -> anyhow::Result<String> {
    eval_js_url_with_headers_inner(
        script, result, key, page, source_key, base_url, bindings, headers, true,
    )
}

fn eval_js_url_with_headers_inner(
    script: &str,
    result: &str,
    key: &str,
    page: i32,
    source_key: &str,
    base_url: &str,
    bindings: Option<&HashMap<String, JsonValue>>,
    headers: &mut Vec<(String, String)>,
    template_result: bool,
) -> anyhow::Result<String> {
    let initial: serde_json::Map<String, JsonValue> = headers
        .iter()
        .map(|(name, value)| (name.clone(), JsonValue::String(value.clone())))
        .collect();
    let updated = std::cell::RefCell::new(None);
    let result = eval_js_inner_with_source(
        script,
        Some(result),
        Some(base_url),
        Some(key),
        Some(page),
        Some(source_key),
        bindings,
        template_result,
        Some((&initial, &updated)),
    )?;
    if let Some(values) = updated.into_inner() {
        *headers = values;
    }
    Ok(result)
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
        None,
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
        None,
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
        None,
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
    eval_js_inner_with_source(
        script, input, base_url, key, page, None, bindings, false, None,
    )
}

fn install_header_map<'js>(
    ctx: &rquickjs::Ctx<'js>,
    java: &Object<'js>,
    initial: &serde_json::Map<String, JsonValue>,
) -> anyhow::Result<()> {
    java.set(
        "headerMap",
        ctx.json_parse(JsonValue::Object(initial.clone()).to_string())?,
    )?;
    eval_script(
        ctx.clone(),
        r#"(function(map) {
        Object.defineProperties(map, {
            put: { value: function(key, value) {
                const previous = this[key]; this[key] = String(value); return previous;
            } },
            get: { value: function(key) { return this[key] ?? null; } },
            remove: { value: function(key) {
                const previous = this[key]; delete this[key]; return previous;
            } }
        });
    })(java.headerMap)"#,
    )?;
    Ok(())
}

fn collect_header_map(ctx: &rquickjs::Ctx<'_>) -> anyhow::Result<Vec<(String, String)>> {
    let map = eval_script(ctx.clone(), "java.headerMap")?;
    let json = ctx
        .json_stringify(map)?
        .ok_or_else(|| anyhow::anyhow!("invalid java.headerMap"))?;
    let values: serde_json::Map<String, JsonValue> = serde_json::from_str(&json.to_string()?)?;
    Ok(values
        .into_iter()
        .filter_map(|(key, value)| value.as_str().map(|value| (key, value.to_owned())))
        .collect())
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
    header_map: Option<(
        &serde_json::Map<String, JsonValue>,
        &std::cell::RefCell<Option<Vec<(String, String)>>>,
    )>,
) -> anyhow::Result<String> {
    if let Some(raw_ctx) = ACTIVE_JS_REENTRANT_CTX.with(|cell| *cell.borrow()) {
        // SAFETY: the pointer is installed only for the duration of a native
        // callback invoked by this same QuickJS context and thread.
        let ctx = unsafe { rquickjs::Ctx::from_raw(raw_ctx) };
        if let Some((initial, updated)) = header_map {
            let java: Object<'_> = ctx.globals().get("java")?;
            let original = if java.contains_key("headerMap")? {
                Some(java.get::<_, Value<'_>>("headerMap")?)
            } else {
                None
            };
            let result = (|| {
                install_header_map(&ctx, &java, initial)?;
                let result = eval_js_reentrant(
                    ctx.clone(),
                    script,
                    input,
                    base_url,
                    key,
                    page,
                    source_key,
                    bindings,
                    template_result,
                )?;
                *updated.borrow_mut() = Some(collect_header_map(&ctx)?);
                Ok(result)
            })();
            match original {
                Some(value) => {
                    let _ = java.set("headerMap", value);
                }
                None => {
                    let _ = java.remove("headerMap");
                }
            }
            return result;
        }
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

    JS_ENV.with(|(runtime, start_time)| {
        // A fresh context prevents top-level `const` in jsLib from being
        // redeclared and keeps implicit JS globals out of other sources.
        // Native callbacks still reuse this context through ACTIVE_JS_REENTRANT_CTX.
        let ctx = Context::full(runtime)?;
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
            let base_url_state = Arc::new(Mutex::new(base_url_value.to_string()));
            let variable_overrides = Arc::new(Mutex::new(HashMap::<String, String>::new()));
            let shared_js = active_js_lib_script()?;

            globals.set("input", input_value)?;
            globals.set("result", input_value)?;
            globals.set("src", input_value)?;
            globals.set("loginInfo", ctx.json_parse("null")?)?;
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
            let source_key_val = source_key
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .or_else(|| {
                    ACTIVE_JS_BOOK_SOURCE.with(|cell| {
                        cell.borrow()
                            .as_ref()
                            .map(|source| source.book_source_url.clone())
                    })
                })
                .unwrap_or_default();
            let source_obj = Object::new(ctx.clone())?;
            let sk_clone = source_key_val.clone();
            source_obj.set("key", source_key_val.clone())?;
            source_obj.set("getKey", Func::new(move || sk_clone.clone()))?;
            if let Some(active_source) = ACTIVE_JS_BOOK_SOURCE.with(|cell| cell.borrow().clone()) {
                source_obj.set("bookSourceUrl", active_source.book_source_url)?;
                source_obj.set("header", active_source.header.unwrap_or_default())?;
            }

            let source_key_for_get = source_key_val.clone();
            source_obj.set(
                "get",
                Func::new(move |key: String| -> String {
                    let storage_key = format!("v_{}_{}", source_key_for_get, key);
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        return active
                            .get_variable(&storage_key)
                            .map(|value| match value {
                                serde_json::Value::String(value) => value,
                                serde_json::Value::Null => String::new(),
                                other => other.to_string(),
                            })
                            .unwrap_or_default();
                    }
                    JS_KV
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .get(&storage_key)
                        .cloned()
                        .unwrap_or_default()
                }),
            )?;

            let source_key_for_put = source_key_val.clone();
            source_obj.set(
                "put",
                Func::new(move |key: String, value: String| -> String {
                    let storage_key = format!("v_{}_{}", source_key_for_put, key);
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.set_variable_exact(
                            &storage_key,
                            serde_json::Value::String(value.clone()),
                        );
                    } else {
                        JS_KV
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .insert(storage_key, value.clone());
                    }
                    value
                }),
            )?;

            let source_key_for_login_info = source_key_val.clone();
            source_obj.set(
                "__removeLoginInfo",
                Func::new(move || {
                    let storage_key = format!("userInfo_{}", source_key_for_login_info);
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.remove_variable(&storage_key);
                    } else {
                        JS_KV
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .remove(&storage_key);
                    }
                }),
            )?;

            let source_variable_storage_key = format!("__source_variable:{source_key_val}");
            let source_variable_storage_key_for_get = source_variable_storage_key.clone();
            source_obj.set(
                "getVariable",
                Func::new(move |key: rquickjs::function::Opt<String>| -> String {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        let value = match key.0.as_deref() {
                            Some(key) => active.get_variable(key),
                            None => active.get_variable(""),
                        };
                        return value
                            .map(|val| match val {
                                serde_json::Value::String(s) => s,
                                serde_json::Value::Null => String::new(),
                                other => other.to_string(),
                            })
                            .unwrap_or_default();
                    }
                    let key = key
                        .0
                        .unwrap_or_else(|| source_variable_storage_key_for_get.clone());
                    JS_KV
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&key)
                        .cloned()
                        .unwrap_or_default()
                }),
            )?;

            let source_variable_storage_key_for_set = source_variable_storage_key.clone();
            source_obj.set(
                "setVariable",
                Func::new(
                    move |first: String, second: rquickjs::function::Opt<String>| {
                        if let Some(active) = crate::crawler::session::current_active_session() {
                            match second.0 {
                                Some(value) => active.set_variable_exact(
                                    &first,
                                    serde_json::Value::String(value),
                                ),
                                None => active.set_variable(
                                    "",
                                    serde_json::Value::String(first),
                                ),
                            }
                        } else {
                            let (key, value) = match second.0 {
                                Some(value) => (first, value),
                                None => (source_variable_storage_key_for_set.clone(), first),
                            };
                            JS_KV
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(key, value);
                        }
                    },
                ),
            )?;
            let source_variable_storage_key_for_remove = source_variable_storage_key.clone();
            source_obj.set(
                "__removeVariable",
                Func::new(move || {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.remove_variable("");
                    } else {
                        JS_KV
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .remove(&source_variable_storage_key_for_remove);
                    }
                }),
            )?;

            source_obj.set(
                "getLoginHeader",
                Func::new(|| -> Option<String> {
                    crate::crawler::session::current_active_session()
                        .and_then(|active| active.get_login_header())
                        .map(|value| match value {
                            serde_json::Value::String(s) => s,
                            other => other.to_string(),
                        })
                }),
            )?;

            source_obj.set(
                "putLoginHeader",
                Func::new(|ctx: rquickjs::Ctx<'_>, val: String| -> rquickjs::Result<()> {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.put_login_header(serde_json::Value::String(val))
                            .map_err(|message| rquickjs::Exception::throw_type(&ctx, &message))?;
                    }
                    Ok(())
                }),
            )?;

            source_obj.set(
                "removeLoginHeader",
                Func::new(|| {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.remove_login_header();
                    }
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
                Func::new(|url: String, cookie: String| {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.set_cookie(&url, &cookie);
                    }
                }),
            )?;
            cookie_obj.set(
                "replaceCookie",
                Func::new(|url: String, cookie: String| {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        let mut merged = parse_cookie_pairs(
                            &active.get_cookie(&url).unwrap_or_default(),
                        );
                        for (key, value) in parse_cookie_pairs(&cookie) {
                            merged.insert(key, value);
                        }
                        if !merged.is_empty() {
                            active.set_cookie(&url, &cookie_pairs_to_string(&merged));
                        }
                    }
                }),
            )?;
            cookie_obj.set(
                "set",
                Func::new(|url: String, cookie: String| {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.set_cookie(&url, &cookie);
                    }
                }),
            )?;
            cookie_obj.set(
                "removeCookie",
                Func::new(|url: String| {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.remove_cookie(&url);
                    }
                }),
            )?;
            cookie_obj.set(
                "remove",
                Func::new(|url: String| {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.remove_cookie(&url);
                    }
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
                Func::new(|key: String| {
                    let _ = js_cache_delete(&key);
                }),
            )?;
            cache_obj.set(
                "__memoryGet",
                Func::new(|key: String| -> Option<String> {
                    crate::crawler::session::current_active_session()
                        .and_then(|session| session.memory_cache_get(&key))
                        .and_then(|value| serde_json::to_string(&value).ok())
                }),
            )?;
            cache_obj.set(
                "__memoryPut",
                Func::new(|key: String, value: String| {
                    if let (Some(session), Ok(value)) = (
                        crate::crawler::session::current_active_session(),
                        serde_json::from_str(&value),
                    ) {
                        session.memory_cache_put(key, value);
                    }
                }),
            )?;
            cache_obj.set(
                "__memoryDelete",
                Func::new(|key: String| {
                    if let Some(session) = crate::crawler::session::current_active_session() {
                        session.memory_cache_delete(&key);
                    }
                }),
            )?;
            globals.set("cache", cache_obj)?;

            let java_obj = Object::new(ctx.clone())?;
            let file_cache_namespace = ACTIVE_JS_BOOK_SOURCE.with(|cell| {
                cell.borrow().as_ref().map(|source| source.book_source_url.clone())
            }).unwrap_or_else(|| source_key_val.clone());
            java_obj.set(
                "__fileCache",
                Func::new(move |action: String, arguments: String| -> String {
                    let operation = match action.as_str() {
                        "get" => "cache.file.get",
                        "put" => "cache.file.put",
                        "delete" => "cache.file.delete",
                        _ => return serde_json::json!({"ok":false,"error":{
                            "kind":"invalid_argument","message":"invalid cache operation"}}).to_string(),
                    };
                    if file_cache_namespace.is_empty() {
                        return serde_json::json!({"ok":false,"error":{
                            "kind":"unavailable","message":"file cache requires a source context"}}).to_string();
                    }
                    if arguments.len() > 2 * 1024 * 1024 {
                        return serde_json::json!({"ok":false,"error":{
                            "kind":"limit_exceeded","message":"cache request too large"}}).to_string();
                    }
                    let Ok(mut args) = serde_json::from_str::<JsonValue>(&arguments) else {
                        return serde_json::json!({"ok":false,"error":{
                            "kind":"invalid_argument","message":"invalid cache request"}}).to_string();
                    };
                    let Some(object) = args.as_object_mut() else {
                        return serde_json::json!({"ok":false,"error":{
                            "kind":"invalid_argument","message":"invalid cache request"}}).to_string();
                    };
                    object.insert("namespace".into(), JsonValue::String(file_cache_namespace.clone()));
                    crate::host_services::call(operation, &args).to_string()
                }),
            )?;
            let content_for_set = content_state.clone();
            let base_url_for_set = base_url_state.clone();
            java_obj.set(
                "__setContent",
                Func::new(
                    move |content: String, new_base_url: rquickjs::function::Opt<String>| {
                        *content_for_set.lock().unwrap_or_else(|e| e.into_inner()) = content;
                        if let Some(base_url) = new_base_url.0 {
                            *base_url_for_set.lock().unwrap_or_else(|e| e.into_inner()) = base_url;
                        }
                    },
                ),
            )?;
            java_obj.set(
                "__nativeAjax",
                Func::new(|ctx: rquickjs::Ctx<'_>, url: String| -> String {
                    with_js_reentrant_ctx(&ctx, || java_analyzed_request_body(&url))
                }),
            )?;
            java_obj.set(
                "__importScript",
                Func::new(|ctx: rquickjs::Ctx<'_>, path: String| -> Option<String> {
                    with_js_reentrant_ctx(&ctx, || java_import_script(&path))
                }),
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
                "toNumChapter",
                Func::new(|input: String| -> String { java_to_num_chapter(&input) }),
            )?;
            java_obj.set(
                "__digestHex",
                Func::new(|data: String, algorithm: String| -> Option<String> {
                    java_digest_bytes(&data, &algorithm).map(hex::encode)
                }),
            )?;
            java_obj.set(
                "__digestBase64",
                Func::new(|data: String, algorithm: String| -> Option<String> {
                    java_digest_bytes(&data, &algorithm)
                        .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
                }),
            )?;
            java_obj.set(
                "__hmacHexString",
                Func::new(
                    |data: String, algorithm: String, key: String| -> Option<String> {
                        java_hmac_string_bytes(&data, &algorithm, &key).map(hex::encode)
                    },
                ),
            )?;
            java_obj.set(
                "__hmacBase64String",
                Func::new(
                    |data: String, algorithm: String, key: String| -> Option<String> {
                        java_hmac_string_bytes(&data, &algorithm, &key)
                            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
                    },
                ),
            )?;
            java_obj.set(
                "__archiveInput",
                Func::new(|url: String| -> String { java_archive_input(&url) }),
            )?;
            java_obj.set(
                "__hostCall",
                Func::new(|operation: String, arguments: String| -> String {
                    match serde_json::from_str::<JsonValue>(&arguments) {
                        Ok(arguments) => crate::host_services::call(&operation, &arguments).to_string(),
                        Err(_) => serde_json::json!({"ok":false,"error":{"kind":"invalid_argument","message":"invalid host arguments JSON"}}).to_string(),
                    }
                }),
            )?;
            java_obj.set(
                "__toURL",
                Func::new(
                    |url: String, base_url: rquickjs::function::Opt<String>| -> String {
                        java_to_url_json(&url, base_url.0.as_deref())
                    },
                ),
            )?;
            java_obj.set(
                "getWebViewUA",
                Func::new(|| -> String {
                    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.0.0 Mobile Safari/537.36".to_string()
                }),
            )?;
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
                "__decodeArchiveText",
                Func::new(|bytes_json: String, charset: String| -> Option<String> {
                    let bytes = serde_json::from_str::<Vec<u8>>(&bytes_json).ok()?;
                    if bytes.len() > 262144 {
                        return None;
                    }
                    let label = charset.trim();
                    if !label.is_empty()
                        && encoding_rs::Encoding::for_label(label.as_bytes()).is_none()
                    {
                        return None;
                    }
                    Some(decode_body(
                        &bytes,
                        (!label.is_empty()).then_some(label),
                        None,
                    ))
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
                "__signature",
                Func::new(|request: String| -> String {
                    crate::parser::crypto::signature_json(&request)
                }),
            )?;
            java_obj.set(
                "__symmetricCrypto",
                Func::new(
                    |mode: String,
                     transformation: String,
                     key_json: String,
                     iv_json: String,
                     data_json: String|
                     -> Option<String> {
                        java_symmetric_crypto(
                            &mode,
                            &transformation,
                            &key_json,
                            &iv_json,
                            &data_json,
                        )
                    },
                ),
            )?;
            java_obj.set(
                "__decodeSymmetricInput",
                Func::new(|input: String| -> String {
                    serde_json::to_string(&java_decode_symmetric_input(&input))
                        .unwrap_or_else(|_| "[]".to_string())
                }),
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
                    if let Ok(compressed) = crate::parser::compression::gzip(input.as_bytes()) {
                        base64::engine::general_purpose::STANDARD.encode(compressed)
                    } else {
                        String::new()
                    }
                }),
            )?;
            java_obj.set(
                "ungzip",
                Func::new(|input: String| -> String {
                    let input = input.trim();
                    if input.len() > crate::parser::compression::MAX_INPUT.div_ceil(3) * 4 {
                        return String::new();
                    }
                    base64::engine::general_purpose::STANDARD
                        .decode(input)
                        .ok()
                        .and_then(|bytes| crate::parser::compression::gunzip(&bytes).ok())
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                        .unwrap_or_default()
                }),
            )?;
            java_obj.set(
                "__gunzipBytes",
                Func::new(|input: String| -> String {
                    use crate::parser::compression::{self, Error};
                    let result = if input.len() > compression::MAX_INPUT * 4 + 2 {
                        Err(Error::LimitExceeded)
                    } else {
                        serde_json::from_str::<Vec<u8>>(&input)
                            .map_err(|_| Error::InvalidInput)
                            .and_then(|bytes| compression::gunzip(&bytes))
                    };
                    match result {
                        Ok(bytes) => serde_json::json!({"ok":true,"data":bytes}),
                        Err(error) => serde_json::json!({"ok":false,"error":{
                            "kind":error.kind(),"message":"gzip operation failed"}}),
                    }.to_string()
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
            let base_url_for_get_string = base_url_state.clone();
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
                        let base_url = base_url_for_get_string
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .clone();
                        java_get_string(
                            rule.as_deref(),
                            content.as_deref(),
                            &default_content,
                            &base_url,
                            is_url.unwrap_or(false),
                            unescape.unwrap_or(true),
                        )
                    },
                ),
            )?;

            let default_content_for_get_string_list = content_state.clone();
            let base_url_for_get_string_list = base_url_state.clone();
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
                        let base_url = base_url_for_get_string_list
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .clone();
                        java_get_string_list(
                            rule.as_deref(),
                            content.as_deref(),
                            &default_content,
                            &base_url,
                            is_url.unwrap_or(false),
                        )
                    },
                ),
            )?;

            let content_for_elements = content_state.clone();
            let base_url_for_elements = base_url_state.clone();
            java_obj.set(
                "getElements",
                Func::new(
                    move |rule: String, content: Option<String>, raw_css: Option<bool>| -> String {
                        let default_content = content_for_elements
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .clone();
                        let base_url = base_url_for_elements
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .clone();
                        java_get_elements_json_with_mode(
                            &rule,
                            content.as_deref().unwrap_or(&default_content),
                            &base_url,
                            raw_css.unwrap_or(false),
                        )
                    },
                ),
            )?;
            let content_for_element = content_state.clone();
            let base_url_for_element = base_url_state.clone();
            java_obj.set(
                "getElement",
                Func::new(move |rule: String, content: Option<String>| -> String {
                    let default_content = content_for_element
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    let base_url = base_url_for_element
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    java_get_elements_json(
                        &rule,
                        content.as_deref().unwrap_or(&default_content),
                        &base_url,
                    )
                }),
            )?;

            let variable_overrides_for_put = variable_overrides.clone();
            java_obj.set(
                "put",
                Func::new(move |key: String, val: String| -> String {
                    variable_overrides_for_put
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(key.clone(), val.clone());
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        active.set_variable_exact(&key, serde_json::Value::String(val.clone()));
                    } else {
                        JS_KV
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(key, val.clone());
                    }
                    val
                }),
            )?;
            let rule_bindings = bindings.cloned().unwrap_or_default();
            let variable_overrides_for_get = variable_overrides.clone();
            java_obj.set(
                "__nativeVariableGet",
                Func::new(move |key: String| -> String {
                    variable_overrides_for_get
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&key)
                        .cloned()
                        .or_else(|| scoped_java_variable(&rule_bindings, &key))
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
                Func::new(|msg: rquickjs::function::Opt<rquickjs::Coerced<String>>| {
                    if let Some(m) = msg.0 {
                        eprintln!("[legado::js] {}", m.0);
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
            let base_url_for_html_format = base_url_state.clone();
            java_obj.set(
                "htmlFormat",
                Func::new(move |html: String| -> String {
                    let base_url = base_url_for_html_format
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    crate::parser::html::format_keep_img(&html, &base_url)
                }),
            )?;

            globals.set("java", java_obj)?;
            eval_script(
                ctx.clone(),
                r#"(function() {
                    const java = globalThis.java;
                    java.hostCall = function(operation, arguments) {
                        const response = JSON.parse(java.__hostCall(
                            String(operation), JSON.stringify(arguments == null ? null : arguments)));
                        if (!response.ok) {
                            const error = new Error(response.error.message);
                            error.kind = response.error.kind;
                            throw error;
                        }
                        return response.data;
                    };
                    const chineseConvert = (direction, value) => {
                        const text = String(value == null ? '' : value);
                        if (text.length > 65536) {
                            const error = new Error('Chinese text input too large');
                            error.kind = 'limit_exceeded'; throw error;
                        }
                        if (text === '') return '';
                        const output = java.hostCall('text.chinese.convert', {direction, text});
                        if (typeof output !== 'string' || output.length > 262144) {
                            const error = new Error('invalid Chinese conversion response');
                            error.kind = 'invalid_response'; throw error;
                        }
                        return output;
                    };
                    java.t2s = value => chineseConvert('t2s', value);
                    java.s2t = value => chineseConvert('s2t', value);
                    const nativeSourceSetVariable = globalThis.source.setVariable;
                    const nativeSourceRemoveVariable = globalThis.source.__removeVariable;
                    const nativeSourceRemoveLoginInfo = globalThis.source.__removeLoginInfo;
                    const nativeSourceGetLoginHeader = globalThis.source.getLoginHeader;
                    globalThis.source.removeLoginInfo = function() {
                        nativeSourceRemoveLoginInfo();
                        globalThis.loginInfo = null;
                    };
                    globalThis.source.getLoginHeader = function() {
                        const value = nativeSourceGetLoginHeader();
                        return value == null ? null : value;
                    };
                    globalThis.source.getLoginHeaderMap = function() {
                        const raw = source.getLoginHeader();
                        if (raw == null) return null;
                        let value;
                        try { value = JSON.parse(raw); } catch (_) { return null; }
                        return value && typeof value === 'object' && !Array.isArray(value)
                            ? new Map(Object.entries(value).map(([key, item]) => [key, String(item)]))
                            : null;
                    };
                    globalThis.source.setVariable = function(value, extendedValue) {
                        if (arguments.length > 1) {
                            nativeSourceSetVariable(
                                String(value == null ? '' : value),
                                String(extendedValue == null ? '' : extendedValue));
                            return;
                        }
                        if (value == null) {
                            nativeSourceRemoveVariable();
                            return;
                        }
                        nativeSourceSetVariable(String(value));
                    };
                    const nativeBase64Encode = java.base64Encode;
                    const nativeBase64Decode = java.base64Decode;
                    const cryptoResult = (name, algorithm, value) => {
                        if (value == null) {
                            throw new Error(name + ': unsupported algorithm ' + algorithm);
                        }
                        return value;
                    };
                    java.digestHex = (data, algorithm) => cryptoResult(
                        'digestHex', algorithm,
                        java.__digestHex(String(data), String(algorithm)));
                    java.digestBase64Str = (data, algorithm) => cryptoResult(
                        'digestBase64Str', algorithm,
                        java.__digestBase64(String(data), String(algorithm)));
                    java.HMacHex = (data, algorithm, key) => cryptoResult(
                        'HMacHex', algorithm,
                        java.__hmacHexString(
                            String(data), String(algorithm), String(key)));
                    java.HMacBase64 = (data, algorithm, key) => cryptoResult(
                        'HMacBase64', algorithm,
                        java.__hmacBase64String(
                            String(data), String(algorithm), String(key)));
                    java.toURL = function(url, baseUrl) {
                        const payload = baseUrl == null
                            ? java.__toURL(String(url))
                            : java.__toURL(String(url), String(baseUrl));
                        const raw = JSON.parse(payload);
                        if (raw.error) throw new Error(raw.error);
                        return {
                            searchParams: raw.searchParams == null
                                ? null
                                : new Map(Object.entries(raw.searchParams)),
                            host: String(raw.host || ''),
                            origin: String(raw.origin || ''),
                            pathname: String(raw.pathname || '')
                        };
                    };
                    java.logType = value => {
                        let type;
                        if (value === null || value === undefined) type = 'null';
                        else if (typeof value === 'string') type = 'java.lang.String';
                        else if (typeof value === 'boolean') type = 'java.lang.Boolean';
                        else if (typeof value === 'number') type = 'java.lang.Double';
                        else if (value instanceof Uint8Array) type = '[B';
                        else if (Array.isArray(value)) type = 'org.mozilla.javascript.NativeArray';
                        else if (typeof value === 'function') type = 'org.mozilla.javascript.NativeFunction';
                        else type = 'org.mozilla.javascript.NativeObject';
                        java.log(type);
                    };
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
                    java.ajax = value => {
                        const target = Array.isArray(value) ? value[0] : value;
                        return java.__nativeAjax(String(target == null ? '' : target));
                    };
                    java.importScript = path => {
                        const value = java.__importScript(String(path == null ? '' : path));
                        if (value == null) {
                            throw new Error('importScript: content is empty or local paths are unsupported by this host');
                        }
                        return value;
                    };
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
                    java.base64Encode = function(value, flags) {
                        const text = String(value == null ? '' : value);
                        if (arguments.length < 2) return nativeBase64Encode(text);
                        return java.__base64EncodeBytes(
                            JSON.stringify(java.strToBytes(text, 'UTF-8')),
                            Number(flags || 0));
                    };
                    java.base64Decode = function(value, charsetOrFlags) {
                        const text = String(value == null ? '' : value);
                        if (typeof charsetOrFlags === 'number') {
                            const bytes = JSON.parse(java.__base64DecodeBytes(
                                text, Number(charsetOrFlags)));
                            return java.bytesToStr(bytes, 'UTF-8');
                        }
                        return charsetOrFlags == null
                            ? nativeBase64Decode(text)
                            : nativeBase64Decode(text, String(charsetOrFlags));
                    };
                    java.base64DecodeToByteArray = function(value, flags) {
                        if (value == null || String(value).trim() === '') return null;
                        return JSON.parse(java.__base64DecodeBytes(
                            String(value), Number(flags || 0)));
                    };
                    const fileCacheCall = (action, arguments) => {
                        const response = JSON.parse(java.__fileCache(action, JSON.stringify(arguments)));
                        if (!response.ok) {
                            const error = new Error(response.error.message);
                            error.kind = response.error.kind; throw error;
                        }
                        return response.data;
                    };
                    globalThis.cache.getFile = key => {
                        const value = fileCacheCall('get', {key: String(key)});
                        if (value !== null && (typeof value !== 'string' || value.length > 262144)) {
                            const error = new Error('invalid file cache response');
                            error.kind = 'invalid_response'; throw error;
                        }
                        return value;
                    };
                    globalThis.cache.putFile = (key, value, saveTime) => {
                        const ttl = saveTime == null ? 0 : Number(saveTime);
                        const text = String(value == null ? '' : value);
                        if (!Number.isInteger(ttl) || ttl < -2147483648 || ttl > 2147483647
                            || text.length > 262144) {
                            const error = new Error('invalid file cache value or TTL');
                            error.kind = 'invalid_argument'; throw error;
                        }
                        if (fileCacheCall('put', {key: String(key), value: text, saveTime: ttl}) !== true) {
                            const error = new Error('invalid file cache write response');
                            error.kind = 'invalid_response'; throw error;
                        }
                    };
                    const nativeCacheGet = globalThis.cache.get;
                    const nativeCachePut = globalThis.cache.put;
                    const nativeCacheDelete = globalThis.cache.delete;
                    globalThis.cache.get = key => {
                        const value = nativeCacheGet(String(key));
                        return value == null ? null : value;
                    };
                    globalThis.cache.put = (key, value, saveTime) => {
                        let stored;
                        if (typeof value === 'string') stored = value;
                        else {
                            try { stored = JSON.stringify(value); }
                            catch (_) { stored = String(value); }
                        }
                        if (stored === undefined) stored = String(value);
                        const ok = saveTime == null
                            ? nativeCachePut(String(key), stored)
                            : nativeCachePut(String(key), stored, Number(saveTime));
                        if (!ok) throw new Error('cache.put: session cache limit exceeded');
                    };
                    globalThis.cache.delete = key => {
                        key = String(key);
                        try {
                            if (fileCacheCall('delete', {key}) !== true) {
                                const error = new Error('invalid file cache delete response');
                                error.kind = 'invalid_response'; throw error;
                            }
                        } catch (error) {
                            // Keep legacy memory-only deletion when the optional
                            // service/source context is not configured. Real errors
                            // are terminal and must not clear memory or be retried.
                            if (error.kind !== 'unavailable' && error.kind !== 'unsupported') throw error;
                        }
                        nativeCacheDelete(key);
                        localMemory.delete(key);
                        cache.__memoryDelete(key);
                    };
                    // Memory entries are per active FFI operation, never persisted
                    // into the caller's session delta or shared across users.
                    const localMemory = new Map();
                    globalThis.cache.getFromMemory = key => {
                        key = String(key);
                        const stored = cache.__memoryGet(key);
                        return stored == null ? (localMemory.get(key) ?? null) : JSON.parse(stored);
                    };
                    globalThis.cache.putMemory = (key, value) => {
                        key = String(key);
                        localMemory.set(key, value);
                        const encoded = JSON.stringify(value);
                        if (encoded !== undefined) cache.__memoryPut(key, encoded);
                    };
                    globalThis.cache.deleteMemory = key => {
                        key = String(key);
                        localMemory.delete(key);
                        cache.__memoryDelete(key);
                    };
                })();"#,
            )?;

            globals.set(
                "kv_get",
                Func::new(|key: String| -> Option<String> {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        return active.js_cache_get(&format!("__kv:{key}"));
                    }
                    let map = JS_KV.lock().unwrap_or_else(|e| e.into_inner());
                    map.get(&key).cloned()
                }),
            )?;
            globals.set(
                "kv_put",
                Func::new(|key: String, val: String| -> bool {
                    if let Some(active) = crate::crawler::session::current_active_session() {
                        return active.js_cache_put(&format!("__kv:{key}"), val, None);
                    }
                    let mut map = JS_KV.lock().unwrap_or_else(|e| e.into_inner());
                    map.insert(key, val);
                    true
                }),
            )?;
            globals.set(
                "regex_replace",
                Func::new(
                    |input: String, pattern: String, replace: String| -> String {
                        source_regex::replace_all(&input, &pattern, &replace)
                            .unwrap_or(input)
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
                "source.getLoginInfo = function() { if (globalThis.loginInfo == null) return null; return typeof globalThis.loginInfo === 'string' ? globalThis.loginInfo : JSON.stringify(globalThis.loginInfo); }; source.getLoginInfoMap = function() { const raw = source.getLoginInfo(); if (raw == null) return null; let value; try { value = JSON.parse(raw); } catch (_) { return null; } return value && typeof value === 'object' ? new Map(Object.entries(value).map(([key, item]) => [key, String(item)])) : null; }; java.reGetBook = function() { if (globalThis.__allowTocRefresh !== true) throw new Error('java.reGetBook is only available in preUpdateJs'); throw new Error('java.reGetBook is not supported by this host'); }; java.refreshTocUrl = function() { if (globalThis.__allowTocRefresh !== true) throw new Error('java.refreshTocUrl is only available in preUpdateJs'); throw new Error('java.refreshTocUrl is not supported by this host'); };",
            )?;

            eval_script(
                ctx.clone(),
                r#"if (globalThis.java && globalThis.java.getString) {
                    const _orig_getString = globalThis.java.getString;
                    globalThis.java.getString = function(rule, content, isUrl, unescape) {
                        const r = (rule !== undefined && rule !== null) ? String(rule) : undefined;
                        if (typeof content === 'boolean' && arguments.length === 2) {
                            return _orig_getString(r, undefined, false, content);
                        }
                        if (typeof content === 'object' && content !== null) {
                            try { content = JSON.stringify(content); } catch (e) {}
                        }
                        const c = (content !== undefined && content !== null) ? String(content) : undefined;
                        return _orig_getString(r, c, isUrl, unescape);
                    };
                    const _orig_getStringList = globalThis.java.getStringList;
                    globalThis.java.getStringList = function(rule, content, isUrl) {
                        if (rule == null || String(rule) === '') return null;
                        if (typeof content === 'object' && content !== null) {
                            try { content = JSON.stringify(content); } catch (e) {}
                        }
                        const r = String(rule);
                        const c = (content !== undefined && content !== null) ? String(content) : undefined;
                        return _orig_getStringList(r, c, isUrl);
                    };
                    const _nativeSetContent = globalThis.java.__setContent;
                    globalThis.java.setContent = function(content, newBaseUrl) {
                        if (content == null) throw new Error('content cannot be null');
                        if (typeof content === 'object') {
                            try { content = JSON.stringify(content); } catch (e) {}
                        }
                        const normalized = String(content);
                        const base = newBaseUrl == null ? undefined : String(newBaseUrl);
                        if (base === undefined) _nativeSetContent(normalized);
                        else _nativeSetContent(normalized, base);
                        if (base !== undefined) {
                            globalThis.baseUrl = base;
                            globalThis.base_url = base;
                        }
                        return globalThis.java;
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

            globals.get::<_, Object<'_>>("java")?.set(
                "__jsoupRemove",
                Func::new(|source: String, selector: String| -> Option<String> {
                    jsoup_remove_elements(&source, &selector)
                }),
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
                            let source = String(html == null ? '' : html);
                            return {
                                select(selector) {
                                    const rule = String(selector);
                                    const items = globalThis.java.getElements(rule, source, true);
                                    items.remove = function() {
                                        const updated = globalThis.java.__jsoupRemove(source, rule);
                                        if (updated == null) throw new Error('invalid jsoup remove selector');
                                        source = updated;
                                        return items;
                                    };
                                    return items;
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
                    java.createSymmetricCrypto = function(transformation, key, iv) {
                        const algorithm = String(transformation == null ? '' : transformation);
                        const normalized = algorithm.toUpperCase() === 'DES'
                            ? 'DES/ECB/PKCS5PADDING' : algorithm.toUpperCase();
                        if (!/^(AES|DES)\/(CBC|ECB)\/(PKCS5PADDING|PKCS7PADDING|NOPADDING)$/.test(normalized)) {
                            throw new Error(
                                'createSymmetricCrypto: unsupported transformation ' + algorithm);
                        }
                        const des = normalized.startsWith('DES/');
                        const symmetricBytes = value => {
                            if (Array.isArray(value) || value instanceof Uint8Array) {
                                return Array.from(value, byte => {
                                    if (!Number.isInteger(byte) || byte < -128 || byte > 255) {
                                        throw new Error('createSymmetricCrypto: invalid byte');
                                    }
                                    return (byte + 256) % 256;
                                });
                            }
                            return toBytes(value);
                        };
                        const keyBytes = symmetricBytes(key);
                        const ivBytes = iv == null ? [] : symmetricBytes(iv);
                        const cbc = normalized.split('/')[1] === 'CBC';
                        const blockSize = des ? 8 : 16;
                        if (!(des ? keyBytes.length === 8 : [16, 24, 32].includes(keyBytes.length))
                            || (cbc ? ivBytes.length !== blockSize : ivBytes.length !== 0)) {
                            throw new Error('createSymmetricCrypto: invalid key or iv');
                        }
                        const native = !des;
                        let capabilities;
                        if (!native) {
                            capabilities = java.hostCall('crypto.capabilities', {});
                            const combination = capabilities && capabilities.symmetric
                                && capabilities.symmetric[normalized];
                            if (!capabilities || capabilities.protocol !== 1 || !combination
                                || !Array.isArray(combination.keyBytes)
                                || !combination.keyBytes.includes(keyBytes.length)
                                || !Number.isSafeInteger(capabilities.maxInputBytes)
                                || capabilities.maxInputBytes < 0) {
                                throw new Error('createSymmetricCrypto: host combination unavailable');
                            }
                        }
                        const invoke = (mode, data) => {
                            const dataBytes = Array.isArray(data) || data instanceof Uint8Array
                                ? symmetricBytes(data)
                                : mode.startsWith('decrypt')
                                    ? JSON.parse(java.__decodeSymmetricInput(String(data == null ? '' : data)))
                                    : symmetricBytes(data);
                            if (!native) {
                                if (dataBytes.length > capabilities.maxInputBytes) {
                                    throw new Error('createSymmetricCrypto: input too large');
                                }
                                const bytes = java.hostCall('crypto.symmetric', {
                                    action: mode, transformation: normalized,
                                    key: keyBytes, iv: ivBytes, data: dataBytes
                                });
                                if (!Array.isArray(bytes) || bytes.length > dataBytes.length + 16
                                    || !bytes.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
                                    throw new Error('createSymmetricCrypto: invalid host byte response');
                                }
                                return bytes;
                            }
                            const nativeLimit = 262144 + (mode === 'decrypt' && !normalized.endsWith('/NOPADDING') ? 16 : 0);
                            if (dataBytes.length > nativeLimit) {
                                const error = new Error('createSymmetricCrypto: input too large');
                                error.kind = 'limit_exceeded'; throw error;
                            }
                            const result = java.__symmetricCrypto(
                                mode,
                                algorithm,
                                JSON.stringify(keyBytes),
                                JSON.stringify(ivBytes),
                                JSON.stringify(dataBytes));
                            if (result == null) {
                                const error = new Error('createSymmetricCrypto: invalid block length or padding');
                                error.kind = 'operation_failed'; throw error;
                            }
                            return JSON.parse(result);
                        };
                        return {
                            encrypt(data) {
                                return invoke('encrypt', data);
                            },
                            encryptBase64(data) {
                                return java.__base64EncodeBytes(
                                    JSON.stringify(invoke('encrypt', data)), 2);
                            },
                            encryptHex(data) {
                                return invoke('encrypt', data)
                                    .map(byte => byte.toString(16).padStart(2, '0'))
                                    .join('');
                            },
                            decrypt(data) {
                                return invoke('decrypt', data);
                            },
                            decryptStr(data) {
                                return java.bytesToStr(invoke('decrypt', data), 'UTF-8');
                            }
                        };
                    };
                    const cryptoKeyValue = value => {
                        if (Array.isArray(value) || value instanceof Uint8Array) {
                            if (value.length > 16384) throw new Error('crypto key too large');
                            return Array.from(value, byte => {
                                if (!Number.isInteger(byte) || byte < -128 || byte > 255) {
                                    const error = new Error('invalid crypto key byte');
                                    error.kind = 'invalid_argument'; throw error;
                                }
                                return (byte + 256) % 256;
                            });
                        }
                        const text = String(value == null ? '' : value);
                        if (text.length > 16384) throw new Error('crypto key too large');
                        if (text.includes('-----BEGIN ')) return text;
                        return JSON.parse(java.__base64DecodeBytes(text, 0));
                    };
                    java.createAsymmetricCrypto = function(transformation) {
                        const name = String(transformation == null ? '' : transformation).toUpperCase();
                        const algorithm = name === 'RSA' ? 'RSA/ECB/PKCS1PADDING' : name;
                        if (algorithm !== 'RSA/ECB/PKCS1PADDING') {
                            throw new Error('createAsymmetricCrypto: unsupported transformation');
                        }
                        let publicKey, privateKey, capabilities;
                        const keyValue = cryptoKeyValue;
                        const invoke = (action, data, usePublicKey) => {
                            // Android defaults to PUBLIC for BOTH encrypt and decrypt.
                            const usePublic = usePublicKey === undefined ? true : Boolean(usePublicKey);
                            if ((action === 'decrypt') === usePublic) {
                                const error = new Error('createAsymmetricCrypto: unsupported key direction');
                                error.kind = 'unsupported';
                                throw error;
                            }
                            const key = usePublic ? publicKey : privateKey;
                            if (key == null) throw new Error('createAsymmetricCrypto: selected key is missing');
                            if (!capabilities) capabilities = java.hostCall('crypto.rsa.capabilities', {});
                            if (!capabilities || capabilities.protocol !== 1 || capabilities.available !== true
                                || capabilities.transformation !== algorithm
                                || !Number.isSafeInteger(capabilities.maxInputBytes)
                                || capabilities.maxInputBytes < 0
                                || !Number.isSafeInteger(capabilities.maxEncryptBytes)
                                || capabilities.maxEncryptBytes < 0
                                || !Number.isSafeInteger(capabilities.maxOutputBytes)
                                || capabilities.maxOutputBytes < 0) {
                                throw new Error('createAsymmetricCrypto: host capability unavailable');
                            }
                            const input = action === 'decrypt' && typeof data === 'string'
                                ? JSON.parse(java.__decodeSymmetricInput(data)) : toBytes(data);
                            const limit = action === 'encrypt'
                                ? capabilities.maxEncryptBytes : capabilities.maxInputBytes;
                            if (input.length > limit) {
                                throw new Error('createAsymmetricCrypto: input too large');
                            }
                            const output = java.hostCall('crypto.asymmetric', {
                                action, transformation: algorithm, usePublicKey: usePublic, key, data: input
                            });
                            if (!Array.isArray(output) || output.length > capabilities.maxOutputBytes
                                || !output.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
                                throw new Error('createAsymmetricCrypto: invalid host byte response');
                            }
                            return output;
                        };
                        const object = {
                            setPublicKey(value) { publicKey = keyValue(value); return object; },
                            setPrivateKey(value) { privateKey = keyValue(value); return object; },
                            encrypt(data, usePublicKey) { return invoke('encrypt', data, usePublicKey); },
                            encryptBase64(data, usePublicKey) {
                                return java.__base64EncodeBytes(JSON.stringify(invoke('encrypt', data, usePublicKey)), 2);
                            },
                            encryptHex(data, usePublicKey) {
                                return invoke('encrypt', data, usePublicKey)
                                    .map(byte => byte.toString(16).padStart(2, '0')).join('');
                            },
                            decrypt(data, usePublicKey) { return invoke('decrypt', data, usePublicKey); },
                            decryptStr(data, usePublicKey) {
                                return java.bytesToStr(invoke('decrypt', data, usePublicKey), 'UTF-8');
                            }
                        };
                        return object;
                    };
                    java.createSign = function(algorithm) {
                        const name = String(algorithm == null ? '' : algorithm).toUpperCase();
                        if (name !== 'SHA256WITHRSA') throw new Error('createSign: unsupported algorithm');
                        let privateKey, publicKey;
                        const capabilities = {maxInputBytes:16384,maxSignatureBytes:512};
                        const signatureError = (kind, message) => {
                            const error = new Error('createSign: ' + message);
                            error.kind = kind; return error;
                        };
                        const signatureBytes = value => Array.from(value, byte => {
                            if (!Number.isInteger(byte) || byte < -128 || byte > 255) {
                                const error = new Error('createSign: invalid byte');
                                error.kind = 'invalid_argument'; throw error;
                            }
                            return (byte + 256) % 256;
                        });
                        const invoke = (action, data, signature, charset) => {
                            const key = action === 'sign' ? privateKey : publicKey;
                            if (key == null) throw signatureError('invalid_argument', 'selected key is missing');
                            if (typeof data !== 'string' && !Array.isArray(data) && !(data instanceof Uint8Array)) {
                                throw signatureError('invalid_argument', 'text or byte input required');
                            }
                            if (data.length > capabilities.maxInputBytes) throw signatureError('limit_exceeded', 'input too large');
                            const input = typeof data === 'string'
                                ? java.strToBytes(data, charset == null ? 'UTF-8' : String(charset)) : signatureBytes(data);
                            if (input.length > capabilities.maxInputBytes) throw signatureError('limit_exceeded', 'input too large');
                            let sig;
                            if (action === 'verify') {
                                if (!Array.isArray(signature) && !(signature instanceof Uint8Array)) {
                                    throw signatureError('invalid_argument', 'signature bytes required');
                                }
                                if (signature.length > capabilities.maxSignatureBytes) throw signatureError('limit_exceeded', 'signature too large');
                                sig = signatureBytes(signature);
                            }
                            const response = JSON.parse(java.__signature(JSON.stringify({
                                action, algorithm: name, key, data: input, signature: sig
                            })));
                            if (!response.ok) {
                                const error = new Error(response.error.message);
                                error.kind = response.error.kind; throw error;
                            }
                            const result = response.data;
                            if (action === 'verify') {
                                if (typeof result !== 'boolean') throw new Error('createSign: invalid verification response');
                            } else if (!Array.isArray(result) || result.length < 128
                                || result.length > capabilities.maxSignatureBytes
                                || !result.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
                                throw new Error('createSign: invalid signature response');
                            }
                            return result;
                        };
                        const object = {
                            setPrivateKey(value) { privateKey = cryptoKeyValue(value); return object; },
                            setPublicKey(value) { publicKey = cryptoKeyValue(value); return object; },
                            sign(data, charset) { return invoke('sign', data, undefined, charset); },
                            signHex(data, charset) {
                                return invoke('sign', data, undefined, charset)
                                    .map(byte => byte.toString(16).padStart(2, '0')).join('');
                            },
                            verify(data, signature) { return invoke('verify', data, signature); }
                        };
                        return object;
                    };
                    const archiveInput = value => {
                        if (Array.isArray(value) || value instanceof Uint8Array) {
                            if (value.length > 524288) throw new Error('archive input too large');
                            return toBytes(value);
                        }
                        const text = String(value == null ? '' : value);
                        if (/^https?:\/\//i.test(text)) {
                            const response = JSON.parse(java.__archiveInput(text));
                            if (!response.ok) {
                                const error = new Error(response.error.message);
                                error.kind = response.error.kind; throw error;
                            }
                            return response.data;
                        }
                        if (text.length > 1048576 || text.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(text)) {
                            throw new Error('archive input must be hexadecimal or bytes');
                        }
                        return JSON.parse(java.__hexDecodeBytes(text));
                    };
                    const archiveBytes = (operation, arguments) => {
                        const output = java.hostCall(operation, arguments);
                        if (output === null) return null;
                        if (!Array.isArray(output) || output.length > 262144
                            || !output.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
                            throw new Error('invalid archive byte response');
                        }
                        return output;
                    };
                    java.getZipByteArrayContent = function(input, path) {
                        return archiveBytes('compression.zip.read', {
                            data: archiveInput(input), path: String(path)
                        });
                    };
                    java.getZipStringContent = function(input, path, charset) {
                        const bytes = java.getZipByteArrayContent(input, path);
                        if (bytes === null) return '';
                        const text = java.__decodeArchiveText(
                            JSON.stringify(bytes), charset == null ? '' : String(charset));
                        if (text === null || text === undefined) {
                            const error = new Error('getZipStringContent: invalid bytes or unsupported charset');
                            error.kind = 'invalid_argument';
                            throw error;
                        }
                        return text;
                    };
                    // Project extension: unlike existing ungzip, this returns raw bytes.
                    java.gunzipBytes = function(input) {
                        const response = JSON.parse(java.__gunzipBytes(JSON.stringify(archiveInput(input))));
                        if (!response.ok) {
                            const error = new Error(response.error.message);
                            error.kind = response.error.kind;
                            throw error;
                        }
                        return response.data;
                    };
                    const base64 = {
                        DEFAULT: 0, NO_PADDING: 1, NO_WRAP: 2, CRLF: 4, URL_SAFE: 8,
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
                        getEncoder() { return javaBase64Encoder(base64.NO_WRAP); },
                        getDecoder() { return { decode: value => base64.decode(value, 0) }; },
                        getUrlEncoder() { return javaBase64Encoder(base64.URL_SAFE | base64.NO_WRAP); },
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
                    const streamRange = (bytes, offset, length) => {
                        if (!Array.isArray(bytes) && !(bytes instanceof Uint8Array)) {
                            throw new Error('byte array required');
                        }
                        const start = offset === undefined ? 0 : Number(offset);
                        const count = length === undefined ? bytes.length - start : Number(length);
                        if (!Number.isInteger(start) || !Number.isInteger(count)
                            || start < 0 || count < 0 || start + count > bytes.length) {
                            throw new Error('invalid stream byte range');
                        }
                        return [start, count];
                    };
                    function ByteArrayInputStream(bytes, offset, length) {
                        if (!new.target) return new ByteArrayInputStream(bytes, offset, length);
                        const [start, count] = streamRange(bytes, offset, length);
                        if (count > 524288) throw new Error('stream input too large');
                        this.bytes = toBytes(bytes.slice(start, start + count));
                        this.position = 0;
                        this.markPosition = 0;
                        this.closed = false;
                    }
                    ByteArrayInputStream.prototype = {
                        checkOpen() { if (this.closed) throw new Error('stream is closed'); },
                        read(buffer, offset, length) {
                            this.checkOpen();
                            if (buffer === undefined) {
                                return this.position < this.bytes.length ? this.bytes[this.position++] : -1;
                            }
                            const [start, count] = streamRange(buffer, offset, length);
                            if (count === 0) return 0;
                            if (this.position === this.bytes.length) return -1;
                            const n = Math.min(count, this.bytes.length - this.position);
                            for (let i = 0; i < n; ++i) buffer[start + i] = this.bytes[this.position++];
                            return n;
                        },
                        readAllBytes() {
                            this.checkOpen();
                            const result = this.bytes.slice(this.position);
                            this.position = this.bytes.length;
                            return result;
                        },
                        readNBytes(length) {
                            this.checkOpen();
                            if (!Number.isInteger(length) || length < 0) throw new Error('invalid read length');
                            const result = this.bytes.slice(this.position, this.position + length);
                            this.position += result.length;
                            return result;
                        },
                        available() { this.checkOpen(); return this.bytes.length - this.position; },
                        skip(count) {
                            this.checkOpen();
                            if (!Number.isSafeInteger(count)) throw new Error('invalid skip count');
                            const n = Math.min(Math.max(0, count), this.bytes.length - this.position);
                            this.position += n;
                            return n;
                        },
                        mark() { this.markPosition = this.position; },
                        reset() { this.checkOpen(); this.position = this.markPosition; },
                        markSupported() { return true; },
                        close() {} // JDK ByteArrayInputStream close is a no-op.
                    };
                    function GZIPInputStream(input, size) {
                        if (!new.target) return new GZIPInputStream(input, size);
                        if (!(input instanceof ByteArrayInputStream)) throw new Error('ByteArrayInputStream required');
                        if (size !== undefined && (!Number.isInteger(size) || size <= 0 || size > 262144)) {
                            throw new Error('invalid gzip buffer size');
                        }
                        input.checkOpen();
                        const decoded = java.gunzipBytes(input.bytes.slice(input.position));
                        input.position = input.bytes.length;
                        this.bytes = decoded;
                        this.position = 0;
                        this.closed = false;
                        this.input = input;
                    }
                    GZIPInputStream.prototype = Object.create(ByteArrayInputStream.prototype);
                    Object.assign(GZIPInputStream.prototype, {
                        available() { this.checkOpen(); return this.position < this.bytes.length ? 1 : 0; },
                        markSupported() { return false; },
                        mark() {},
                        reset() { throw new Error('gzip mark/reset is unsupported'); },
                        close() { if (!this.closed) { this.closed = true; this.input.close(); } }
                    });
                    function ByteArrayOutputStream(size) {
                        if (!new.target) return new ByteArrayOutputStream(size);
                        if (size !== undefined && (!Number.isInteger(size) || size < 0 || size > 262144)) {
                            throw new Error('invalid output stream size');
                        }
                        this.bytes = [];
                    }
                    ByteArrayOutputStream.prototype = {
                        write(value, offset, length) {
                            if (typeof value === 'number') {
                                if (!Number.isInteger(value)) throw new Error('integer byte required');
                                if (this.bytes.length >= 262144) throw new Error('output stream too large');
                                this.bytes.push(value & 255);
                                return;
                            }
                            const [start, count] = streamRange(value, offset, length);
                            if (this.bytes.length + count > 262144) throw new Error('output stream too large');
                            for (let i = 0; i < count; ++i) this.bytes.push(Number(value[start + i]) & 255);
                        },
                        toByteArray() { return this.bytes.slice(); },
                        toString(charset) { return java.bytesToStr(this.bytes, charset == null ? 'UTF-8' : String(charset)); },
                        size() { return this.bytes.length; },
                        reset() { this.bytes = []; },
                        writeTo(stream) { stream.write(this.bytes); },
                        flush() {},
                        close() {} // JDK ByteArrayOutputStream close is a no-op.
                    };
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
                    Packages.java.io = Packages.java.io || {};
                    Packages.java.util = Packages.java.util || {};
                    Packages.java.util.zip = Packages.java.util.zip || {};
                    Packages.javax = Packages.javax || {};
                    Packages.javax.crypto = Packages.javax.crypto || {};
                    Packages.javax.crypto.spec = Packages.javax.crypto.spec || {};
                    Packages.javax.xml = Packages.javax.xml || {};
                    Packages.javax.xml.bind = Packages.javax.xml.bind || {};
                    Packages.android = Packages.android || {};
                    Packages.android.util = Packages.android.util || {};

                    Packages.java.lang.String = markClass('String', JavaString);
                    Packages.java.io.ByteArrayInputStream = markClass('ByteArrayInputStream', ByteArrayInputStream);
                    Packages.java.io.ByteArrayOutputStream = markClass('ByteArrayOutputStream', ByteArrayOutputStream);
                    Packages.java.util.zip.GZIPInputStream = markClass('GZIPInputStream', GZIPInputStream);
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

            eval_script(ctx.clone(), include_str!("js_security.js"))?;
            eval_script(ctx.clone(), include_str!("js_des.js"))?;

            if !shared_js.trim().is_empty() {
                eval_script(ctx.clone(), &shared_js)?;
            }

            eval_script(
                ctx.clone(),
                r#"if (globalThis.result && globalThis.result.__ffiStrResponse === true) {
                    globalThis.result = globalThis.__readerMakeStrResponse(globalThis.result);
                }"#,
            )?;

            // Keep rule lexical declarations local within this evaluation too.
            if let Some((initial, _)) = header_map {
                let java: Object<'_> = globals.get("java")?;
                install_header_map(&ctx, &java, initial)?;
            }
            let scoped_script = format!("{{\n{script}\n}}");
            let v = eval_script(ctx.clone(), &scoped_script)?;
            if let Some((_, updated)) = header_map {
                *updated.borrow_mut() = Some(collect_header_map(&ctx)?);
            }

            let result = if v.is_null() {
                String::new()
            } else if v.is_undefined() {
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

fn snapshot_object_properties<'js>(
    object: &Object<'js>,
) -> anyhow::Result<HashMap<String, Value<'js>>> {
    let mut snapshot = HashMap::new();
    for key in object.keys::<String>() {
        let key = key?;
        snapshot.insert(key.clone(), object.get::<_, Value<'js>>(key.as_str())?);
    }
    Ok(snapshot)
}

fn restore_object_properties<'js>(
    object: &Object<'js>,
    snapshot: HashMap<String, Value<'js>>,
) -> anyhow::Result<()> {
    let current_keys = object
        .keys::<String>()
        .collect::<rquickjs::Result<Vec<_>>>()?;
    for key in current_keys {
        if !snapshot.contains_key(&key) {
            object.remove(key.as_str())?;
        }
    }
    for (key, value) in snapshot {
        object.set(key.as_str(), value)?;
    }
    Ok(())
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
    let globals_snapshot = snapshot_object_properties(&globals)?;
    let java: Object<'js> = globals.get("java")?;
    let java_snapshot = snapshot_object_properties(&java)?;
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

    for name in [
        "input", "result", "src", "base_url", "baseUrl", "url", "key", "page",
    ] {
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

        // Direct eval inside a temporary function keeps nested AnalyzeUrl
        // var/function declarations local while preserving eval's completion value.
        // Explicit globalThis/java mutations are restored by the snapshots below.
        let source = serde_json::to_string(script)?;
        let scoped_script = format!("(function() {{ return eval({source}); }})()");
        let value = eval_script(ctx.clone(), &scoped_script)?;
        if value.is_null() {
            return Ok(String::new());
        }
        if value.is_undefined() {
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

    let java_restore = restore_object_properties(&java, java_snapshot);
    let globals_restore = restore_object_properties(&globals, globals_snapshot);
    match result {
        Err(error) => Err(error),
        Ok(value) => {
            java_restore?;
            globals_restore?;
            Ok(value)
        }
    }
}

fn finalize_java_get_string_url(value: String, base_url: &str, is_url: bool) -> String {
    if !is_url {
        value
    } else if value.trim().is_empty() {
        base_url.to_string()
    } else {
        rule_engine::resolve_url(base_url, &value)
    }
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
        return finalize_java_get_string_url(String::new(), base_url, is_url);
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
                    false,
                    unescape,
                );
                if !res.is_empty() {
                    return finalize_java_get_string_url(res, base_url, is_url);
                }
            }
            return finalize_java_get_string_url(String::new(), base_url, is_url);
        } else if delim == "&&" {
            let mut results = Vec::new();
            for part in split.parts {
                let res = java_get_string(
                    Some(&part),
                    content,
                    default_content,
                    base_url,
                    false,
                    unescape,
                );
                if !res.is_empty() {
                    results.push(res);
                }
            }
            return finalize_java_get_string_url(results.join("\n"), base_url, is_url);
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
        html::select_xpath(target_content, pure).join("\n")
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
        source_regex::captures_first(pure, target_content)
            .and_then(|captures| {
                captures
                    .get(1)
                    .and_then(Clone::clone)
                    .or_else(|| captures.first().and_then(Clone::clone))
            })
            .unwrap_or_default()
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

    finalize_java_get_string_url(res, base_url, is_url)
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
        } else if delim == "&&" {
            let mut results = Vec::new();
            for part in split.parts {
                results.extend(java_get_string_list(
                    Some(&part),
                    content,
                    default_content,
                    base_url,
                    is_url,
                ));
            }
            return results;
        } else if delim == "%%" {
            let groups = split
                .parts
                .iter()
                .map(|part| {
                    java_get_string_list(Some(part), content, default_content, base_url, is_url)
                })
                .collect();
            return rule_analyzer::interleave_result_groups(groups);
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
        source_regex::captures_all(pure, target_content)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|captures| {
                captures
                    .get(1)
                    .and_then(Clone::clone)
                    .or_else(|| captures.first().and_then(Clone::clone))
            })
            .collect()
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

fn jsoup_remove_elements(source: &str, selector: &str) -> Option<String> {
    if !html::css_rule_is_valid(selector) {
        return None;
    }
    let mut document = html::parse_document(source);
    let ids = html::select_css_list(&document, selector)
        .iter()
        .map(|element| element.id())
        .collect::<Vec<_>>();
    for id in ids {
        if let Some(mut node) = document.tree.get_mut(id) {
            node.detach();
        }
    }
    Some(document.html())
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

fn java_decode_symmetric_input(input: &str) -> Vec<u8> {
    let input = input.trim();
    if !input.is_empty()
        && input.len().is_multiple_of(2)
        && input.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        if let Ok(bytes) = hex::decode(input) {
            return bytes;
        }
    }
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(input))
        .unwrap_or_default()
}

fn java_symmetric_crypto(
    mode: &str,
    transformation: &str,
    key_json: &str,
    iv_json: &str,
    data_json: &str,
) -> Option<String> {
    let key: Vec<u8> = serde_json::from_str(key_json).ok()?;
    let iv: Vec<u8> = serde_json::from_str(iv_json).ok()?;
    let data: Vec<u8> = serde_json::from_str(data_json).ok()?;
    let output = crate::parser::crypto::symmetric(mode, transformation, &key, &iv, &data)?;
    serde_json::to_string(&output).ok()
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
    // A remote library can depend on a user's cookies. Keep it in the active
    // operation only; a process-global cache would expose one user's script
    // to another user of the same book source.
    let remote = serde_json::from_str::<JsonValue>(&js_lib)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .is_some_and(|map| {
            map.values()
                .filter_map(JsonValue::as_str)
                .any(is_absolute_http_url)
        });
    if remote {
        let active = crate::crawler::session::current_active_session();
        if let Some(cached) = active
            .as_ref()
            .and_then(|session| session.script_cache_get(&cache_key))
        {
            return Ok(cached);
        }
        let compiled = compile_js_lib(&js_lib)?;
        if let Some(session) = active {
            session.script_cache_put(cache_key, compiled.clone());
        }
        return Ok(compiled);
    }
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

fn java_import_script(path: &str) -> Option<String> {
    let path = path.trim();
    if path.is_empty() || !is_absolute_http_url(path) {
        return None;
    }

    let cache_key = format!("import_script:{}", md5_hex(path));
    let active = crate::crawler::session::current_active_session();
    if let Some(cached) = active
        .as_ref()
        .and_then(|session| session.script_cache_get(&cache_key))
    {
        return Some(cached);
    }
    let body = java_analyzed_request_body(path);
    if body.is_empty() {
        return None;
    }
    if let Some(session) = active {
        session.script_cache_put(cache_key, body.clone());
    }
    Some(body)
}

fn java_to_num_chapter(input: &str) -> String {
    static TITLE_NUM_RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"(第)(.+?)(章)").expect("valid title number regex"));

    let Some(captures) = TITLE_NUM_RE.captures(input) else {
        return input.to_string();
    };
    let Some(number) = captures.get(2) else {
        return input.to_string();
    };

    let value = legado_string_to_int(number.as_str());
    let whole = captures.get(0).expect("full regex match");
    let mut output = String::with_capacity(input.len());
    output.push_str(&input[..whole.start()]);
    output.push('第');
    output.push_str(&value.to_string());
    output.push('章');
    output.push_str(&input[whole.end()..]);
    output
}

fn legado_string_to_int(input: &str) -> i32 {
    let normalized = input
        .chars()
        .map(fullwidth_to_halfwidth)
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    normalized
        .parse::<i32>()
        .unwrap_or_else(|_| legado_chinese_num_to_int(&normalized))
}

fn fullwidth_to_halfwidth(ch: char) -> char {
    match ch {
        '　' => ' ',
        '！'..='～' => char::from_u32(ch as u32 - 0xFEE0).unwrap_or(ch),
        _ => ch,
    }
}

fn chinese_digit_value(ch: char) -> Option<i32> {
    match ch {
        '零' | '〇' => Some(0),
        '一' | '壹' => Some(1),
        '二' | '贰' | '两' => Some(2),
        '三' | '叁' => Some(3),
        '四' | '肆' => Some(4),
        '五' | '伍' => Some(5),
        '六' | '陆' => Some(6),
        '七' | '柒' => Some(7),
        '八' | '捌' => Some(8),
        '九' | '玖' => Some(9),
        '十' | '拾' => Some(10),
        '百' | '佰' => Some(100),
        '千' | '仟' => Some(1000),
        '万' => Some(10_000),
        '亿' => Some(100_000_000),
        _ => None,
    }
}

fn is_plain_chinese_digits(input: &str) -> bool {
    !input.is_empty()
        && input.chars().all(|ch| {
            matches!(
                ch,
                '〇' | '零'
                    | '一'
                    | '二'
                    | '三'
                    | '四'
                    | '五'
                    | '六'
                    | '七'
                    | '八'
                    | '九'
                    | '壹'
                    | '贰'
                    | '叁'
                    | '肆'
                    | '伍'
                    | '陆'
                    | '柒'
                    | '捌'
                    | '玖'
            )
        })
}

fn legado_chinese_num_to_int(input: &str) -> i32 {
    if input.is_empty() {
        return -1;
    }

    if is_plain_chinese_digits(input) {
        let mut value: i64 = 0;
        for ch in input.chars() {
            let Some(digit) = chinese_digit_value(ch) else {
                return -1;
            };
            value = value.saturating_mul(10).saturating_add(digit as i64);
            if value > i32::MAX as i64 {
                return -1;
            }
        }
        return value as i32;
    }

    let chars = input.chars().collect::<Vec<_>>();
    let mut result: i64 = 0;
    let mut tmp: i64 = 0;
    let mut billion: i64 = 0;

    for (index, ch) in chars.iter().copied().enumerate() {
        let Some(value) = chinese_digit_value(ch).map(i64::from) else {
            return -1;
        };

        match value {
            100_000_000 => {
                result = result.saturating_add(tmp);
                result = result.saturating_mul(value);
                billion = billion.saturating_add(result);
                result = 0;
                tmp = 0;
            }
            10_000 => {
                result = result.saturating_add(tmp);
                result = result.saturating_mul(value);
                tmp = 0;
            }
            10.. => {
                if tmp == 0 {
                    tmp = 1;
                }
                result = result.saturating_add(value.saturating_mul(tmp));
                tmp = 0;
            }
            digit => {
                if index + 1 == chars.len() && index > 0 {
                    if let Some(previous) = chinese_digit_value(chars[index - 1]).map(i64::from) {
                        if previous >= 10 {
                            tmp = digit.saturating_mul(previous / 10);
                            continue;
                        }
                    }
                }
                tmp = tmp.saturating_mul(10).saturating_add(digit);
            }
        }

        if result > i32::MAX as i64 || tmp > i32::MAX as i64 || billion > i32::MAX as i64 {
            return -1;
        }
    }

    let total = result.saturating_add(tmp).saturating_add(billion);
    if total > i32::MAX as i64 {
        -1
    } else {
        total as i32
    }
}

fn java_time_format(timestamp_ms: i64) -> String {
    match Local.timestamp_millis_opt(timestamp_ms).single() {
        Some(dt) => dt.format("%Y/%m/%d %H:%M").to_string(),
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
    let no_wrap = flags & 2 != 0;
    let crlf = flags & 4 != 0;
    let encoded = match (url_safe, no_padding) {
        (true, true) => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
        (true, false) => base64::engine::general_purpose::URL_SAFE.encode(bytes),
        (false, true) => base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes),
        (false, false) => base64::engine::general_purpose::STANDARD.encode(bytes),
    };
    if no_wrap || encoded.is_empty() {
        return encoded;
    }

    let separator = if crlf { "\r\n" } else { "\n" };
    let mut wrapped = String::with_capacity(encoded.len() + encoded.len() / 76 + 2);
    for (index, chunk) in encoded.as_bytes().chunks(76).enumerate() {
        if index > 0 {
            wrapped.push_str(separator);
        }
        wrapped.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    wrapped.push_str(separator);
    wrapped
}

fn java_base64_decode_bytes(input: &str, flags: i32) -> String {
    let input = input
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
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

fn normalize_crypto_algorithm(algorithm: &str) -> String {
    algorithm
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_uppercase())
        .collect()
}

fn java_digest_bytes(data: &str, algorithm: &str) -> Option<Vec<u8>> {
    let normalized = normalize_crypto_algorithm(algorithm);
    match normalized.as_str() {
        "MD5" => hex::decode(md5_hex(data)).ok(),
        "SHA1" => Some(
            digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data.as_bytes())
                .as_ref()
                .to_vec(),
        ),
        "SHA256" => Some(
            digest::digest(&digest::SHA256, data.as_bytes())
                .as_ref()
                .to_vec(),
        ),
        "SHA384" => Some(
            digest::digest(&digest::SHA384, data.as_bytes())
                .as_ref()
                .to_vec(),
        ),
        "SHA512" => Some(
            digest::digest(&digest::SHA512, data.as_bytes())
                .as_ref()
                .to_vec(),
        ),
        _ => None,
    }
}

fn java_hmac_algorithm(algorithm: &str) -> Option<hmac::Algorithm> {
    match normalize_crypto_algorithm(algorithm).as_str() {
        "HMACSHA1" => Some(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY),
        "HMACSHA256" => Some(hmac::HMAC_SHA256),
        "HMACSHA384" => Some(hmac::HMAC_SHA384),
        "HMACSHA512" => Some(hmac::HMAC_SHA512),
        _ => None,
    }
}

fn java_hmac_string_bytes(data: &str, algorithm: &str, key: &str) -> Option<Vec<u8>> {
    let algorithm = java_hmac_algorithm(algorithm)?;
    let key = hmac::Key::new(algorithm, key.as_bytes());
    Some(hmac::sign(&key, data.as_bytes()).as_ref().to_vec())
}

fn java_hmac_bytes(algorithm: &str, key_json: &str, data_json: &str) -> String {
    let Some(algorithm) = java_hmac_algorithm(algorithm) else {
        return "[]".to_string();
    };
    let key = hmac::Key::new(algorithm, &json_byte_array(key_json));
    let tag = hmac::sign(&key, &json_byte_array(data_json));
    serde_json::to_string(tag.as_ref()).unwrap_or_else(|_| "[]".to_string())
}

fn java_to_url_json(raw_url: &str, base_url: Option<&str>) -> String {
    let parsed = match base_url.filter(|base| !base.trim().is_empty()) {
        Some(base_url) => url::Url::parse(base_url).and_then(|base| base.join(raw_url)),
        None => url::Url::parse(raw_url),
    };
    let url = match parsed {
        Ok(url) => url,
        Err(error) => {
            return serde_json::json!({
                "error": error.to_string(),
            })
            .to_string();
        }
    };

    let search_params = if let Some(query) = url.query() {
        let mut values = serde_json::Map::new();
        for item in query.split('&') {
            let (key, value) = item.split_once('=').unwrap_or((item, ""));
            let decoded = urlencoding::decode(&value.replace('+', " "))
                .map(|value| value.into_owned())
                .unwrap_or_else(|_| value.to_string());
            values.insert(key.to_string(), JsonValue::String(decoded));
        }
        JsonValue::Object(values)
    } else {
        JsonValue::Null
    };

    serde_json::json!({
        "searchParams": search_params,
        "host": url.host_str().unwrap_or_default(),
        "origin": url.origin().ascii_serialization(),
        "pathname": url.path(),
    })
    .to_string()
}

fn java_encode_uri(input: &str, charset: Option<&str>) -> String {
    let bytes = java_str_to_bytes(input, charset);
    let mut encoded = String::with_capacity(bytes.len());
    for byte in bytes {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => {
                encoded.push(byte as char)
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn parse_cookie_pairs(input: &str) -> HashMap<String, String> {
    input
        .split(';')
        .filter_map(|part| {
            let (key, value) = part.split_once('=')?;
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() || value.is_empty() {
                return None;
            }
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

fn cookie_pairs_to_string(pairs: &HashMap<String, String>) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn js_cache_get(key: &str) -> Option<String> {
    if let Some(active) = crate::crawler::session::current_active_session() {
        return active.js_cache_get(key);
    }
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
    if let Some(active) = crate::crawler::session::current_active_session() {
        return active.js_cache_put(key, value, save_time_secs);
    }
    let expires_at = save_time_secs
        .filter(|seconds| *seconds > 0)
        .and_then(|seconds| Instant::now().checked_add(Duration::from_secs(seconds as u64)));
    let mut cache = JS_CACHE.lock().unwrap_or_else(|error| error.into_inner());
    cache.insert(key.to_string(), JsCacheEntry { value, expires_at });
    true
}

fn js_cache_delete(key: &str) -> bool {
    if let Some(active) = crate::crawler::session::current_active_session() {
        return active.js_cache_delete(key);
    }
    JS_CACHE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(key)
        .is_some()
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
    let response = client.execute_once(
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
        }),
    };
    payload.to_string()
}

fn java_archive_input(url: &str) -> String {
    const LIMIT: usize = 512 * 1024;
    let result = (|| {
        if url.len() > 8192 {
            return Err(("invalid_argument", "archive URL too long"));
        }
        let client = active_js_http_client();
        let source = ACTIVE_JS_BOOK_SOURCE.with(|cell| cell.borrow().clone());
        let response = if let Some(source) = source {
            let spec = analyze_url_with_headers(url, "", 0, &source.book_source_url, &source, None)
                .map_err(|_| ("invalid_argument", "invalid archive request"))?;
            execute_request_spec_limited(&client, &spec, Some(LIMIT))
        } else {
            client.execute(Method::GET, url, &[], None, Some(LIMIT))
        }
        .map_err(|error| match error {
            crate::crawler::HttpClientError::ResponseTooLarge { .. } => {
                ("limit_exceeded", "archive response too large")
            }
            _ => ("network_error", "archive request failed"),
        })?;
        if !(200..300).contains(&response.status) {
            return Err(("network_error", "archive HTTP status is unsuccessful"));
        }
        Ok(response.body)
    })();
    match result {
        Ok(bytes) => serde_json::json!({"ok":true,"data":bytes}),
        Err((kind, message)) => {
            serde_json::json!({"ok":false,"error":{"kind":kind,"message":message}})
        }
    }
    .to_string()
}

fn java_analyzed_request_body(url: &str) -> String {
    let payload = java_analyzed_request_response(url, "");
    serde_json::from_str::<JsonValue>(&payload)
        .ok()
        .and_then(|value| value.get("body").map(json_value_to_string))
        .unwrap_or_default()
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
    let explicit_headers = (!headers_json.is_empty()).then(|| java_request_headers(headers_json));
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
    let body = match format_analyzed_body(
        &spec,
        &response.body,
        decoded_body,
        content_type,
        &response.url,
    ) {
        Ok(body) => body,
        Err(error) => return java_error_response(&response.url, &error),
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
    // Android returns a JVM stack trace for request failures; preserve the
    // string/StrResponse contract without inventing a Java stack in the SO.
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
    use std::io::{BufRead, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn invalid_login_header_throws_without_changing_session() {
        let (result, delta) = with_active_session(None, "https://example.test/", |_| {
            eval_js(
                r#"source.putLoginHeader('{"Cookie":"sid=old","Authorization":"old"}');
                let rejected = false;
                try { source.putLoginHeader('{"Cookie":"sid=new; broken"}'); }
                catch (error) { rejected = error instanceof TypeError; }
                [rejected, source.getLoginHeaderMap().get('Authorization'), cookie.getKey('', 'sid')].join('|')"#,
                "", "https://example.test/",
            ).unwrap()
        });
        assert_eq!(result, "true|old|old");
        assert!(delta.is_some());
    }

    #[test]
    fn scoped_js_contexts_restore_after_nested_unwind() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        assert!(ACTIVE_JS_LIB.with(|cell| cell.borrow().is_none()));
        with_js_lib(Some("outer"), || {
            let result: Result<(), ()> = with_js_lib(None, || Err(()));
            assert_eq!(result, Err(()));
            assert!(catch_unwind(AssertUnwindSafe(|| {
                with_js_lib(Some("inner"), || panic!("expected"));
            }))
            .is_err());
            assert_eq!(
                ACTIVE_JS_LIB.with(|cell| cell.borrow().clone()),
                Some("outer".into())
            );
        });
        assert!(ACTIVE_JS_LIB.with(|cell| cell.borrow().is_none()));

        let client = HttpClient::standalone();
        let outer = BookSource {
            book_source_url: "https://outer.test".into(),
            ..Default::default()
        };
        let inner = BookSource {
            book_source_url: "https://inner.test".into(),
            ..Default::default()
        };
        assert!(catch_unwind(AssertUnwindSafe(|| {
            with_js_http_context(&client, &outer, || {
                assert!(catch_unwind(AssertUnwindSafe(|| {
                    with_js_http_context(&client, &inner, || {
                        assert!(ACTIVE_JS_HTTP_CLIENT.with(|cell| cell.borrow().is_some()));
                        panic!("expected");
                    });
                }))
                .is_err());
                assert_eq!(
                    ACTIVE_JS_BOOK_SOURCE.with(|cell| cell
                        .borrow()
                        .as_ref()
                        .unwrap()
                        .book_source_url
                        .clone()),
                    outer.book_source_url
                );
                assert!(ACTIVE_JS_HTTP_CLIENT.with(|cell| cell.borrow().is_some()));
                panic!("expected");
            });
        }))
        .is_err());
        assert!(ACTIVE_JS_HTTP_CLIENT.with(|cell| cell.borrow().is_none()));
        assert!(ACTIVE_JS_BOOK_SOURCE.with(|cell| cell.borrow().is_none()));

        let runtime = Runtime::new().unwrap();
        let outer_ctx = Context::full(&runtime).unwrap();
        let inner_runtime = Runtime::new().unwrap();
        let inner_ctx = Context::full(&inner_runtime).unwrap();
        outer_ctx.with(|outer| {
            with_js_reentrant_ctx(&outer, || {
                inner_ctx.with(|inner| {
                    assert!(catch_unwind(AssertUnwindSafe(|| {
                        with_js_reentrant_ctx(&inner, || {
                            assert_eq!(
                                ACTIVE_JS_REENTRANT_CTX.with(|cell| *cell.borrow()),
                                Some(inner.as_raw())
                            );
                            panic!("expected");
                        });
                    }))
                    .is_err());
                });
                assert_eq!(
                    ACTIVE_JS_REENTRANT_CTX.with(|cell| *cell.borrow()),
                    Some(outer.as_raw())
                );
            });
        });
        assert!(ACTIVE_JS_REENTRANT_CTX.with(|cell| cell.borrow().is_none()));
    }

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

        with_active_session(None, &url, |_| {
            with_js_lib(Some(&js_lib), || {
                let expression = format!("{marker} + 1");
                assert_eq!(eval_js(&expression, "", &url).unwrap(), "42");
                assert_eq!(eval_js(&expression, "", &url).unwrap(), "42");
            });
        });
        server.join().unwrap();
        assert_eq!(
            compile_js_lib(r#"{"inline":"var notLoaded=1"}"#).unwrap(),
            ""
        );
    }

    #[test]
    fn inline_js_lib_const_functions_survive_repeated_rules_without_cross_source_leaks() {
        // 爱发电 / 引力圈 use a top-level `const urlsData` plus helper functions.
        let first =
            "const urlsData = ['ifdian.net']; function getSourceHost() { return urlsData[0]; }";
        let second = "const urlsData = ['app2.unifans.io']; function getSourceHost() { return urlsData[0]; }";
        with_js_lib(Some(first), || {
            assert_eq!(
                eval_js("getSourceHost()", "", "https://example.com").unwrap(),
                "ifdian.net"
            );
            assert_eq!(
                eval_js("getSourceHost()", "", "https://example.com").unwrap(),
                "ifdian.net"
            );
        });
        with_js_lib(Some(second), || {
            assert_eq!(
                eval_js("getSourceHost()", "", "https://example.com").unwrap(),
                "app2.unifans.io"
            );
        });
        assert_eq!(
            eval_js("typeof getSourceHost", "", "https://example.com").unwrap(),
            "undefined"
        );
    }

    #[test]
    fn remote_js_lib_is_not_shared_between_sessions() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/user-library.js");
        let library = serde_json::json!({"remote": url}).to_string();
        let server = thread::spawn(move || {
            for user in ["userA", "userB"] {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request);
                let body = format!("globalThis.scopedLibraryValue = '{user}';");
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        with_js_lib(Some(&library), || {
            with_active_session(None, &url, |_| {
                assert_eq!(eval_js("scopedLibraryValue", "", &url).unwrap(), "userA");
                assert_eq!(eval_js("scopedLibraryValue", "", &url).unwrap(), "userA");
            });
            with_active_session(None, &url, |_| {
                assert_eq!(eval_js("scopedLibraryValue", "", &url).unwrap(), "userB");
            });
        });
        server.join().unwrap();
    }

    #[test]
    fn java_archive_input_preserves_binary_and_source_header_plan() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
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
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n\x00\xff\x80\x01").unwrap();
            request.to_ascii_lowercase()
        });
        let source = BookSource {
            book_source_url: base.clone(),
            header: Some(r#"{"X-Source":"source"}"#.to_owned()),
            enabled_cookie_jar: Some(false),
            ..Default::default()
        };
        let state = ExecuteSession {
            header: Some(json!({"X-Login":"login"})),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let target = format!(r#"{base}/binary,{{"headers":{{"X-Option":"yes"}}}}"#);
        let (payload, _) = with_active_session(Some(&state), &base, |_| {
            with_js_http_context(&client, &source, || java_archive_input(&target))
        });
        let result: JsonValue = serde_json::from_str(&payload).unwrap();
        assert_eq!(result["data"], json!([0, 255, 128, 1]));
        let request = server.join().unwrap();
        for header in ["x-source: source", "x-login: login", "x-option: yes"] {
            assert!(request.contains(header), "{request}");
        }
        let offline: JsonValue = serde_json::from_str(&crate::host_services::with_offline(|| {
            java_archive_input(&base)
        }))
        .unwrap();
        assert_eq!(offline["error"]["kind"], "network_error");
    }

    #[test]
    fn java_zip_text_detects_encoding_and_respects_explicit_charset() {
        let text = "这是一段中文小说内容，测试压缩文件字符编码自动识别。";
        let gbk = encoding_rs::GBK.encode(text).0.into_owned();
        let script = format!(
            r#"(() => {{
                const inputs = {{gbk: {gbk}, utf8: {utf8}, bom: [255,254,45,78,135,101], empty: []}};
                java.getZipByteArrayContent = (_, path) => path === 'missing' ? null : inputs[path];
                const read = (path, charset) => java.getZipStringContent([], path, charset);
                let invalid;
                try {{ read('gbk', 'not-a-charset'); }} catch (e) {{ invalid = e.kind; }}
                return JSON.stringify([
                    read('gbk'), read('gbk', 'GBK'), read('utf8'), read('bom'),
                    read('empty'), read('missing'), read('gbk', 'UTF-8') !== read('gbk'), invalid,
                    java.bytesToStr(inputs.gbk, 'UTF-8') === read('gbk', 'UTF-8')
                ]);
            }})()"#,
            gbk = serde_json::to_string(&gbk).unwrap(),
            utf8 = serde_json::to_string(text.as_bytes()).unwrap(),
        );
        let result = eval_js(&script, "", "https://example.com").unwrap();
        assert_eq!(
            serde_json::from_str::<JsonValue>(&result).unwrap(),
            json!([
                text,
                text,
                text,
                "中文",
                "",
                "",
                true,
                "invalid_argument",
                true
            ])
        );
    }

    #[test]
    fn java_security_facade_validates_specs_states_and_overloads() {
        let result = eval_js(
            r#"(() => {
                const j = new JavaImporter();
                j.importPackage(Packages.java.security, Packages.java.security.spec);
                const source = [-1, 0, 127];
                const spec = new j.PKCS8EncodedKeySpec(source);
                source[0] = 0; spec.getEncoded()[0] = 0;
                const s = j.Signature.getInstance('SHA256withRSA');
                const f = j.KeyFactory.getInstance('RSA');
                let count = 0;
                for (const action of [
                    () => s.sign(), () => s.verify([]), () => s.update([1]),
                    () => s.initSign({}), () => f.generatePrivate(spec),
                    () => f.generatePublic(new j.X509EncodedKeySpec([48,0])),
                    () => new j.PKCS8EncodedKeySpec([NaN]),
                    () => new j.PKCS8EncodedKeySpec([256]),
                    () => j.Signature.getInstance('SHA256withRSA','provider'),
                    () => s.sign([]), () => s.update([1],0)
                ]) { try { action(); } catch(e) { if (e.kind === 'invalid_argument') count++; } }
                return [spec.getEncoded().join(','),spec.getFormat(),s.getAlgorithm(),count].join('|');
            })()"#,
            "",
            "https://example.com",
        ).unwrap();
        assert_eq!(result, "255,0,127|PKCS#8|SHA256withRSA|11");
    }

    #[test]
    fn java_memory_streams_preserve_ranges_eof_and_close_semantics() {
        let result = eval_js(
            r#"
            const j = new JavaImporter(Packages.java.io);
            const input = new j.ByteArrayInputStream([9,255,1,2],1,3);
            const buffer = [0,0,0,0];
            const count = input.read(buffer,1,2);
            input.close();
            const output = new j.ByteArrayOutputStream();
            output.write(buffer,1,count); output.write(input.read()); output.close();
            [count,output.toByteArray().join(','),input.read(),input.read([],0,0)].join('|')
        "#,
            "",
            "https://example.com",
        )
        .unwrap();
        assert_eq!(result, "2|255,1,2|-1|0");
    }

    #[test]
    fn java_log_coerces_numbers_and_other_values_to_strings() {
        let result = eval_js(
            r#"java.log(1700000000.125); java.log(true); java.log({ timestamp: 1700000000 }); java.log(null); java.log(); 'ok'"#,
            "",
            "https://example.com",
        )
        .unwrap();
        assert_eq!(result, "ok");
    }

    #[test]
    fn low_risk_compat_apis_cover_headers_encodings_cache_and_utc_time() {
        let cache_key = format!("js-compat-{}", Uuid::new_v4());
        let script = format!(
            r#"
                const bytes = java.strToBytes('中文', 'GBK');
                const decoded = java.bytesToStr(bytes, 'GBK');
                const encoded = java.encodeURI('中文', 'GBK');
                const formEncoded = java.encodeURI('a b/c~');
                const b64 = java.base64Decode('5Lit5paH', 'UTF-8');
                const hex = java.hexEncodeToString('reader');
                const hexBytes = java.hexDecodeToByteArray(hex).join(',');
                const hexText = java.hexDecodeToString(hex);
                const digestAlias = java.md5Encode16('reader') === java.md5To16('reader');
                const utc = java.timeFormatUTC(0, "yyyy-MM-dd HH:mm:ss.SSS", 28800000);
                const localFormat = /^\d{{4}}\/\d{{2}}\/\d{{2}} \d{{2}}:\d{{2}}$/.test(java.timeFormat(0));
                cache.put('{cache_key}', 'cached', 60);
                const cached = cache.get('{cache_key}');
                const removed = cache.delete('{cache_key}');
                [decoded, encoded, formEncoded, b64, hex, hexBytes, hexText, digestAlias, utc,
                 localFormat, cached, typeof removed === 'undefined',
                 cache.get('{cache_key}') === null].join('|');
            "#
        );
        let output = eval_js(&script, "", "https://example.com").unwrap();
        assert_eq!(
            output,
            "中文|%D6%D0%CE%C4|a+b%2Fc%7E|中文|726561646572|114,101,97,100,101,114|reader|true|1970-01-01 08:00:00.000|true|cached|true|true"
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
    fn memory_cache_spellings_keep_values_in_operation_only() {
        let url = "https://memory-cache.example/books";
        let (value, delta) = with_active_session(None, url, |_| {
            eval_js(
                "cache.putMemory('item', {count: 2}); cache.getFromMemory('item').count",
                "",
                url,
            )
            .unwrap();
            eval_js("cache.getFromMemory('item').count", "", url).unwrap()
        });
        assert_eq!(value, "2");
        assert!(
            delta.is_none(),
            "memory cache must not change the session DTO"
        );
        let (isolated, _) = with_active_session(None, url, |_| {
            eval_js("cache.getFromMemory('item') === null", "", url).unwrap()
        });
        assert_eq!(isolated, "true");
        let (deleted, _) = with_active_session(None, url, |_| {
            eval_js(
                "cache.putMemory('item', 'text'); cache.deleteMemory('item'); cache.getFromMemory('item') === null",
                "",
                url,
            )
            .unwrap()
        });
        assert_eq!(deleted, "true");
    }

    #[test]
    fn js_cache_is_isolated_by_session_and_restored_from_session_delta() {
        let url = "https://same-source.example/books";
        let key = format!("session-cache-{}", Uuid::new_v4());
        let (value, saved) = with_active_session(None, url, |_| {
            eval_js(
                &format!("cache.put('{key}', 'user-a', 60); cache.get('{key}')"),
                "",
                url,
            )
            .unwrap()
        });
        assert_eq!(value, "user-a");
        let saved = saved.expect("cache write must be returned to the caller");
        let (other_user, delta) = with_active_session(None, url, |_| {
            eval_js(&format!("cache.get('{key}') === null"), "", url).unwrap()
        });
        assert_eq!(other_user, "true");
        assert!(delta.is_none());
        let (restored, _) = with_active_session(Some(&saved), url, |_| {
            eval_js(&format!("cache.get('{key}')"), "", url).unwrap()
        });
        assert_eq!(restored, "user-a");

        let (kv_saved, kv_state) = with_active_session(None, url, |_| {
            eval_js("kv_put('private', 'user-a'); kv_get('private')", "", url).unwrap()
        });
        assert_eq!(kv_saved, "user-a");
        let (kv_other, _) = with_active_session(None, url, |_| {
            eval_js("kv_get('private') == null", "", url).unwrap()
        });
        assert_eq!(kv_other, "true");
        let (kv_restored, _) = with_active_session(kv_state.as_ref(), url, |_| {
            eval_js("kv_get('private')", "", url).unwrap()
        });
        assert_eq!(kv_restored, "user-a");

        let (oversized, _) = with_active_session(None, url, |_| {
            eval_js(&format!("cache.put('{key}', 'x'.repeat(16385))"), "", url)
        });
        assert!(oversized
            .unwrap_err()
            .to_string()
            .contains("session cache limit exceeded"));
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
        let result = with_js_http_context(&client, &source, || eval_js(&script, "", &url).unwrap());
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
    fn java_ajax_and_connect_keep_http_errors_separate_from_transport_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/missing", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                }
                write!(stream, "HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\nConnection: close\r\n\r\nmissing").unwrap();
            }
        });
        let source = BookSource {
            book_source_url: url.clone(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let script = format!(
            "(() => {{ const body = java.ajax({url:?}); const response = java.connect({url:?}); return [body, response.code(), response.body(), response.isSuccessful()].join('|'); }})()"
        );
        let result = with_js_http_context(&client, &source, || eval_js(&script, "", &url).unwrap());
        assert_eq!(result, "missing|404|missing|false");
        server.join().unwrap();

        let result = with_js_http_context(&client, &source, || {
            eval_js(
                "(() => { const body = java.ajax('ftp://invalid'); const response = java.connect('ftp://invalid'); return [typeof body, body.length > 0, response.code(), response.body().length > 0].join('|'); })()",
                "", &url,
            ).unwrap()
        });
        assert_eq!(result, "string|true|200|true");
    }

    #[test]
    fn java_ajax_and_connect_return_values_on_broken_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/broken", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                }
                write!(stream, "not an HTTP response\r\n").unwrap();
            }
        });
        let source = BookSource {
            book_source_url: url.clone(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let script = format!(
            "(() => {{ const body = java.ajax({url:?}); const response = java.connect({url:?}); return [typeof body, body.length > 0, response.code(), response.body().length > 0].join('|'); }})()"
        );
        let result = with_js_http_context(&client, &source, || eval_js(&script, "", &url).unwrap());
        assert_eq!(result, "string|true|200|true");
        server.join().unwrap();
    }

    #[test]
    fn java_connect_applies_analyze_url_body_js_without_changing_status() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            write!(stream, "HTTP/1.1 418 Teapot\r\nContent-Type: text/plain\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest").unwrap();
        });
        let url = format!("http://{address}/test");
        let source = BookSource {
            book_source_url: url.clone(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let script = format!(
            r#"(() => {{ const response = java.connect('{url},{{"bodyJs":"result.toUpperCase()"}}'); return response.code() + '|' + response.body(); }})()"#
        );
        let result = with_js_http_context(&client, &source, || eval_js(&script, "", &url).unwrap());
        assert_eq!(result, "418|TEST");
        server.join().unwrap();
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
    fn java_network_helpers_follow_analyze_url_header_precedence() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..4 {
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
            "(() => {{ const ajax = java.ajax([{}]); const all = java.ajaxAll([{}, {}]); const one = java.connect({}, {{'X-Order':'connect','X-Connect':'configured'}}); return [ajax, all[0].code(), all[1].code(), one.code(), all[0].body(), all[1].body(), one.body(), source.get('header-evaluation-count')].join('|'); }})()",
            serde_json::to_string(&url).unwrap(),
            serde_json::to_string(&url).unwrap(),
            serde_json::to_string(&url).unwrap(),
            serde_json::to_string(&url).unwrap()
        );
        let source = BookSource {
            book_source_url: format!("http://{address}/source"),
            header: Some(
                r#"js:const count=Number(source.get('header-evaluation-count')||'0')+1;source.put('header-evaluation-count',String(count));JSON.stringify({"X-Source":String(count),"X-Order":"source"})"#
                    .to_string(),
            ),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let result = with_js_http_context(&client, &source, || {
            eval_js(&script, "", &source.book_source_url).unwrap()
        });
        assert_eq!(result, "ok|201|201|201|ok|ok|ok|3");

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 4);
        for (index, (request, body)) in requests[..3].iter().enumerate() {
            assert!(request.starts_with("post /ajax "));
            assert!(
                request.contains(&format!("x-source: {}", index + 1)),
                "source header evaluation {} was not reflected in request: {request}",
                index + 1
            );
            assert!(request.contains("x-url: configured"));
            assert!(request.contains("x-order: url"));
            assert_eq!(body, "payload");
        }

        assert!(requests[3].0.starts_with("post /ajax "));
        assert!(!requests[3].0.contains("x-source:"));
        assert!(requests[3].0.contains("x-connect: configured"));
        assert!(requests[3].0.contains("x-url: configured"));
        assert!(requests[3].0.contains("x-order: url"));
        assert_eq!(requests[3].1, "payload");
    }

    #[test]
    fn jsoup_document_remove_updates_later_select_without_leaking() {
        // Core of the local 菠萝猫 content rule: remove hidden nodes, then read paragraphs.
        let script = r#"
            var doc = org.jsoup.Jsoup.parse(result);
            doc.select("[style*='display:none']").remove();
            doc.select("[style*='display: none']").remove();
            doc.select("[style*='font-size:0']").remove();
            doc.select("[style*='font-size: 0']").remove();
            doc.select("[style*='visibility:hidden']").remove();
            doc.select("[style*='visibility: hidden']").remove();
            var paragraphs = doc.select("div.content p").toArray();
            var textList = [];
            for (var i = 0; i < paragraphs.length; i++) {
                var txt = paragraphs[i].text().trim();
                if (txt) textList.push(txt);
            }
            textList.join('\n\n');
        "#;
        let html = r#"<div class="content"><p>first</p><p style="display:none">hidden</p><p style="font-size: 0">tiny</p><div style="visibility: hidden"><p>also hidden</p></div><p>second</p></div>"#;
        assert_eq!(
            eval_js(script, html, "https://example.com").unwrap(),
            "first\n\nsecond"
        );
        let next = r#"<div class="content"><p style="display:none">secret</p><p>another</p></div>"#;
        assert_eq!(
            eval_js(script, next, "https://example.com").unwrap(),
            "another"
        );
        assert_eq!(
            eval_js("var a=org.jsoup.Jsoup.parse(result), b=org.jsoup.Jsoup.parse(result); a.select('p').remove(); a.select('p').size() + '|' + b.select('p').size()", "<p>fresh</p>", "https://example.com").unwrap(),
            "0|1"
        );
        assert!(eval_js(
            "org.jsoup.Jsoup.parse(result).select('p').first().text()",
            "<p>fresh</p>",
            "https://example.com"
        )
        .unwrap()
        .contains("fresh"));
    }

    #[test]
    fn jsoup_contains_next_page_rule_returns_url_and_absence() {
        use crate::model::rule::ContentRule;
        use crate::parser::rule_engine::RuleEngine;

        // nextContentUrl from the local 菠萝猫 source, including its URL options.
        let rule = r#"<js>
var doc = org.jsoup.Jsoup.parse(result);
var a = doc.select("div.readPage a:contains(下一页)").first();
if (a) {
    var href = a.attr("href");
    if (href && href.trim() != "") {
        var url = href.startsWith("http") ? href : "https://www.boluomao.com" + href;
        url + ',{"webView":true}';
    } else { null; }
} else { null; }
</js>"#;
        let source = BookSource {
            book_source_url: "https://www.boluomao.com".to_owned(),
            rule_content: Some(ContentRule {
                next_content_url: Some(rule.to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let engine = RuleEngine::new().unwrap();
        let base = "https://www.boluomao.com/book/1.html";
        let html = r#"<div class="readPage"><a href="/book/2.html"><span>下一页</span></a><a href="/book/3.html">下一章</a></div>"#;
        assert_eq!(
            engine.next_content_url(&source, html, base).as_deref(),
            Some("https://www.boluomao.com/book/2.html,{\"webView\":true}")
        );
        assert_eq!(
            engine.next_content_url(&source, "<div class='readPage'>完</div>", base),
            None
        );
        assert_eq!(eval_js("null", "old result", base).unwrap(), "");
        assert_eq!(
            eval_js("undefined", "old result", base).unwrap(),
            "old result"
        );
    }

    #[test]
    fn next_content_url_options_reach_following_request() {
        use crate::crawler::{analyze_url, HttpSession};
        use crate::model::rule::ContentRule;
        use crate::parser::rule_engine::RuleEngine;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/chapter", listener.local_addr().unwrap());
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
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )
            .unwrap();
            request.to_ascii_lowercase()
        });
        let source = BookSource {
            book_source_url: base.clone(),
            rule_content: Some(ContentRule {
                next_content_url: Some(r#"@js:'/next,{"headers":{"X-Next":"rule"}}'"#.to_owned()),
                ..Default::default()
            }),
            enabled_cookie_jar: Some(false),
            ..Default::default()
        };
        let next = RuleEngine::new()
            .unwrap()
            .next_content_url(&source, "<p>first</p>", &base)
            .unwrap();
        assert_eq!(
            next,
            format!(
                "http://{}/next,{{\"headers\":{{\"X-Next\":\"rule\"}}}}",
                base.split('/').nth(2).unwrap()
            )
        );
        let spec = analyze_url(&next, "", 1, &base, &source).unwrap();
        assert_eq!(
            HttpSession::new(&source, 3000)
                .unwrap()
                .fetch(&spec, 1024)
                .unwrap()
                .body,
            "ok"
        );
        let request = server.join().unwrap();
        assert!(request.starts_with("get /next http/1.1"), "{request}");
        assert!(request.contains("x-next: rule\r\n"), "{request}");
    }

    #[test]
    fn java_connect_and_ajax_share_normal_url_header_plan() {
        use crate::crawler::session::{with_active_session, ExecuteSession};
        use crate::crawler::{analyze_url, HttpSession};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..4 {
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
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )
                .unwrap();
            }
            requests
        });
        let source = BookSource {
            book_source_url: base.clone(),
            header: Some(r#"{"X-Source":"source","X-Order":"source"}"#.to_owned()),
            enabled_cookie_jar: Some(false),
            ..Default::default()
        };
        let state = ExecuteSession {
            header: Some(serde_json::json!({"X-Login":"login","X-Order":"login"})),
            ..Default::default()
        };
        let rule = r#"/page,{"headers":{"X-Order":"option"},"js":"java.headerMap.put('X-Order','js'); java.headerMap.put('X-Js','signed'); result"}"#;
        let client = HttpClient::standalone();
        let (result, _) = with_active_session(Some(&state), &source.book_source_url, |_| {
            let spec = analyze_url(rule, "", 1, &base, &source).unwrap();
            let normal = HttpSession::new(&source, 3000)
                .unwrap()
                .fetch(&spec, 1024)
                .unwrap()
                .body;
            let target = format!("{base}{rule}");
            let connect = with_js_http_context(&client, &source, || {
                eval_js(
                    &format!(
                        "(() => {{ const body = java.connect({}).body(); return body + '|' + (java.headerMap === undefined); }})()",
                        serde_json::to_string(&target).unwrap()
                    ),
                    "",
                    &base,
                )
                .unwrap()
            });
            let ajax = with_js_http_context(&client, &source, || {
                eval_js(
                    &format!(
                        "(() => {{ const body = java.ajax({}); return body + '|' + (java.headerMap === undefined); }})()",
                        serde_json::to_string(&target).unwrap()
                    ),
                    "",
                    &base,
                )
                .unwrap()
            });
            let explicit = with_js_http_context(&client, &source, || {
                eval_js(
                    &format!(
                        "(() => {{ const body = java.connect({}, {{'X-Explicit':'yes','X-Order':'passed'}}).body(); return body + '|' + (java.headerMap === undefined); }})()",
                        serde_json::to_string(&target).unwrap()
                    ),
                    "",
                    &base,
                )
                .unwrap()
            });
            (normal, connect, ajax, explicit)
        });
        assert_eq!(
            result,
            (
                "ok".into(),
                "ok|true".into(),
                "ok|true".into(),
                "ok|true".into()
            )
        );
        let requests = server.join().unwrap();
        for request in &requests[..3] {
            assert!(request.contains("x-source: source\r\n"), "{request}");
            assert!(request.contains("x-login: login\r\n"), "{request}");
            assert!(request.contains("x-order: js\r\n"), "{request}");
            assert!(request.contains("x-js: signed\r\n"), "{request}");
        }
        let explicit = &requests[3];
        assert!(!explicit.contains("x-source:"), "{explicit}");
        assert!(!explicit.contains("x-login:"), "{explicit}");
        assert!(explicit.contains("x-explicit: yes\r\n"), "{explicit}");
        assert!(explicit.contains("x-order: js\r\n"), "{explicit}");
        assert!(explicit.contains("x-js: signed\r\n"), "{explicit}");
    }

    #[test]
    fn nested_connect_restores_outer_scope_and_header_map_after_failure() {
        let source = BookSource {
            book_source_url: "https://example.com".to_owned(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let mut headers = vec![("X-Outer".to_owned(), "before".to_owned())];
        let result = with_js_http_context(&client, &source, || {
            eval_js_url_with_headers(
                r#"globalThis.outerMarker=1;
java.outerMarker=1;
java.headerMap.put('X-Outer','after');
java.connect('ftp://invalid,{"js":"var leakedVar=1; globalThis.leakedGlobal=1; java.leakedJava=1; globalThis.outerMarker=2; java.outerMarker=2; throw 123"}');
[globalThis.outerMarker, typeof leakedVar, typeof globalThis.leakedGlobal, java.outerMarker, typeof java.leakedJava, java.headerMap.get('X-Outer')].join('|')"#,
                "https://example.com", "", 1, &source.book_source_url,
                &source.book_source_url, None, &mut headers,
            ).unwrap()
        });
        assert_eq!(result, "1|undefined|undefined|1|undefined|after");
        assert_eq!(headers, vec![("X-Outer".to_owned(), "after".to_owned())]);
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
        let source = BookSource {
            book_source_url: url.clone(),
            header: Some(r#"{"X-Source":"not-for-simple-helpers"}"#.to_owned()),
            ..Default::default()
        };
        let result = with_js_http_context(&client, &source, || {
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
        assert!(requests
            .iter()
            .all(|request| !request.contains("x-source:")));
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
            const long = Array.from({length: 60}, (_, i) => i);
            const wrapped = android.util.Base64.encodeToString(
                long, android.util.Base64.DEFAULT);
            const crlf = android.util.Base64.encodeToString(
                long, android.util.Base64.CRLF);
            [
                standard,
                decoded,
                urlSafe,
                wrapped.includes('\n'),
                wrapped.endsWith('\n'),
                crlf.includes('\r\n'),
                crlf.endsWith('\r\n')
            ].join('|');
        "#;
        assert_eq!(
            eval_js(script, "", "https://example.com").unwrap(),
            "YWJj|97,98,99|-_8|true|true|true|true"
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
    fn compat_cookie_replace_merges_existing_values() {
        let initial = ExecuteSession {
            cookies: Some("sid=old; keep=yes".to_string()),
            ..Default::default()
        };
        let (result, _) = with_active_session(Some(&initial), "https://example.com", |_| {
            eval_js(
                "cookie.replaceCookie('https://example.com/path', 'sid=new; added=1'); [cookie.getKey('example.com','sid'), cookie.getKey('example.com','keep'), cookie.getKey('example.com','added')].join('|')",
                "",
                "https://example.com",
            )
            .unwrap()
        });

        assert_eq!(result, "new|yes|1");
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
    fn real_source_get_string_json_fallback_values_and_blank_url() {
        let body = r#"{"data":{"list":[{"publish_sn":"first"},{"publish_sn":"last"}]},"fallback":"备用","path":"/next","count":0,"enabled":false,"blank":""}"#;
        let result = eval_js(
            r#"[
                java.getString('$.data.list[-1].publish_sn'),
                java.getString('$.missing||$.fallback'),
                java.getString('$.count'),
                java.getString('$.enabled'),
                java.getString('$.missing'),
                java.getString('$.missing', null, true),
                java.getString('$.blank', null, true),
                java.getString('$.missing||$.path', null, true),
                java.getString('$.missing||$.absent', null, true),
                java.getString('$.fallback', '', true),
                java.getString('', null, true)
            ].join('|')"#,
            body,
            "https://example.com/chapter/",
        )
        .unwrap();
        assert_eq!(
            result,
            "last|备用|0|false||https://example.com/chapter/|https://example.com/chapter/|https://example.com/next|https://example.com/chapter/|https://example.com/chapter/|"
        );
    }

    #[test]
    fn analyze_rule_overloads_and_base64_public_api_match_legado_shapes() {
        let script = r#"
            const twoArg = java.getString('$.value', false);
            const blankList = java.getStringList('') === null;
            const chained = java
                .setContent('{"path":"/next"}', 'https://new.example/base/')
                .getString('$.path', undefined, true);
            const bytes = java.base64DecodeToByteArray('YWJj').join(',');
            const flagsDecode = java.base64Decode('YWJj', 0);
            const flagsEncode = java.base64Encode('abc', 2);
            [twoArg, blankList, chained, bytes, flagsDecode, flagsEncode].join('|')
        "#;
        let result = eval_js(script, r#"{"value":"ok"}"#, "https://example.com/old/").unwrap();
        assert_eq!(result, "ok|true|https://new.example/next|97,98,99|abc|YWJj");
    }

    #[test]
    fn source_exposes_url_and_raw_header_in_execute_context() {
        let source = BookSource {
            book_source_url: "https://source.example".to_string(),
            header: Some(r#"{"User-Agent":"reader"}"#.to_string()),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let result = with_js_http_context(&client, &source, || {
            eval_js(
                "[source.bookSourceUrl, JSON.parse(source.header)['User-Agent'], source.getKey()].join('|')",
                "",
                &source.book_source_url,
            )
            .unwrap()
        });
        assert_eq!(
            result,
            "https://source.example|reader|https://source.example"
        );
    }

    #[test]
    fn source_contract_uses_book_source_key_and_single_source_variable() {
        let source = BookSource {
            book_source_url: "https://source.example".to_string(),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let initial = ExecuteSession {
            variables: Some(
                [
                    ("sourceVariable".to_string(), json!("initial")),
                    (
                        "userInfo_https://source.example".to_string(),
                        json!("encrypted"),
                    ),
                ]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        };
        let (result, delta) = with_active_session(Some(&initial), &source.book_source_url, |_| {
            with_js_http_context(&client, &source, || {
                eval_js(
                    r#"
                            const initialValue = source.getVariable();
                            const setResult = source.setVariable('saved');
                            const saved = source.getVariable();
                            const putResult = source.put('token', 'value');
                            const sourceValue = source.get('token');
                            const removeLoginResult = source.removeLoginInfo();
                            source.setVariable(null);
                            [
                                source.getKey(),
                                initialValue,
                                saved,
                                source.getVariable(),
                                putResult,
                                sourceValue,
                                source.getLoginHeader() === null,
                                source.getLoginInfo() === null,
                                typeof setResult === 'undefined',
                                typeof removeLoginResult === 'undefined'
                            ].join('|')
                        "#,
                    "",
                    &source.book_source_url,
                )
                .unwrap()
            })
        });
        assert_eq!(
            result,
            "https://source.example|initial|saved||value|value|true|true|true|true"
        );
        let variables = delta.unwrap().variables.unwrap();
        assert_eq!(
            variables.get("v_https://source.example_token"),
            Some(&json!("value"))
        );
        assert!(!variables.contains_key("userInfo_https://source.example"));
    }

    #[test]
    fn symmetric_crypto_matches_legado_aes_cbc_shapes() {
        let script = r#"
            const cipher = java.createSymmetricCrypto(
                'AES/CBC/PKCS5Padding',
                '1234567890abcdef',
                'abcdef1234567890'
            );
            const encryptedBytes = cipher.encrypt('reader');
            const encryptedBase64 = cipher.encryptBase64('reader');
            const encryptedHex = cipher.encryptHex('reader');
            const decryptedFromBytes = cipher.decryptStr(encryptedBytes);
            const decryptedFromBase64 = cipher.decryptStr(encryptedBase64);
            const decryptedFromHex = cipher.decryptStr(encryptedHex);
            [
                Array.isArray(encryptedBytes),
                encryptedBytes.length > 0,
                decryptedFromBytes,
                decryptedFromBase64,
                decryptedFromHex
            ].join('|')
        "#;
        assert_eq!(
            eval_js(script, "", "https://example.com").unwrap(),
            "true|true|reader|reader|reader"
        );

        assert_eq!(eval_js(
            "(()=>{const c=java.createSymmetricCrypto('AES/ECB/PKCS5Padding', '1234567890abcdef');return c.decryptStr(c.encrypt('reader'));})()",
            "",
            "https://example.com"
        ).unwrap(), "reader");
        assert!(eval_js(
            "java.createSymmetricCrypto('AES/CBC/PKCS5Padding', 'short', 'abcdef1234567890').encryptBase64('reader')",
            "",
            "https://example.com"
        )
        .is_err());
    }

    #[test]
    fn to_num_chapter_matches_legado_number_normalization() {
        let script = r#"
            [
                java.toNumChapter('第123章'),
                java.toNumChapter('第１２３章'),
                java.toNumChapter('第一二三章'),
                java.toNumChapter('第一百零二章'),
                java.toNumChapter('第十二章'),
                java.toNumChapter('第二十章'),
                java.toNumChapter('第一千二章'),
                java.toNumChapter('前言'),
                java.toNumChapter('第abc章')
            ].join('|')
        "#;
        assert_eq!(
            eval_js(script, "", "https://example.com").unwrap(),
            "第123章|第123章|第123章|第102章|第12章|第20章|第1200章|前言|第-1章"
        );
    }

    #[test]
    fn import_script_returns_remote_text_without_auto_eval() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let body = "globalThis.__importedValue = 42;";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });

        let source = BookSource {
            book_source_url: format!("http://{address}/"),
            ..Default::default()
        };
        let client = HttpClient::standalone();
        let url = format!("http://{address}/script.js");
        let script = format!(
            "(() => {{ const imported = java.importScript('{}'); const before = typeof globalThis.__importedValue; eval(String(imported)); return [before, globalThis.__importedValue, imported.includes('__importedValue')].join('|'); }})()",
            url
        );
        let result = with_js_http_context(&client, &source, || {
            eval_js(&script, "", &source.book_source_url).unwrap()
        });
        assert_eq!(result, "undefined|42|true");
        server.join().unwrap();

        assert!(with_js_http_context(&client, &source, || {
            eval_js(
                "java.importScript('./local.js')",
                "",
                &source.book_source_url,
            )
        })
        .is_err());
    }

    #[test]
    fn simple_http_methods_do_not_follow_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });

        let url = format!("http://{address}/redirect");
        let client = HttpClient::standalone();
        let result = with_js_http_client(&client, || {
            eval_js(
                &format!(
                    "(() => {{ const response = java.get('{url}', {{}}); return [response.code(), response.header('location'), response.url()].join('|'); }})()"
                ),
                "",
                &url,
            )
            .unwrap()
        });
        assert_eq!(result, format!("302|/final|{url}"));
        server.join().unwrap();
    }

    #[test]
    fn digest_hmac_url_and_system_helpers_match_legado_shapes() {
        let script = r#"
            const parsed = java.toURL(
                '../p?q=first&q=last&name=a+b&flag',
                'https://example.com/base/x'
            );
            const logTypeResult = java.logType('reader');
            [
                java.digestHex('abc', 'SHA-256'),
                java.digestBase64Str('abc', 'SHA-256'),
                java.HMacHex('abc', 'HmacSHA256', 'key'),
                java.HMacBase64('abc', 'HmacSHA256', 'key'),
                parsed.host,
                parsed.origin,
                parsed.pathname,
                parsed.searchParams.get('q'),
                parsed.searchParams.get('name'),
                parsed.searchParams.get('flag'),
                java.getWebViewUA().startsWith('Mozilla/5.0'),
                typeof logTypeResult === 'undefined'
            ].join('|')
        "#;
        assert_eq!(
            eval_js(script, "", "https://example.com").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad|ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=|9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab|nBluMtwBdfhvSxy4konWYZ3mvuaZ5MN45oMJ7Zehpqs=|example.com|https://example.com|/p|last|a b||true|true"
        );
        assert!(eval_js(
            "java.digestHex('abc', 'unsupported')",
            "",
            "https://example.com"
        )
        .is_err());
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
            "[java.get('bookOnly'), java.get('chapterOnly'), java.get('shadowed'), java.put('shadowed', 'updated'), java.get('shadowed'), java.get('headers'), java.get('bookName'), java.get('title')].join('|')",
            "",
            "https://example.com",
            &bindings,
        )
        .unwrap();
        assert_eq!(
            result,
            r#"book-value|chapter-value|chapter-value|updated|updated|{"headers":{"X-Test":"ok"}}|Book|Chapter"#
        );
    }

    #[test]
    fn login_header_map_handles_missing_invalid_and_valid_headers() {
        let url = "https://headers.example/books";
        let (missing, unchanged) = with_active_session(None, url, |_| {
            eval_js("source.getLoginHeaderMap() === null", "", url).unwrap()
        });
        assert_eq!(missing, "true");
        assert!(unchanged.is_none());

        let invalid = ExecuteSession {
            header: Some(json!("not JSON")),
            ..Default::default()
        };
        let (bad, unchanged) = with_active_session(Some(&invalid), url, |_| {
            eval_js("source.getLoginHeaderMap() === null", "", url).unwrap()
        });
        assert_eq!(bad, "true");
        assert!(unchanged.is_none());

        let non_object = ExecuteSession {
            header: Some(json!("[1,2]")),
            ..Default::default()
        };
        let (bad_type, _) = with_active_session(Some(&non_object), url, |_| {
            eval_js("source.getLoginHeaderMap() === null", "", url).unwrap()
        });
        assert_eq!(bad_type, "true");

        let valid = ExecuteSession {
            header: Some(json!({"X-Reader": "ok", "X-Count": "2"})),
            ..Default::default()
        };
        let (result, unchanged) = with_active_session(Some(&valid), url, |_| {
            eval_js(
                "const headers = source.getLoginHeaderMap(); [headers instanceof Map, headers.size, headers.get('X-Reader'), headers.get('X-Count')].join('|')",
                "",
                url,
            )
            .unwrap()
        });
        assert_eq!(result, "true|2|ok|2");
        assert!(unchanged.is_none());
    }

    #[test]
    fn test_js_session_bindings() {
        let initial = ExecuteSession {
            cookies: Some("sid=initial_token".to_string()),
            cookie_jar: None,
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
                assert_eq!(res, "");
                assert_eq!(
                    eval_js("source.getVariable('myVar')", "", "https://example.com").unwrap(),
                    "updated_val"
                );

                // Read login header
                let h = eval_js("source.getLoginHeader()", "", "https://example.com").unwrap();
                assert!(h.contains("init_auth"));
                assert_eq!(
                    eval_js(
                        "source.getLoginHeaderMap().get('Authorization')",
                        "",
                        "https://example.com"
                    )
                    .unwrap(),
                    "Bearer init_auth"
                );

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
    fn compat_java_xpath_strings_join_and_interleave() {
        let body = "<root><a>A1</a><a>A2</a><b>B1</b><b>B2</b><b>B3</b><c>C1</c></root>";

        assert_eq!(
            java_get_string(
                Some("@XPath://a"),
                Some(body),
                "",
                "https://example.com",
                false,
                false,
            ),
            "A1\nA2"
        );
        assert_eq!(
            java_get_string_list(
                Some("@XPath://a/text()%%@XPath://b/text()%%@XPath://c/text()"),
                Some(body),
                "",
                "https://example.com",
                false,
            ),
            vec!["A1", "B1", "C1", "A2", "B2"]
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
