//! 书源执行引擎的对称会话（Symmetric Session）状态机与 Cookie/Header/变量存储。
//!
//! 契约严格遵循 `Rust_FFI_Architecture.md`：
//! - `data`、`session`、`meta` 三大正交关注点分离；
//! - 输入与输出 100% 同构对称（State In, State Out）；
//! - 若会话状态无变动，输出 `session` 必须为 `None`（JSON 序列化为 `null`），零额外开销；
//! - 在执行期间与 QuickJS 和 HTTP 客户端同步共享 Cookie 与私有变量。

use crate::crawler::SharedCookieStore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

const JS_CACHE_STATE_KEY: &str = "__reader_js_cache_v1";
const JS_CACHE_MAX_ENTRIES: usize = 64;
const JS_CACHE_MAX_VALUE_BYTES: usize = 16 * 1024;

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 对称会话 DTO：输入与输出同构
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteSession {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookies: Option<String>,
    /// Optional full cookie jar; `cookies` remains the legacy source-host view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_jar: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variables: Option<HashMap<String, Value>>,
}

/// 执行运行时的活动会话状态句柄
#[derive(Debug)]
pub struct ActiveSession {
    source_url: String,
    cookie_store: SharedCookieStore,
    header: Mutex<Option<Value>>,
    variables: Mutex<HashMap<String, Value>>,
    // Fetched JS is reused only inside this operation; never shared across users.
    script_cache: Mutex<HashMap<String, String>>,
    // Legado's putMemory stores process-local values; never serialize them to session.
    memory_cache: Mutex<HashMap<String, Value>>,
    pub(crate) public_suffix_cache: Arc<crate::parser::http_url::SuffixCache>,
    unknown_method_fallback: AtomicBool,
    initial_session: ExecuteSession,
}

thread_local! {
    static ACTIVE_SESSION: RefCell<Option<Arc<ActiveSession>>> = const { RefCell::new(None) };
}

impl ActiveSession {
    pub fn new(session_opt: Option<&ExecuteSession>, source_url: &str) -> Self {
        let cookie_store = SharedCookieStore::default();
        let parsed_url = Url::parse(source_url).ok();

        let mut initial_cookies = None;
        let mut initial_header = None;
        let mut initial_variables = None;

        if let Some(session) = session_opt {
            // A valid jar is authoritative; replaying the flattened source cookie
            // would erase its path/domain attributes and resurrect removed entries.
            let restored_jar = session
                .cookie_jar
                .as_ref()
                .is_some_and(|jar| cookie_store.restore(jar));
            if !restored_jar {
                if let Some(ref cookies_str) = session.cookies {
                    if !cookies_str.trim().is_empty() {
                        if let Some(ref url) = parsed_url {
                            cookie_store.add_cookie_header(cookies_str, url);
                        }
                        initial_cookies = Some(cookies_str.clone());
                    }
                }
            }
            if let Some(ref header_val) = session.header {
                if !restored_jar {
                    if let Some(ref url) = parsed_url {
                        extract_and_sync_cookies_from_header(&cookie_store, header_val, url);
                    }
                }
                // Keep only a marker for Cookie; the jar is authoritative even
                // after its final cookie is deleted and its snapshot becomes None.
                let parsed = match header_val {
                    Value::String(raw) => serde_json::from_str::<Value>(raw).ok(),
                    value => Some(value.clone()),
                };
                initial_header = Some(match parsed {
                    Some(Value::Object(mut map))
                        if map.keys().any(|key| key.eq_ignore_ascii_case("cookie")) =>
                    {
                        for (name, value) in &mut map {
                            if name.eq_ignore_ascii_case("cookie") {
                                *value = Value::String(String::new());
                            }
                        }
                        Value::Object(map)
                    }
                    _ => header_val.clone(),
                });
            }
            if restored_jar {
                initial_cookies = parsed_url
                    .as_ref()
                    .and_then(|url| cookie_store.get_cookie_header(url));
            }

            if let Some(ref vars) = session.variables {
                if !vars.is_empty() {
                    initial_variables = Some(vars.clone());
                }
            }
        }

        let initial_cookie_jar = cookie_store.snapshot();
        Self {
            source_url: source_url.to_string(),
            cookie_store,
            header: Mutex::new(initial_header.clone()),
            variables: Mutex::new(initial_variables.clone().unwrap_or_default()),
            script_cache: Mutex::new(HashMap::new()),
            memory_cache: Mutex::new(HashMap::new()),
            public_suffix_cache: Arc::new(Mutex::new(None)),
            unknown_method_fallback: AtomicBool::new(false),
            initial_session: ExecuteSession {
                cookies: initial_cookies,
                cookie_jar: initial_cookie_jar,
                header: initial_header,
                variables: initial_variables,
            },
        }
    }

    pub(crate) fn note_unknown_method_fallback(&self) {
        self.unknown_method_fallback.store(true, Ordering::Relaxed);
    }

    pub(crate) fn had_unknown_method_fallback(&self) -> bool {
        self.unknown_method_fallback.load(Ordering::Relaxed)
    }

    pub(crate) fn cookie_store(&self) -> &SharedCookieStore {
        &self.cookie_store
    }

    pub fn source_url(&self) -> &str {
        &self.source_url
    }

    pub fn resolve_url(&self, target: &str) -> Option<Url> {
        let target = target.trim();
        if target.is_empty() {
            return Url::parse(&self.source_url).ok();
        }
        if target.starts_with("http://") || target.starts_with("https://") {
            return Url::parse(target).ok();
        }
        if let Ok(url) = Url::parse(&format!("https://{target}")) {
            return Some(url);
        }
        Url::parse(&self.source_url).ok()
    }

    pub fn get_variable(&self, key: &str) -> Option<Value> {
        let map = self.variables.lock().unwrap_or_else(|e| e.into_inner());
        if key.is_empty() {
            map.get("variable")
                .or_else(|| map.get("sourceVariable"))
                .cloned()
        } else {
            map.get(key).cloned()
        }
    }

    pub fn set_variable(&self, key: &str, value: Value) {
        let mut map = self.variables.lock().unwrap_or_else(|e| e.into_inner());
        if key.is_empty() {
            map.insert("variable".to_string(), value.clone());
            map.insert("sourceVariable".to_string(), value);
        } else {
            map.insert(key.to_string(), value.clone());
            // Also maintain default variable if not set
            if !map.contains_key("variable") {
                map.insert("variable".to_string(), value);
            }
        }
    }

    pub fn set_variable_exact(&self, key: &str, value: Value) {
        self.variables
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_string(), value);
    }

    /// Cache values live in the caller-owned session, never in a process-wide map.
    pub(crate) fn script_cache_get(&self, key: &str) -> Option<String> {
        self.script_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned()
    }

    pub(crate) fn script_cache_put(&self, key: String, script: String) {
        let mut cache = self.script_cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() < 16 && script.len() <= 512 * 1024 {
            cache.insert(key, script);
        }
    }

    pub(crate) fn memory_cache_get(&self, key: &str) -> Option<Value> {
        self.memory_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned()
    }

    pub(crate) fn memory_cache_put(&self, key: String, value: Value) {
        self.memory_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, value);
    }

    pub(crate) fn memory_cache_delete(&self, key: &str) {
        self.memory_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }

    pub(crate) fn js_cache_get(&self, key: &str) -> Option<String> {
        let mut variables = self.variables.lock().unwrap_or_else(|e| e.into_inner());
        let entries = variables.get_mut(JS_CACHE_STATE_KEY)?.as_object_mut()?;
        let entry = entries.get(key)?;
        let expired = entry
            .get("expiresAt")
            .and_then(Value::as_u64)
            .is_some_and(|expiry| expiry <= now_epoch_seconds());
        if expired {
            entries.remove(key);
            return None;
        }
        entry.get("value")?.as_str().map(str::to_string)
    }

    pub(crate) fn js_cache_put(
        &self,
        key: &str,
        value: String,
        save_time_secs: Option<i64>,
    ) -> bool {
        if key.len() > 256 || value.len() > JS_CACHE_MAX_VALUE_BYTES {
            return false;
        }
        let mut variables = self.variables.lock().unwrap_or_else(|e| e.into_inner());
        let entries = variables
            .entry(JS_CACHE_STATE_KEY.to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        let Some(entries) = entries.as_object_mut() else {
            return false;
        };
        let now = now_epoch_seconds();
        entries.retain(|_, entry| {
            entry
                .get("expiresAt")
                .and_then(Value::as_u64)
                .is_none_or(|expiry| expiry > now)
        });
        if !entries.contains_key(key) && entries.len() >= JS_CACHE_MAX_ENTRIES {
            return false;
        }
        let expiry = save_time_secs
            .filter(|seconds| *seconds > 0)
            .map(|seconds| now.saturating_add(seconds as u64));
        entries.insert(
            key.to_string(),
            serde_json::json!({"value":value,"expiresAt":expiry}),
        );
        true
    }

    pub(crate) fn js_cache_delete(&self, key: &str) -> bool {
        let mut variables = self.variables.lock().unwrap_or_else(|e| e.into_inner());
        variables
            .get_mut(JS_CACHE_STATE_KEY)
            .and_then(Value::as_object_mut)
            .and_then(|entries| entries.remove(key))
            .is_some()
    }

    pub fn remove_variable(&self, key: &str) {
        let mut map = self.variables.lock().unwrap_or_else(|e| e.into_inner());
        if key.is_empty() {
            map.remove("variable");
            map.remove("sourceVariable");
        } else {
            map.remove(key);
        }
    }

    pub fn get_login_header(&self) -> Option<Value> {
        let header = self.header.lock().unwrap_or_else(|e| e.into_inner());
        let mut value = header.clone()?;
        // Preserve legacy malformed values for compatibility on State In. Valid
        // objects use the live jar, never the persisted Cookie header's old value.
        let parsed = match &value {
            Value::String(raw) => serde_json::from_str::<Value>(raw).ok(),
            _ => None,
        };
        if let Some(Value::Object(map)) = parsed {
            value = Value::Object(map);
        }
        if let Value::Object(map) = &mut value {
            let keys: Vec<_> = map
                .keys()
                .filter(|key| key.eq_ignore_ascii_case("cookie"))
                .cloned()
                .collect();
            if !keys.is_empty() {
                let cookie = self.get_cookie("");
                for key in keys {
                    if let Some(cookie) = &cookie {
                        map.insert(key, Value::String(cookie.clone()));
                    } else {
                        map.remove(&key);
                    }
                }
            }
        }
        Some(value)
    }

    pub fn put_login_header(&self, value: Value) -> Result<(), String> {
        use ureq::http::{HeaderName, HeaderValue};

        let value = match value {
            Value::String(raw) => serde_json::from_str(&raw)
                .map_err(|_| "login Header must be a JSON object".to_string())?,
            value => value,
        };
        let Value::Object(mut map) = value else {
            return Err("login Header must be a JSON object".into());
        };
        let mut cookie = None;
        for (name, value) in &map {
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| "invalid login Header name".to_string())?;
            let value = value
                .as_str()
                .ok_or_else(|| "login Header values must be strings".to_string())?;
            HeaderValue::from_str(value).map_err(|_| "invalid login Header value".to_string())?;
            if name.eq_ignore_ascii_case("cookie") && cookie.replace(value.to_string()).is_some() {
                return Err("duplicate login Cookie header".into());
            }
        }
        // Lock order is Header -> jar, also used by the getter. No publication
        // occurs before full validation; the jar update itself is transactional.
        let mut header = self.header.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cookie) = cookie {
            let url = self
                .resolve_url("")
                .ok_or_else(|| "invalid login source URL".to_string())?;
            self.cookie_store.import_login_cookies(&cookie, &url)?;
            for (name, value) in &mut map {
                if name.eq_ignore_ascii_case("cookie") {
                    *value = Value::String(String::new());
                }
            }
        }
        *header = Some(Value::Object(map));
        Ok(())
    }

    pub fn remove_login_header(&self) {
        self.remove_cookie(&self.source_url);
        let mut h = self.header.lock().unwrap_or_else(|e| e.into_inner());
        *h = None;
    }

    pub fn get_cookie(&self, target_url: &str) -> Option<String> {
        let url = self.resolve_url(target_url)?;
        self.cookie_store.get_cookie_header(&url)
    }

    pub fn get_cookie_key(&self, target_url: &str, key: &str) -> Option<String> {
        self.get_cookie(target_url)?.split(';').find_map(|cookie| {
            let (name, value) = cookie.trim().split_once('=')?;
            (name.trim() == key.trim()).then(|| value.trim().to_string())
        })
    }

    pub fn set_cookie(&self, target_url: &str, cookie_str: &str) {
        if let Some(url) = self.resolve_url(target_url) {
            self.cookie_store.add_cookie_header(cookie_str, &url);
        }
    }

    pub fn remove_cookie(&self, target_url: &str) {
        let Some(url) = self.resolve_url(target_url) else {
            return;
        };
        let cookie_header = self.get_cookie(target_url).unwrap_or_default();
        let mut paths = vec!["/".to_string(), url.path().to_string()];
        for (index, _) in url.path().match_indices('/') {
            if index > 0 {
                paths.push(url.path()[..index].to_string());
            }
        }
        paths.sort();
        paths.dedup();

        for part in cookie_header.split(';') {
            let Some((name, _)) = part.trim().split_once('=') else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            for path in &paths {
                let expired = format!("{name}=; Max-Age=0; Path={path}");
                self.cookie_store.add_set_cookie(&expired, &url);
            }
        }
    }

    pub fn current_session(&self) -> ExecuteSession {
        let cookies = Url::parse(&self.source_url)
            .ok()
            .and_then(|url| self.cookie_store.get_cookie_header(&url))
            .filter(|s| !s.is_empty());

        let header = self
            .header
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        let variables_map = self
            .variables
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let variables = if variables_map.is_empty() {
            None
        } else {
            Some(variables_map)
        };

        ExecuteSession {
            cookies,
            cookie_jar: self.cookie_store.snapshot(),
            header,
            variables,
        }
    }

    pub fn extract_delta(&self) -> Option<ExecuteSession> {
        let current = self.current_session();
        if current == self.initial_session {
            None
        } else {
            Some(current)
        }
    }
}

pub fn with_active_session<T>(
    session_opt: Option<&ExecuteSession>,
    source_url: &str,
    f: impl FnOnce(&ActiveSession) -> T,
) -> (T, Option<ExecuteSession>) {
    let active = Arc::new(ActiveSession::new(session_opt, source_url));
    let result = ACTIVE_SESSION.with(|cell| {
        crate::util::scoped::with_scoped_value(cell, Some(Arc::clone(&active)), || f(&active))
    });
    let delta = active.extract_delta();
    (result, delta)
}

pub fn current_active_session() -> Option<Arc<ActiveSession>> {
    ACTIVE_SESSION.with(|cell| cell.borrow().clone())
}

fn extract_and_sync_cookies_from_header(
    cookies: &SharedCookieStore,
    header_val: &Value,
    url: &Url,
) {
    match header_val {
        Value::Object(map) => {
            for (k, v) in map {
                if k.eq_ignore_ascii_case("cookie") {
                    if let Some(cookie_str) = v.as_str() {
                        cookies.add_cookie_header(cookie_str, url);
                    }
                }
            }
        }
        Value::String(raw) => {
            if let Ok(Value::Object(map)) = serde_json::from_str(raw) {
                for (k, v) in map {
                    if k.eq_ignore_ascii_case("cookie") {
                        if let Some(cookie_str) = v.as_str() {
                            cookies.add_cookie_header(cookie_str, url);
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scoped_session_restores_parent_after_error_and_unwind() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        assert!(current_active_session().is_none());
        let (_, delta) = with_active_session(None, "https://outer.test", |outer| {
            let parent = current_active_session().unwrap();
            let (result, child_delta) = with_active_session(None, "https://inner.test", |inner| {
                inner.set_variable("child", json!(true));
                Err::<(), _>("expected")
            });
            assert_eq!(result, Err("expected"));
            assert!(child_delta.is_some());
            assert!(Arc::ptr_eq(&parent, &current_active_session().unwrap()));
            assert!(catch_unwind(AssertUnwindSafe(|| {
                with_active_session(None, "https://inner.test", |_| panic!("expected"));
            }))
            .is_err());
            assert!(Arc::ptr_eq(&parent, &current_active_session().unwrap()));
            assert!(outer.extract_delta().is_none());
        });
        assert!(delta.is_none());
        assert!(current_active_session().is_none());
        assert!(catch_unwind(AssertUnwindSafe(|| {
            with_active_session(None, "https://outer.test", |_| panic!("expected"));
        }))
        .is_err());
        assert!(current_active_session().is_none());
    }

    #[test]
    fn login_header_validation_does_not_partially_commit() {
        let session = ActiveSession::new(None, "https://example.test/");
        session
            .put_login_header(json!({"Authorization":"old", "Cookie":"sid=old"}))
            .unwrap();
        let before = session.current_session();
        for invalid in [
            json!([1]),
            json!("not json"),
            json!({"X-Count": 2}),
            json!({"bad name":"x", "Cookie":"sid=new"}),
            json!({"Cookie":"sid=new", "X-Z":"bad\r\nvalue"}),
            json!({"Cookie":"sid=new; broken"}),
            json!({"Cookie":"sid=new", "cookie":"other=new"}),
        ] {
            assert!(session.put_login_header(invalid).is_err());
            assert_eq!(session.current_session(), before);
        }
        session
            .put_login_header(json!("{\"Authorization\":\"new\",\"Cookie\":\"sid=new\"}"))
            .unwrap();
        assert_eq!(session.get_cookie_key("", "sid").as_deref(), Some("new"));
        assert_eq!(session.get_login_header().unwrap()["Authorization"], "new");
    }

    #[test]
    fn login_header_cookie_uses_live_jar_and_does_not_resurrect_on_roundtrip() {
        let initial = ExecuteSession {
            header: Some(json!(
                "{\"Cookie\":\"sid=old\",\"Authorization\":\"token\"}"
            )),
            ..Default::default()
        };
        let session = ActiveSession::new(Some(&initial), "https://example.test/");
        session.set_cookie("", "sid=fresh");
        assert_eq!(session.get_login_header().unwrap()["Cookie"], "sid=fresh");
        session.remove_cookie("");
        assert!(session.get_login_header().unwrap().get("Cookie").is_none());
        let state = session.current_session();
        let restored = ActiveSession::new(Some(&state), "https://example.test/");
        assert!(restored.get_cookie("").is_none());
        assert!(restored.get_login_header().unwrap().get("Cookie").is_none());
        assert_eq!(
            restored.get_login_header().unwrap()["Authorization"],
            "token"
        );
    }

    #[test]
    fn test_session_lifecycle_and_delta() {
        let source_url = "https://example.com/books";
        let initial = ExecuteSession {
            cookies: Some("uid=100".to_string()),
            cookie_jar: None,
            header: Some(json!({"User-Agent": "Test"})),
            variables: None,
        };

        // Case 1: No modification -> Delta is None
        let (_, delta) = with_active_session(Some(&initial), source_url, |session| {
            assert_eq!(
                session.get_cookie("https://example.com"),
                Some("uid=100".to_string())
            );
        });
        assert_eq!(delta, None);

        // Case 2: Modify variable -> Delta contains new variable
        let (_, delta) = with_active_session(Some(&initial), source_url, |session| {
            session.set_variable("token", json!("xyz789"));
        });
        assert!(delta.is_some());
        let delta = delta.unwrap();
        assert_eq!(
            delta
                .variables
                .as_ref()
                .unwrap()
                .get("token")
                .and_then(Value::as_str),
            Some("xyz789")
        );

        // Case 3: Modify loginHeader with Cookie -> Cookie synced to jar and delta emitted
        let (_, delta) = with_active_session(None, source_url, |session| {
            session
                .put_login_header(json!({"Cookie": "sess=new_sess_token"}))
                .unwrap();
            assert_eq!(
                session.get_cookie("https://example.com"),
                Some("sess=new_sess_token".to_string())
            );
        });
        assert!(delta.is_some());
        let delta = delta.unwrap();
        assert_eq!(delta.cookies, Some("sess=new_sess_token".to_string()));

        let initial = ExecuteSession {
            cookies: Some("sid=clear_me".to_string()),
            cookie_jar: None,
            header: Some(json!({"Cookie": "sid=clear_me"})),
            variables: None,
        };
        let (_, delta) = with_active_session(Some(&initial), source_url, |session| {
            assert_eq!(
                session.get_cookie(source_url),
                Some("sid=clear_me".to_string())
            );
            session.remove_login_header();
            assert_eq!(session.get_cookie(source_url), None);
        });
        let delta = delta.expect("removing the login state must emit a session delta");
        assert_eq!(delta.cookies, None);
        assert_eq!(delta.header, None);
    }

    #[test]
    fn cookie_jar_round_trips_other_domains_paths_and_legacy_cookies() {
        let source = "https://source.example/books";
        let (_, state) = with_active_session(None, source, |active| {
            let other = Url::parse("https://login.example/private/page").unwrap();
            active
                .cookie_store()
                .add_set_cookie("token=private; Path=/private; Secure", &other);
            active
                .cookie_store()
                .add_set_cookie("expired=no; Max-Age=0; Path=/", &other);
            assert_eq!(active.get_cookie(source), None);
            assert_eq!(
                active.get_cookie("https://login.example/private/page"),
                Some("token=private".into())
            );
        });
        let state = state.expect("third-party cookie must produce a delta");
        assert_eq!(state.cookies, None);
        assert!(state.cookie_jar.is_some());
        let json = serde_json::to_string(&state).unwrap();
        let state: ExecuteSession = serde_json::from_str(&json).unwrap();
        let (_, delta) = with_active_session(Some(&state), source, |active| {
            assert_eq!(
                active.get_cookie("https://login.example/private/next"),
                Some("token=private".into())
            );
            assert_eq!(active.get_cookie("https://login.example/public"), None);
            assert_eq!(active.get_cookie("https://source.example/private"), None);
        });
        assert_eq!(delta, None);

        let legacy: ExecuteSession = serde_json::from_str(r#"{"cookies":"sid=old"}"#).unwrap();
        let (_, delta) = with_active_session(Some(&legacy), source, |active| {
            assert_eq!(active.get_cookie(source), Some("sid=old".into()));
        });
        assert_eq!(delta, None);
    }

    #[test]
    fn js_cache_expires_and_has_a_bounded_session_footprint() {
        let initial = ExecuteSession {
            variables: Some(HashMap::from([(
                JS_CACHE_STATE_KEY.to_string(),
                json!({"expired":{"value":"old","expiresAt":1}}),
            )])),
            ..Default::default()
        };
        let (_, delta) = with_active_session(Some(&initial), "https://example.com", |session| {
            assert_eq!(session.js_cache_get("expired"), None);
            for index in 0..JS_CACHE_MAX_ENTRIES {
                assert!(session.js_cache_put(&format!("key-{index}"), "v".into(), None));
            }
            assert!(!session.js_cache_put("one-more", "v".into(), None));
            assert!(!session.js_cache_put("huge", "x".repeat(JS_CACHE_MAX_VALUE_BYTES + 1), None));
            assert!(session.js_cache_delete("key-0"));
            assert!(session.js_cache_put("replacement", "v".into(), None));
        });
        assert!(delta.is_some());
    }
}
