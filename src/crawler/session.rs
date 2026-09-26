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
use std::sync::{Arc, Mutex};
use url::Url;

/// 对称会话 DTO：输入与输出同构
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteSession {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookies: Option<String>,
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
            if let Some(ref cookies_str) = session.cookies {
                if !cookies_str.trim().is_empty() {
                    if let Some(ref url) = parsed_url {
                        cookie_store.add_cookie_header(cookies_str, url);
                    }
                    initial_cookies = Some(cookies_str.clone());
                }
            }

            if let Some(ref header_val) = session.header {
                // If header contains cookie, also sync to cookie_jar
                if let Some(ref url) = parsed_url {
                    extract_and_sync_cookies_from_header(&cookie_store, header_val, url);
                }
                initial_header = Some(header_val.clone());
            }

            if let Some(ref vars) = session.variables {
                if !vars.is_empty() {
                    initial_variables = Some(vars.clone());
                }
            }
        }

        Self {
            source_url: source_url.to_string(),
            cookie_store,
            header: Mutex::new(initial_header.clone()),
            variables: Mutex::new(initial_variables.clone().unwrap_or_default()),
            initial_session: ExecuteSession {
                cookies: initial_cookies,
                header: initial_header,
                variables: initial_variables,
            },
        }
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
        self.header
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn put_login_header(&self, value: Value) {
        if let Some(url) = self.resolve_url("") {
            extract_and_sync_cookies_from_header(&self.cookie_store, &value, &url);
        }
        let mut h = self.header.lock().unwrap_or_else(|e| e.into_inner());
        *h = Some(value);
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
    let previous = ACTIVE_SESSION.with(|cell| cell.replace(Some(Arc::clone(&active))));
    let result = f(&active);
    ACTIVE_SESSION.with(|cell| cell.replace(previous));
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
    fn test_session_lifecycle_and_delta() {
        let source_url = "https://example.com/books";
        let initial = ExecuteSession {
            cookies: Some("uid=100".to_string()),
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
            session.put_login_header(json!({"Cookie": "sess=new_sess_token"}));
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
}
