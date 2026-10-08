use cookie_store::CookieStore;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use ureq::http::header::SET_COOKIE;
use ureq::http::HeaderMap;
use url::Url;

#[derive(Debug, Clone, Default)]
pub(crate) struct SharedCookieStore(Arc<Mutex<CookieStore>>);

impl SharedCookieStore {
    pub(crate) fn get_cookie_header(&self, url: &Url) -> Option<String> {
        let store = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let value = store
            .get_request_values(url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        (!value.is_empty()).then_some(value)
    }

    /// Preserve domain, path, expiry and session cookies across FFI calls.
    pub(crate) fn snapshot(&self) -> Option<Value> {
        let store = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut cookies: Vec<Value> = store
            .iter_unexpired()
            .filter_map(|cookie| serde_json::to_value(cookie).ok())
            .collect();
        if cookies.is_empty() {
            return None;
        }
        cookies.sort_by_key(Value::to_string);
        Some(Value::Array(cookies))
    }

    pub(crate) fn restore(&self, snapshot: &Value) -> bool {
        let Ok(store) = serde_json::from_value::<CookieStore>(snapshot.clone()) else {
            return false;
        };
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = store;
        true
    }

    pub(crate) fn add_cookie_header(&self, cookie_header: &str, url: &Url) {
        let mut store = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for part in cookie_header.split(';') {
            let part = part.trim();
            let Some((name, value)) = part.split_once('=') else {
                continue;
            };
            let name = name.trim();
            if name.is_empty()
                || matches!(
                    name.to_ascii_lowercase().as_str(),
                    "path" | "domain" | "expires" | "max-age" | "samesite" | "httponly" | "secure"
                )
            {
                continue;
            }
            let _ = store.parse(&format!("{name}={}; Path=/", value.trim()), url);
        }
    }

    /// Validate in a private candidate while holding the live jar lock; publish only
    /// after every pair succeeds, so concurrent response cookies are not overwritten.
    pub(crate) fn import_login_cookies(
        &self,
        cookie_header: &str,
        url: &Url,
    ) -> Result<(), String> {
        let mut store = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut candidate = store.clone();
        if !cookie_header.trim().is_empty() {
            for part in cookie_header.split(';') {
                let (name, value) = part
                    .trim()
                    .split_once('=')
                    .ok_or_else(|| "invalid login Cookie pair".to_string())?;
                let name = name.trim();
                if name.is_empty()
                    || !name.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
                    })
                {
                    return Err("invalid login Cookie name".into());
                }
                candidate
                    .parse(&format!("{name}={}; Path=/", value.trim()), url)
                    .map_err(|_| "invalid login Cookie value".to_string())?;
            }
        }
        *store = candidate;
        Ok(())
    }

    pub(crate) fn add_set_cookie(&self, set_cookie: &str, url: &Url) {
        let mut store = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = store.parse(set_cookie, url);
    }

    pub(crate) fn store_response_cookies(&self, headers: &HeaderMap, url: &Url) {
        let mut store = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for value in headers.get_all(SET_COOKIE) {
            if let Ok(value) = value.to_str() {
                let _ = store.parse(value, url);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SharedCookieStore;
    use url::Url;

    #[test]
    fn snapshot_preserves_domain_path_expiry_and_secure_scope() {
        let origin = Url::parse("https://books.example.com/chapter/1").unwrap();
        let jar = SharedCookieStore::default();
        jar.add_set_cookie(
            "token=secret; Domain=example.com; Path=/chapter; Secure",
            &origin,
        );
        jar.add_set_cookie("host=only; Path=/", &origin);
        jar.add_set_cookie("expired=no; Max-Age=0; Path=/", &origin);
        jar.add_set_cookie("foreign=no; Domain=other.example; Path=/", &origin);
        let snapshot = jar.snapshot().unwrap();
        let restored = SharedCookieStore::default();
        assert!(restored.restore(&snapshot));
        assert_eq!(restored.snapshot(), Some(snapshot));
        for (url, expected) in [
            ("https://other.example.com/chapter/2", Some("token=secret")),
            ("https://other.example.com/", None),
            ("http://other.example.com/chapter/2", None),
            ("https://unrelated.example/chapter/2", None),
            ("https://books.example.com/", Some("host=only")),
        ] {
            assert_eq!(
                restored
                    .get_cookie_header(&Url::parse(url).unwrap())
                    .as_deref(),
                expected
            );
        }
    }
}
