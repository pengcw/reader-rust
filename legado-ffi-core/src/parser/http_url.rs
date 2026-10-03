//! HTTP URL parsing and host-provided public suffix data. No embedded PSL or network fallback.
use publicsuffix::{List, Psl};
use serde_json::{json, Value};
use std::sync::Mutex;
use url::{Host, Url};

pub(crate) type SuffixCache = Mutex<Option<List>>;
const MAX_PSL_BYTES: usize = 512 * 1024;

fn error(kind: &str, message: &str) -> Value {
    json!({"ok": false, "error": {"kind": kind, "message": message}})
}

pub(crate) fn parse(spec: &str) -> Option<String> {
    let url = Url::parse(spec).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = match url.host()? {
        Host::Domain(host) => host.to_owned(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    };
    Some(json!({"url": url.as_str(), "host": host}).to_string())
}

pub(crate) fn top_private_domain(spec: &str, cache: &SuffixCache) -> Value {
    let Ok(url) = Url::parse(spec) else {
        return error("invalid_argument", "invalid HTTP URL");
    };
    if !matches!(url.scheme(), "http" | "https") {
        return error("invalid_argument", "expected HTTP or HTTPS URL");
    }
    let Some(Host::Domain(host)) = url.host() else {
        return json!({"ok": true, "data": null});
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    if !host.contains('.') {
        return json!({"ok": true, "data": null});
    }
    // Cached data must not bypass the existing offline-diagnostics policy.
    if crate::host_services::is_offline() {
        return error(
            "permission_denied",
            "host services are disabled in offline diagnostics",
        );
    }
    if cache.lock().unwrap_or_else(|e| e.into_inner()).is_none() {
        // Never hold the cache lock while invoking host code.
        let response = crate::host_services::call("url.public_suffix.load", &json!({}));
        if response["ok"] != true {
            return response;
        }
        let data = &response["data"];
        let Some(text) = data["text"].as_str() else {
            return error("invalid_response", "host PSL text is missing");
        };
        if data["revision"].as_str().is_none_or(str::is_empty) {
            return error("invalid_response", "host PSL revision is missing");
        }
        if text.len() > MAX_PSL_BYTES {
            return error("limit_exceeded", "host PSL data exceeds 512 KiB");
        }
        let mut offset = 0;
        for marker in [
            "// ===BEGIN ICANN DOMAINS===",
            "// ===END ICANN DOMAINS===",
            "// ===BEGIN PRIVATE DOMAINS===",
            "// ===END PRIVATE DOMAINS===",
        ] {
            let Some(position) = text[offset..].find(marker) else {
                return error("invalid_response", "host PSL data is incomplete");
            };
            offset += position + marker.len();
        }
        let Ok(list) = List::from_bytes(text.as_bytes()) else {
            return error("invalid_response", "host PSL data is invalid");
        };
        *cache.lock().unwrap_or_else(|e| e.into_inner()) = Some(list);
    }
    let cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    let domain = cache
        .as_ref()
        .and_then(|list| list.domain(host.as_bytes()))
        .and_then(|domain| {
            std::str::from_utf8(domain.as_bytes())
                .ok()
                .map(str::to_owned)
        });
    json!({"ok": true, "data": domain})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_suffix_data_cannot_bypass_offline_policy() {
        let list = List::from_bytes(b"// ===BEGIN ICANN DOMAINS===\ncom\n").unwrap();
        let cache = Mutex::new(Some(list));
        let response = crate::host_services::with_offline(|| {
            top_private_domain("https://example.com", &cache)
        });
        assert_eq!(response["error"]["kind"], "permission_denied");
    }
}
