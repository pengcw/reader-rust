//! Thin HTTP URL parser. No PSL data, host callbacks or domain guessing.
use serde_json::json;
use url::{Host, Url};

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
