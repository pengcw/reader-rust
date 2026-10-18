//! Shared URL bridge for the render runtime and build-time bootstrap validation.

use rquickjs::{Ctx, Function};

fn parse_url(href: &str, base: &str) -> String {
    let parsed = if base.is_empty() {
        url::Url::parse(href)
    } else {
        url::Url::parse(base).and_then(|base| base.join(href))
    };
    let Ok(url) = parsed else {
        return "null".to_owned();
    };
    let hostname = url.host_str().unwrap_or_default();
    let port = url.port().map(|port| port.to_string()).unwrap_or_default();
    let host = if port.is_empty() {
        hostname.to_owned()
    } else {
        format!("{hostname}:{port}")
    };
    serde_json::json!({
        "href": url.as_str(),
        "protocol": format!("{}:", url.scheme()),
        "host": host,
        "hostname": hostname,
        "port": port,
        "pathname": url.path(),
        "search": url.query().filter(|query| !query.is_empty())
            .map(|query| format!("?{query}")).unwrap_or_default(),
        "hash": url.fragment().filter(|fragment| !fragment.is_empty())
            .map(|fragment| format!("#{fragment}")).unwrap_or_default(),
        "origin": url.origin().ascii_serialization(),
    }).to_string()
}

pub(crate) fn install(ctx: &Ctx<'_>) -> rquickjs::Result<()> {
    let parse = Function::new(ctx.clone(), |href: String, base: String| parse_url(&href, &base))?;
    ctx.globals().set("_r_url_parse", parse)
}
