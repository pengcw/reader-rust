//! Core rendering pipeline for rakers.
//!
//! Parses HTML, collects and executes scripts in a sandboxed JS context,
//! then serializes the post-execution DOM back to HTML.

#[cfg(feature = "diff")]
mod diff;
mod dom;
mod pretty;
mod runtime;
mod select;

#[cfg(feature = "diff")]
pub use diff::diff_html;
pub use pretty::pretty_print;
pub use select::select_html;

use std::borrow::Cow;
use std::cell::Cell;
use std::io::Read;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

thread_local! {
    static VERBOSE: Cell<bool> = const { Cell::new(false) };
}

/// Enable or disable verbose stderr output for the current thread.
///
/// When `false` (default) only `[js error]` and `[fetch error]` are printed.
/// When `true` all messages — `[fetch]`, `[skip]`, `[console]`, `[module-shim]`
/// — are also printed.
pub fn set_verbose(v: bool) {
    VERBOSE.with(|c| c.set(v));
}

fn is_verbose() -> bool {
    VERBOSE.with(std::cell::Cell::get)
}

/// Serialize render results as a JSON object with three fields:
/// `raw_bytes`, `rendered_bytes`, and `html`.
///
/// The `html` string is JSON-escaped; no external dependency is required.
#[must_use]
pub fn to_json(raw_bytes: usize, html: &str) -> String {
    format!(
        "{{\n  \"raw_bytes\": {},\n  \"rendered_bytes\": {},\n  \"html\": \"{}\"\n}}\n",
        raw_bytes,
        html.len(),
        json_escape(html)
    )
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// A host-provided HTTP request used by page scripts and external resources.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// A text HTTP response returned to the renderer.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// Host HTTP boundary. Embedders can reuse their own cookies, redirects and proxy policy.
pub trait HttpTransport: Send + Sync {
    fn execute(&self, request: HttpRequest) -> Result<HttpResponse, String>;
}

/// Render-scoped request/deadline accounting shared by static scripts and JS requests.
#[derive(Clone)]
pub(crate) struct RequestBudget {
    requests: Arc<AtomicUsize>,
    max_requests: usize,
    max_response_bytes: usize,
    deadline: Option<Instant>,
}

impl RequestBudget {
    fn new(cfg: &HttpConfig) -> Self {
        Self {
            requests: Arc::new(AtomicUsize::new(0)),
            max_requests: cfg.max_requests.unwrap_or(32).max(1),
            max_response_bytes: cfg.max_response_bytes.unwrap_or(8 * 1024 * 1024).max(1),
            deadline: cfg
                .render_timeout
                .and_then(|timeout| Instant::now().checked_add(timeout)),
        }
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    fn before_request(&self) -> Result<(), String> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err("Rakers render deadline exceeded".to_string());
        }
        let request = self.requests.fetch_add(1, Ordering::Relaxed) + 1;
        if request > self.max_requests {
            return Err(format!(
                "Rakers network request limit exceeded ({})",
                self.max_requests
            ));
        }
        Ok(())
    }

    fn check_response(&self, bytes: usize) -> Result<(), String> {
        if bytes > self.max_response_bytes {
            return Err(format!(
                "Rakers network response exceeds {} bytes",
                self.max_response_bytes
            ));
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err("Rakers render deadline exceeded".to_string());
        }
        Ok(())
    }
}

/// HTTP options applied to every outbound request made by rakers.
#[derive(Default, Clone)]
pub struct HttpConfig {
    /// Value for the `User-Agent` header. `None` sends no `User-Agent`.
    pub user_agent: Option<String>,
    /// Additional headers sent with every request, in `(name, value)` form.
    pub headers: Vec<(String, String)>,
    /// Optional proxy URL. This vendored reader-rust build disables ureq's
    /// `socks-proxy` feature: do not pass SOCKS URLs to the standalone ureq
    /// fallback, which may fail or panic. HTTP/HTTPS proxies remain supported.
    /// With a custom transport, proxy handling is the transport's responsibility;
    /// reader-rust's shared HttpClient explicitly rejects SOCKS.
    /// See Cargo.toml's ureq feature comment before restoring SOCKS support.
    pub proxy: Option<String>,
    /// When `true`, custom `-H` headers are also forwarded on XHR requests
    /// the page's JavaScript initiates. Defaults to `false` to avoid leaking
    /// credentials to cross-origin destinations controlled by page scripts.
    pub forward_headers: bool,
    /// Optional host transport. When absent, rakers falls back to its own ureq client.
    pub transport: Option<Arc<dyn HttpTransport>>,
    /// Maximum total network requests made during one render.
    pub max_requests: Option<usize>,
    /// Maximum text bytes accepted from any single renderer subrequest.
    pub max_response_bytes: Option<usize>,
    /// Optional wall-clock deadline for the whole render, including subrequests.
    pub render_timeout: Option<Duration>,
    /// Opt-in asynchronous fetch/XHR, only enabled for subprocess-based preview.
    pub async_http: bool,
}

impl HttpConfig {
    fn build_agent(&self, http_status_as_error: bool) -> ureq::Agent {
        let mut builder = ureq::Agent::config_builder()
            .http_status_as_error(http_status_as_error)
            .max_redirects(5)
            .timeout_global(Some(Duration::from_secs(8)))
            .timeout_connect(Some(Duration::from_secs(3)));
        if let Some(ref proxy_url) = self.proxy {
            match ureq::Proxy::new(proxy_url) {
                Ok(proxy) => builder = builder.proxy(Some(proxy)),
                Err(error) => eprintln!("[proxy error] {proxy_url}: {error}"),
            }
        }
        ureq::Agent::new_with_config(builder.build())
    }

    /// Build the legacy public ureq agent. Preserve the original behavior where
    /// non-success HTTP statuses are reported as request errors.
    #[must_use]
    pub fn agent(&self) -> ureq::Agent {
        self.build_agent(true)
    }

    /// Apply the configured User-Agent and custom headers to a ureq request.
    pub fn apply<B>(&self, mut req: ureq::RequestBuilder<B>) -> ureq::RequestBuilder<B> {
        if let Some(ua) = &self.user_agent {
            req = req.header("User-Agent", ua);
        }
        for (name, value) in &self.headers {
            req = req.header(name, value);
        }
        req
    }

    fn request_headers(
        &self,
        headers: &[(String, String)],
        include_config_headers: bool,
    ) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if let Some(ua) = &self.user_agent
            && !headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        {
            out.push(("User-Agent".to_string(), ua.clone()));
        }
        if include_config_headers {
            out.extend(self.headers.iter().cloned());
        }
        out.extend(headers.iter().cloned());
        out
    }

    pub(crate) fn execute(
        &self,
        budget: &RequestBudget,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&str>,
        include_config_headers: bool,
    ) -> Result<HttpResponse, String> {
        let request = self.prepare_request(budget, method, url, headers, body, include_config_headers)?;
        self.execute_prepared(budget, request)
    }

    pub(crate) fn prepare_request(
        &self,
        budget: &RequestBudget,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&str>,
        include_config_headers: bool,
    ) -> Result<HttpRequest, String> {
        let method = method.trim().to_ascii_uppercase();
        if !matches!(
            method.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
        ) {
            return Err(format!("unsupported Rakers HTTP method: {method}"));
        }
        let parsed = url::Url::parse(url).map_err(|error| format!("invalid URL: {error}"))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(
                "Rakers requests require an absolute http(s) URL without credentials".to_string(),
            );
        }
        budget.before_request()?;
        let headers = self.request_headers(headers, include_config_headers);
        Ok(HttpRequest {
            method,
            url: url.to_string(),
            headers,
            body: body.map(str::to_string),
        })
    }

    pub(crate) fn execute_prepared(
        &self,
        budget: &RequestBudget,
        request: HttpRequest,
    ) -> Result<HttpResponse, String> {
        let HttpRequest { method, url, headers, body } = request;
        let response = if let Some(transport) = &self.transport {
            transport.execute(HttpRequest { method, url, headers, body })?
        } else {
            let method = ureq::http::Method::from_bytes(method.as_bytes())
                .map_err(|error| format!("invalid HTTP method: {error}"))?;
            let mut builder = ureq::http::Request::builder().method(method).uri(url.as_str());
            for (name, value) in &headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            let mut response = if let Some(body) = body {
                self.build_agent(false).run(
                    builder
                        .body(body)
                        .map_err(|error| error.to_string())?,
                )
            } else {
                self.build_agent(false)
                    .run(builder.body(()).map_err(|error| error.to_string())?)
            }
            .map_err(|error| error.to_string())?;
            let status = response.status().as_u16();
            let response_headers = response
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_string(), value.to_string()))
                })
                .collect();
            let mut bytes = Vec::new();
            response
                .body_mut()
                .as_reader()
                .take(budget.max_response_bytes.saturating_add(1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|error| error.to_string())?;
            HttpResponse {
                url,
                status,
                headers: response_headers,
                body: String::from_utf8_lossy(&bytes).into_owned(),
            }
        };
        budget.check_response(response.body.len())?;
        Ok(response)
    }
}

/// Resolve `src` against an optional `base` URL, returning an absolute `http`/`https` URL.
///
/// Returns `None` for `data:` and `blob:` URLs (not fetchable), and when `src` is relative
/// but no base is available.
fn resolve_url(src: &str, base: Option<&str>) -> Option<String> {
    if src.starts_with("data:") || src.starts_with("blob:") {
        return None;
    }
    if src.starts_with("http://") || src.starts_with("https://") {
        return Some(src.to_owned());
    }
    if src.starts_with("//") {
        return Some(format!("https:{src}"));
    }
    let base_url = url::Url::parse(base?).ok()?;
    let resolved = base_url.join(src).ok()?;
    Some(resolved.to_string())
}

/// Fetch the script at `url` and return its source text.
///
/// Returns `None` on network error or if the response body is not valid UTF-8.
/// Files that open with `import`/`export` are skipped — they are ES module entry
/// points that require a full module loader with relative specifier resolution.
fn fetch_script(url: &str, cfg: &HttpConfig, budget: &RequestBudget) -> Option<String> {
    let response = match cfg.execute(budget, "GET", url, &[], None, true) {
        Ok(response) if (200..300).contains(&response.status) => response,
        Ok(response) => {
            eprintln!("[fetch error] {url}: HTTP {}", response.status);
            return None;
        }
        Err(error) => {
            eprintln!("[fetch error] {url}: {error}");
            return None;
        }
    };
    let body = response.body;
    // Skip ES module files that use static import/export — they require a full
    // module loader with relative specifier resolution that we can't provide.
    // Self-contained bundles tagged type="module" by their bundler are fine.
    let trimmed = body.trim_start();
    if trimmed.starts_with("import ")
        || trimmed.starts_with("import{")
        || trimmed.starts_with("export ")
    {
        // Narrow exception: a file whose entire content is a single bare side-effect
        // import (`import './bundle.js'`) is a Vite/Rollup entry-point shim that
        // just loads one self-contained bundle.  Follow that one hop.
        if let Some(target) = single_reexport_target(trimmed)
            && let Some(resolved) = resolve_url(target, Some(url))
        {
            if is_verbose() {
                eprintln!("[module-shim] {url} → {resolved}");
            }
            return fetch_script(&resolved, cfg, budget);
        }
        if is_verbose() {
            eprintln!("[skip] {url}: ES module syntax requires a module loader");
        }
        return None;
    }
    Some(body)
}

/// If `src` is a JS module whose only statement is a single side-effect import
/// (`import './bundle.js'` or `import "../path/to/bundle.js"`), return the
/// specifier string.  Returns `None` for anything more complex.
///
/// This handles the common Vite/Rollup entry-point shim pattern where the HTML
/// `<script type="module">` points at a tiny file that just re-exports a bundle.
fn single_reexport_target(src: &str) -> Option<&str> {
    // Strip block comments and collapse whitespace just enough to check structure.
    let s = src.trim();
    // Must start with `import ` and contain exactly one statement.
    if !s.starts_with("import ") {
        return None;
    }
    // A bare side-effect import looks like: import 'specifier' or import "specifier"
    // optionally followed by a semicolon and nothing else (modulo whitespace).
    let after_import = s["import".len()..].trim_start();
    let (quote, rest) = match after_import.chars().next()? {
        '\'' => ('\'', &after_import[1..]),
        '"' => ('"', &after_import[1..]),
        _ => return None, // not a bare side-effect import
    };
    let specifier_end = rest.find(quote)?;
    let specifier = &rest[..specifier_end];
    // Verify there is nothing meaningful after the closing quote.
    let tail = rest[specifier_end + 1..]
        .trim()
        .trim_start_matches(';')
        .trim();
    if !tail.is_empty() {
        return None; // more than one statement
    }
    // Only follow relative or absolute-path specifiers; skip bare specifiers
    // (npm package names) that require a module resolver.
    if specifier.starts_with("./") || specifier.starts_with("../") || specifier.starts_with('/') {
        Some(specifier)
    } else {
        None
    }
}

/// Resolve and fetch all script sources, returning a list of executable JS strings.
///
/// Inline scripts are returned as-is and do not count toward `max_remote`.
/// External scripts are resolved and fetched up to `max_remote` times; any
/// beyond the cap are skipped with a `[skip]` message.
fn load_scripts(
    sources: Vec<dom::ScriptSource>,
    page_url: Option<&str>,
    cfg: &HttpConfig,
    budget: &RequestBudget,
    max_remote: Option<usize>,
) -> Vec<String> {
    let mut remote_fetched = 0usize;
    let mut result = Vec::new();
    for s in sources {
        match s {
            dom::ScriptSource::Inline(code) => result.push(code),
            dom::ScriptSource::External(src) => {
                if max_remote.is_some_and(|max| remote_fetched >= max) {
                    if is_verbose() {
                        eprintln!("[skip] --max-scripts limit reached, skipping {src}");
                    }
                    continue;
                }
                let Some(url) = resolve_url(&src, page_url) else {
                    continue;
                };
                if is_verbose() {
                    eprintln!("[fetch] {url}");
                }
                if let Some(code) = fetch_script(&url, cfg, budget) {
                    remote_fetched += 1;
                    result.push(code);
                }
            }
        }
    }
    result
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderOutput {
    pub html: String,
    pub script_result: Option<String>,
}

/// Parse `input`, execute its scripts, and return the rendered HTML.
///
/// `is_js` — when `true`, `input` is treated as a bare JS snippet and wrapped in a
/// minimal HTML document before processing (used for `.js` file inputs).
///
/// `page_url` — the URL the page was fetched from, used for resolving relative script
/// `src` attributes and populating `window.location`.
///
/// Script errors are non-fatal; execution continues with the next script.
/// `console.log/warn/error` output is printed to stderr with a `[console]` prefix.
///
/// When `clean` is `true` a post-processing pass is applied (see [`clean_document`]).
///
/// # Errors
///
/// Returns an error if the JS bootstrap fails to evaluate.
pub fn render(
    input: &str,
    is_js: bool,
    page_url: Option<&str>,
    cfg: &HttpConfig,
    clean: bool,
    max_scripts: Option<usize>,
    script_timeout: Option<Duration>,
) -> anyhow::Result<String> {
    Ok(render_detailed(
        input,
        is_js,
        page_url,
        cfg,
        clean,
        max_scripts,
        script_timeout,
        None,
    )?
    .html)
}

/// Render a page while optionally evaluating one caller-provided script after
/// page lifecycle/timer work has settled. Existing `render` callers remain unchanged.
pub fn render_detailed(
    input: &str,
    is_js: bool,
    page_url: Option<&str>,
    cfg: &HttpConfig,
    clean: bool,
    max_scripts: Option<usize>,
    script_timeout: Option<Duration>,
    final_script: Option<&str>,
) -> anyhow::Result<RenderOutput> {
    let html = if is_js {
        Cow::Owned(format!("<!DOCTYPE html><html><head></head><body><script>{input}</script></body></html>"))
    } else {
        Cow::Borrowed(input)
    };

    let budget = RequestBudget::new(cfg);
    let doc = dom::parse(&html)?;
    let scripts = load_scripts(doc.extract_scripts(), page_url, cfg, &budget, max_scripts);
    let rt = match script_timeout {
        Some(t) => runtime::JsRuntime::with_timeout(t),
        None => runtime::JsRuntime::without_timeout(),
    };
    let script_result = rt.execute_with_final_script(
        &scripts, page_url, cfg, &budget, &html, final_script,
    )?;
    // A skipped lifecycle/Promise continuation is not a completed static preview.
    if budget
        .deadline()
        .is_some_and(|deadline| Instant::now() >= deadline)
    {
        anyhow::bail!("Rakers render deadline exceeded");
    }

    for msg in runtime::JsRuntime::logged_messages() {
        if is_verbose() {
            eprintln!("[console] {msg}");
        }
    }

    let rendered_html = runtime::JsRuntime::body_inner_html();
    let written_html = runtime::JsRuntime::written_html();
    // LinkeDOM owns the entire mutated document, including <head> and <html>.
    let out = dom::inject_written_html(rendered_html, &written_html);
    Ok(RenderOutput {
        html: if clean { clean_document(out) } else { out },
        script_result,
    })
}

/// Strip scripts and unwrap `<noscript>` elements from rendered HTML.
///
/// Intended to produce a static, crawlable snapshot similar to what
/// prerendering services (Prerender.io, rendertron) deliver to bots:
///
/// - `<script>` elements (both inline and `src=`) are removed entirely.
/// - `<link rel="modulepreload">` and `<link rel="preload" as="script">` are removed.
/// - `<noscript>` wrappers are removed but their inner content is kept, so
///   crawlers see any fallback markup (e.g. `<meta>` redirects, image links).
#[must_use]
pub fn clean_document(mut html: String) -> String {
    // Unwrap fallback content first: otherwise a <script> nested in
    // <noscript> is skipped as inert text and survives the cleaning pass.
    html = unwrap_noscript(html);
    html = remove_script_elements(html);
    html = remove_preload_links(html);
    html
}

// The HTML serializer retains literal text inside comments and raw-text
// elements. Fake tags in these regions must not be treated as real markup.
fn in_opaque_html_text(html: &str, before: usize) -> bool {
    let mut cursor = 0;
    while let Some(next) = html[cursor..before].find('<') {
        let start = cursor + next;
        if html[start..].starts_with("<!--") {
            let end = html[start + 4..].find("-->")
                .map(|offset| start + 4 + offset + 3)
                .unwrap_or(html.len());
            if end > before {
                return true;
            }
            cursor = end;
            continue;
        }
        let raw_tag = [
            "style", "textarea", "title", "noscript", "xmp", "iframe", "noembed", "noframes",
            "plaintext",
        ]
        .into_iter()
        .find(|tag| {
            let prefix = format!("<{tag}");
            html[start..].starts_with(&prefix)
                && matches!(
                    html.as_bytes().get(start + prefix.len()),
                    Some(b' ' | b'\t' | b'\n' | b'>' | b'/')
                )
        });
        if let Some(tag) = raw_tag {
            let close = format!("</{tag}>");
            let end = html[start..].find(&close)
                .map(|offset| start + offset + close.len())
                .unwrap_or(html.len());
            if end > before {
                return true;
            }
            cursor = end;
            continue;
        }
        // A '<script>' inside a quoted attribute is not an HTML tag.
        // Skip the whole opening tag, respecting quoted '>' characters.
        let mut quote = None;
        let mut end = start + 1;
        while end < html.len() {
            let byte = html.as_bytes()[end];
            if let Some(active) = quote {
                if byte == active {
                    quote = None;
                }
            } else if byte == b'\'' || byte == b'"' {
                quote = Some(byte);
            } else if byte == b'>' {
                break;
            }
            end += 1;
        }
        if end >= before {
            return true;
        }
        cursor = end + 1;
    }
    false
}

/// Remove actual `<script>…</script>` elements, skipping opaque text.
fn remove_script_elements(mut html: String) -> String {
    const OPEN: &str = "<script";
    const CLOSE: &str = "</script>";
    let mut cursor = 0;
    while let Some(start) = html[cursor..].find(OPEN).map(|index| cursor + index) {
        if in_opaque_html_text(&html, start) {
            cursor = start + OPEN.len();
            continue;
        }
        // Guard against false matches like a hypothetical <scriptures> tag.
        let next = html.as_bytes().get(start + OPEN.len()).copied();
        if !matches!(
            next,
            Some(b' ' | b'\t' | b'\n' | b'\r' | b'>' | b'/') | None
        ) {
            cursor = start + OPEN.len();
            continue;
        }
        let end = html[start..]
            .find(CLOSE)
            .map_or(html.len(), |p| start + p + CLOSE.len());
        html.drain(start..end);
        cursor = start;
    }
    html
}

/// Remove `<link rel="modulepreload">` and `<link rel="preload" as="script">` elements.
fn remove_preload_links(mut html: String) -> String {
    const OPEN: &str = "<link";
    let mut pos = 0;
    while let Some(rel) = html[pos..].find(OPEN).map(|p| p + pos) {
        if in_opaque_html_text(&html, rel) {
            pos = rel + OPEN.len();
            continue;
        }
        let tag_end = match html[rel..].find('>') {
            Some(p) => rel + p + 1,
            None => break,
        };
        let tag = &html[rel..tag_end];
        let is_modulepreload = tag.contains("modulepreload");
        let is_preload_script = tag.contains("preload") && tag.contains("as=\"script\"");
        if is_modulepreload || is_preload_script {
            html.drain(rel..tag_end);
        } else {
            pos = tag_end;
        }
    }
    html
}

/// Remove `<noscript>` and `</noscript>` tags, keeping the content between them.
fn unwrap_noscript(mut html: String) -> String {
    // html5ever always lowercases tag names; no attributes appear on <noscript>.
    let mut cursor = 0;
    #[allow(clippy::while_let_loop)] // two let-else breaks inside; while-let doesn't fit
    loop {
        // Ignore literal tags embedded in comments or raw-text elements.
        let Some(open_start) = html[cursor..].find("<noscript").map(|pos| cursor + pos) else {
            break;
        };
        if in_opaque_html_text(&html, open_start) {
            cursor = open_start + "<noscript".len();
            continue;
        }
        let Some(open_end) = html[open_start..].find('>').map(|p| open_start + p + 1) else {
            break;
        };
        html.drain(open_start..open_end);
        // Remove the matching closing tag (now starts searching from open_start).
        if let Some(close) = html[open_start..]
            .find("</noscript>")
            .map(|p| open_start + p)
        {
            html.drain(close..close + "</noscript>".len());
        }
        cursor = open_start;
    }
    html
}

/// Fetch `url`, execute its scripts, and return the rendered HTML.
///
/// Convenience wrapper around [`render`] that handles the HTTP fetch.
///
/// # Errors
///
/// Returns an error if the HTTP request fails or if script execution fails.
pub fn render_url(url: &str, cfg: &HttpConfig, clean: bool) -> anyhow::Result<String> {
    let mut response = cfg.apply(cfg.agent().get(url)).call()?;
    let body = response.body_mut().read_to_string()?;
    render(
        &body,
        false,
        Some(url),
        cfg,
        clean,
        None,
        Some(Duration::from_secs(30)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_simple(input: &str, is_js: bool, page_url: Option<&str>) -> anyhow::Result<String> {
        render(
            input,
            is_js,
            page_url,
            &HttpConfig::default(),
            false,
            None,
            None,
        )
    }

    struct TestTransport;

    impl HttpTransport for TestTransport {
        fn execute(&self, request: HttpRequest) -> Result<HttpResponse, String> {
            let (status, body) = if request.url.ends_with("/api/data") {
                (200, "payload".to_string())
            } else if request.url.ends_with("/dynamic.js") {
                (200, "document.write('<p>fetched</p>');".to_string())
            } else if request.url.ends_with("/api") {
                (200, r#"{"value":"json-ok"}"#.to_string())
            } else if request.url.ends_with("/missing") {
                (404, "missing".to_string())
            } else {
                return Err(format!("unexpected test URL: {}", request.url));
            };
            Ok(HttpResponse {
                url: request.url,
                status,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body,
            })
        }
    }

    fn test_http_config() -> HttpConfig {
        HttpConfig {
            transport: Some(std::sync::Arc::new(TestTransport)),
            max_requests: Some(16),
            max_response_bytes: Some(64 * 1024),
            render_timeout: Some(Duration::from_secs(2)),
            ..Default::default()
        }
    }

    #[test]
    fn linkedom_native_meta_preserves_escaped_content() {
        let input = concat!(
            "<html><head><meta name=\"viewport\" content=\"line1\nline2\\'\"></head><body>",
            "<script>document.write('<p>' + document.querySelector('meta[name=\"viewport\"]').getAttribute('content') + '</p>');</script>",
            "</body></html>",
        );
        let out = render_simple(input, false, None).unwrap();
        assert!(
            out.contains("<p>line1\nline2\\'</p>"),
            "meta bridge failed: {out}"
        );
    }

    #[test]
    fn cumulative_network_deadline_is_not_a_successful_preview() {
        struct DelayedTransport;
        impl HttpTransport for DelayedTransport {
            fn execute(&self, request: HttpRequest) -> Result<HttpResponse, String> {
                std::thread::sleep(Duration::from_millis(100));
                let body = if request.url.ends_with("/emoji.js") {
                    "var emojiReady = true;"
                } else {
                    "comments-ok"
                };
                Ok(HttpResponse {
                    url: request.url,
                    status: 200,
                    headers: Vec::new(),
                    body: body.to_string(),
                })
            }
        }
        let input = concat!(
            "<html><body><script src='/emoji.js'></script><script>",
            "document.addEventListener('DOMContentLoaded', function() {",
            "fetch('/comments').then(function(r) {return r.text();})",
            ".then(function(text) {document.body.innerHTML = '<p>' + text + '</p>';});",
            "});</script></body></html>",
        );
        for (timeout, succeeds) in [(150, false), (1000, true)] {
            let cfg = HttpConfig {
                transport: Some(Arc::new(DelayedTransport)),
                render_timeout: Some(Duration::from_millis(timeout)),
                ..Default::default()
            };
            let result = render(
                input,
                false,
                Some("https://fixture.invalid/page"),
                &cfg,
                false,
                None,
                None,
            );
            if succeeds {
                assert!(result.unwrap().contains("<p>comments-ok</p>"));
            } else {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("render deadline exceeded")
                );
            }
        }
    }

    #[test]
    fn p0_render_deadline_cannot_preempt_in_flight_transport() {
        struct BlockingTransport(Arc<AtomicUsize>);
        impl HttpTransport for BlockingTransport {
            fn execute(&self, request: HttpRequest) -> Result<HttpResponse, String> {
                self.0.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(200));
                Ok(HttpResponse {
                    url: request.url,
                    status: 200,
                    headers: Vec::new(),
                    body: "ok".to_string(),
                })
            }
        }

        // Exercise the budget directly: no QuickJS startup can consume this
        // deadline before the network request begins.
        let calls = Arc::new(AtomicUsize::new(0));
        let cfg = HttpConfig {
            transport: Some(Arc::new(BlockingTransport(calls.clone()))),
            render_timeout: Some(Duration::from_millis(100)),
            ..Default::default()
        };
        let budget = RequestBudget::new(&cfg);
        let started = Instant::now();
        let error = cfg
            .execute(&budget, "GET", "https://fixture.invalid/slow", &[], None, false)
            .unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            started.elapsed() >= Duration::from_millis(180),
            "blocking transport unexpectedly returned early"
        );
        assert!(error.contains("render deadline exceeded"), "{error}");
    }

    #[test]
    fn html_inline_script_document_write() {
        let input = concat!(
            "<!DOCTYPE html><html><head><title>Test</title></head>",
            "<body><h1>Before</h1>",
            r#"<script>document.write("<p>Hello from JS!</p>"); console.log("done");</script>"#,
            "</body></html>"
        );
        let out = render_simple(input, false, None).unwrap();
        assert!(out.contains("<h1>Before</h1>"), "static content preserved");
        assert!(
            out.contains("<p>Hello from JS!</p>"),
            "document.write injected"
        );
    }

    #[test]
    fn js_file_mode_loop() {
        let js = concat!(
            r#"document.write("<ul>");"#,
            "\n",
            r#"for (let i = 1; i <= 3; i++) { document.write("<li>Item " + i + "</li>"); }"#,
            "\n",
            r#"document.write("</ul>");"#,
            "\n",
            r#"console.log("rendered", 3, "items");"#,
        );
        let out = render_simple(js, true, None).unwrap();
        assert!(out.contains("<li>Item 1</li>"), "first item");
        assert!(out.contains("<li>Item 2</li>"), "second item");
        assert!(out.contains("<li>Item 3</li>"), "third item");
    }

    #[test]
    fn dynamically_appended_script_uses_http_transport() {
        let input = concat!(
            "<!DOCTYPE html><html><head></head><body>",
            "<script>var s = document.createElement('script'); s.src = '/dynamic.js'; document.body.appendChild(s);</script>",
            "</body></html>",
        );
        let cfg = test_http_config();
        let out = render(
            input,
            false,
            Some("https://example.test/page"),
            &cfg,
            false,
            None,
            None,
        )
        .unwrap();
        assert!(
            out.contains("<p>fetched</p>"),
            "dynamic script must use host transport"
        );
    }

    #[test]
    fn console_messages_captured() {
        let js = r#"console.log("hello", "world"); console.warn("oops");"#;
        let rt = runtime::JsRuntime::with_timeout(std::time::Duration::from_secs(30));
        let cfg = HttpConfig::default();
        let budget = RequestBudget::new(&cfg);
        rt.execute(&[js.to_owned()], None, &cfg, &budget).unwrap();
        let msgs = runtime::JsRuntime::logged_messages();
        assert_eq!(msgs[0], "hello world");
        assert_eq!(msgs[1], "oops");
    }

    #[test]
    fn detailed_render_runs_final_script_after_page_lifecycle() {
        let html =
            "<!DOCTYPE html><html><body><script>window.pageRan = true;</script></body></html>";
        let output = render_detailed(
            html,
            false,
            Some("https://example.test/page"),
            &HttpConfig::default(),
            false,
            None,
            None,
            Some("document.body.innerHTML = '<p>' + document.readyState + '</p>'; 'final-ok'"),
        )
        .unwrap();
        assert_eq!(output.script_result.as_deref(), Some("final-ok"));
        assert!(
            output.html.contains("<p>complete</p>"),
            "final script must run after load lifecycle"
        );
    }

    #[test]
    fn document_writeln_adds_newline() {
        let js = r#"document.writeln("line1"); document.writeln("line2");"#;
        let out = render_simple(js, true, None).unwrap();
        assert!(out.contains("line1\nline2\n"), "writeln appends newline");
    }

    #[test]
    fn window_aliases_global() {
        let js = r#"window.document.write("<p>via window</p>");"#;
        let out = render_simple(js, true, None).unwrap();
        assert!(
            out.contains("<p>via window</p>"),
            "window.document.write works"
        );
    }

    #[test]
    fn script_errors_are_non_fatal() {
        let html = concat!(
            "<!DOCTYPE html><html><body>",
            "<script>throw new Error('deliberate');</script>",
            "<script>document.write('<p>survived</p>');</script>",
            "</body></html>"
        );
        let out = render_simple(html, false, None).unwrap();
        assert!(
            out.contains("<p>survived</p>"),
            "rendering continues after script error"
        );
    }

    #[test]
    fn location_href_reflects_page_url() {
        let js = r#"document.write(window.location.href);"#;
        let out = render_simple(js, true, Some("https://example.com/page")).unwrap();
        assert!(
            out.contains("https://example.com/page"),
            "location.href set from page_url"
        );
    }

    #[test]
    fn common_globals_accessible() {
        let js = r#"
            var ua = window.navigator.userAgent;
            var tid = window.setTimeout(function(){}, 100);
            var mq  = window.matchMedia('(max-width: 768px)');
            var mo  = new window.MutationObserver(function(){});
            document.write('<p>' + ua + '</p>');
        "#;
        let out = render_simple(js, true, None).unwrap();
        assert!(out.contains("<p>rakers/"), "navigator.userAgent accessible");
    }

    #[test]
    fn document_create_element_is_accessible() {
        let js = r#"
            var el = document.createElement('div');
            el.className = 'test';
            document.write('<p>' + el.className + '</p>');
        "#;
        let out = render_simple(js, true, None).unwrap();
        assert!(out.contains("<p>test</p>"), "createElement stub works");
    }

    #[test]
    fn settimeout_callback_flushed() {
        let html = concat!(
            "<!DOCTYPE html><html><body>",
            r#"<div id="app"></div>"#,
            "<script>setTimeout(function() {",
            r#"document.getElementById('app').innerHTML = '<h1>Rendered via setTimeout</h1>';"#,
            "}, 0);</script>",
            "</body></html>"
        );
        let out = render_simple(html, false, None).unwrap();
        assert!(
            out.contains("<h1>Rendered via setTimeout</h1>"),
            "setTimeout callback flushed before readback"
        );
    }

    #[test]
    fn virtual_timers_preserve_order_cancellation_and_clock() {
        let js = r#"
            document.body.innerHTML = '';
            var start = Date.now();
            queueMicrotask(function() { document.body.innerHTML += 'micro>'; });
            var cancelled = setTimeout(function() { document.body.innerHTML += 'cancelled>'; }, 5);
            clearTimeout(cancelled);
            setTimeout(function() { document.body.innerHTML += 't1>'; }, 1);
            var count = 0;
            var interval = setInterval(function() {
                count += 1;
                document.body.innerHTML += 'i' + count + '>';
                if (count === 2) clearInterval(interval);
            }, 2);
            setTimeout(function() {
                document.body.innerHTML += 't10:' + performance.now() + ':' + (Date.now() - start);
            }, 10);
        "#;
        let out = render_simple(js, true, None).unwrap();
        assert!(
            out.contains("micro&gt;t1&gt;i1&gt;i2&gt;t10:10:10")
                || out.contains("micro>t1>i1>i2>t10:10:10"),
            "virtual timers must preserve deadline order and virtual clock: {out}"
        );
        assert!(!out.contains("cancelled"));
    }

    #[test]
    fn timer_microtasks_run_before_the_next_timer_task() {
        let js = r#"
            document.body.innerHTML = '';
            setTimeout(function() {
                document.body.innerHTML += 'first>';
                Promise.resolve().then(function() { document.body.innerHTML += 'micro>'; });
            }, 0);
            setTimeout(function() { document.body.innerHTML += 'second'; }, 0);
        "#;
        let out = render_simple(js, true, None).unwrap();
        assert!(
            out.contains("first&gt;micro&gt;second") || out.contains("first>micro>second"),
            "microtasks from one timer must drain before the next timer: {out}"
        );
    }

    #[test]
    fn long_timer_is_outside_render_horizon() {
        let js = r#"
            document.body.innerHTML = 'ready';
            setTimeout(function() { document.body.innerHTML = 'too-late'; }, 5000);
        "#;
        let out = render_simple(js, true, None).unwrap();
        assert!(out.contains("ready"));
        assert!(!out.contains("too-late"));
    }

    #[test]
    fn document_and_window_lifecycle_events_fire_once() {
        let js = r#"
            document.body.innerHTML = 'start:' + document.readyState + '>';
            document.addEventListener('DOMContentLoaded', function() {
                document.body.innerHTML += 'dom:' + document.readyState + '>';
            });
            window.addEventListener('load', function() {
                document.body.innerHTML += 'load:' + document.readyState;
            });
        "#;
        let out = render_simple(js, true, None).unwrap();
        assert!(
            out.contains("start:loading&gt;dom:interactive&gt;load:complete")
                || out.contains("start:loading>dom:interactive>load:complete")
        );
    }

    #[test]
    fn navigator_uses_configured_user_agent() {
        let cfg = HttpConfig {
            user_agent: Some("reader-rust-test/1.0".to_string()),
            ..Default::default()
        };
        let out = render(
            "document.body.innerHTML = navigator.userAgent;",
            true,
            None,
            &cfg,
            false,
            None,
            None,
        )
        .unwrap();
        assert!(out.contains("reader-rust-test/1.0"));
    }

    #[test]
    fn browser_bootstrap_uses_runtime_values_without_leaking_inputs() {
        let ua = "reader-rust/\"\\test\n\u{2028}__HREF__";
        let page_url = "https://example.test/path?marker=__USER_AGENT__";
        let cfg = HttpConfig {
            user_agent: Some(ua.to_string()),
            ..Default::default()
        };
        let output = render_detailed(
            "<html><body><main>hello</main></body></html>",
            false,
            Some(page_url),
            &cfg,
            false,
            None,
            None,
            Some("JSON.stringify([location.href,navigator.userAgent,typeof globalThis.__r_initial_href,typeof globalThis.__r_initial_ua])"),
        ).unwrap();
        let values: Vec<String> = serde_json::from_str(output.script_result.as_deref().unwrap()).unwrap();
        assert_eq!(values, vec![page_url, ua, "undefined", "undefined"]);
    }

    #[test]
    fn linkedom_initialization_preserves_large_html_string_values() {
        let content = "中文😀\"\\\u{2028}\n".repeat(1024);
        let html = format!("<html><body><main id=\"payload\">{content}</main></body></html>");
        let output = render_detailed(
            &html,
            false,
            None,
            &HttpConfig::default(),
            false,
            None,
            None,
            Some("document.getElementById('payload').textContent"),
        ).unwrap();
        assert_eq!(output.script_result.as_deref(), Some(content.as_str()));
    }

    #[test]
    fn body_inner_html_set_directly() {
        let js = r#"document.body.innerHTML = '<h1>Set directly</h1>';"#;
        let out = render_simple(js, true, None).unwrap();
        assert!(
            out.contains("<h1>Set directly</h1>"),
            "body.innerHTML = '...' captured"
        );
    }

    #[test]
    fn append_child_to_body() {
        let js = r#"
            var h1 = document.createElement('h1');
            h1.innerHTML = 'Appended';
            document.body.appendChild(h1);
        "#;
        let out = render_simple(js, true, None).unwrap();
        assert!(
            out.contains("<h1>Appended</h1>"),
            "appendChild serialized into output"
        );
    }

    #[test]
    fn nested_elements_serialized() {
        let js = r#"
            var ul = document.createElement('ul');
            for (var i = 1; i <= 3; i++) {
                var li = document.createElement('li');
                li.innerHTML = 'Item ' + i;
                ul.appendChild(li);
            }
            document.body.appendChild(ul);
        "#;
        let out = render_simple(js, true, None).unwrap();
        assert!(out.contains("<li>Item 1</li>"), "nested li 1");
        assert!(out.contains("<li>Item 3</li>"), "nested li 3");
    }

    #[test]
    fn get_element_by_id_content_with_append() {
        let js = r#"
            var app = document.getElementById('app');
            app.innerHTML = '<p>App content</p>';
            document.body.appendChild(app);
        "#;
        let out = render_simple(js, true, None).unwrap();
        assert!(
            out.contains("<p>App content</p>"),
            "getElementById + appendChild captured"
        );
    }

    #[test]
    fn clean_removes_scripts_and_unwraps_noscript() {
        let html = concat!(
            "<!DOCTYPE html><html><head>",
            r#"<link rel="modulepreload" href="/bundle.js">"#,
            r#"<link rel="preload" as="script" href="/chunk.js">"#,
            r#"<link rel="stylesheet" href="/style.css">"#, // must be kept
            "</head><body>",
            "<h1>Hello</h1>",
            r#"<script src="/app.js"></script>"#,
            "<script>var x = 1;</script>",
            "<noscript><p>JS required</p></noscript>",
            "</body></html>",
        );
        let out = render(html, false, None, &HttpConfig::default(), true, None, None).unwrap();
        assert!(!out.contains("<script"), "script tags removed");
        assert!(!out.contains("modulepreload"), "modulepreload link removed");
        assert!(
            !out.contains(r#"as="script""#),
            "preload-script link removed"
        );
        assert!(
            out.contains(r#"rel="stylesheet""#),
            "stylesheet link preserved"
        );
        assert!(!out.contains("<noscript"), "noscript tags removed");
        assert!(
            out.contains("<p>JS required</p>"),
            "noscript content preserved"
        );
        assert!(out.contains("<h1>Hello</h1>"), "regular content preserved");
    }

    #[test]
    fn clean_keeps_markup_examples_in_comments_and_raw_text() {
        let html = concat!(
            r#"<html><head><style>.x::before{content:'<script>fake'}</style></head><body>"#,
            r#"<!-- <style>example <script>example <link rel="modulepreload"> <noscript> -->"#,
            "<textarea><script>example</script></textarea>",
            r#"<p id="catalog">Chapter One</p>"#,
            "<script>var remove_me = 1;</script>",
            "<noscript><p>Backup</p></noscript>",
            "</body></html>",
        );
        let out = clean_document(html.to_string());
        assert!(out.contains(r#"<p id="catalog">Chapter One</p>"#), "{out}");
        assert!(out.contains("<!-- <style>example <script>example"), "{out}");
        assert!(out.contains(r#"<style>.x::before{content:'<script>fake'}</style>"#), "{out}");
        assert!(out.contains("<textarea><script>example</script></textarea>"), "{out}");
        assert!(!out.contains("remove_me"), "{out}");
        assert!(out.contains("<p>Backup</p>"), "{out}");
        assert!(!out.contains("<noscript><p>Backup</p></noscript>"), "{out}");
    }

    #[test]
    fn clean_removes_scripts_from_unwrapped_noscript() {
        let html = r#"<html><body><noscript><script>inert_call()</script><p>Fallback chapter</p></noscript></body></html>"#;
        let out = clean_document(html.to_owned());
        assert!(out.contains("<p>Fallback chapter</p>"), "{out}");
        assert!(!out.contains("<script"), "{out}");
        assert!(!out.contains("<noscript"), "{out}");
    }

    #[test]
    fn clean_does_not_remove_fake_tags_inside_attributes() {
        let html = concat!(
            r#"<html><body><div data-html='<script>example</script>' "#,
            r#"title='<link rel="modulepreload">' "#,
            r#"data-example='<noscript>literal</noscript>'>"#,
            r#"<p id="catalog">Chapter One</p></div>"#,
            "<script>var remove_me = 1;</script></body></html>",
        );
        let out = clean_document(html.to_owned());
        assert!(out.contains(r#"data-html='<script>example</script>'"#), "{out}");
        assert!(out.contains(r#"title='<link rel="modulepreload">'"#), "{out}");
        assert!(out.contains(r#"data-example='<noscript>literal</noscript>'"#), "{out}");
        assert!(out.contains(r#"<p id="catalog">Chapter One</p>"#), "{out}");
        assert!(!out.contains("remove_me"), "{out}");
    }

    #[test]
    fn script_timeout_is_non_fatal() {
        // An infinite loop must be interrupted; the next script must still run.
        let rt = runtime::JsRuntime::with_timeout(std::time::Duration::from_millis(100));
        let cfg = HttpConfig::default();
        let budget = RequestBudget::new(&cfg);
        rt.execute(
            &[
                "while(true){}".to_owned(),
                "document.write('<p>survived</p>');".to_owned(),
            ],
            None,
            &cfg,
            &budget,
        )
        .unwrap();
        assert!(
            runtime::JsRuntime::written_html().contains("<p>survived</p>"),
            "second script must run after timeout interrupts the first"
        );
    }

    #[test]
    fn promise_callback_timeout_is_non_fatal() {
        // Pending Promise jobs must obey the same interrupt deadline as scripts.
        let rt = runtime::JsRuntime::with_timeout(std::time::Duration::from_millis(100));
        let cfg = HttpConfig::default();
        let budget = RequestBudget::new(&cfg);
        rt.execute(
            &[
                "Promise.resolve().then(function(){ while(true){} });".to_owned(),
                "document.write('<p>survived-job</p>');".to_owned(),
            ],
            None,
            &cfg,
            &budget,
        )
        .unwrap();
        assert!(
            runtime::JsRuntime::written_html().contains("<p>survived-job</p>"),
            "second script must run after a pending job is interrupted"
        );
    }

    #[test]
    fn to_json_fields() {
        let out = to_json(100, "<h1>hi</h1>");
        assert!(out.contains("\"raw_bytes\": 100"), "raw_bytes field");
        assert!(
            out.contains("\"rendered_bytes\": 11"),
            "rendered_bytes field"
        );
        assert!(out.contains("\"html\""), "html field present");
        assert!(out.contains("<h1>hi</h1>"), "html content");
    }

    #[test]
    fn to_json_escapes_special_chars() {
        let out = to_json(0, "say \"hello\"\nline2\\end");
        assert!(
            out.contains(r#"say \"hello\"\nline2\\end"#),
            "quotes, newline, backslash escaped: {out}"
        );
    }

    #[test]
    fn fetch_get_resolves_real_body() {
        let js = concat!(
            "window.fetch('/api/data')",
            ".then(function(r){ return r.text(); })",
            ".then(function(t){ document.write('<p>' + t + '</p>'); });",
        );
        let cfg = test_http_config();
        let out = render(
            js,
            true,
            Some("https://example.test/page"),
            &cfg,
            false,
            None,
            None,
        )
        .unwrap();
        assert!(
            out.contains("<p>payload</p>"),
            "real fetch body must hydrate, got: {out}"
        );
    }

    #[test]
    fn fetch_json_resolves_real_body() {
        let js = concat!(
            "window.fetch('/api').then(function(r){ return r.json(); })",
            ".then(function(d){ document.write('<p>' + d.value + '</p>'); });",
        );
        let cfg = test_http_config();
        let out = render(
            js,
            true,
            Some("https://example.test/page"),
            &cfg,
            false,
            None,
            None,
        )
        .unwrap();
        assert!(
            out.contains("<p>json-ok</p>"),
            "fetch.json() must use response body, got: {out}"
        );
    }

    #[test]
    fn fetch_transport_failure_rejects() {
        let js = concat!(
            "window.fetch('/network-fail')",
            ".then(function(){ document.write('<p>unexpected</p>'); })",
            ".catch(function(){ document.write('<p>rejected</p>'); });",
        );
        let cfg = test_http_config();
        let out = render(
            js,
            true,
            Some("https://example.test/page"),
            &cfg,
            false,
            None,
            None,
        )
        .unwrap();
        assert!(
            out.contains("<p>rejected</p>"),
            "transport failures must reject fetch, got: {out}"
        );
        assert!(!out.contains("<p>unexpected</p>"));
    }

    #[test]
    fn fetch_http_error_resolves_with_real_status() {
        let js = concat!(
            "window.fetch('/missing')",
            ".then(function(r){ document.write('<p>' + r.status + ':' + r.ok + '</p>'); })",
            ".catch(function(){ document.write('<p>rejected</p>'); });",
        );
        let cfg = test_http_config();
        let out = render(
            js,
            true,
            Some("https://example.test/page"),
            &cfg,
            false,
            None,
            None,
        )
        .unwrap();
        assert!(
            out.contains("<p>404:false</p>"),
            "HTTP errors must resolve as responses, got: {out}"
        );
        assert!(!out.contains("<p>rejected</p>"));
    }

    #[test]
    fn fetch_request_limit_rejects_cleanly() {
        let js = concat!(
            "window.fetch('/api/data');",
            "window.fetch('/api').catch(function(e){ document.write('<p>limited</p>'); });",
        );
        let mut cfg = test_http_config();
        cfg.max_requests = Some(1);
        let out = render(
            js,
            true,
            Some("https://example.test/page"),
            &cfg,
            false,
            None,
            None,
        )
        .unwrap();
        assert!(
            out.contains("<p>limited</p>"),
            "request budget must reject excess fetches, got: {out}"
        );
    }

    #[test]
    fn fetch_response_limit_rejects_cleanly() {
        let js = concat!(
            "window.fetch('/api/data')",
            ".then(function(){ document.write('<p>unexpected</p>'); })",
            ".catch(function(){ document.write('<p>too-large</p>'); });",
        );
        let mut cfg = test_http_config();
        cfg.max_response_bytes = Some(3);
        let out = render(
            js,
            true,
            Some("https://example.test/page"),
            &cfg,
            false,
            None,
            None,
        )
        .unwrap();
        assert!(
            out.contains("<p>too-large</p>"),
            "response limit must reject fetch, got: {out}"
        );
        assert!(!out.contains("<p>unexpected</p>"));
    }

    #[test]
    fn render_deadline_bounds_self_replenishing_microtasks() {
        let js = concat!(
            "Promise.resolve().then(function again(){ Promise.resolve().then(again); });",
            "document.write('<p>started</p>');",
        );
        let cfg = HttpConfig {
            render_timeout: Some(Duration::from_millis(20)),
            ..Default::default()
        };
        let started = Instant::now();
        let error = render(js, true, None, &cfg, false, None, None).unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "microtask loop escaped render budget"
        );
        assert!(error.to_string().contains("render deadline exceeded"));
    }

    #[test]
    fn xhr_async_fires_onload_with_real_response() {
        let js = concat!(
            "var xhr = new XMLHttpRequest();",
            "xhr.open('GET', '/api/data');",
            "xhr.onload = function() { document.write('<p>' + xhr.status + ':' + xhr.responseText + ':' + xhr.getResponseHeader('content-type') + '</p>'); };",
            "xhr.send();",
        );
        let cfg = test_http_config();
        let out = render(
            js,
            true,
            Some("https://example.test/page"),
            &cfg,
            false,
            None,
            None,
        )
        .unwrap();
        assert!(
            out.contains("<p>200:payload:application/json</p>"),
            "XHR must expose real response/status/headers, got: {out}"
        );
    }

    #[test]
    fn xhr_addeventlistener_load_fires() {
        let js = concat!(
            "var xhr = new XMLHttpRequest();",
            "xhr.open('GET', '/api');",
            "xhr.addEventListener('load', function() { document.write('<p>xhr-addev-ok</p>'); });",
            "xhr.send();",
        );
        let cfg = test_http_config();
        let out = render(
            js,
            true,
            Some("https://example.test/page"),
            &cfg,
            false,
            None,
            None,
        )
        .unwrap();
        assert!(
            out.contains("<p>xhr-addev-ok</p>"),
            "XHR load listener must fire, got: {out}"
        );
    }

    #[test]
    fn location_pathname_reflects_page_url() {
        let js = r#"document.write(window.location.pathname)"#;
        let out = render(
            js,
            true,
            Some("https://example.com/foo/bar"),
            &HttpConfig::default(),
            false,
            None,
            None,
        )
        .unwrap();
        assert!(
            out.contains("/foo/bar"),
            "pathname should be /foo/bar, got: {out}"
        );
    }

    #[test]
    fn location_fields_parsed_from_url() {
        let js = concat!(
            "document.write(window.location.protocol + '|');",
            "document.write(window.location.hostname + '|');",
            "document.write(window.location.pathname + '|');",
            "document.write(window.location.search + '|');",
            "document.write(window.location.hash);",
        );
        let out = render(
            js,
            true,
            Some("https://example.com/path?q=1#sec"),
            &HttpConfig::default(),
            false,
            None,
            None,
        )
        .unwrap();
        assert!(out.contains("https:|"), "protocol wrong: {out}");
        assert!(out.contains("example.com|"), "hostname wrong: {out}");
        assert!(out.contains("/path|"), "pathname wrong: {out}");
        assert!(out.contains("?q=1|"), "search wrong: {out}");
        assert!(out.contains("#sec"), "hash wrong: {out}");
    }

    #[test]
    fn location_defaults_when_no_url() {
        let js = r#"document.write(window.location.href)"#;
        let out = render(js, true, None, &HttpConfig::default(), false, None, None).unwrap();
        assert!(
            out.contains("about:blank"),
            "href should be about:blank when no URL given, got: {out}"
        );
    }

    #[test]
    fn history_state_updated_by_push() {
        let js = concat!(
            "window.history.pushState({page:1}, '');",
            "document.write(JSON.stringify(window.history.state));",
        );
        let out = render(js, true, None, &HttpConfig::default(), false, None, None).unwrap();
        assert!(
            out.contains(r#""page""#) && out.contains('1'.to_string().as_str()),
            "history.state should reflect pushed state, got: {out}"
        );
    }

    #[test]
    fn single_reexport_target_detects_shim() {
        assert_eq!(
            single_reexport_target("import './bundle.js'"),
            Some("./bundle.js")
        );
        assert_eq!(
            single_reexport_target("import \"../dist/app.js\";"),
            Some("../dist/app.js")
        );
        assert_eq!(
            single_reexport_target("import '/assets/main.js'\n"),
            Some("/assets/main.js")
        );
        // Multiple statements — not a shim
        assert_eq!(
            single_reexport_target("import './a.js'\nimport './b.js'"),
            None
        );
        // Named import — not a bare side-effect import
        assert_eq!(
            single_reexport_target("import { foo } from './lib.js'"),
            None
        );
        // Bare specifier (npm package) — don't follow
        assert_eq!(single_reexport_target("import 'react'"), None);
        // Regular IIFE bundle — not a module
        assert_eq!(single_reexport_target("(function(){ var x = 1; })()"), None);
    }

    #[test]
    fn proxy_config_does_not_break_inline_rendering() {
        let cfg = HttpConfig {
            proxy: Some("socks5://127.0.0.1:9050".to_owned()),
            ..Default::default()
        };
        let html = r#"<html><body><script>document.write('<p>ok</p>');</script></body></html>"#;
        let out = render(html, false, None, &cfg, false, None, None).unwrap();
        assert!(
            out.contains("<p>ok</p>"),
            "inline script renders with proxy configured"
        );
    }

    #[test]
    fn proxy_fetch_failure_is_non_fatal() {
        // Port 1 is reserved and will always refuse the connection immediately.
        let cfg = HttpConfig {
            proxy: Some("socks5://127.0.0.1:1".to_owned()),
            ..Default::default()
        };
        // A script that tries to XHR-load an external URL; the fetch will fail
        // through the dead proxy but the render should complete without panicking.
        let html = concat!(
            "<html><body><script>",
            "var x = new XMLHttpRequest();",
            "x.open('GET','http://example.com/data.json',false);",
            "try { x.send(); } catch(e) {}",
            "document.write('<p>done</p>');",
            "</script></body></html>"
        );
        let out = render(html, false, None, &cfg, false, None, None).unwrap();
        assert!(
            out.contains("<p>done</p>"),
            "render completes despite proxy failure"
        );
    }
}
