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

use std::cell::Cell;
use std::time::Duration;

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

/// HTTP options applied to every outbound request made by rakers.
#[derive(Default, Clone)]
pub struct HttpConfig {
    /// Value for the `User-Agent` header. `None` sends no `User-Agent`.
    pub user_agent: Option<String>,
    /// Additional headers sent with every request, in `(name, value)` form.
    pub headers: Vec<(String, String)>,
    /// Optional proxy URL. Supports SOCKS5 (`socks5://`), SOCKS4 (`socks4://`),
    /// and HTTP (`http://`) proxies. Use `socks5://127.0.0.1:9050` for Tor.
    pub proxy: Option<String>,
    /// When `true`, custom `-H` headers are also forwarded on XHR requests
    /// the page's JavaScript initiates. Defaults to `false` to avoid leaking
    /// credentials to cross-origin destinations controlled by page scripts.
    pub forward_headers: bool,
}

impl HttpConfig {
    /// Build a `ureq` agent with proxy configured (if any).
    #[must_use]
    pub fn agent(&self) -> ureq::Agent {
        let mut builder = ureq::Agent::config_builder()
            .http_status_as_error(true)
            .max_redirects(5)
            .timeout_global(Some(Duration::from_secs(8)))
            .timeout_connect(Some(Duration::from_secs(3)));
        if let Some(ref proxy_url) = self.proxy {
            match ureq::Proxy::new(proxy_url) {
                Ok(proxy) => {
                    builder = builder.proxy(Some(proxy));
                }
                Err(e) => {
                    eprintln!("[proxy error] {proxy_url}: {e}");
                }
            }
        }
        ureq::Agent::new_with_config(builder.build())
    }

    /// Apply configured headers to a ureq 3 request builder.
    pub fn apply<B>(&self, mut req: ureq::RequestBuilder<B>) -> ureq::RequestBuilder<B> {
        if let Some(ua) = &self.user_agent {
            req = req.header("User-Agent", ua);
        }
        for (name, value) in &self.headers {
            req = req.header(name, value);
        }
        req
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
fn fetch_script(url: &str, cfg: &HttpConfig) -> Option<String> {
    let body = match cfg.apply(cfg.agent().get(url)).call() {
        Ok(mut response) => response.body_mut().read_to_string().ok()?,
        Err(e) => {
            eprintln!("[fetch error] {url}: {e}");
            return None;
        }
    };
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
            return fetch_script(&resolved, cfg);
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
                if let Some(code) = fetch_script(&url, cfg) {
                    remote_fetched += 1;
                    result.push(code);
                }
            }
        }
    }
    result
}

/// Build a JS snippet that declares `_r_meta`, exposing all `<meta name=… content=…>`
/// elements so `document.querySelector('meta[name="X"]')` can look them up.
fn build_meta_script(meta: &std::collections::HashMap<String, String>) -> String {
    if meta.is_empty() {
        return String::new();
    }
    let mut out = String::from("var _r_meta = {");
    for (name, content) in meta {
        let name_esc = name.replace('\\', "\\\\").replace('\'', "\\'");
        let content_esc = content.replace('\\', "\\\\").replace('\'', "\\'");
        out.push_str(&format!(
            "'{name_esc}':{{name:'{name_esc}',content:'{content_esc}',\\\
            getAttribute:function(n){{return n==='content'?this.content:n==='name'?this.name:null;}},\\\
            hasAttribute:function(n){{return n==='content'||n==='name';}}}},",
        ));
    }
    out.push_str("};");
    out
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
    let html = if is_js {
        format!("<!DOCTYPE html><html><head></head><body><script>{input}</script></body></html>")
    } else {
        input.to_owned()
    };

    let doc = dom::parse(&html)?;
    let meta_script = build_meta_script(&doc.collect_meta());
    let mut scripts = load_scripts(doc.extract_scripts(), page_url, cfg, max_scripts);
    if !meta_script.is_empty() {
        scripts.insert(0, meta_script);
    }

    let rt = match script_timeout {
        Some(t) => runtime::JsRuntime::with_timeout(t),
        None => runtime::JsRuntime::without_timeout(),
    };
    rt.execute(&scripts, page_url, cfg)?;

    for msg in runtime::JsRuntime::logged_messages() {
        if is_verbose() {
            eprintln!("[console] {msg}");
        }
    }

    let body_html = runtime::JsRuntime::body_inner_html();

    // Avoid clobbering large server-rendered bodies (SSR sites) with a tiny JS DOM
    // result (e.g. a measurement div appended for scrollbar detection).
    // Only substitute the body when either:
    //   a) the raw HTML body was small (SPA skeleton, unit-test wrapper, bare JS mode), or
    //   b) the JS body is at least half the size of the server body (JS rendered real content).
    let raw_body_len = raw_body_content_len(&html);
    let effective_body = if raw_body_len < 512 || body_html.len() * 2 >= raw_body_len {
        body_html.as_str()
    } else {
        ""
    };

    let out =
        doc.serialize_with_body_and_injection(effective_body, &runtime::JsRuntime::written_html())?;
    Ok(if clean { clean_document(out) } else { out })
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
    html = remove_script_elements(html);
    html = remove_preload_links(html);
    html = unwrap_noscript(html);
    html
}

/// Remove all `<script>…</script>` elements.
fn remove_script_elements(mut html: String) -> String {
    const OPEN: &str = "<script";
    const CLOSE: &str = "</script>";
    while let Some(start) = html.find(OPEN) {
        // Guard against false matches like a hypothetical <scriptures> tag.
        let next = html.as_bytes().get(start + OPEN.len()).copied();
        if !matches!(
            next,
            Some(b' ' | b'\t' | b'\n' | b'\r' | b'>' | b'/') | None
        ) {
            break;
        }
        let end = html[start..]
            .find(CLOSE)
            .map_or(html.len(), |p| start + p + CLOSE.len());
        html.drain(start..end);
    }
    html
}

/// Remove `<link rel="modulepreload">` and `<link rel="preload" as="script">` elements.
fn remove_preload_links(mut html: String) -> String {
    const OPEN: &str = "<link";
    let mut pos = 0;
    while let Some(rel) = html[pos..].find(OPEN).map(|p| p + pos) {
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
    #[allow(clippy::while_let_loop)] // two let-else breaks inside; while-let doesn't fit
    loop {
        // Remove opening tag (may have no attributes, so just "<noscript>")
        let Some(open_start) = html.find("<noscript") else {
            break;
        };
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
    }
    html
}

/// Return the byte length of the content inside `<body>...</body>`, excluding the tags.
///
/// Used by [`render`] to decide whether the JS-rendered body is substantial enough to
/// replace the server-rendered body (SSR heuristic).
fn raw_body_content_len(html: &str) -> usize {
    let body_start = html.find("<body").unwrap_or(0);
    let content_start = html[body_start..]
        .find('>')
        .map_or(0, |i| i + body_start + 1);
    let body_end = html.rfind("</body>").unwrap_or(html.len());
    let body = &html[content_start.min(body_end)..body_end];
    // Exclude <script> tags so SPAs with many script src= references aren't
    // mistaken for large server-rendered pages.
    let mut len = body.len();
    let mut rest = body;
    while let Some(s) = rest.find("<script") {
        let end = rest[s..]
            .find("</script>")
            .map(|e| s + e + 9)
            .or_else(|| rest[s..].find("/>").map(|e| s + e + 2))
            .unwrap_or(rest.len());
        len -= end - s;
        rest = &rest[end.min(rest.len())..];
    }
    len
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
