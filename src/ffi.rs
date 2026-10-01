use crate::executor;
use crate::model::book_source::book_source_from_value;
use crate::model::replace_rule::ReplaceRule;
use crate::model::search::SearchBook;
use crate::parser::js::eval_js;
use crate::parser::rule_engine::{apply_legado_regex, RuleEngine};
use safer_ffi::prelude::*;
use serde_json::{json, Value};

const MAX_RAKERS_EVAL_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_RAKERS_EVAL_HTML_BYTES: usize = 8 * 1024 * 1024;
const RAKERS_EVAL_MAX_REMOTE_SCRIPTS: usize = 8;
const DEFAULT_RAKERS_EVAL_TIMEOUT_MS: u64 = 15_000;
const MAX_RAKERS_EVAL_TIMEOUT_MS: u64 = 120_000;
const MAX_RAKERS_EVAL_REDIRECTS: usize = 5;

#[derive(Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RakersEvalRequest {
    url: Option<String>,
    html: Option<String>,
    base_url: Option<String>,
    method: Option<String>,
    headers: Option<Value>,
    #[serde(alias = "cookie")]
    cookies: Option<Value>,
    #[serde(alias = "source", alias = "data")]
    body: Option<String>,
    proxy: Option<String>,
    /// Seconds, matching the common LuaSocket/KOReader timeout unit.
    timeout: Option<u64>,
    timeout_ms: Option<u64>,
    redirect: Option<bool>,
    #[serde(alias = "maxredirects")]
    max_redirects: Option<usize>,
    charset: Option<String>,
}

/// 释放所有 `reader_*` 返回给 C/Lua 的字符串。每个非空指针必须且只能释放一次。
#[ffi_export]
pub fn reader_free_string(value: Option<char_p::Box>) {
    drop(value);
}

/// 通用规则/求值/清洗/微指令入口。该函数保持 ABI v1 已有语义，但不承担书源抓取。
#[ffi_export]
pub fn reader_eval(input: char_p::Ref<'_>, rule: char_p::Ref<'_>) -> char_p::Box {
    let input = input.to_str();
    let rule = rule.to_str().trim();
    if crate::host_services::in_callback() {
        return ffi_string(
            json!({"error":"host callbacks cannot re-enter reader_eval"}).to_string(),
        );
    }
    if rule == "@debug_parse" {
        return debug_parse_request(input);
    }
    if rule == "@http_request" {
        return eval_http_request(input);
    }
    if rule == "@rakers_render" {
        return rakers_render_request(input);
    }
    if rule == "@host_call" {
        let result = match serde_json::from_str::<Value>(input) {
            Ok(request) => match request.get("operation").and_then(Value::as_str) {
                Some(operation) => crate::host_services::call(
                    operation,
                    request.get("arguments").unwrap_or(&Value::Null),
                ),
                None => {
                    json!({"ok":false,"error":{"kind":"invalid_argument","message":"operation is required"}})
                }
            },
            Err(_) => {
                json!({"ok":false,"error":{"kind":"invalid_argument","message":"invalid host request JSON"}})
            }
        };
        return ffi_string(result.to_string());
    }

    if rule == "@version" {
        return ffi_string(env!("CARGO_PKG_VERSION").to_string());
    }
    if rule == "@uuid" {
        return ffi_string(uuid::Uuid::new_v4().to_string());
    }
    if rule == "@android_id" {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let id = (0..16)
            .map(|_| format!("{:x}", rng.gen_range(0..16)))
            .collect();
        return ffi_string(id);
    }
    if rule == "@encode" {
        return ffi_string(urlencoding::encode(input).into_owned());
    }
    if rule == "@decode" {
        return ffi_string(
            urlencoding::decode(input)
                .map(|value| value.into_owned())
                .unwrap_or_default(),
        );
    }
    if rule == "@clean" {
        return ffi_string(crate::parser::html::clean_html(input));
    }
    if rule == "@text" {
        return ffi_string(crate::parser::html::html_to_text(input));
    }
    if rule == "@merge" {
        return ffi_string(merge_search_results(input));
    }
    if rule == "@validate" {
        return ffi_string(validate_source(input));
    }

    if rule.contains(" -") || rule.starts_with('-') {
        let parts = rule.split(" -").collect::<Vec<_>>();
        let target_rule = parts.first().copied().unwrap_or_default().trim();
        let mut output = if !target_rule.is_empty() && !target_rule.starts_with('-') {
            let document = crate::parser::html::parse_document(input);
            crate::parser::html::select_text(&document, &format!("{target_rule}@outerHtml"))
                .unwrap_or_else(|| input.to_string())
        } else {
            input.to_string()
        };
        for excluded in parts
            .iter()
            .skip(if target_rule.starts_with('-') { 0 } else { 1 })
        {
            let excluded = excluded.trim().trim_start_matches('-').trim();
            if !excluded.is_empty() {
                output = apply_legado_regex(&output, excluded);
            }
        }
        return ffi_string(output);
    }

    if rule.starts_with("##") {
        return ffi_string(apply_legado_regex(input, rule));
    }
    if rule.starts_with('[') {
        return ffi_string(apply_replace_rules(input, rule));
    }
    if let Some(script) = strip_js_prefix(rule) {
        return ffi_string(
            eval_js(script, input, "")
                .unwrap_or_else(|error| format!(r#"{{"error":"JS Eval Failed: {error}"}}"#)),
        );
    }
    if rule.starts_with("//") {
        let results = crate::parser::html::select_xpath(input, rule);
        return ffi_string(serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string()));
    }

    let document = crate::parser::html::parse_document(input);
    let results = crate::parser::html::select_text_list(&document, rule);
    ffi_string(serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string()))
}

/// ABI v2 书源业务入口：SO 自行完成 URL 规则、HTTP、Cookie、分页和解析。
#[ffi_export]
pub fn reader_execute(source_json: char_p::Ref<'_>, request_json: char_p::Ref<'_>) -> char_p::Box {
    if crate::host_services::in_callback() {
        return ffi_string(json!({"ok":false,"error":{"kind":"host_reentrant","message":"host callbacks cannot re-enter reader_execute"}}).to_string());
    }
    ffi_string(executor::execute(
        source_json.to_str(),
        request_json.to_str(),
    ))
}

/// Register services in this thread/process. NULL unregisters; host owns pointers.
/// Returns 0 on success, -1 for invalid configuration, -2 during a host callback.
#[ffi_export]
/// # Safety
/// The host must keep callback/user_data alive until unregistering and obey the
/// callback's buffer, same-thread and non-unwinding contract.
pub unsafe fn reader_set_host_services(
    services: Option<&crate::host_services::ReaderHostServices>,
) -> i32 {
    unsafe { crate::host_services::set(services) }
}

fn rakers_render_request(input: &str) -> char_p::Box {
    if input.len() > MAX_RAKERS_EVAL_JSON_BYTES {
        return rakers_eval_error("Rakers render input exceeds 16 MiB");
    }
    let request = match parse_rakers_eval_request(input) {
        Ok(request) => request,
        Err(error) => return rakers_eval_error(&error),
    };

    let rendered = match (request.url.as_deref(), request.html.as_deref()) {
        (Some(_), Some(_)) => return rakers_eval_error("provide either url or html, not both"),
        (Some(url), None) => match fetch_and_render_rakers_url(url, &request) {
            Ok(rendered) => rendered,
            Err(error) => return rakers_eval_error(&error),
        },
        (None, Some(html)) => {
            if request.method.is_some()
                || request.headers.is_some()
                || request.cookies.is_some()
                || request.body.is_some()
                || request.proxy.is_some()
                || request.timeout.is_some()
                || request.timeout_ms.is_some()
                || request.redirect.is_some()
                || request.max_redirects.is_some()
                || request.charset.is_some()
            {
                return rakers_eval_error("HTTP request options require url input");
            }
            let base_url = match request.base_url.as_deref() {
                Some(raw_url) => match validate_rakers_http_url(raw_url) {
                    Ok(url) => Some(url),
                    Err(error) => return rakers_eval_error(&error),
                },
                None => None,
            };
            match render_rakers_html(html, base_url.as_ref().map(url::Url::as_str), None, None) {
                Ok(rendered) => rendered,
                Err(error) => return rakers_eval_error(&error),
            }
        }
        (None, None) => return rakers_eval_error("request must contain url or html"),
    };

    ffi_string(rendered)
}

fn eval_http_request(input: &str) -> char_p::Box {
    if input.len() > MAX_RAKERS_EVAL_JSON_BYTES {
        return rakers_eval_error("HTTP request input exceeds 16 MiB");
    }
    let request = match parse_rakers_eval_request(input) {
        Ok(request) => request,
        Err(error) => return rakers_eval_error(&error),
    };
    if request.html.is_some() || request.base_url.is_some() {
        return rakers_eval_error("@http_request requires a URL, not HTML input");
    }
    let Some(url) = request.url.as_deref() else {
        return rakers_eval_error("@http_request requires url");
    };
    let response = match execute_eval_http_request(url, &request) {
        Ok(response) => response,
        Err(error) => return rakers_eval_error(&error),
    };
    let content_type = response
        .headers
        .get(ureq::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let body =
        crate::crawler::decode_body(&response.body, request.charset.as_deref(), content_type);
    if body.len() > MAX_RAKERS_EVAL_HTML_BYTES {
        return rakers_eval_error("HTTP response text exceeds 8 MiB");
    }
    let headers = eval_response_headers(&response.headers);
    ffi_string(
        json!({
            "url": response.url,
            "status": response.status,
            "headers": headers,
            "body": body,
        })
        .to_string(),
    )
}

fn eval_response_headers(headers: &ureq::http::HeaderMap) -> Value {
    let mut grouped = std::collections::BTreeMap::<String, Vec<String>>::new();
    for (name, value) in headers {
        if let Ok(value) = value.to_str() {
            grouped
                .entry(name.as_str().to_ascii_lowercase())
                .or_default()
                .push(value.to_string());
        }
    }
    let mut output = serde_json::Map::new();
    for (name, values) in grouped {
        let value = if values.len() == 1 {
            Value::String(values.into_iter().next().unwrap_or_default())
        } else {
            Value::Array(values.into_iter().map(Value::String).collect())
        };
        output.insert(name, value);
    }
    Value::Object(output)
}

fn parse_rakers_eval_request(input: &str) -> Result<RakersEvalRequest, String> {
    let trimmed = input.trim();
    if trimmed.starts_with('{') {
        return serde_json::from_str(trimmed)
            .map_err(|error| format!("Invalid Rakers render request: {error}"));
    }
    if !trimmed.starts_with('<') {
        if let Ok(url) = url::Url::parse(trimmed) {
            return Ok(RakersEvalRequest {
                url: Some(url.to_string()),
                ..Default::default()
            });
        }
        if trimmed.starts_with("http:") || trimmed.starts_with("https:") {
            return Err("invalid URL".to_string());
        }
    }
    Ok(RakersEvalRequest {
        html: Some(input.to_string()),
        ..Default::default()
    })
}

fn fetch_and_render_rakers_url(
    raw_url: &str,
    request: &RakersEvalRequest,
) -> Result<String, String> {
    let response = execute_eval_http_request(raw_url, request)?;
    let content_type = response
        .headers
        .get(ureq::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let html =
        crate::crawler::decode_body(&response.body, request.charset.as_deref(), content_type);
    let headers = rakers_eval_headers(request.headers.as_ref())?;
    let user_agent = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        .map(|(_, value)| value.clone())
        .or_else(|| Some(crate::crawler::DEFAULT_USER_AGENT.to_string()));
    let proxy = request
        .proxy
        .as_deref()
        .map(str::trim)
        .filter(|proxy| !proxy.is_empty())
        .map(str::to_string);

    render_rakers_html(&html, Some(&response.url), user_agent, proxy)
}

fn execute_eval_http_request(
    raw_url: &str,
    request: &RakersEvalRequest,
) -> Result<crate::crawler::RawHttpResponse, String> {
    if request.base_url.is_some() {
        return Err("baseUrl is only valid with html input".to_string());
    }
    let page_url = validate_rakers_http_url(raw_url)?;
    let headers = rakers_eval_headers(request.headers.as_ref())?;
    let cookie_header = rakers_eval_cookie_header(request.cookies.as_ref())?;
    let timeout_ms = rakers_eval_timeout_ms(request)?;
    let max_redirects = request.max_redirects.unwrap_or(MAX_RAKERS_EVAL_REDIRECTS);
    if max_redirects > MAX_RAKERS_EVAL_REDIRECTS {
        return Err(format!(
            "maxRedirects must be at most {MAX_RAKERS_EVAL_REDIRECTS}"
        ));
    }
    let proxy = request
        .proxy
        .as_deref()
        .map(str::trim)
        .filter(|proxy| !proxy.is_empty());

    let cookies = crate::crawler::SharedCookieStore::default();
    if let Some(cookie_header) = cookie_header.as_deref() {
        cookies.add_cookie_header(cookie_header, &page_url);
    }
    let client = crate::crawler::HttpClient::new(timeout_ms, Some(cookies), proxy)
        .map_err(|error| format!("HTTP client setup failed: {error}"))?;
    let method = request.method.as_deref().unwrap_or("GET");
    let method = ureq::http::Method::from_bytes(method.as_bytes())
        .map_err(|error| format!("invalid HTTP method: {error}"))?;
    if request.redirect == Some(false) || max_redirects == 0 {
        client.execute_once(
            method,
            page_url.as_str(),
            &headers,
            request.body.as_deref(),
            Some(MAX_RAKERS_EVAL_HTML_BYTES),
        )
    } else {
        client.execute_with_redirect_limit(
            method,
            page_url.as_str(),
            &headers,
            request.body.as_deref(),
            Some(MAX_RAKERS_EVAL_HTML_BYTES),
            max_redirects,
        )
    }
    .map_err(|error| format!("HTTP request failed: {error}"))
}

fn validate_rakers_http_url(raw_url: &str) -> Result<url::Url, String> {
    match url::Url::parse(raw_url) {
        Ok(url)
            if matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none() =>
        {
            Ok(url)
        }
        _ => Err("URL must be an absolute http(s) URL without credentials".to_string()),
    }
}

fn rakers_eval_headers(raw: Option<&Value>) -> Result<Vec<(String, String)>, String> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let Value::Object(headers) = raw else {
        return Err("headers must be a JSON object".to_string());
    };

    let mut parsed = Vec::new();
    for (name, value) in headers {
        let values = match value {
            Value::Array(values) => values
                .iter()
                .map(eval_header_value)
                .collect::<Option<Vec<_>>>(),
            value => eval_header_value(value).map(|value| vec![value]),
        }
        .ok_or_else(|| format!("header {name:?} values must be strings, numbers, or booleans"))?;
        parsed.extend(values.into_iter().map(|value| (name.clone(), value)));
    }
    Ok(parsed)
}

fn eval_header_value(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn rakers_eval_cookie_header(raw: Option<&Value>) -> Result<Option<String>, String> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    match raw {
        Value::Null => Ok(None),
        Value::String(value) => Ok((!value.trim().is_empty()).then(|| value.clone())),
        Value::Object(cookies) => {
            let mut pairs = Vec::new();
            for (name, value) in cookies {
                let value = eval_header_value(value).ok_or_else(|| {
                    format!("cookie {name:?} value must be a string, number, or boolean")
                })?;
                pairs.push(format!("{name}={value}"));
            }
            Ok((!pairs.is_empty()).then(|| pairs.join("; ")))
        }
        _ => Err("cookie/cookies must be a string or JSON object".to_string()),
    }
}

fn rakers_eval_timeout_ms(request: &RakersEvalRequest) -> Result<u64, String> {
    let timeout_ms = if let Some(timeout_ms) = request.timeout_ms {
        timeout_ms
    } else if let Some(timeout_seconds) = request.timeout {
        timeout_seconds
            .checked_mul(1000)
            .ok_or_else(|| "timeout is too large".to_string())?
    } else {
        DEFAULT_RAKERS_EVAL_TIMEOUT_MS
    };
    if !(1..=MAX_RAKERS_EVAL_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(format!(
            "timeout must be between 1 and {} ms",
            MAX_RAKERS_EVAL_TIMEOUT_MS
        ));
    }
    Ok(timeout_ms)
}

fn render_rakers_html(
    html: &str,
    page_url: Option<&str>,
    user_agent: Option<String>,
    proxy: Option<String>,
) -> Result<String, String> {
    if html.len() > MAX_RAKERS_EVAL_HTML_BYTES {
        return Err("Rakers render HTML exceeds 8 MiB".to_string());
    }
    let config = rakers::HttpConfig {
        user_agent,
        headers: Vec::new(),
        proxy,
        forward_headers: false,
    };
    let rendered = rakers::render(
        html,
        false,
        page_url,
        &config,
        true,
        Some(RAKERS_EVAL_MAX_REMOTE_SCRIPTS),
        Some(std::time::Duration::from_secs(3)),
    )
    .map_err(|error| format!("Rakers render failed: {error}"))?;
    if rendered.len() > MAX_RAKERS_EVAL_HTML_BYTES {
        return Err("Rakers rendered HTML exceeds 8 MiB".to_string());
    }
    Ok(rendered)
}

fn rakers_eval_error(message: &str) -> char_p::Box {
    ffi_string(json!({"error":message}).to_string())
}

fn debug_parse_request(input: &str) -> char_p::Box {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Request {
        source: Value,
        body: String,
        base_url: String,
        mode: String,
    }
    let request: Request = match serde_json::from_str(input) {
        Ok(request) => request,
        Err(error) => {
            return ffi_string(
                json!({"error":format!("Invalid debug request: {error}")}).to_string(),
            )
        }
    };
    let source = match request.source {
        Value::String(source) => source,
        value => value.to_string(),
    };
    // JSON may contain escaped NUL; replace it rather than constructing invalid C strings.
    let source = ffi_string(source);
    let body = ffi_string(request.body);
    let base_url = ffi_string(request.base_url);
    let mode = ffi_string(request.mode);
    crate::host_services::with_offline(|| {
        debug_parse(
            source.as_ref(),
            body.as_ref(),
            base_url.as_ref(),
            mode.as_ref(),
        )
    })
}

/// Internal offline diagnostic, exposed only via reader_eval(..., "@debug_parse").
fn debug_parse(
    source_json: char_p::Ref<'_>,
    html_body: char_p::Ref<'_>,
    base_url: char_p::Ref<'_>,
    mode: char_p::Ref<'_>,
) -> char_p::Box {
    let source = match parse_book_source(source_json.to_str()) {
        Ok(source) => source,
        Err(error) => return ffi_string(json!({"error": error}).to_string()),
    };
    let engine = match RuleEngine::new() {
        Ok(engine) => engine,
        Err(error) => {
            return ffi_string(json!({"error": format!("Engine Init: {error}")}).to_string())
        }
    };
    let body = html_body.to_str();
    let base_url = base_url.to_str();
    let result = match mode.to_str() {
        "search" => serde_json::to_value(engine.search_books(&source, body, base_url)),
        "explore" => serde_json::to_value(engine.explore_books(&source, body, base_url)),
        "info" => serde_json::to_value(engine.book_info(&source, body, base_url, base_url)),
        "toc" | "chapter" => {
            let (chapters, next_urls) = engine.chapter_list(&source, body, base_url);
            Ok(json!({"chapters": chapters, "nextUrls": next_urls}))
        }
        "content" => Ok(json!({
            "content": engine.content(&source, body, base_url),
            "nextUrl": engine.next_content_url(&source, body, base_url),
        })),
        other => Err(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown mode: {other}"),
        ))),
    }
    .unwrap_or_else(|error| json!({"error": error.to_string()}));

    ffi_string(
        json!({
            "result": result,
            "logs": ["Offline debug mode: network and host services are disabled. Detailed RuleEngine traces are not implemented yet."],
        })
        .to_string(),
    )
}

fn ffi_string(value: String) -> char_p::Box {
    // serde_json and all user-visible strings are NUL-free at this boundary. Replacing a
    // theoretical NUL keeps the C ABI total rather than panicking in safer-ffi.
    char_p::Box::try_from(value.replace('\0', "\\u0000"))
        .expect("C ABI output must be a valid NUL-terminated string")
}

fn parse_book_source(raw: &str) -> Result<crate::model::book_source::BookSource, String> {
    let value = serde_json::from_str::<Value>(raw)
        .map_err(|error| format!("Invalid Source JSON: {error}"))?;
    book_source_from_value(value).map_err(|error| format!("Invalid Source: {error}"))
}

fn strip_js_prefix(rule: &str) -> Option<&str> {
    rule.strip_prefix("@js:")
        .or_else(|| rule.strip_prefix("js:"))
        .or_else(|| rule.strip_prefix("<js>"))
}

fn apply_replace_rules(content: &str, raw_rules: &str) -> String {
    let Ok(rules) = serde_json::from_str::<Vec<ReplaceRule>>(raw_rules) else {
        return content.to_string();
    };
    apply_replace_rule_list(content, &rules)
}

fn apply_replace_rule_list(content: &str, rules: &[ReplaceRule]) -> String {
    let mut output = content.to_string();
    for rule in rules.iter().filter(|rule| rule.is_enabled) {
        if rule.is_regex {
            let expression = if rule.pattern.starts_with("##") {
                if rule.pattern.contains(&format!("##{}", rule.replacement)) {
                    rule.pattern.clone()
                } else {
                    format!("{}##{}", rule.pattern, rule.replacement)
                }
            } else {
                format!("##{}##{}", rule.pattern, rule.replacement)
            };
            output = apply_legado_regex(&output, &expression);
        } else {
            output = output.replace(&rule.pattern, &rule.replacement);
        }
    }
    output
}

fn merge_search_results(raw_books: &str) -> String {
    let Ok(books) = serde_json::from_str::<Vec<SearchBook>>(raw_books) else {
        return "[]".to_string();
    };
    let mut merged = std::collections::HashMap::<String, SearchBook>::new();
    for mut book in books {
        let key = book.merge_key();
        if let Some(existing) = merged.get_mut(&key) {
            let mut source_urls = existing
                .book_source_urls
                .clone()
                .unwrap_or_else(|| vec![existing.origin.clone()]);
            if !source_urls.contains(&book.origin) {
                source_urls.push(book.origin.clone());
            }
            existing.book_source_urls = Some(source_urls);
        } else {
            book.book_source_urls = Some(vec![book.origin.clone()]);
            merged.insert(key, book);
        }
    }
    serde_json::to_string(&merged.into_values().collect::<Vec<_>>())
        .unwrap_or_else(|_| "[]".to_string())
}

fn validate_source(raw: &str) -> String {
    let mut errors = Vec::new();
    match parse_book_source(raw) {
        Ok(source) => {
            if source.book_source_url.trim().is_empty() {
                errors.push("bookSourceUrl is empty".to_string());
            }
            if source.book_source_name.trim().is_empty() {
                errors.push("bookSourceName is empty".to_string());
            }
        }
        Err(error) => errors.push(error),
    }
    json!({"valid": errors.is_empty(), "errors": errors}).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn reader_execute_content_uses_jsoup_cleanup_and_next_page_headers() {
        use std::io::{BufRead, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let deadline = Instant::now() + Duration::from_secs(5);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("content fixture did not receive request: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
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
                let request = request.to_ascii_lowercase();
                let body = if request.starts_with("get /chapter/1-2 ") {
                    r#"<div class="content"><p>second</p></div><div class="readPage">完</div>"#
                } else {
                    assert!(request.starts_with("get /chapter/1 "), "{request}");
                    r#"<div class="content"><p>first</p><p style="display:none">hidden</p></div><div class="readPage"><a href="/chapter/1-2">下一页</a></div>"#
                };
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                requests.push(request);
            }
            requests
        });
        let content_rule = r#"<js>
var doc = org.jsoup.Jsoup.parse(result);
doc.select("[style*='display:none']").remove();
var paragraphs = doc.select("div.content p").toArray();
var textList = [];
for (var i = 0; i < paragraphs.length; i++) {
    var txt = paragraphs[i].text().trim();
    if (txt) textList.push(txt);
}
textList.join('\n\n');
</js>"#;
        let next_rule = r#"<js>
var doc = org.jsoup.Jsoup.parse(result);
var a = doc.select("div.readPage a:contains(下一页)").first();
a ? a.attr("href") + ',{"headers":{"X-Page":"second"}}' : null;
</js>"#;
        let source = json!({"bookSourceUrl":base,"bookSourceName":"jsoup content fixture", "ruleContent":{"content":content_rule,"nextContentUrl":next_rule}}).to_string();
        let request = json!({"api":2,"op":"content","params":{"url":format!("{base}/chapter/1")}})
            .to_string();
        let c_source = CString::new(source).unwrap();
        let c_request = CString::new(request).unwrap();
        let output = reader_execute(
            char_p::Ref::try_from(c_source.as_c_str()).unwrap(),
            char_p::Ref::try_from(c_request.as_c_str()).unwrap(),
        );
        let response: serde_json::Value = serde_json::from_str(output.to_str()).unwrap();
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(response["data"]["content"], "first\nsecond", "{response}");
        assert_eq!(response["data"]["pages"], 2, "{response}");
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(!requests[0].contains("x-page:"));
        assert!(
            requests[1].starts_with("get /chapter/1-2 "),
            "{}",
            requests[1]
        );
        assert!(
            requests[1].contains("x-page: second\r\n"),
            "{}",
            requests[1]
        );
    }

    #[test]
    fn reader_execute_reuses_inline_js_lib_across_rules_without_cross_source_globals() {
        use std::io::{BufRead, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut paths = Vec::new();
            for _ in 0..6 {
                let deadline = Instant::now() + Duration::from_secs(5);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("jsLib fixture did not receive request: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut first_line = String::new();
                reader.read_line(&mut first_line).unwrap();
                let path = first_line.split_whitespace().nth(1).unwrap().to_string();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                }
                let body = if path.ends_with("/1-2") {
                    "<p>two</p>"
                } else {
                    assert!(path.ends_with("/1"), "{path}");
                    "<p>one</p><a id='next'>next</a>"
                };
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                paths.push(path);
            }
            paths
        });
        for name in ["a", "b", "a"] {
            // Same top-level const/function identifiers, different source-owned values.
            let library = format!(
                r#"const urlsData = ['{name}'];
function route(path) {{ return path; }}
function formatPage(html) {{ return urlsData[0] + ':' + org.jsoup.Jsoup.parse(html).select('p').first().text(); }}
function nextPage(html) {{ return org.jsoup.Jsoup.parse(html).select('a#next').first() ? '/chapter/{name}/1-2' : null; }}"#
            );
            let source = json!({
                "bookSourceUrl": format!("{base}/source/{name}"),
                "bookSourceName": name,
                "enabledCookieJar": false,
                "jsLib": library,
                "ruleContent": {
                    "content": "<js>formatPage(result)</js>",
                    "nextContentUrl": "<js>nextPage(result)</js>"
                }
            })
            .to_string();
            let url_rule = format!(r#"{base}/chapter/{name}/1,{{"js":"route(result)"}}"#);
            let request = json!({"api":2,"op":"content","params":{"url":url_rule}}).to_string();
            let c_source = CString::new(source).unwrap();
            let c_request = CString::new(request).unwrap();
            let output = reader_execute(
                char_p::Ref::try_from(c_source.as_c_str()).unwrap(),
                char_p::Ref::try_from(c_request.as_c_str()).unwrap(),
            );
            let response: serde_json::Value = serde_json::from_str(output.to_str()).unwrap();
            assert_eq!(response["ok"], true, "{name}: {response}");
            assert_eq!(
                response["data"]["content"],
                format!("{name}:one\n{name}:two")
            );
            assert_eq!(response["data"]["pages"], 2);
        }
        let paths = server.join().unwrap();
        assert_eq!(
            paths,
            [
                "/chapter/a/1",
                "/chapter/a/1-2",
                "/chapter/b/1",
                "/chapter/b/1-2",
                "/chapter/a/1",
                "/chapter/a/1-2"
            ]
        );
    }

    #[test]
    fn reader_execute_content_get_string_keeps_json_fallback_and_url_base() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 2048];
            stream.read(&mut request).unwrap();
            let body = r#"{"data":{"path":"/next","count":0,"fallback":"ok"}}"#;
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        });
        let source = json!({
            "bookSourceUrl": base,
            "bookSourceName": "getString fixture",
            "ruleContent": {"content": "<js>[java.getString('$.data.missing||$.data.fallback'), java.getString('$.data.count'), java.getString('$.data.missing', null, true), java.getString('$.data.path', null, true)].join('|')</js>"}
        }).to_string();
        let chapter = format!("{base}/chapter");
        let request = json!({"api":2,"op":"content","params":{"url":chapter}}).to_string();
        let c_source = CString::new(source).unwrap();
        let c_request = CString::new(request).unwrap();
        let output = reader_execute(
            char_p::Ref::try_from(c_source.as_c_str()).unwrap(),
            char_p::Ref::try_from(c_request.as_c_str()).unwrap(),
        );
        let result: serde_json::Value = serde_json::from_str(output.to_str()).unwrap();
        server.join().unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(
            result["data"]["content"],
            format!("ok|0|{chapter}|{base}/next")
        );
    }

    #[test]
    fn debug_microcommand_parses_offline_and_rejects_network() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let source = json!({"bookSourceUrl":url,"bookSourceName":"debug fixture",
            "ruleBookInfo":{"name":"h1@text"},
            "ruleContent":{"content":format!("@js: java.ajax('{url}')")}});
        let request = json!({"source":source,"body":"<h1>书名</h1>","baseUrl":url,"mode":"info"});
        let output = debug_parse_request(&request.to_string());
        let result: Value = serde_json::from_str(output.to_str()).unwrap();
        assert_eq!(result["result"]["name"], "书名");
        let mut request = request;
        request["mode"] = json!("content");
        debug_parse_request(&request.to_string());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(!crate::host_services::is_offline());
        assert!(
            serde_json::from_str::<Value>(debug_parse_request("{}").to_str())
                .unwrap()
                .get("error")
                .is_some()
        );
        let input = CString::new(request.to_string()).unwrap();
        let rule = CString::new("@debug_parse").unwrap();
        let result = reader_eval(
            char_p::Ref::try_from(input.as_c_str()).unwrap(),
            char_p::Ref::try_from(rule.as_c_str()).unwrap(),
        );
        assert!(serde_json::from_str::<Value>(result.to_str())
            .unwrap()
            .get("result")
            .is_some());
    }

    #[test]
    fn test_reader_eval_text_and_clean() {
        let input = "<div><p>段落一</p><ul><li>项A</li><li>项B</li></ul><br>尾部</div>";
        let c_input = CString::new(input).unwrap();
        let c_rule_text = CString::new("@text").unwrap();
        let c_rule_clean = CString::new("@clean").unwrap();

        let ref_input = char_p::Ref::try_from(c_input.as_c_str()).unwrap();
        let ref_text = char_p::Ref::try_from(c_rule_text.as_c_str()).unwrap();
        let ref_clean = char_p::Ref::try_from(c_rule_clean.as_c_str()).unwrap();

        let res_text = reader_eval(ref_input, ref_text);
        assert_eq!(res_text.to_str(), "段落一\n项A\n项B\n尾部");

        let res_clean = reader_eval(ref_input, ref_clean);
        assert_eq!(
            res_clean.to_str(),
            "<p>段落一</p><ul><li>项A</li><li>项B</li></ul><br>尾部"
        );
    }

    #[test]
    fn reader_eval_rakers_render_executes_external_script_without_source_credentials() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("Rakers did not fetch its script: {error}"),
                }
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                let finished = line == "\r\n";
                request.push_str(&line);
                if finished {
                    break;
                }
            }
            let script = "document.getElementById('app').innerHTML = '<p>rendered from external script</p>';";
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{script}", script.len()).unwrap();
            request
        });

        let input = serde_json::json!({
            "html": "<html><body><div id='app'>Loading</div><script src='/hydrate.js'></script></body></html>",
            "baseUrl": format!("{base_url}/chapter")
        })
        .to_string();
        let c_input = CString::new(input).unwrap();
        let c_rule = CString::new("@rakers_render").unwrap();
        let rendered = reader_eval(
            char_p::Ref::try_from(c_input.as_c_str()).unwrap(),
            char_p::Ref::try_from(c_rule.as_c_str()).unwrap(),
        );
        let request = server.join().unwrap();

        assert!(rendered.to_str().contains("rendered from external script"));
        assert!(request.starts_with("GET /hydrate.js "), "{request}");
        assert!(
            !request.to_ascii_lowercase().contains("cookie:"),
            "{request}"
        );
        assert!(
            !request.to_ascii_lowercase().contains("authorization:"),
            "{request}"
        );
    }

    #[test]
    fn reader_eval_rakers_render_accepts_koreader_http_request_fields() {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("reader_eval did not fetch its URL: {error}"),
                }
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut headers = String::new();
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                if let Some(value) = line
                    .strip_prefix("Content-Length:")
                    .or_else(|| line.strip_prefix("content-length:"))
                {
                    content_length = value.trim().parse().unwrap();
                }
                let finished = line == "\r\n";
                headers.push_str(&line);
                if finished {
                    break;
                }
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            let page = "<html><body><div id='app'>Loading</div><script>document.getElementById('app').innerHTML='<p>URL request rendered</p>';</script></body></html>";
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}", page.len()).unwrap();
            (headers, String::from_utf8(body).unwrap())
        });

        let input = serde_json::json!({
            "url": format!("{base_url}/submit"),
            "method": "POST",
            "headers": {
                "Content-Type": "text/plain",
                "User-Agent": "KOReader fixture",
                "X-Book-Source": "eval-test"
            },
            "cookies": {"sid": "eval-cookie"},
            "source": "payload=chapter",
            "timeout": 5,
            "redirect": true,
            "maxRedirects": 3
        })
        .to_string();
        let c_input = CString::new(input).unwrap();
        let c_rule = CString::new("@rakers_render").unwrap();
        let rendered = reader_eval(
            char_p::Ref::try_from(c_input.as_c_str()).unwrap(),
            char_p::Ref::try_from(c_rule.as_c_str()).unwrap(),
        );
        let (request_headers, request_body) = server.join().unwrap();

        assert!(rendered.to_str().contains("URL request rendered"));
        assert!(
            request_headers.starts_with("POST /submit "),
            "{request_headers}"
        );
        assert!(request_headers
            .to_ascii_lowercase()
            .contains("x-book-source: eval-test"));
        assert!(request_headers
            .to_ascii_lowercase()
            .contains("user-agent: koreader fixture"));
        assert!(request_headers
            .to_ascii_lowercase()
            .contains("cookie: sid=eval-cookie"));
        assert_eq!(request_body, "payload=chapter");
    }

    #[test]
    fn reader_eval_rakers_render_accepts_raw_html_and_url() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let html = "<div id='app'>Loading</div><script>document.getElementById('app').innerHTML='<p>raw HTML rendered</p>';</script>";
        let c_html = CString::new(html).unwrap();
        let c_rule = CString::new("@rakers_render").unwrap();
        let rendered_html = reader_eval(
            char_p::Ref::try_from(c_html.as_c_str()).unwrap(),
            char_p::Ref::try_from(c_rule.as_c_str()).unwrap(),
        );
        assert!(rendered_html.to_str().contains("raw HTML rendered"));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/page", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request);
            let page = "<html><body><div id='app'>Loading</div><script>document.getElementById('app').innerHTML='<p>raw URL rendered</p>';</script></body></html>";
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}", page.len()).unwrap();
        });
        let c_url = CString::new(url).unwrap();
        let rendered_url = reader_eval(
            char_p::Ref::try_from(c_url.as_c_str()).unwrap(),
            char_p::Ref::try_from(c_rule.as_c_str()).unwrap(),
        );
        server.join().unwrap();
        assert!(rendered_url.to_str().contains("raw URL rendered"));
    }

    #[test]
    fn reader_eval_http_request_returns_status_headers_and_unrendered_body() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/error-page", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request);
            let body = "<div id='app'>server response</div><script>document.getElementById('app').innerHTML='must not render';</script>";
            write!(stream, "HTTP/1.1 418 I'm a teapot\r\nContent-Type: text/html; charset=utf-8\r\nX-Fixture: eval-http\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        });

        let input = serde_json::json!({"url": url, "method": "GET"}).to_string();
        let c_input = CString::new(input).unwrap();
        let c_rule = CString::new("@http_request").unwrap();
        let output = reader_eval(
            char_p::Ref::try_from(c_input.as_c_str()).unwrap(),
            char_p::Ref::try_from(c_rule.as_c_str()).unwrap(),
        );
        server.join().unwrap();
        let response: Value = serde_json::from_str(output.to_str()).unwrap();

        assert_eq!(response["status"], 418);
        assert_eq!(response["headers"]["x-fixture"], "eval-http");
        assert!(response["body"]
            .as_str()
            .unwrap()
            .contains("server response"));
        assert!(response["body"]
            .as_str()
            .unwrap()
            .contains("must not render"));
    }
}
