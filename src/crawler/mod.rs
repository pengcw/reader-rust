//! 同步书源 HTTP 会话与 URL 规则解析。
//!
//! 此模块从主分支的 `crawler/url_analyzer.rs` 提炼而来，但仅保留 FFI
//! 执行引擎需要的同步路径，避免为 `cdylib` 引入异步 runtime。

use crate::model::book_source::BookSource;
use crate::parser::js::{eval_js, eval_js_url, eval_js_url_template, with_js_lib};
use chardetng::EncodingDetector;
use encoding_rs::{Encoding, UTF_16BE, UTF_16LE, UTF_8};
use once_cell::sync::Lazy;
mod http;
pub mod session;
pub(crate) use http::{HttpClient, HttpClientError, SharedCookieStore, DEFAULT_USER_AGENT};
pub use session::{current_active_session, with_active_session, ActiveSession, ExecuteSession};

use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use ureq::http::header::{CONTENT_TYPE, USER_AGENT};
use ureq::http::{HeaderMap, Method};
const SESSION_CACHE_LIMIT: usize = 32;
const SESSION_CACHE_TTL: Duration = Duration::from_secs(20 * 60);

#[derive(Clone)]
struct CachedSession {
    key: String,
    client: HttpClient,
    last_used: Instant,
}

static SESSION_CACHE: Lazy<Mutex<VecDeque<CachedSession>>> =
    Lazy::new(|| Mutex::new(VecDeque::new()));

/// 每次 `reader_execute` 使用一个同步会话。启用 Cookie jar 的书源会复用一个
/// 有上限、会过期的客户端，借此在 operation 与 operation 之间保持 Cookie。
#[derive(Clone)]
pub struct HttpSession {
    client: HttpClient,
}

#[derive(Debug, Clone)]
pub struct RequestSpec {
    pub url: String,
    pub method: Method,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub charset: Option<String>,
    pub retry: usize,
    pub proxy: Option<String>,
    pub response_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub url: String,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

#[derive(Debug, Clone)]
pub enum FetchError {
    InvalidUrl(String),
    Network(String),
    Timeout {
        url: Option<String>,
        message: String,
    },
    HttpStatus {
        status: u16,
        url: String,
    },
    ResponseTooLarge {
        url: String,
        limit: usize,
    },
    AuthChallenge {
        kind: &'static str,
        message: String,
        status: Option<u16>,
        url: String,
        mode: String,
        login_url: Option<String>,
        action_url: Option<String>,
    },
}

impl HttpSession {
    pub fn new(source: &BookSource, timeout_ms: u64) -> Result<Self, FetchError> {
        let cookie_enabled = source.enabled_cookie_jar != Some(false);
        let timeout_ms = timeout_ms.max(1);

        if let Some(active) = current_active_session() {
            let cookies = cookie_enabled.then(|| active.cookie_store().clone());
            let client = build_client(timeout_ms, cookies, None)?;
            return Ok(Self { client });
        }

        let cache_key = format!("{}\u{1f}{timeout_ms}", source.book_source_url);

        if cookie_enabled {
            let now = Instant::now();
            let mut cache = SESSION_CACHE
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            cache
                .retain(|entry| now.saturating_duration_since(entry.last_used) < SESSION_CACHE_TTL);
            if let Some(index) = cache.iter().position(|entry| entry.key == cache_key) {
                let mut entry = cache.remove(index).expect("cached session index is valid");
                entry.last_used = now;
                let client = entry.client.clone();
                cache.push_back(entry);
                return Ok(Self { client });
            }

            let client = build_client(timeout_ms, Some(SharedCookieStore::default()), None)?;
            while cache.len() >= SESSION_CACHE_LIMIT {
                cache.pop_front();
            }
            cache.push_back(CachedSession {
                key: cache_key,
                client: client.clone(),
                last_used: now,
            });
            return Ok(Self { client });
        }

        Ok(Self {
            client: build_client(timeout_ms, None, None)?,
        })
    }

    pub(crate) fn client(&self) -> &HttpClient {
        &self.client
    }

    pub fn fetch(
        &self,
        spec: &RequestSpec,
        max_response_bytes: usize,
    ) -> Result<HttpResponse, FetchError> {
        let client = if let Some(proxy) = spec
            .proxy
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            build_client_from_existing_policy(spec, proxy)?
        } else {
            self.client.clone()
        };

        let headers = spec.headers.clone();

        let mut last_error = None;
        for attempt in 0..=spec.retry.min(3) {
            match client.execute(
                spec.method.clone(),
                &spec.url,
                &headers,
                spec.body.as_deref(),
                Some(max_response_bytes.max(1)),
            ) {
                Ok(response) => {
                    let status = response.status;
                    let url = response.url;
                    let content_type = response
                        .headers
                        .get(CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned);

                    let mut response_headers = HashMap::new();
                    for (name, value) in &response.headers {
                        if let Ok(value) = value.to_str() {
                            let name = name.as_str().to_ascii_lowercase();
                            response_headers
                                .entry(name)
                                .and_modify(|existing: &mut String| {
                                    existing.push_str(", ");
                                    existing.push_str(value);
                                })
                                .or_insert_with(|| value.to_string());
                        }
                    }

                    let decoded_body = decode_body(
                        &response.body,
                        spec.charset.as_deref(),
                        content_type.as_deref(),
                    );
                    let body_snippet = response_body_snippet(&decoded_body);
                    if let Some(challenge) =
                        detect_auth_challenge(status, &response.headers, body_snippet, &url)
                    {
                        return Err(challenge);
                    }

                    if !(200..300).contains(&status) {
                        if status >= 500 && attempt < spec.retry.min(3) {
                            continue;
                        }
                        return Err(FetchError::HttpStatus { status, url });
                    }

                    let body = format_response_body(
                        &response.body,
                        decoded_body,
                        content_type.as_deref(),
                        spec.response_type.as_deref(),
                    );
                    return Ok(HttpResponse {
                        url,
                        status,
                        headers: response_headers,
                        body,
                    });
                }
                Err(HttpClientError::ResponseTooLarge { url, limit }) => {
                    return Err(FetchError::ResponseTooLarge { url, limit });
                }
                Err(HttpClientError::InvalidUrl(message)) => {
                    return Err(FetchError::InvalidUrl(message));
                }
                Err(HttpClientError::Timeout(message)) => {
                    last_error = Some(FetchError::Timeout {
                        url: Some(spec.url.clone()),
                        message,
                    });
                }
                Err(HttpClientError::Network(message)) => {
                    last_error = Some(FetchError::Network(message));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| FetchError::Network("request failed".to_string())))
    }
}

fn response_body_snippet(body: &str) -> &str {
    let mut end = body.len().min(4096);
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    &body[..end]
}

fn detect_auth_challenge(
    status: u16,
    headers: &HeaderMap,
    body_snippet: &str,
    url: &str,
) -> Option<FetchError> {
    let is_cf_header = headers
        .get("cf-mitigated")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("challenge"))
        .unwrap_or(false);
    let server_cf = headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("cloudflare"))
        .unwrap_or(false);
    let cf_body_match = body_snippet.contains("challenges.cloudflare.com")
        || body_snippet.contains("cf-chl-bypass")
        || body_snippet.contains("<title>Just a moment...")
        || body_snippet.contains("Attention Required! | Cloudflare");

    if is_cf_header || cf_body_match || (server_cf && (status == 403 || status == 503)) {
        return Some(FetchError::AuthChallenge {
            kind: "waf_challenge",
            message: "源站触发 Cloudflare 人机防护挑战".to_string(),
            status: Some(status),
            url: url.to_string(),
            mode: "cloudflare".to_string(),
            login_url: None,
            action_url: None,
        });
    }

    let captcha_match = body_snippet.contains("geetest")
        || body_snippet.contains("vaptcha")
        || body_snippet.contains("滑块验证")
        || body_snippet.contains("人机安全验证")
        || body_snippet.contains("verify_code");

    if captcha_match {
        return Some(FetchError::AuthChallenge {
            kind: "waf_challenge",
            message: "源站触发验证码/滑块人机验证".to_string(),
            status: Some(status),
            url: url.to_string(),
            mode: "captcha".to_string(),
            login_url: None,
            action_url: None,
        });
    }

    if status == 401 {
        return Some(FetchError::AuthChallenge {
            kind: "auth_required",
            message: "HTTP 401 鉴权失效，需要登录".to_string(),
            status: Some(status),
            url: url.to_string(),
            mode: "form".to_string(),
            login_url: None,
            action_url: None,
        });
    }

    if status == 403 {
        return Some(FetchError::AuthChallenge {
            kind: "auth_required",
            message: "HTTP 403 访问被拒绝，可能需要重新登录".to_string(),
            status: Some(status),
            url: url.to_string(),
            mode: "form".to_string(),
            login_url: None,
            action_url: None,
        });
    }

    None
}

fn build_client(
    timeout_ms: u64,
    cookies: Option<SharedCookieStore>,
    proxy: Option<&str>,
) -> Result<HttpClient, FetchError> {
    HttpClient::new(timeout_ms, cookies, proxy).map_err(|error| match error {
        HttpClientError::InvalidUrl(message) => FetchError::InvalidUrl(message),
        HttpClientError::Timeout(message) => FetchError::Timeout { url: None, message },
        HttpClientError::Network(message) => FetchError::Network(message),
        HttpClientError::ResponseTooLarge { url, limit } => {
            FetchError::ResponseTooLarge { url, limit }
        }
    })
}

// Proxy URL rules intentionally use an isolated client, so they never contaminate
// the source cookie session.
fn build_client_from_existing_policy(
    spec: &RequestSpec,
    proxy: &str,
) -> Result<HttpClient, FetchError> {
    let _ = spec;
    build_client(15_000, None, Some(proxy))
}

/// 将 Legado URL 规则变成可直接执行的请求。支持 source/header、JSON options、
/// JS URL、`{{key}}` / `{key}`、`{{page}}` / `{page}` 与相对 URL。
pub fn analyze_url(
    raw_rule: &str,
    key: &str,
    page: i32,
    base_url: &str,
    source: &BookSource,
) -> Result<RequestSpec, String> {
    with_js_lib(source.js_lib.as_deref(), || {
        compile_url_request(raw_rule, key, page, base_url, source)
    })
}

fn compile_url_request(
    raw_rule: &str,
    key: &str,
    page: i32,
    base_url: &str,
    source: &BookSource,
) -> Result<RequestSpec, String> {
    let raw_rule = raw_rule.trim();
    if raw_rule.is_empty() {
        return Err("URL rule is empty".to_string());
    }

    // Stage 1: initialize source/login headers and pull transport proxy out of headers.
    let mut headers = source_headers(source)?;
    let mut proxy = take_proxy_header(&mut headers).filter(|value| !value.trim().is_empty());
    if let Some(active) = current_active_session() {
        if let Some(login_header) = active.get_login_header() {
            merge_headers(&mut headers, headers_from_value(&login_header));
        }
    }
    ensure_user_agent(&mut headers);

    let base = strip_url_options(base_url).trim();

    // Stages 2-4: URL JS segments, embedded JS templates, legacy placeholders, page choices.
    let mut rule = eval_url_rule_js_segments(raw_rule, key, page, source, base)?;
    rule = expand_url_templates(&rule, key, page, source, base)?;
    rule = replace_legacy_placeholders(&rule, key, page);
    rule = replace_page_choices_before_options(&rule, page);

    // Stage 5: split the final URL rule and parse optional JSON.
    let (url_part, options_text) = split_url_options(&rule);
    let options = match options_text {
        Some(text) => parse_url_options(text)?,
        None => Value::Null,
    };

    // Stage 6: resolve URL and apply options that modify the request context.
    let mut url = absolute_url(base, url_part.trim());
    if let Some(script) = options
        .get("js")
        .and_then(Value::as_str)
        .filter(|script| !script.trim().is_empty())
    {
        let rewritten = eval_js_url(script, &url, key, page, &source.book_source_url, base)
            .map_err(|error| format!("URL option JavaScript failed: {error}"))?;
        url = absolute_url(base, &rewritten);
    }
    validate_http_url(&url)?;

    if let Some(extra) = options.get("headers") {
        merge_headers(&mut headers, headers_from_value(extra));
    }
    if let Some(raw_proxy) = options
        .get("proxy")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        proxy = Some(raw_proxy.to_string());
    }
    ensure_user_agent(&mut headers);

    let method = if options
        .get("method")
        .and_then(Value::as_str)
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("POST"))
    {
        Method::POST
    } else {
        Method::GET
    };
    let body = options.get("body").and_then(value_to_string);
    let charset = options
        .get("charset")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string());
    let retry = options
        .get("retry")
        .and_then(value_to_usize)
        .unwrap_or(0)
        .min(3);
    let response_type = options
        .get("type")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned);
    let body = prepare_request_body(
        method == Method::POST,
        body,
        &mut headers,
        charset.as_deref(),
    );

    Ok(RequestSpec {
        url: encode_get_query(&url, charset.as_deref()),
        method,
        headers,
        body,
        charset,
        retry,
        proxy,
        response_type,
    })
}

fn strip_js_prefix(value: &str) -> Option<&str> {
    value
        .strip_prefix("@js:")
        .or_else(|| value.strip_prefix("js:"))
        .or_else(|| {
            value
                .strip_prefix("<js>")
                .and_then(|body| body.strip_suffix("</js>"))
        })
}

fn eval_url_rule_js_segments(
    rule: &str,
    key: &str,
    page: i32,
    source: &BookSource,
    base_url: &str,
) -> Result<String, String> {
    static URL_JS_SEGMENTS: Lazy<Option<regex::Regex>> =
        Lazy::new(|| regex::Regex::new(r"(?is)<js>(.*?)</js>|@js:(.*)$|^js:(.*)$").ok());
    let Some(regex) = URL_JS_SEGMENTS.as_ref() else {
        return Ok(rule.to_string());
    };

    let mut result = rule.to_string();
    let mut previous_end = 0;
    for captures in regex.captures_iter(rule) {
        let Some(matched) = captures.get(0) else {
            continue;
        };
        if matched.start() > previous_end {
            let prefix = rule[previous_end..matched.start()].trim();
            if !prefix.is_empty() {
                result = prefix.replace("@result", &result);
            }
        }
        let script = captures
            .get(1)
            .or_else(|| captures.get(2))
            .or_else(|| captures.get(3))
            .map(|value| value.as_str())
            .unwrap_or_default();
        result = eval_js_url(
            script,
            &result,
            key,
            page,
            &source.book_source_url,
            base_url,
        )
        .map_err(|error| format!("URL JavaScript failed: {error}"))?;
        previous_end = matched.end();
    }
    if previous_end < rule.len() {
        let suffix = rule[previous_end..].trim();
        if !suffix.is_empty() {
            result = suffix.replace("@result", &result);
        }
    }
    Ok(result)
}

fn expand_url_templates(
    rule: &str,
    key: &str,
    page: i32,
    source: &BookSource,
    base_url: &str,
) -> Result<String, String> {
    let mut output = String::with_capacity(rule.len());
    let mut cursor = 0;
    while let Some(relative_start) = rule[cursor..].find("{{") {
        let start = cursor + relative_start;
        output.push_str(&rule[cursor..start]);
        let expression_start = start + 2;
        let Some(relative_end) = rule[expression_start..].find("}}") else {
            output.push_str(&rule[start..]);
            return Ok(output);
        };
        let end = expression_start + relative_end;
        let expression = rule[expression_start..end].trim();
        let replacement = eval_js_url_template(
            expression,
            rule,
            key,
            page,
            &source.book_source_url,
            base_url,
        )
        .map_err(|error| format!("URL template JavaScript failed: {error}"))?;
        output.push_str(&replacement);
        cursor = end + 2;
    }
    output.push_str(&rule[cursor..]);
    Ok(output)
}

fn replace_legacy_placeholders(rule: &str, key: &str, page: i32) -> String {
    let encoded_key = urlencoding::encode(key);
    let page = page.max(1).to_string();
    rule.replace("{key}", &encoded_key)
        .replace("searchKey", &encoded_key)
        .replace("{page}", &page)
        .replace("searchPage", &page)
}

fn replace_page_choices_before_options(rule: &str, page: i32) -> String {
    let (url, options) = split_url_options(rule);
    match options {
        Some(options) => format!("{},{}", replace_page_choices(url, page), options),
        None => replace_page_choices(url, page),
    }
}

fn replace_page_choices(rule: &str, page: i32) -> String {
    let Ok(re) = regex::Regex::new(r"<([^<>]*)>") else {
        return rule.to_string();
    };
    re.replace_all(rule, |captures: &regex::Captures| {
        let choices = captures[1]
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        choices
            .get(page.saturating_sub(1) as usize)
            .or_else(|| choices.last())
            .copied()
            .unwrap_or_default()
            .to_string()
    })
    .into_owned()
}

fn split_url_options(rule: &str) -> (&str, Option<&str>) {
    let mut in_string = false;
    let mut quote = '\0';
    let mut escaped = false;
    let mut depth = 0i32;
    for (index, ch) in rule.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_string => escaped = true,
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
                let after = rule[index + ch.len_utf8()..].trim_start();
                if after.starts_with('{') {
                    return (&rule[..index], Some(after));
                }
            }
            _ => {}
        }
    }
    (rule, None)
}

fn strip_url_options(rule: &str) -> &str {
    split_url_options(rule).0
}

fn parse_url_options(raw: &str) -> Result<Value, String> {
    serde_json::from_str(raw)
        .or_else(|_| serde_json::from_str(&escape_control_chars_in_json_strings(raw)))
        .map_err(|error| format!("invalid URL options: {error}"))
}

fn escape_control_chars_in_json_strings(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len());
    let mut in_string = false;
    let mut escaped = false;
    for ch in raw.chars() {
        if in_string {
            if escaped {
                output.push(ch);
                escaped = false;
                continue;
            }
            match ch {
                '\\' => {
                    output.push(ch);
                    escaped = true;
                }
                '"' => {
                    output.push(ch);
                    in_string = false;
                }
                '\n' => output.push_str("\\n"),
                '\r' => output.push_str("\\r"),
                '\t' => output.push_str("\\t"),
                control if control.is_control() => {
                    output.push_str(&format!("\\u{:04X}", control as u32))
                }
                other => output.push(other),
            }
        } else {
            output.push(ch);
            if ch == '"' {
                in_string = true;
            }
        }
    }
    output
}

fn source_headers(source: &BookSource) -> Result<Vec<(String, String)>, String> {
    let Some(raw) = source
        .header
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(Vec::new());
    };
    let raw = if let Some(script) = strip_js_prefix(raw.trim()) {
        eval_js(script, "", &source.book_source_url)
            .map_err(|error| format!("source header JavaScript failed: {error}"))?
    } else {
        raw.to_string()
    };
    Ok(parse_source_headers(&raw))
}

fn parse_source_headers(raw: &str) -> Vec<(String, String)> {
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(raw) {
        return map
            .iter()
            .filter(|(name, _)| !name.trim().is_empty())
            .map(|(name, value)| (name.clone(), value_to_string(value).unwrap_or_default()))
            .collect();
    }

    let normalized = raw.trim().trim_start_matches('{').trim_end_matches('}');
    normalized
        .split(',')
        .filter_map(|part| {
            let (name, value) = part.split_once(':')?;
            let name = name.trim().trim_matches(['\'', '"']);
            let value = value.trim().trim_matches(['\'', '"']);
            (!name.is_empty()).then(|| (name.to_string(), value.to_string()))
        })
        .collect()
}

fn headers_from_value(value: &Value) -> Vec<(String, String)> {
    match value {
        Value::String(raw) => parse_source_headers(raw),
        Value::Object(map) => map
            .iter()
            .filter(|(name, _)| !name.trim().is_empty())
            .map(|(name, value)| (name.clone(), value_to_string(value).unwrap_or_default()))
            .collect(),
        _ => Vec::new(),
    }
}

fn take_proxy_header(headers: &mut Vec<(String, String)>) -> Option<String> {
    let mut proxy = None;
    headers.retain(|(name, value)| {
        if name.eq_ignore_ascii_case("proxy") {
            proxy = Some(value.clone());
            false
        } else {
            true
        }
    });
    proxy
}

fn merge_headers(target: &mut Vec<(String, String)>, extra: Vec<(String, String)>) {
    for (name, value) in extra {
        if name.eq_ignore_ascii_case("proxy") {
            continue;
        }
        if let Some((_, old_value)) = target
            .iter_mut()
            .find(|(old_name, _)| old_name.eq_ignore_ascii_case(&name))
        {
            *old_value = value;
        } else {
            target.push((name, value));
        }
    }
}

fn ensure_user_agent(headers: &mut Vec<(String, String)>) {
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(USER_AGENT.as_str()))
    {
        headers.push(("User-Agent".to_string(), DEFAULT_USER_AGENT.to_string()));
    }
}

fn absolute_url(base: &str, raw_url: &str) -> String {
    let raw_url = raw_url.trim();
    if raw_url.starts_with("http://") || raw_url.starts_with("https://") {
        return raw_url.to_string();
    }
    if raw_url.starts_with("//") {
        return format!("https:{raw_url}");
    }
    url::Url::parse(base)
        .and_then(|base| base.join(raw_url))
        .map(|url| url.to_string())
        .unwrap_or_else(|_| raw_url.to_string())
}

fn validate_http_url(raw_url: &str) -> Result<(), String> {
    let url = url::Url::parse(raw_url).map_err(|error| format!("invalid URL: {error}"))?;
    match url.scheme() {
        "http" | "https" => Ok(()),
        scheme => Err(format!("unsupported URL scheme: {scheme}")),
    }
}

fn encode_get_query(raw_url: &str, charset: Option<&str>) -> String {
    let Some(charset) = charset.filter(|value| {
        !value.eq_ignore_ascii_case("utf-8") && !value.eq_ignore_ascii_case("utf8")
    }) else {
        return raw_url.to_string();
    };
    let escape_mode = charset.eq_ignore_ascii_case("escape");
    let encoding = if escape_mode {
        None
    } else {
        Encoding::for_label(charset.as_bytes())
    };
    if !escape_mode && encoding.is_none() {
        return raw_url.to_string();
    }
    let Ok(url) = url::Url::parse(raw_url) else {
        return raw_url.to_string();
    };
    let Some(query) = url.query().map(str::to_owned) else {
        return raw_url.to_string();
    };
    let encoded = query
        .split('&')
        .map(|part| {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            let value = urlencoding::decode(value)
                .unwrap_or_else(|_| value.into())
                .into_owned();
            let encoded_value = if escape_mode {
                escape_component(&value)
            } else {
                let (bytes, _, _) = encoding.expect("known encoding").encode(&value);
                percent_encode_bytes(&bytes)
            };
            format!("{name}={encoded_value}")
        })
        .collect::<Vec<_>>()
        .join("&");
    let serialized = url.to_string();
    replace_serialized_query(&serialized, &encoded)
}

fn replace_serialized_query(url: &str, query: &str) -> String {
    let fragment_at = url.find('#').unwrap_or(url.len());
    let query_at = url[..fragment_at].find('?');
    match query_at {
        Some(index) => format!("{}?{}{}", &url[..index], query, &url[fragment_at..]),
        None => format!("{}?{}{}", &url[..fragment_at], query, &url[fragment_at..]),
    }
}

fn percent_encode_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
                (*byte as char).to_string()
            } else {
                format!("%{:02X}", byte)
            }
        })
        .collect()
}

fn escape_component(value: &str) -> String {
    value
        .encode_utf16()
        .map(|unit| {
            if unit <= 0x7F {
                let byte = unit as u8;
                if byte.is_ascii_alphanumeric()
                    || matches!(byte, b'*' | b'+' | b'-' | b'.' | b'/' | b'@' | b'_')
                {
                    (byte as char).to_string()
                } else {
                    format!("%{:02X}", byte)
                }
            } else {
                format!("%u{:04X}", unit)
            }
        })
        .collect()
}

fn prepare_request_body(
    is_post: bool,
    body: Option<String>,
    headers: &mut Vec<(String, String)>,
    charset: Option<&str>,
) -> Option<String> {
    let body = body?;
    if !is_post || body.trim().is_empty() || has_content_type(headers) {
        return Some(body);
    }

    let trimmed = body.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        headers.push((
            CONTENT_TYPE.as_str().to_string(),
            "application/json".to_string(),
        ));
        return Some(body);
    }
    if trimmed.starts_with("<?xml") || (trimmed.starts_with('<') && trimmed.contains('>')) {
        headers.push((
            CONTENT_TYPE.as_str().to_string(),
            "application/xml".to_string(),
        ));
        return Some(body);
    }

    headers.push((
        CONTENT_TYPE.as_str().to_string(),
        "application/x-www-form-urlencoded".to_string(),
    ));
    Some(encode_form_body(&body, charset))
}

fn has_content_type(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(CONTENT_TYPE.as_str()))
}

fn encode_form_body(body: &str, charset: Option<&str>) -> String {
    if charset.is_none_or(|value| value.trim().is_empty()) && is_encoded_form(body) {
        return body.to_string();
    }
    let charset = charset.map(str::trim).filter(|value| !value.is_empty());
    let escape_mode = charset.is_some_and(|value| value.eq_ignore_ascii_case("escape"));
    let encoding = charset
        .filter(|value| !value.eq_ignore_ascii_case("escape"))
        .and_then(|value| Encoding::for_label(value.as_bytes()))
        .unwrap_or(UTF_8);
    body.split('&')
        .map(|part| {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            let name = encode_form_component(name, encoding, escape_mode);
            let value = encode_form_component(value, encoding, escape_mode);
            format!("{name}={value}")
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn encode_form_component(value: &str, encoding: &'static Encoding, escape_mode: bool) -> String {
    if escape_mode {
        return escape_component(value);
    }
    let (bytes, _, _) = encoding.encode(value);
    bytes
        .iter()
        .map(|byte| match *byte {
            b' ' => "+".to_string(),
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                (*byte as char).to_string()
            }
            _ => format!("%{:02X}", byte),
        })
        .collect()
}

fn is_encoded_form(body: &str) -> bool {
    let bytes = body.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len()
                && bytes[index + 1].is_ascii_hexdigit()
                && bytes[index + 2].is_ascii_hexdigit() =>
            {
                index += 3
            }
            b'%' => return false,
            byte if byte.is_ascii_alphanumeric()
                || matches!(byte, b'*' | b'-' | b'.' | b'_' | b'+' | b'&' | b'=') =>
            {
                index += 1
            }
            _ => return false,
        }
    }
    true
}

fn format_response_body(
    raw_body: &[u8],
    decoded_body: String,
    content_type: Option<&str>,
    response_type: Option<&str>,
) -> String {
    if response_type.is_some_and(|value| !value.trim().is_empty()) {
        return raw_body.iter().map(|byte| format!("{byte:02x}")).collect();
    }
    if content_type.is_some_and(is_xml_content_type) && !decoded_body.starts_with("<?xml") {
        return format!("<?xml version=\"1.0\"?>{decoded_body}");
    }
    decoded_body
}

fn is_xml_content_type(content_type: &str) -> bool {
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    mime == "text/xml" || mime == "application/xml" || mime.ends_with("+xml")
}

fn decode_body(bytes: &[u8], charset: Option<&str>, content_type: Option<&str>) -> String {
    // An explicitly supplied URL charset is authoritative when it is known.
    if let Some(encoding) = charset.and_then(|label| Encoding::for_label(label.as_bytes())) {
        return decode_with_encoding(bytes, encoding).0;
    }

    // A BOM is stronger evidence than response headers and must not leak into
    // the resulting text as a leading U+FEFF.
    if let Some((encoding, body)) = charset_from_bom(bytes) {
        return decode_with_encoding(body, encoding).0;
    }

    // Honor valid HTTP declarations. A broken UTF-8 declaration is common for
    // legacy pages, so allow meta declarations and statistical detection to
    // recover instead of immediately returning replacement characters.
    if let Some(encoding) = charset_from_content_type(content_type)
        .and_then(|label| Encoding::for_label(label.as_bytes()))
    {
        let (text, had_errors) = decode_with_encoding(bytes, encoding);
        if !had_errors {
            return text;
        }
    }

    if let Some(encoding) =
        charset_from_html_meta(bytes).and_then(|label| Encoding::for_label(label.as_bytes()))
    {
        let (text, had_errors) = decode_with_encoding(bytes, encoding);
        if !had_errors {
            return text;
        }
    }

    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_owned();
    }

    let mut detector = EncodingDetector::new();
    detector.feed(bytes, true);
    let encoding = detector.guess(None, true);
    let (text, had_errors) = decode_with_encoding(bytes, encoding);
    if !had_errors {
        return text;
    }

    String::from_utf8_lossy(bytes).into_owned()
}

fn charset_from_content_type(content_type: Option<&str>) -> Option<String> {
    content_type?.split(';').find_map(|part| {
        let (name, value) = part.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| value.trim().trim_matches(['\'', '"']).to_string())
    })
}

fn charset_from_bom(bytes: &[u8]) -> Option<(&'static Encoding, &[u8])> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        Some((UTF_8, &bytes[3..]))
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        Some((UTF_16LE, &bytes[2..]))
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        Some((UTF_16BE, &bytes[2..]))
    } else {
        None
    }
}

fn charset_from_html_meta(bytes: &[u8]) -> Option<String> {
    static META_TAG: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"(?is)<meta\b[^>]*>").expect("valid meta tag regex"));
    static META_ATTRIBUTE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r#"(?is)([a-z_:][a-z0-9_:.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#)
            .expect("valid meta attribute regex")
    });
    static CONTENT_CHARSET: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r#"(?i)charset\s*=\s*["']?([a-z0-9._:-]+)"#)
            .expect("valid content charset regex")
    });

    let prefix = &bytes[..bytes.len().min(4096)];
    let html = String::from_utf8_lossy(prefix);
    for tag in META_TAG.find_iter(&html) {
        let mut charset = None;
        let mut http_equiv = None;
        let mut content = None;
        for attribute in META_ATTRIBUTE.captures_iter(tag.as_str()) {
            let name = attribute.get(1)?.as_str();
            let value = (2..=4)
                .find_map(|index| attribute.get(index))
                .map(|value| value.as_str())
                .unwrap_or_default();
            if name.eq_ignore_ascii_case("charset") {
                charset = Some(value.to_string());
            } else if name.eq_ignore_ascii_case("http-equiv") {
                http_equiv = Some(value);
            } else if name.eq_ignore_ascii_case("content") {
                content = Some(value);
            }
        }
        if let Some(charset) = charset.filter(|value| !value.trim().is_empty()) {
            return Some(charset.trim().to_string());
        }
        if http_equiv.is_some_and(|value| value.eq_ignore_ascii_case("content-type")) {
            if let Some(capture) = content.and_then(|value| CONTENT_CHARSET.captures(value)) {
                return capture.get(1).map(|value| value.as_str().to_string());
            }
        }
    }
    None
}

fn decode_with_encoding(bytes: &[u8], encoding: &'static Encoding) -> (String, bool) {
    let (text, _, had_errors) = encoding.decode(bytes);
    (text.into_owned(), had_errors)
}

fn value_to_string(value: &Value) -> Option<String> {
    (!value.is_null()).then(|| {
        value
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| value.to_string())
    })
}

fn value_to_usize(value: &Value) -> Option<usize> {
    value
        .as_u64()
        .map(|value| value as usize)
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(text: &str, label: &str) -> Vec<u8> {
        let encoding = Encoding::for_label(label.as_bytes()).unwrap();
        let (bytes, _, had_errors) = encoding.encode(text);
        assert!(!had_errors, "test sample must be representable in {label}");
        bytes.into_owned()
    }

    fn test_source(header: Option<&str>) -> BookSource {
        BookSource {
            book_source_name: "URL compatibility".to_string(),
            book_source_url: "https://a.test".to_string(),
            header: header.map(str::to_owned),
            ..Default::default()
        }
    }

    #[test]
    fn compat_url_compile_expands_key_page_and_headers() {
        let source = test_source(None);
        let spec = analyze_url(
            "/search?q={{key}}&page=<1,2,3>,{\"headers\":{\"Referer\":\"https://a.test\"}}",
            "斗破",
            2,
            "https://a.test",
            &source,
        )
        .unwrap();

        assert_eq!(
            spec.url,
            "https://a.test/search?q=%E6%96%97%E7%A0%B4&page=2"
        );
        assert!(spec.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("referer") && value == "https://a.test"
        }));
    }

    #[test]
    fn compat_url_rule_js_segments_and_templates() {
        let source = test_source(None);
        let spec = analyze_url(
            "start<js>result + '-one'</js>@result<js>result + '-two'</js>@result",
            "keyword",
            1,
            "https://a.test",
            &source,
        )
        .unwrap();
        assert_eq!(spec.url, "https://a.test/start-one-two");

        let spec = analyze_url(
            "@js:'https://a.test/search?q='+encodeURIComponent(key)",
            "a b",
            1,
            "https://a.test",
            &source,
        )
        .unwrap();
        assert_eq!(spec.url, "https://a.test/search?q=a%20b");

        let spec = analyze_url(
            "js:'https://a.test/legacy'",
            "keyword",
            1,
            "https://a.test",
            &source,
        )
        .unwrap();
        assert_eq!(spec.url, "https://a.test/legacy");

        let spec = analyze_url(
            "/search?q={{1 + 1}}&a={{'word'}}&empty={{null}}",
            "keyword",
            1,
            "https://a.test",
            &source,
        )
        .unwrap();
        assert_eq!(spec.url, "https://a.test/search?q=2&a=word&empty=");
        assert_eq!(
            eval_js_url_template(
                "({value: 1})",
                "",
                "key",
                1,
                "https://a.test",
                "https://a.test"
            )
            .unwrap(),
            "[object Object]"
        );
    }

    #[test]
    fn compat_url_option_js_and_source_proxy() {
        let source = test_source(Some(
            "@js:JSON.stringify({proxy:'http://source-proxy:8080', Referer:'https://source.test'})",
        ));
        let spec = analyze_url(
            "/search,{\"proxy\":\"http://option-proxy:8080\",\"js\":\"'/final'\"}",
            "key",
            1,
            "https://a.test",
            &source,
        )
        .unwrap();
        assert_eq!(spec.url, "https://a.test/final");
        assert_eq!(spec.proxy.as_deref(), Some("http://option-proxy:8080"));
        assert!(!spec
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("proxy")));
        assert!(spec
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("user-agent")));
        assert!(spec.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("referer") && value == "https://source.test"
        }));

        let spec = analyze_url("/search", "key", 1, "https://a.test", &source).unwrap();
        assert_eq!(spec.proxy.as_deref(), Some("http://source-proxy:8080"));
    }

    #[test]
    fn compat_url_escape_charset_and_form_encoding() {
        let source = test_source(None);
        let query = analyze_url(
            "/search?q=中文, {\"charset\":\"escape\"}",
            "key",
            1,
            "https://a.test",
            &source,
        )
        .unwrap();
        assert_eq!(query.url, "https://a.test/search?q=%u4E2D%u6587");

        let form = analyze_url(
            "/submit,{\"method\":\"POST\",\"body\":\"q=中文&title=a b\"}",
            "key",
            1,
            "https://a.test",
            &source,
        )
        .unwrap();
        assert_eq!(form.body.as_deref(), Some("q=%E4%B8%AD%E6%96%87&title=a+b"));
        assert!(form.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type")
                && value == "application/x-www-form-urlencoded"
        }));

        let encoded = analyze_url(
            "/submit,{\"method\":\"POST\",\"body\":\"q=hello+world&x=%2F\"}",
            "key",
            1,
            "https://a.test",
            &source,
        )
        .unwrap();
        assert_eq!(encoded.body.as_deref(), Some("q=hello+world&x=%2F"));

        let gbk_form = analyze_url(
            "/submit,{\"method\":\"POST\",\"charset\":\"gbk\",\"body\":\"q=中文\"}",
            "key",
            1,
            "https://a.test",
            &source,
        )
        .unwrap();
        assert_eq!(gbk_form.body.as_deref(), Some("q=%D6%D0%CE%C4"));

        let escape_form = analyze_url(
            "/submit,{\"method\":\"POST\",\"charset\":\"escape\",\"body\":\"q=中文\"}",
            "key",
            1,
            "https://a.test",
            &source,
        )
        .unwrap();
        assert_eq!(escape_form.body.as_deref(), Some("q=%u4E2D%u6587"));
    }

    #[test]
    fn compat_url_json_body_charset_and_response_type() {
        let source = test_source(None);
        let json = analyze_url(
            "/submit,{\"method\":\"POST\",\"body\":{\"q\":\"中文\"},\"charset\":\"gbk\",\"type\":\"hex\"}",
            "key",
            1,
            "https://a.test",
            &source,
        )
        .unwrap();
        assert_eq!(json.body.as_deref(), Some(r#"{"q":"中文"}"#));
        assert_eq!(json.response_type.as_deref(), Some("hex"));
        assert!(json.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type") && value == "application/json"
        }));

        let xml = analyze_url(
            "/submit,{\"method\":\"POST\",\"body\":\"<root/>\"}",
            "key",
            1,
            "https://a.test",
            &source,
        )
        .unwrap();
        assert_eq!(xml.body.as_deref(), Some("<root/>"));
        assert!(xml.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type") && value == "application/xml"
        }));

        assert_eq!(
            format_response_body(b"<root/>", "<root/>".into(), Some("application/xml"), None),
            "<?xml version=\"1.0\"?><root/>"
        );
        assert_eq!(
            format_response_body(&[0, 255], String::new(), None, Some("hex")),
            "00ff"
        );
        assert_eq!(
            format_response_body(
                b"<?xml version='1.0'?>",
                "<?xml version='1.0'?>".into(),
                Some("text/xml"),
                None
            ),
            "<?xml version='1.0'?>"
        );
    }

    #[test]
    fn decodes_utf8_without_declaration() {
        let text = "Hello, 世界";
        assert_eq!(decode_body(text.as_bytes(), None, None), text);
    }

    #[test]
    fn decodes_utf8_bom_without_returning_bom() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice("你好".as_bytes());
        assert_eq!(decode_body(&bytes, None, None), "你好");
    }

    #[test]
    fn decodes_utf16_bom() {
        let text = "Hello 世界";
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode_body(&bytes, None, None), text);
    }

    #[test]
    fn decodes_utf16be_bom() {
        let text = "Hello 世界";
        let mut bytes = vec![0xFE, 0xFF];
        bytes.extend(text.encode_utf16().flat_map(u16::to_be_bytes));
        assert_eq!(decode_body(&bytes, None, None), text);
    }

    #[test]
    fn decodes_gbk_from_http_charset() {
        let bytes = encode("中文页面", "gbk");
        assert_eq!(
            decode_body(&bytes, None, Some("text/html; charset=gbk")),
            "中文页面"
        );
    }

    #[test]
    fn decodes_gbk_from_html_meta_charset() {
        let text = "这是中文页面";
        let mut bytes = b"<meta charset=gbk><title>".to_vec();
        bytes.extend(encode(text, "gbk"));
        bytes.extend_from_slice(b"</title>");
        let decoded = decode_body(&bytes, None, None);
        assert!(decoded.contains(text));
        assert!(!decoded.contains('\u{FFFD}'));
    }

    #[test]
    fn recovers_when_http_mislabels_gbk_as_utf8() {
        let bytes = encode("错误声明也能正确解码", "gbk");
        let decoded = decode_body(&bytes, None, Some("text/html; charset=utf-8"));
        assert_eq!(decoded, "错误声明也能正确解码");
        assert!(!decoded.contains('\u{FFFD}'));
    }

    #[test]
    fn detects_big5_without_declaration() {
        let text = "繁體中文網頁內容測試，這是一段較長的文字，用來辨識 Big5 編碼。".repeat(4);
        let bytes = encode(&text, "big5");
        let decoded = decode_body(&bytes, None, None);
        assert_eq!(decoded, text);
        assert!(!decoded.contains('\u{FFFD}'));
    }

    #[test]
    fn detects_shift_jis_without_declaration() {
        let text = "日本語の文章です。文字コードを検出するための長めのテストです。".repeat(4);
        let bytes = encode(&text, "shift_jis");
        let decoded = decode_body(&bytes, None, None);
        assert_eq!(decoded, text);
        assert!(!decoded.contains('\u{FFFD}'));
    }

    #[test]
    fn explicit_url_charset_overrides_http_charset() {
        let text = "日本語の内容";
        let bytes = encode(text, "shift_jis");
        assert_eq!(
            decode_body(&bytes, Some("shift_jis"), Some("text/html; charset=gbk")),
            text
        );
    }

    #[test]
    fn ascii_is_unchanged() {
        let text = b"plain ASCII content";
        assert_eq!(decode_body(text, None, None).as_bytes(), text);
    }

    #[test]
    fn test_cookie_store() {
        let cookies = SharedCookieStore::default();
        let url: url::Url = "https://example.com".parse().unwrap();
        cookies.add_set_cookie("token=12345; Path=/", &url);
        assert_eq!(
            cookies.get_cookie_header(&url),
            Some("token=12345".to_string())
        );
    }
}
