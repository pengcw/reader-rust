//! 同步书源 HTTP 会话与 URL 规则解析。
//!
//! 此模块从主分支的 `crawler/url_analyzer.rs` 提炼而来，但仅保留 FFI
//! 执行引擎需要的同步路径，避免为 `cdylib` 引入异步 runtime。

use crate::model::book_source::BookSource;
use crate::parser::js::{eval_js, eval_js_search_with_source, with_js_lib};
use encoding_rs::Encoding;
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

        let mut headers = spec.headers.clone();
        if spec.body.is_some()
            && spec.method == Method::POST
            && !headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case(CONTENT_TYPE.as_str()))
        {
            headers.push((
                CONTENT_TYPE.as_str().to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ));
        }

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

                    let body = decode_body(
                        &response.body,
                        spec.charset.as_deref(),
                        content_type.as_deref(),
                    );
                    let body_snippet = response_body_snippet(&body);
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
        HttpClientError::Timeout(message) => FetchError::Timeout {
            url: None,
            message,
        },
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
        let mut rule = raw_rule.trim().to_string();
        if rule.is_empty() {
            return Err("URL rule is empty".to_string());
        }

        if let Some(script) = strip_js_prefix(&rule) {
            rule = eval_js_search_with_source(script, key, page, &source.book_source_url)
                .map_err(|error| format!("URL JavaScript failed: {error}"))?;
        } else {
            rule = replace_placeholders(&rule, key, page);
        }

        let (url_part, options_text) = split_url_options(&rule);
        let options = match options_text {
            Some(text) => parse_url_options(text)?,
            None => Value::Null,
        };

        let base = strip_url_options(base_url).trim();
        let url = absolute_url(base, url_part.trim());
        validate_http_url(&url)?;

        let mut headers = source_headers(source)?;
        if let Some(active) = current_active_session() {
            if let Some(login_header) = active.get_login_header() {
                merge_headers(&mut headers, headers_from_value(&login_header));
            }
        }
        let mut proxy = None;
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

        let method = options
            .get("method")
            .and_then(Value::as_str)
            .map(|value| Method::from_bytes(value.trim().to_uppercase().as_bytes()))
            .transpose()
            .map_err(|error| format!("invalid HTTP method: {error}"))?
            .unwrap_or(Method::GET);
        let body = options.get("body").and_then(value_to_string);
        let charset = options
            .get("charset")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned);
        let retry = options
            .get("retry")
            .and_then(value_to_usize)
            .unwrap_or(0)
            .min(3);

        Ok(RequestSpec {
            url: encode_get_query(&url, charset.as_deref()),
            method,
            headers,
            body,
            charset,
            retry,
            proxy,
        })
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

fn replace_placeholders(rule: &str, key: &str, page: i32) -> String {
    let encoded_key = urlencoding::encode(key);
    let page = page.max(1).to_string();
    let with_page_choices = replace_page_choices(rule, page.parse().unwrap_or(1));
    with_page_choices
        .replace("{{key}}", &encoded_key)
        .replace("{key}", &encoded_key)
        .replace("searchKey", &encoded_key)
        .replace("{{page}}", &page)
        .replace("{page}", &page)
        .replace("searchPage", &page)
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
    let Some(charset) = charset.filter(|value| !value.eq_ignore_ascii_case("utf-8")) else {
        return raw_url.to_string();
    };
    let Some(encoding) = Encoding::for_label(charset.as_bytes()) else {
        return raw_url.to_string();
    };
    let Ok(mut url) = url::Url::parse(raw_url) else {
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
            let (bytes, _, _) = encoding.encode(&value);
            let encoded_value = bytes
                .iter()
                .map(|byte| {
                    if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
                        (*byte as char).to_string()
                    } else {
                        format!("%{:02X}", byte)
                    }
                })
                .collect::<String>();
            format!("{name}={encoded_value}")
        })
        .collect::<Vec<_>>()
        .join("&");
    url.set_query(Some(&encoded));
    url.to_string()
}

fn decode_body(bytes: &[u8], charset: Option<&str>, content_type: Option<&str>) -> String {
    let charset = charset.map(str::to_owned).or_else(|| {
        content_type.and_then(|value| {
            value.split(';').find_map(|part| {
                let (name, value) = part.split_once('=')?;
                name.trim()
                    .eq_ignore_ascii_case("charset")
                    .then(|| value.trim().trim_matches(['\'', '"']).to_string())
            })
        })
    });
    if let Some(charset) = charset.and_then(|value| Encoding::for_label(value.as_bytes())) {
        let (text, _, _) = charset.decode(bytes);
        return text.into_owned();
    }
    String::from_utf8_lossy(bytes).into_owned()
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
