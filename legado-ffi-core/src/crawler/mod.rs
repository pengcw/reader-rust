//! 同步书源 HTTP 会话与 URL 规则解析。
//!
//! 此模块从主分支的 `crawler/url_analyzer.rs` 提炼而来，但仅保留 FFI
//! 执行引擎需要的同步路径，避免为 `cdylib` 引入异步 runtime。

use crate::model::book_source::BookSource;
use base64::{engine::general_purpose, Engine};
#[cfg(test)]
use encoding_rs::Encoding;
use once_cell::sync::Lazy;
mod http;
mod response;
pub mod session;
mod url_rule;
pub(crate) use crate::runtime::SharedCookieStore;
pub(crate) use http::{
    HttpClient, HttpClientError, RawHttpResponse, DEFAULT_USER_AGENT, DEFAULT_WEBVIEW_USER_AGENT,
};
pub(crate) use response::{decode_body, format_analyzed_body};
pub use session::{current_active_session, with_active_session, ActiveSession, ExecuteSession};
pub use url_rule::{analyze_url, analyze_url_with_context, UrlRuleContext};
pub(crate) use url_rule::{analyze_url_with_headers, split_url_options, strip_url_options};
#[cfg(test)]
use url_rule::parse_source_headers;

use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use ureq::http::header::CONTENT_TYPE;
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

/// 每次 `reader_execute` 使用一个同步会话。普通请求遵循书源 CookieJar 策略；
/// WebView 请求始终使用浏览器式 Cookie 会话，以匹配 Android WebView 行为。
#[derive(Clone)]
pub struct HttpSession {
    client: HttpClient,
    webview_client: HttpClient,
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
    pub render_with_rakers: bool,
    pub(crate) body_js: Option<BodyJs>,
}

#[derive(Debug, Clone)]
pub(crate) struct BodyJs {
    script: String,
    key: String,
    page: i32,
    source_key: String,
    js_lib: Option<String>,
    bindings: Option<HashMap<String, Value>>,
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
    Rule(String),
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
            let webview_cookies = active.cookie_store().clone();
            let client = build_client(
                timeout_ms,
                cookie_enabled.then(|| webview_cookies.clone()),
                None,
            )?;
            let webview_client = if cookie_enabled {
                client.clone()
            } else {
                build_client(timeout_ms, Some(webview_cookies), None)?
            };
            return Ok(Self {
                client,
                webview_client,
            });
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
                return Ok(Self {
                    webview_client: client.clone(),
                    client,
                });
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
            return Ok(Self {
                webview_client: client.clone(),
                client,
            });
        }

        Ok(Self {
            client: build_client(timeout_ms, None, None)?,
            webview_client: build_client(timeout_ms, Some(SharedCookieStore::default()), None)?,
        })
    }

    pub(crate) fn client(&self) -> &HttpClient {
        &self.client
    }

    pub(crate) fn webview_client(&self) -> &HttpClient {
        &self.webview_client
    }

    pub fn fetch(
        &self,
        spec: &RequestSpec,
        max_response_bytes: usize,
    ) -> Result<HttpResponse, FetchError> {
        if let Some(response) = data_uri_response(spec, Some(max_response_bytes)) {
            let response = response.map_err(map_http_client_error)?;
            let body =
                format_analyzed_body(spec, &response.body, String::new(), None, &response.url)
                    .map_err(FetchError::Rule)?;
            return Ok(HttpResponse {
                url: response.url,
                status: response.status,
                headers: HashMap::new(),
                body,
            });
        }
        let proxy = spec
            .proxy
            .as_deref()
            .filter(|value| !value.trim().is_empty());
        let client = if spec.render_with_rakers {
            match proxy {
                Some(proxy) => self
                    .webview_client
                    .with_proxy(proxy)
                    .map_err(map_http_client_error)?,
                None => self.webview_client.clone(),
            }
        } else if let Some(proxy) = proxy {
            build_client_from_existing_policy(spec, proxy)?
        } else {
            self.client.clone()
        };

        let mut headers = spec.headers.clone();
        if spec.render_with_rakers {
            if let Ok(url) = url::Url::parse(&spec.url) {
                let cookie = headers
                    .iter()
                    .filter(|(name, _)| name.eq_ignore_ascii_case("cookie"))
                    .map(|(_, value)| value.as_str())
                    .collect::<Vec<_>>()
                    .join("; ");
                if !cookie.is_empty() && client.seed_cookie_header(&cookie, &url) {
                    headers.retain(|(name, _)| !name.eq_ignore_ascii_case("cookie"));
                }
            }
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

                    let body = format_analyzed_body(
                        spec,
                        &response.body,
                        decoded_body,
                        content_type.as_deref(),
                        &url,
                    )
                    .map_err(FetchError::Rule)?;
                    let body = if spec.render_with_rakers {
                        render_with_rakers(&client, spec, &url, &body, max_response_bytes)?
                    } else {
                        body
                    };
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

const RAKERS_MAX_REMOTE_SCRIPTS: usize = 8;
const RAKERS_MAX_REQUESTS: usize = 32;
const RAKERS_SCRIPT_TIMEOUT: Duration = Duration::from_secs(3);
const RAKERS_RENDER_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
struct RakersHttpTransport {
    client: HttpClient,
    max_response_bytes: usize,
}

impl rakers::HttpTransport for RakersHttpTransport {
    fn execute(&self, request: rakers::HttpRequest) -> Result<rakers::HttpResponse, String> {
        let method = Method::from_bytes(request.method.as_bytes())
            .map_err(|error| format!("invalid HTTP method: {error}"))?;
        let response = self
            .client
            .execute(
                method,
                &request.url,
                &request.headers,
                request.body.as_deref(),
                Some(self.max_response_bytes.max(1)),
            )
            .map_err(|error| error.to_string())?;
        let headers = response
            .headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_string(), value.to_string()))
            })
            .collect();
        Ok(rakers::HttpResponse {
            url: response.url,
            status: response.status,
            headers,
            body: String::from_utf8_lossy(&response.body).into_owned(),
        })
    }
}

pub(crate) fn rakers_http_transport(
    client: &HttpClient,
    max_response_bytes: usize,
) -> std::sync::Arc<dyn rakers::HttpTransport> {
    std::sync::Arc::new(RakersHttpTransport {
        client: client.clone(),
        max_response_bytes,
    })
}

fn render_rakers_page(
    client: &HttpClient,
    page_url: Option<&str>,
    html: &str,
    final_script: Option<&str>,
    user_agent: Option<String>,
    proxy: Option<String>,
    clean: bool,
    max_response_bytes: usize,
) -> Result<rakers::RenderOutput, FetchError> {
    let limit = max_response_bytes.max(1);
    // Do not copy raw source credentials into page-controlled requests. Cookies
    // flow through the shared WebView-style jar with normal domain/path rules.
    let config = rakers::HttpConfig {
        user_agent,
        headers: Vec::new(),
        proxy,
        forward_headers: false,
        transport: Some(rakers_http_transport(client, max_response_bytes)),
        max_requests: Some(RAKERS_MAX_REQUESTS),
        max_response_bytes: Some(max_response_bytes.max(1)),
        render_timeout: Some(RAKERS_RENDER_TIMEOUT),
    };
    let rendered = rakers::render_detailed(
        html,
        false,
        page_url,
        &config,
        clean,
        Some(RAKERS_MAX_REMOTE_SCRIPTS),
        Some(RAKERS_SCRIPT_TIMEOUT),
        final_script,
    )
    .map_err(|error| FetchError::Rule(format!("Rakers render failed: {error}")))?;
    if rendered.html.len() > limit
        || rendered
            .script_result
            .as_ref()
            .is_some_and(|result| result.len() > limit)
    {
        return Err(FetchError::ResponseTooLarge {
            url: page_url.unwrap_or_default().to_string(),
            limit,
        });
    }
    Ok(rendered)
}

pub(crate) fn render_webview_with_rakers(
    client: &HttpClient,
    page_url: Option<&str>,
    html: &str,
    final_script: Option<&str>,
    max_response_bytes: usize,
) -> Result<rakers::RenderOutput, FetchError> {
    let limit = max_response_bytes.max(1);
    if html.len() > limit {
        return Err(FetchError::ResponseTooLarge {
            url: page_url.unwrap_or_default().to_string(),
            limit,
        });
    }
    render_rakers_page(
        client,
        page_url,
        html,
        final_script,
        Some(DEFAULT_WEBVIEW_USER_AGENT.to_string()),
        None,
        false,
        max_response_bytes,
    )
}

fn render_with_rakers(
    client: &HttpClient,
    spec: &RequestSpec,
    page_url: &str,
    html: &str,
    max_response_bytes: usize,
) -> Result<String, FetchError> {
    let user_agent = spec
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        .map(|(_, value)| value.clone())
        .or_else(|| Some(DEFAULT_USER_AGENT.to_string()));
    Ok(render_rakers_page(
        client,
        Some(page_url),
        html,
        None,
        user_agent,
        spec.proxy.clone(),
        true,
        max_response_bytes,
    )?
    .html)
}

/// Typed data URIs carry bytes locally; type-less data requests remain unsupported.
fn data_uri_response(
    spec: &RequestSpec,
    max_response_bytes: Option<usize>,
) -> Option<Result<RawHttpResponse, HttpClientError>> {
    if !spec.url.starts_with("data:") {
        return None;
    }
    Some((|| {
        let invalid = || HttpClientError::InvalidUrl("invalid typed Base64 data URI".to_string());
        if spec.response_type.is_none() {
            return Err(invalid());
        }
        let (_, payload) = spec.url.split_once(";base64,").ok_or_else(invalid)?;
        // Android Base64.DEFAULT accepts whitespace and optional padding.
        // Bound decoded allocation before copying/decoding the payload.
        let digits = payload
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace() && *byte != b'=')
            .count();
        let limit = max_response_bytes
            .unwrap_or(crate::executor::DEFAULT_MAX_RESPONSE_BYTES)
            .max(1);
        let symbols = payload
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .count();
        if digits.saturating_mul(6) / 8 > limit || symbols > limit.div_ceil(3).saturating_mul(4) {
            return Err(HttpClientError::ResponseTooLarge {
                url: "data:".to_string(),
                limit,
            });
        }
        let compact: Vec<u8> = payload
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        let config = general_purpose::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent);
        let body = general_purpose::GeneralPurpose::new(&base64::alphabet::STANDARD, config)
            .decode(&compact)
            .map_err(|_| invalid())?;
        if body.len() > limit {
            return Err(HttpClientError::ResponseTooLarge {
                url: "data:".to_string(),
                limit,
            });
        }
        Ok(RawHttpResponse {
            url: spec.url.clone(),
            status: 200,
            headers: HeaderMap::new(),
            body,
        })
    })())
}

/// Execute an AnalyzeUrl request for JavaScript APIs while preserving its request
/// options and the source-bound cookie session. Unlike `fetch`, this returns
/// non-2xx HTTP responses instead of converting their status into an error.
pub(crate) fn execute_request_spec(
    client: &HttpClient,
    spec: &RequestSpec,
) -> Result<RawHttpResponse, HttpClientError> {
    execute_request_spec_limited(client, spec, None)
}

pub(crate) fn execute_request_spec_limited(
    client: &HttpClient,
    spec: &RequestSpec,
    max_response_bytes: Option<usize>,
) -> Result<RawHttpResponse, HttpClientError> {
    if let Some(response) = data_uri_response(spec, max_response_bytes) {
        return response;
    }
    let client = match spec
        .proxy
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        Some(proxy) => client.with_proxy(proxy)?,
        None => client.clone(),
    };
    let retries = spec.retry.min(3);
    let mut last_error = None;

    for attempt in 0..=retries {
        match client.execute(
            spec.method.clone(),
            &spec.url,
            &spec.headers,
            spec.body.as_deref(),
            max_response_bytes,
        ) {
            Ok(response) if response.status >= 500 && attempt < retries => continue,
            Ok(response) => return Ok(response),
            Err(error @ HttpClientError::InvalidUrl(_))
            | Err(error @ HttpClientError::ResponseTooLarge { .. }) => return Err(error),
            Err(error) if attempt < retries => last_error = Some(error),
            Err(error) => return Err(error),
        }
    }

    Err(last_error.unwrap_or_else(|| HttpClientError::Network("request failed".to_string())))
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

fn map_http_client_error(error: HttpClientError) -> FetchError {
    match error {
        HttpClientError::InvalidUrl(message) => FetchError::InvalidUrl(message),
        HttpClientError::Timeout(message) => FetchError::Timeout { url: None, message },
        HttpClientError::Network(message) => FetchError::Network(message),
        HttpClientError::ResponseTooLarge { url, limit } => {
            FetchError::ResponseTooLarge { url, limit }
        }
    }
}

fn build_client(
    timeout_ms: u64,
    cookies: Option<SharedCookieStore>,
    proxy: Option<&str>,
) -> Result<HttpClient, FetchError> {
    HttpClient::new(timeout_ms, cookies, proxy).map_err(map_http_client_error)
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
    fn loose_source_headers_preserve_quoted_delimiters() {
        for raw in [
            r#"{'User-Agent': 'Bot, Extra:1', 'Referer': 'https://a.test/a,b', 'X-Empty': ''}"#,
            r#"{User-Agent: "Bot, Extra:1", Referer: "https://a.test/a,b", X-Empty: ""}"#,
        ] {
            assert_eq!(
                parse_source_headers(raw),
                vec![
                    ("User-Agent".to_string(), "Bot, Extra:1".to_string()),
                    ("Referer".to_string(), "https://a.test/a,b".to_string()),
                    ("X-Empty".to_string(), "".to_string()),
                ]
            );
        }
        assert_eq!(
            parse_source_headers(r#"{'X-Note': 'a\'b,c', 'X-End': 'ok'}"#),
            vec![
                ("X-Note".to_string(), r#"a\'b,c"#.to_string()),
                ("X-End".to_string(), "ok".to_string())
            ],
        );
    }

    #[test]
    fn source_headers_keep_json_decoding_and_unquoted_fallback() {
        let headers = parse_source_headers(r#"{"X-Note":"a\"b,c", "X-Number":7}"#);
        assert!(headers.contains(&("X-Note".to_string(), "a\"b,c".to_string())));
        assert!(headers.contains(&("X-Number".to_string(), "7".to_string())));
        assert_eq!(
            parse_source_headers("X-One: first, X-Two: token:part"),
            vec![
                ("X-One".to_string(), "first".to_string()),
                ("X-Two".to_string(), "token:part".to_string())
            ]
        );
    }

    #[test]
    fn android_url_methods_send_expected_requests() {
        use std::io::{BufRead, Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let source = BookSource {
            book_source_url: base.clone(),
            enabled_cookie_jar: Some(false),
            ..Default::default()
        };
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut first_line = String::new();
                reader.read_line(&mut first_line).unwrap();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                requests.push((first_line, String::from_utf8(body).unwrap()));
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .unwrap();
            }
            requests
        });
        let session = HttpSession::new(&source, 3000).unwrap();
        for (method, body) in [
            ("GET", ""),
            ("POST", "q=hello"),
            ("HEAD", ""),
            ("PUT", ""), // Android's unknown URL method falls back to GET.
        ] {
            let rule = format!(r#"/method,{{"method":"{method}","body":"{body}"}}"#);
            let spec = analyze_url(&rule, "", 1, &base, &source).unwrap();
            assert_eq!(
                spec.method.to_string(),
                if method == "PUT" { "GET" } else { method }
            );
            session.fetch(&spec, 1024).unwrap();
        }
        let requests = server.join().unwrap();
        for (index, method) in ["GET", "POST", "HEAD", "GET"].into_iter().enumerate() {
            assert!(requests[index].0.starts_with(&format!("{method} /method ")));
        }
        assert_eq!(requests[1].1, "q=hello");
        assert_eq!(requests[3].1, "");
    }

    #[test]
    fn android_body_js_transforms_response_unless_xml_header_is_inserted() {
        use std::io::Write;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let source = BookSource {
            book_source_url: base.clone(),
            enabled_cookie_jar: Some(false),
            ..Default::default()
        };
        let server = std::thread::spawn(move || {
            for (content_type, body) in [
                ("text/plain", "original"),
                ("application/xml", "<root/>"),
                ("application/xml", "<?xml version=\"1.0\"?><root/>"),
                ("text/plain", "original"),
                ("text/plain", "original"),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                crate::util::test_http::consume_request(&mut stream);
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let session = HttpSession::new(&source, 3000).unwrap();
        let context = UrlRuleContext {
            chapter_title: Some("Chapter".to_string()),
            ..Default::default()
        };
        let script = "result + ':' + title + ':' + key + ':' + page";
        let rule = format!(r#"/page,{{"bodyJs":"{script}"}}"#);
        let spec =
            analyze_url_with_context(&rule, "word", 2, &base, &source, Some(&context)).unwrap();
        let plain = session.fetch(&spec, 1024).unwrap();
        assert_eq!(plain.body, "original:Chapter:word:2");
        assert_eq!(plain.status, 200);
        assert_eq!(
            session.fetch(&spec, 1024).unwrap().body,
            "<?xml version=\"1.0\"?><root/>"
        );
        assert_eq!(
            session.fetch(&spec, 1024).unwrap().body,
            "<?xml version=\"1.0\"?><root/>:Chapter:word:2"
        );

        let hex_spec = analyze_url(
            &format!(r#"/page,{{"type":"hex","bodyJs":"{script}"}}"#),
            "",
            1,
            &base,
            &source,
        )
        .unwrap();
        assert_eq!(
            session.fetch(&hex_spec, 1024).unwrap().body,
            "6f726967696e616c"
        );
        let bad_spec = analyze_url(
            r#"/page,{"bodyJs":"throw new Error('boom')"}"#,
            "",
            1,
            &base,
            &source,
        )
        .unwrap();
        assert!(
            matches!(session.fetch(&bad_spec, 1024), Err(FetchError::Rule(message)) if message.contains("bodyJs") && message.contains("boom"))
        );
        server.join().unwrap();
    }

    #[test]
    fn webview_option_follows_android_value_contract() {
        let base = "https://webview-value.test";
        let source = BookSource {
            book_source_url: base.into(),
            ..Default::default()
        };
        assert!(
            !analyze_url("/page", "", 1, base, &source)
                .unwrap()
                .render_with_rakers
        );
        for (value, expected) in [
            (serde_json::json!(null), false),
            (serde_json::json!(false), false),
            (serde_json::json!(""), false),
            (serde_json::json!("false"), false),
            (serde_json::json!(true), true),
            (serde_json::json!("true"), true),
            (serde_json::json!(0), true),
            (serde_json::json!(1), true),
            (serde_json::json!(-1), true),
            (serde_json::json!("FALSE"), true),
            (serde_json::json!(" false "), true),
            (serde_json::json!([]), true),
            (serde_json::json!({}), true),
        ] {
            let rule = format!(
                "/page,{}",
                serde_json::json!({"webView":value,"headers":{"X-Test":"keep"}})
            );
            let spec = analyze_url(&rule, "", 1, base, &source).unwrap();
            assert_eq!(spec.render_with_rakers, expected, "webView={value}");
            assert_eq!(spec.url, format!("{base}/page"));
            assert!(spec
                .headers
                .iter()
                .any(|(name, value)| name == "X-Test" && value == "keep"));
        }
    }

    #[test]
    fn webview_opt_in_renders_inline_javascript_before_rule_parsing() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let source = BookSource {
            book_source_url: base.clone(),
            enabled_cookie_jar: Some(false),
            ..Default::default()
        };
        let html = r#"<!doctype html><html><body><div id="app">Loading</div><script>document.getElementById('app').innerHTML = '<p>' + 'hydrated' + ' chapter' + '</p>';</script></body></html>"#;
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 2048];
                let _ = stream.read(&mut request);
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html}", html.len()).unwrap();
            }
        });
        let session = HttpSession::new(&source, 3000).unwrap();
        let plain_spec = analyze_url("/page", "", 1, &base, &source).unwrap();
        let rendered_spec =
            analyze_url(r#"/page,{"webView":true}"#, "", 1, &base, &source).unwrap();
        assert!(!plain_spec.render_with_rakers);
        assert!(rendered_spec.render_with_rakers);

        let plain = session.fetch(&plain_spec, 4096).unwrap();
        let rendered = session.fetch(&rendered_spec, 4096).unwrap();
        assert!(plain.body.contains("Loading"));
        assert!(!plain.body.contains("<p>hydrated chapter</p>"));
        assert!(rendered.body.contains("<p>hydrated chapter</p>"));
        server.join().unwrap();
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
    fn android_source_header_uses_source_and_session_before_url_options() {
        use crate::crawler::session::{with_active_session, ExecuteSession};

        let source = test_source(Some(
            r#"@js:JSON.stringify({'X-Source':source.getKey(),'X-Token':source.getVariable(),'X-Order':'source'})"#,
        ));
        let request = r#"/chapter,{"headers":{"X-Order":"url"}}"#;
        let state = |token: &str| ExecuteSession {
            header: Some(serde_json::json!({"X-Order":"login","X-Login":"active"})),
            variables: Some(HashMap::from([(
                "variable".to_string(),
                Value::String(token.to_string()),
            )])),
            ..Default::default()
        };
        for token in ["first-user", "second-user"] {
            let (spec, _) =
                with_active_session(Some(&state(token)), &source.book_source_url, |_| {
                    analyze_url(request, "", 1, &source.book_source_url, &source).unwrap()
                });
            let header = |name: &str| {
                spec.headers
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(header("X-Source"), Some(source.book_source_url.as_str()));
            assert_eq!(header("X-Token"), Some(token));
            assert_eq!(header("X-Login"), Some("active"));
            assert_eq!(header("X-Order"), Some("url"));
        }
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
            crate::parser::js::eval_js_url_template(
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
    fn compat_url_rules_receive_book_and_chapter_scope() {
        let source = test_source(None);
        let context = UrlRuleContext {
            book_variable: Some(r#"{"token":"BOOK"}"#.to_string()),
            chapter_variable: Some(r#"{"cid":"CHAPTER"}"#.to_string()),
            book_name: Some("Book Name".to_string()),
            chapter_title: Some("Chapter Title".to_string()),
            book_fields: HashMap::new(),
            chapter_fields: serde_json::Map::new(),
        };
        let spec = analyze_url_with_context(
            "/{{book.variableMap.token}}/{{chapter.variableMap.cid}}/{{@get:{cid}}}/{{title}},{\"js\":\"result + '?name=' + encodeURIComponent(book.bookName)\"}",
            "",
            1,
            "https://a.test",
            &source,
            Some(&context),
        )
        .unwrap();

        assert_eq!(
            spec.url,
            "https://a.test/BOOK/CHAPTER/CHAPTER/Chapter%20Title?name=Book%20Name"
        );
    }

    #[test]
    fn compat_url_book_fields_do_not_collide_with_variable_map() {
        let source = test_source(None);
        let context = UrlRuleContext {
            book_variable: Some(r#"{"kind":"VARIABLE"}"#.to_string()),
            book_fields: HashMap::from([("kind".to_string(), "FIELD".to_string())]),
            ..Default::default()
        };
        let spec = analyze_url_with_context(
            "/{{book.kind}}/{{book.variableMap.kind}},{\"js\":\"result + '?direct=' + book.kind + '&variable=' + book.variableMap.kind\"}",
            "",
            1,
            "https://a.test",
            &source,
            Some(&context),
        )
        .unwrap();

        assert_eq!(
            spec.url,
            "https://a.test/FIELD/VARIABLE?direct=FIELD&variable=VARIABLE"
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
    fn android_url_option_js_mutates_request_local_headers() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let size = stream.read(&mut request).unwrap();
            let text = String::from_utf8_lossy(&request[..size]).to_ascii_lowercase();
            assert!(text.starts_with("get /rewritten http/1.1"));
            assert!(text.contains("x-js: dynamic\r\n"));
            assert!(text.contains("x-order: javascript\r\n"));
            assert!(!text.contains("x-removed:"));
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )
            .unwrap();
        });
        let source = BookSource {
            book_source_url: base.clone(),
            header: Some(r#"{"X-Order":"source","X-Removed":"old"}"#.to_string()),
            enabled_cookie_jar: Some(false),
            ..Default::default()
        };
        let script = "java.headerMap.put('X-Js','dynamic'); java.headerMap['X-Order']='javascript'; java.headerMap.remove('X-Removed'); java.headerMap.get('X-Order') === 'javascript' ? '/rewritten' : '/wrong'";
        let rule = format!(
            "/start,{}",
            serde_json::json!({"headers":{"X-Order":"option"},"js":script})
        );
        let spec = analyze_url(&rule, "", 1, &base, &source).unwrap();
        assert_eq!(spec.url, format!("{base}/rewritten"));
        assert_eq!(
            HttpSession::new(&source, 3000)
                .unwrap()
                .fetch(&spec, 1024)
                .unwrap()
                .body,
            "ok"
        );
        server.join().unwrap();

        let next = analyze_url("/next", "", 1, &base, &source).unwrap();
        assert!(!next
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("X-Js")));
        assert!(next
            .headers
            .iter()
            .any(|(name, value)| name == "X-Order" && value == "source"));

        let error = analyze_url(
            r#"/bad,{"js":"java.headerMap.put('X-Js','bad'); throw new Error('stop')"}"#,
            "",
            1,
            &base,
            &source,
        )
        .unwrap_err();
        assert!(error.contains("URL option JavaScript failed"));
        let after_error = analyze_url("/next", "", 1, &base, &source).unwrap();
        assert!(!after_error.headers.iter().any(|(name, _)| name == "X-Js"));
    }

    #[test]
    fn android_url_js_stages_share_request_headers_in_order() {
        let source = test_source(Some(r#"{"X-Flow":"source"}"#));
        let base = "https://example.com";
        let rule = r#"<js>java.headerMap.put('X-Flow','segment'); '/chapter'</js>@result/{{java.headerMap.get('X-Flow') === 'segment' ? (java.headerMap.put('X-Flow','template'), 'read') : 'wrong'}},{"headers":{"X-Flow":"option"},"js":"java.headerMap.get('X-Flow') === 'option' ? (java.headerMap.put('X-Flow','final'), result) : '/wrong'"}"#;
        let spec = analyze_url(rule, "", 1, base, &source).unwrap();
        assert_eq!(spec.url, "https://example.com/chapter/read");
        assert!(spec
            .headers
            .iter()
            .any(|(name, value)| name == "X-Flow" && value == "final"));

        let without_options = analyze_url(
            r#"<js>java.headerMap.put('X-Flow','segment'); '/chapter'</js>@result/{{java.headerMap.get('X-Flow') === 'segment' ? (java.headerMap.put('X-Flow','template'), 'read') : 'wrong'}}"#,
            "", 1, base, &source,
        ).unwrap();
        assert_eq!(without_options.url, "https://example.com/chapter/read");
        assert!(without_options
            .headers
            .iter()
            .any(|(name, value)| name == "X-Flow" && value == "template"));
        let next = analyze_url("/next", "", 1, base, &source).unwrap();
        assert!(next
            .headers
            .iter()
            .any(|(name, value)| name == "X-Flow" && value == "source"));
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
            format_analyzed_body(
                &xml,
                b"<root/>",
                "<root/>".into(),
                Some("application/xml"),
                "https://a.test/submit",
            )
            .unwrap(),
            "<?xml version=\"1.0\"?><root/>"
        );
        assert_eq!(
            format_analyzed_body(
                &json,
                &[0, 255],
                String::new(),
                None,
                "https://a.test/submit"
            )
            .unwrap(),
            "00ff"
        );
        assert_eq!(
            format_analyzed_body(
                &xml,
                b"<?xml version='1.0'?>",
                "<?xml version='1.0'?>".into(),
                Some("text/xml"),
                "https://a.test/submit",
            )
            .unwrap(),
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
