use cookie_store::CookieStore;
use std::fmt;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use ureq::http::header::{
    AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, LOCATION,
    PROXY_AUTHORIZATION, SET_COOKIE, TRANSFER_ENCODING, WWW_AUTHENTICATE,
};
use ureq::http::{HeaderMap, HeaderName, HeaderValue, Method, Request};
use ureq::{Agent, Proxy};
use url::Url;

pub(crate) const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const MAX_REDIRECTS: usize = 5;

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

    pub(crate) fn add_set_cookie(&self, set_cookie: &str, url: &Url) {
        let mut store = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = store.parse(set_cookie, url);
    }

    fn store_response_cookies(&self, headers: &HeaderMap, url: &Url) {
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

#[derive(Debug, Clone)]
pub(crate) enum HttpClientError {
    InvalidUrl(String),
    Timeout(String),
    Network(String),
    ResponseTooLarge { url: String, limit: usize },
}

impl fmt::Display for HttpClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(message) | Self::Timeout(message) | Self::Network(message) => {
                f.write_str(message)
            }
            Self::ResponseTooLarge { url, limit } => {
                write!(f, "response from {url} exceeds {limit} bytes")
            }
        }
    }
}

impl std::error::Error for HttpClientError {}

#[derive(Debug)]
pub(crate) struct RawHttpResponse {
    pub(crate) url: String,
    pub(crate) status: u16,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct HttpClient {
    agent: Agent,
    cookies: Option<SharedCookieStore>,
}

impl HttpClient {
    pub(crate) fn new(
        timeout_ms: u64,
        cookies: Option<SharedCookieStore>,
        proxy: Option<&str>,
    ) -> Result<Self, HttpClientError> {
        let timeout = Duration::from_millis(timeout_ms.max(1));
        let connect_timeout = timeout.min(Duration::from_secs(5));
        let mut config = Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .timeout_global(Some(timeout))
            .timeout_connect(Some(connect_timeout))
            .user_agent(DEFAULT_USER_AGENT)
            .accept_encoding("gzip, deflate");

        if let Some(proxy) = proxy {
            let proxy = Proxy::new(proxy)
                .map_err(|error| HttpClientError::InvalidUrl(error.to_string()))?;
            config = config.proxy(Some(proxy));
        }

        Ok(Self {
            agent: Agent::new_with_config(config.build()),
            cookies,
        })
    }

    pub(crate) fn standalone() -> Self {
        let config = Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .user_agent(DEFAULT_USER_AGENT)
            .accept_encoding("gzip, deflate")
            .build();
        Self {
            agent: Agent::new_with_config(config),
            cookies: Some(SharedCookieStore::default()),
        }
    }

    pub(crate) fn request_text(
        &self,
        method: Method,
        url: &str,
        headers: &[(String, String)],
        body: Option<&str>,
    ) -> Result<String, HttpClientError> {
        let response = self.execute(method, url, headers, body, None)?;
        Ok(String::from_utf8_lossy(&response.body).into_owned())
    }

    pub(crate) fn execute(
        &self,
        mut method: Method,
        url: &str,
        headers: &[(String, String)],
        body: Option<&str>,
        max_response_bytes: Option<usize>,
    ) -> Result<RawHttpResponse, HttpClientError> {
        let mut current_url =
            Url::parse(url).map_err(|error| HttpClientError::InvalidUrl(error.to_string()))?;
        ensure_http_url(&current_url)?;

        let mut base_headers = header_map(headers)?;
        let mut body = body.map(str::to_owned);

        for redirect_count in 0..=MAX_REDIRECTS {
            let mut request_headers = base_headers.clone();
            if !request_headers.contains_key(COOKIE) {
                if let Some(value) = self
                    .cookies
                    .as_ref()
                    .and_then(|cookies| cookies.get_cookie_header(&current_url))
                {
                    if let Ok(value) = HeaderValue::from_str(&value) {
                        request_headers.insert(COOKIE, value);
                    }
                }
            }

            let mut response = self.run_once(
                method.clone(),
                &current_url,
                &request_headers,
                body.as_deref(),
            )?;

            if let Some(cookies) = &self.cookies {
                cookies.store_response_cookies(response.headers(), &current_url);
            }

            let status = response.status().as_u16();
            if let Some(location) = redirect_location(status, response.headers()) {
                if redirect_count == MAX_REDIRECTS {
                    return Err(HttpClientError::Network(
                        "too many redirects (maximum 5)".to_string(),
                    ));
                }

                let next_url = current_url
                    .join(&location)
                    .map_err(|error| HttpClientError::InvalidUrl(error.to_string()))?;
                ensure_http_url(&next_url)?;

                if !same_origin(&current_url, &next_url) {
                    strip_sensitive_headers(&mut base_headers);
                }

                match status {
                    301 | 302 if method == Method::POST => {
                        method = Method::GET;
                        body = None;
                        strip_body_headers(&mut base_headers);
                    }
                    303 if method != Method::HEAD => {
                        method = Method::GET;
                        body = None;
                        strip_body_headers(&mut base_headers);
                    }
                    _ => {}
                }

                current_url = next_url;
                continue;
            }

            let response_headers = response.headers().clone();
            let is_deflate = response_headers
                .get(CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.eq_ignore_ascii_case("deflate"));
            let limit = max_response_bytes.unwrap_or(usize::MAX);
            let reader = response.body_mut().as_reader();
            let bytes = if is_deflate {
                read_limited(flate2::read::ZlibDecoder::new(reader), limit, &current_url)?
            } else {
                read_limited(reader, limit, &current_url)?
            };

            return Ok(RawHttpResponse {
                url: current_url.to_string(),
                status,
                headers: response_headers,
                body: bytes,
            });
        }

        unreachable!("redirect loop is bounded")
    }

    fn run_once(
        &self,
        method: Method,
        url: &Url,
        headers: &HeaderMap,
        body: Option<&str>,
    ) -> Result<ureq::http::Response<ureq::Body>, HttpClientError> {
        let mut builder = Request::builder().method(method).uri(url.as_str());
        let Some(target_headers) = builder.headers_mut() else {
            return Err(HttpClientError::InvalidUrl(url.to_string()));
        };
        *target_headers = headers.clone();

        let result = if let Some(body) = body {
            let request = builder
                .body(body.to_string())
                .map_err(|error| HttpClientError::Network(error.to_string()))?;
            self.agent.run(request)
        } else {
            let request = builder
                .body(())
                .map_err(|error| HttpClientError::Network(error.to_string()))?;
            self.agent.run(request)
        };

        result.map_err(map_ureq_error)
    }
}

fn read_limited(
    mut reader: impl Read,
    limit: usize,
    url: &Url,
) -> Result<Vec<u8>, HttpClientError> {
    let mut bytes = Vec::new();
    if limit == usize::MAX {
        reader
            .read_to_end(&mut bytes)
            .map_err(|error| map_io_error(error, url))?;
    } else {
        reader
            .take(limit.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| map_io_error(error, url))?;
        if bytes.len() > limit {
            return Err(HttpClientError::ResponseTooLarge {
                url: url.to_string(),
                limit,
            });
        }
    }
    Ok(bytes)
}

fn header_map(headers: &[(String, String)]) -> Result<HeaderMap, HttpClientError> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| HttpClientError::Network(error.to_string()))?;
        let value = HeaderValue::from_str(value)
            .map_err(|error| HttpClientError::Network(error.to_string()))?;
        map.append(name, value);
    }
    Ok(map)
}

fn redirect_location(status: u16, headers: &HeaderMap) -> Option<String> {
    matches!(status, 301 | 302 | 303 | 307 | 308)
        .then(|| headers.get(LOCATION)?.to_str().ok().map(str::to_owned))
        .flatten()
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn strip_sensitive_headers(headers: &mut HeaderMap) {
    for name in [AUTHORIZATION, COOKIE, PROXY_AUTHORIZATION, WWW_AUTHENTICATE] {
        headers.remove(name);
    }
}

fn strip_body_headers(headers: &mut HeaderMap) {
    for name in [CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING] {
        headers.remove(name);
    }
}

fn ensure_http_url(url: &Url) -> Result<(), HttpClientError> {
    match url.scheme() {
        "http" | "https" => Ok(()),
        scheme => Err(HttpClientError::InvalidUrl(format!(
            "unsupported URL scheme: {scheme}"
        ))),
    }
}

fn map_ureq_error(error: ureq::Error) -> HttpClientError {
    match error {
        ureq::Error::Timeout(_) => HttpClientError::Timeout(error.to_string()),
        ureq::Error::BadUri(_) | ureq::Error::InvalidProxyUrl => {
            HttpClientError::InvalidUrl(error.to_string())
        }
        _ => HttpClientError::Network(error.to_string()),
    }
}

fn map_io_error(error: std::io::Error, url: &Url) -> HttpClientError {
    if error.kind() == std::io::ErrorKind::TimedOut {
        HttpClientError::Timeout(format!("{url}: {error}"))
    } else {
        HttpClientError::Network(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn follows_redirects_and_carries_set_cookie() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for index in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 2048];
                let read = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..read]);

                if index == 0 {
                    write!(
                        stream,
                        "HTTP/1.1 302 Found\r\nLocation: /final\r\nSet-Cookie: sid=redirect; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .unwrap();
                } else {
                    assert!(request
                        .lines()
                        .any(|line| line.to_ascii_lowercase().starts_with("cookie:")
                            && line.contains("sid=redirect")));
                    let body = "done";
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                }
            }
        });

        let cookies = SharedCookieStore::default();
        let client = HttpClient::new(2_000, Some(cookies.clone()), None).unwrap();
        let response = client
            .execute(
                Method::GET,
                &format!("http://{address}/start"),
                &[],
                None,
                Some(1024),
            )
            .unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.url, format!("http://{address}/final"));
        assert_eq!(response.body, b"done");
        assert_eq!(
            cookies
                .get_cookie_header(&Url::parse(&format!("http://{address}/")).unwrap())
                .as_deref(),
            Some("sid=redirect")
        );
    }

    #[test]
    fn advertises_only_supported_content_encodings() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 2048];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            let accept_encoding = request
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("accept-encoding")
                        .then(|| value.trim().to_ascii_lowercase())
                })
                .expect("Accept-Encoding header is present");

            assert!(accept_encoding.contains("gzip"));
            assert!(accept_encoding.contains("deflate"));
            assert!(!accept_encoding.split(',').any(|value| value.trim() == "br"));

            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )
            .unwrap();
        });

        let client = HttpClient::new(2_000, None, None).unwrap();
        let response = client
            .execute(
                Method::GET,
                &format!("http://{address}/"),
                &[],
                None,
                Some(1024),
            )
            .unwrap();

        assert_eq!(response.body, b"ok");
        server.join().unwrap();
    }

    #[test]
    fn keeps_http_error_response_for_caller() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let body = "forbidden";
            write!(
                stream,
                "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });

        let client = HttpClient::new(2_000, None, None).unwrap();
        let response = client
            .execute(
                Method::GET,
                &format!("http://{address}/"),
                &[],
                None,
                Some(1024),
            )
            .unwrap();

        assert_eq!(response.status, 403);
        assert_eq!(response.body, b"forbidden");
    }

    #[test]
    fn reports_global_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(200));
        });

        let client = HttpClient::new(30, None, None).unwrap();
        let error = client
            .execute(
                Method::GET,
                &format!("http://{address}/"),
                &[],
                None,
                Some(1024),
            )
            .unwrap_err();

        assert!(matches!(error, HttpClientError::Timeout(_)));
    }
}
