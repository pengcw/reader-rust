//! HTTP/WebView bridge used by the QuickJS facade.
//!
//! Keep crawler transport details in this module so `js.rs` and `js_state.rs`
//! do not need to depend directly on crawler networking types.

pub(crate) use crate::crawler::HttpClient;
use crate::crawler::{
    analyze_url_with_headers, decode_body, execute_request_spec, execute_request_spec_limited,
    format_analyzed_body, render_webview_with_rakers, HttpClientError, RequestSpec,
    DEFAULT_WEBVIEW_USER_AGENT, BrowserTimeouts,
};
use crate::model::book_source::BookSource;
use crate::parser::js_compat::json_value_to_string;
use crate::parser::js_state::ACTIVE_JS_BOOK_SOURCE;
use base64::Engine;
use encoding_rs::{Encoding, UTF_8};
use serde_json::Value as JsonValue;
use std::cell::RefCell;
use std::sync::LazyLock as Lazy;
use ureq::http::Method;

#[derive(Clone)]
pub(super) struct JsHttpContext {
    request_client: HttpClient,
    webview_client: HttpClient,
}

thread_local! {
    static BROWSER_TIMEOUTS: RefCell<BrowserTimeouts> = RefCell::new(BrowserTimeouts::default());
}

pub(crate) fn with_browser_http_clients<T>(
    request_client: &HttpClient,
    webview_client: &HttpClient,
    source: &BookSource,
    timeouts: BrowserTimeouts,
    f: impl FnOnce() -> T,
) -> T {
    BROWSER_TIMEOUTS.with(|cell| {
        crate::util::scoped::with_scoped_value(cell, timeouts, || {
            with_js_http_clients(request_client, webview_client, source, f)
        })
    })
}

static JS_HTTP_CLIENT: Lazy<HttpClient> = Lazy::new(HttpClient::standalone);

thread_local! {
    // reader_execute installs both sides of its source-bound HTTP session here:
    // ordinary JsExtensions calls keep native request policy, while WebView calls
    // use the browser-style client without collapsing their cookie semantics.
    pub(super) static ACTIVE_JS_HTTP_CONTEXT: RefCell<Option<JsHttpContext>> =
        const { RefCell::new(None) };
}

/// Bind one synchronous HTTP client for both request and WebView paths.
/// Kept for reader_eval/tests that do not have a full HttpSession.
pub(crate) fn with_js_http_client<T>(client: &HttpClient, f: impl FnOnce() -> T) -> T {
    let context = JsHttpContext {
        request_client: client.clone(),
        webview_client: client.clone(),
    };
    ACTIVE_JS_HTTP_CONTEXT
        .with(|cell| crate::util::scoped::with_scoped_value(cell, Some(context), f))
}

/// Bind the distinct native-request and browser-style clients used by reader_execute.
pub(crate) fn with_js_http_clients<T>(
    request_client: &HttpClient,
    webview_client: &HttpClient,
    source: &BookSource,
    f: impl FnOnce() -> T,
) -> T {
    let context = JsHttpContext {
        request_client: request_client.clone(),
        webview_client: webview_client.clone(),
    };
    ACTIVE_JS_BOOK_SOURCE.with(|source_cell| {
        crate::util::scoped::with_scoped_value(source_cell, Some(source.clone()), || {
            ACTIVE_JS_HTTP_CONTEXT.with(|http_cell| {
                crate::util::scoped::with_scoped_value(http_cell, Some(context), f)
            })
        })
    })
}

pub(crate) fn with_js_http_context<T>(
    client: &HttpClient,
    source: &BookSource,
    f: impl FnOnce() -> T,
) -> T {
    with_js_http_clients(client, client, source, f)
}

fn active_js_http_client() -> HttpClient {
    ACTIVE_JS_HTTP_CONTEXT
        .with(|cell| {
            cell.borrow()
                .as_ref()
                .map(|context| context.request_client.clone())
        })
        .unwrap_or_else(|| JS_HTTP_CLIENT.clone())
}

fn active_js_webview_client() -> HttpClient {
    ACTIVE_JS_HTTP_CONTEXT
        .with(|cell| {
            cell.borrow()
                .as_ref()
                .map(|context| context.webview_client.clone())
        })
        .unwrap_or_else(|| JS_HTTP_CLIENT.clone())
}

pub(super) fn webview_user_agent() -> String {
    DEFAULT_WEBVIEW_USER_AGENT.to_string()
}

pub(super) fn decode_archive_text(bytes: &[u8], charset: &str) -> Option<String> {
    if bytes.len() > 262_144 {
        return None;
    }
    let label = charset.trim();
    if !label.is_empty() && encoding_rs::Encoding::for_label(label.as_bytes()).is_none() {
        return None;
    }
    Some(decode_body(
        bytes,
        (!label.is_empty()).then_some(label),
        None,
    ))
}

pub(super) fn resolve_js_lib_entry(entry: &str) -> anyhow::Result<String> {
    let value = entry.trim();
    if url::Url::parse(value).is_ok_and(|url| matches!(url.scheme(), "http" | "https")) {
        return Ok(active_js_http_client().request_text(Method::GET, value, &[], None)?);
    }
    Ok(value.to_string())
}

pub(super) fn java_web_view(html: &str, url: &str, js: &str) -> Option<String> {
    render_webview(html, url, js, crate::executor::DEFAULT_MAX_RESPONSE_BYTES).map(|(html, _)| html)
}

// Shared by the JS facade and the native preview operation.
pub(crate) fn render_webview(
    html: &str,
    url: &str,
    js: &str,
    limit: usize,
) -> Option<(String, Option<String>)> {
    let client = active_js_webview_client();
    let url = url.trim();

    let (page_html, page_url) = if !html.trim().is_empty() {
        (html.to_string(), (!url.is_empty()).then(|| url.to_string()))
    } else {
        if url.is_empty() {
            return None;
        }
        let headers = [("User-Agent".to_string(), webview_user_agent())];
        let response = if url.starts_with("data:") {
            // Reuse the existing typed data-URI decoding and size limits.
            let spec = RequestSpec {
                url: url.to_string(),
                method: Method::GET,
                headers: Vec::new(),
                body: None,
                charset: None,
                retry: 0,
                proxy: None,
                response_type: Some("base64".to_string()),
                render_with_rakers: false,
                body_js: None,
            };
            execute_request_spec_limited(&client, &spec, Some(limit)).ok()?
        } else {
            client
                .execute(Method::GET, url, &headers, None, Some(limit))
                .ok()?
        };
        let content_type = response
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        (
            decode_body(&response.body, None, content_type.as_deref()),
            (!url.starts_with("data:")).then_some(response.url),
        )
    };

    let final_script = (!js.trim().is_empty()).then_some(js);
    let output = render_webview_with_rakers(
        &client,
        page_url.as_deref(),
        &page_html,
        final_script,
        limit,
        BROWSER_TIMEOUTS.with(|cell| *cell.borrow()),
    )
    .ok()?;
    let rendered = if final_script.is_some() {
        output.script_result?
    } else {
        output.html
    };
    Some((rendered, page_url))
}

pub(super) fn java_request_simple(
    method: &str,
    url: &str,
    body: Option<String>,
    headers_json: &str,
) -> anyhow::Result<String> {
    let method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    Ok(active_js_http_client().request_text(
        method,
        url.trim(),
        &java_request_headers(headers_json),
        body.as_deref(),
    )?)
}

pub(super) fn java_request_simple_response(
    method: &str,
    url: &str,
    body: Option<String>,
    headers_json: &str,
) -> String {
    java_request_simple_response_with_client(
        method,
        url,
        body,
        headers_json,
        &active_js_http_client(),
    )
}

fn java_request_simple_response_with_client(
    method: &str,
    url: &str,
    body: Option<String>,
    headers_json: &str,
    client: &HttpClient,
) -> String {
    let method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    let response = client.execute_once(
        method,
        url.trim(),
        &java_request_headers(headers_json),
        body.as_deref(),
        None,
    );
    let payload = match response {
        Ok(response) => {
            let headers = response
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    value.to_str().ok().map(|value| {
                        (
                            name.as_str().to_string(),
                            JsonValue::String(value.to_string()),
                        )
                    })
                })
                .collect::<serde_json::Map<String, JsonValue>>();
            let mut header_values = std::collections::BTreeMap::<String, Vec<String>>::new();
            for (name, value) in &response.headers {
                if let Ok(value) = value.to_str() {
                    header_values
                        .entry(name.as_str().to_string())
                        .or_default()
                        .push(value.to_string());
                }
            }
            let charset = response
                .headers
                .get(ureq::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(response_charset);
            let encoding = charset.unwrap_or(UTF_8);
            let body = encoding
                .decode_without_bom_handling(&response.body)
                .0
                .into_owned();
            let status = response.status;
            serde_json::json!({
                "__ffiStrResponse": true,
                "body": body,
                "charset": charset.map(Encoding::name),
                "bodyBase64": base64::engine::general_purpose::STANDARD.encode(&response.body),
                "url": response.url,
                "code": status,
                "message": http_status_message(status),
                "headers": headers,
                "headerValues": header_values,
                "isSuccessful": (200..300).contains(&status),
            })
        }
        Err(error) => serde_json::json!({
            "__ffiStrResponse": true,
            "body": error.to_string(),
            "url": url.trim(),
            "code": 0,
            "message": "",
            "headers": {},
            "isSuccessful": false,
        }),
    };
    payload.to_string()
}

pub(super) fn java_archive_input(url: &str) -> String {
    const LIMIT: usize = 512 * 1024;
    let result = (|| {
        if url.len() > 8192 {
            return Err(("invalid_argument", "archive URL too long"));
        }
        let client = active_js_http_client();
        let source = ACTIVE_JS_BOOK_SOURCE.with(|cell| cell.borrow().clone());
        let response = if let Some(source) = source {
            let spec = analyze_url_with_headers(url, "", 0, &source.book_source_url, &source, None)
                .map_err(|_| ("invalid_argument", "invalid archive request"))?;
            execute_request_spec_limited(&client, &spec, Some(LIMIT))
        } else {
            client.execute(Method::GET, url, &[], None, Some(LIMIT))
        }
        .map_err(|error| match error {
            HttpClientError::ResponseTooLarge { .. } => {
                ("limit_exceeded", "archive response too large")
            }
            _ => ("network_error", "archive request failed"),
        })?;
        if !(200..300).contains(&response.status) {
            return Err(("network_error", "archive HTTP status is unsuccessful"));
        }
        Ok(response.body)
    })();

    match result {
        Ok(bytes) => serde_json::json!({"ok":true,"data":bytes}),
        Err((kind, message)) => {
            serde_json::json!({"ok":false,"error":{"kind":kind,"message":message}})
        }
    }
    .to_string()
}

pub(super) fn java_analyzed_request_body(url: &str) -> String {
    let payload = java_analyzed_request_response(url, "");
    serde_json::from_str::<JsonValue>(&payload)
        .ok()
        .and_then(|value| value.get("body").map(json_value_to_string))
        .unwrap_or_default()
}

pub(super) fn java_analyzed_request_response(url: &str, headers_json: &str) -> String {
    let client = active_js_http_client();
    let source = ACTIVE_JS_BOOK_SOURCE.with(|cell| cell.borrow().clone());
    let Some(source) = source else {
        let payload =
            java_request_simple_response_with_client("GET", url, None, headers_json, &client);
        if let Ok(value) = serde_json::from_str::<JsonValue>(&payload) {
            if value.get("code").and_then(JsonValue::as_u64) == Some(0) {
                let error = value
                    .get("body")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("request failed");
                return java_error_response(url, error);
            }
        }
        return payload;
    };

    let explicit_headers = (!headers_json.is_empty()).then(|| java_request_headers(headers_json));
    let spec = match analyze_url_with_headers(
        url,
        "",
        0,
        &source.book_source_url,
        &source,
        explicit_headers,
    ) {
        Ok(spec) => spec,
        Err(error) => return java_error_response(url, &error),
    };

    let response = match execute_request_spec(&client, &spec) {
        Ok(response) => response,
        Err(error) => return java_error_response(&spec.url, &error.to_string()),
    };

    let headers = response
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|value| {
                (
                    name.as_str().to_string(),
                    JsonValue::String(value.to_string()),
                )
            })
        })
        .collect::<serde_json::Map<String, JsonValue>>();
    let content_type = response
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok());
    let decoded_body = decode_body(&response.body, spec.charset.as_deref(), content_type);
    let body = match format_analyzed_body(
        &spec,
        &response.body,
        decoded_body,
        content_type,
        &response.url,
    ) {
        Ok(body) => body,
        Err(error) => return java_error_response(&response.url, &error),
    };

    serde_json::json!({
        "__ffiStrResponse": true,
        "body": body,
        "url": response.url,
        "code": response.status,
        "message": http_status_message(response.status),
        "headers": headers,
        "isSuccessful": (200..300).contains(&response.status),
    })
    .to_string()
}

fn http_status_message(status: u16) -> String {
    ureq::http::StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .unwrap_or("")
        .to_string()
}

fn java_error_response(url: &str, error: &str) -> String {
    // Android returns a JVM stack trace for request failures; preserve the
    // string/StrResponse contract without inventing a Java stack in the SO.
    let raw_url = split_ajax_spec(url).0.trim();
    let response_url = url::Url::parse(raw_url)
        .ok()
        .filter(|parsed| matches!(parsed.scheme(), "http" | "https"))
        .map(|parsed| parsed.to_string())
        .unwrap_or_else(|| "http://localhost/".to_string());
    serde_json::json!({
        "__ffiStrResponse": true,
        "body": error,
        "url": response_url,
        "code": 200,
        "message": "OK",
        "headers": {},
        "isSuccessful": true,
    })
    .to_string()
}

fn response_charset(content_type: &str) -> Option<&'static Encoding> {
    content_type.split(';').find_map(|part| {
        let (name, value) = part.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("charset") {
            return None;
        }
        Encoding::for_label(value.trim().trim_matches(['\'', '"']).as_bytes())
    })
}

/// Jsoup HTML parsing chooses BOM, declared charset, then a meta hint in 5KB.
/// Unlike AnalyzeUrl decoding, this path never statistically guesses an encoding.
pub(super) fn java_response_decode_text(
    base64: &str,
    charset: Option<&str>,
    parse: bool,
) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(base64)
        .ok()?;
    let declared = charset.and_then(|value| Encoding::for_label(value.as_bytes()));
    let (encoding, skip) = if !parse {
        (declared.unwrap_or(UTF_8), 0)
    } else if let Some((encoding, skip)) = Encoding::for_bom(&bytes) {
        (encoding, skip)
    } else if let Some(encoding) = declared {
        (encoding, 0)
    } else {
        let prefix = String::from_utf8_lossy(&bytes[..bytes.len().min(5120)]);
        let document = scraper::Html::parse_document(&prefix);
        static META: Lazy<scraper::Selector> = Lazy::new(|| {
            scraper::Selector::parse("meta[http-equiv=content-type], meta[charset]")
                .expect("valid meta selector")
        });
        let label = document.select(&META).find_map(|meta| {
            meta.value()
                .attr("http-equiv")
                .and_then(|_| meta.value().attr("content"))
                .and_then(response_charset)
                .map(|encoding| encoding.name().to_string())
                .or_else(|| meta.value().attr("charset").map(str::to_string))
        });
        (
            label
                .as_deref()
                .and_then(|value| Encoding::for_label(value.as_bytes()))
                .unwrap_or(UTF_8),
            0,
        )
    };
    let text = encoding.decode_without_bom_handling(&bytes[skip..]).0;
    Some(serde_json::json!({"text":text, "charset":encoding.name()}).to_string())
}

fn java_request_headers(headers_json: &str) -> Vec<(String, String)> {
    serde_json::from_str::<JsonValue>(headers_json)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .map(|headers| {
            headers
                .into_iter()
                .filter_map(|(key, value)| {
                    (!value.is_null()).then(|| (key, json_value_to_string(&value)))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod conversion_tests {
    use super::*;

    #[test]
    fn response_parse_charset_priority_is_bom_header_meta_then_utf8() {
        let decode = |bytes: &[u8], charset: Option<&str>, parse| -> JsonValue {
            let input = base64::engine::general_purpose::STANDARD.encode(bytes);
            serde_json::from_str(&java_response_decode_text(&input, charset, parse).unwrap())
                .unwrap()
        };
        let html = "<meta charset='GBK'><p>中文</p>";
        let encoded = encoding_rs::GBK.encode(html).0;
        assert_eq!(decode(&encoded, Some("GBK"), false)["text"], html);
        assert_ne!(decode(&encoded, None, false)["text"], html);
        assert_eq!(decode(&encoded, None, true)["text"], html);
        assert_eq!(decode(&encoded, Some("UTF-8"), true)["charset"], "UTF-8");
        assert_eq!(
            decode(&[0xef, 0xbb, 0xbf, b'A'], Some("GBK"), true)["text"],
            "A"
        );
        assert_eq!(
            decode(&[0xef, 0xbb, 0xbf, b'A'], Some("UTF-8"), false)["text"],
            "\u{feff}A"
        );
        assert_eq!(decode(&[0xff, 0xfe, b'A', 0], None, true)["text"], "A");
        assert_eq!(
            decode(b"<!-- <meta charset='GBK'> --><p>ASCII</p>", None, true)["charset"],
            "UTF-8"
        );
        assert_eq!(
            decode(b"<meta charset='not-a-charset'><p>ASCII</p>", None, true)["charset"],
            "UTF-8"
        );
        let late = format!("{}<meta charset='GBK'>", " ".repeat(5200));
        assert_eq!(decode(late.as_bytes(), None, true)["charset"], "UTF-8");
        assert_eq!(
            response_charset("text/html; charset=\"GBK\""),
            Some(encoding_rs::GBK)
        );
        assert_eq!(response_charset("text/html; charset='UTF-8'"), Some(UTF_8));
    }

    #[test]
    fn json_conversion_preserves_variable_and_http_contracts() {
        for (value, expected) in [
            (serde_json::json!("text"), "text"),
            (JsonValue::Null, ""),
            (serde_json::json!(42), "42"),
            (serde_json::json!(true), "true"),
            (serde_json::json!([1, "x"]), r#"[1,"x"]"#),
            (serde_json::json!({"key": "value"}), r#"{"key":"value"}"#),
        ] {
            assert_eq!(json_value_to_string(&value), expected);
        }
        assert_eq!(
            java_request_headers(r#"{"X-Count":42,"X-Null":null}"#),
            vec![("X-Count".to_string(), "42".to_string())]
        );
    }
}

fn split_ajax_spec(spec: &str) -> (&str, Option<&str>) {
    let mut depth = 0i32;
    let mut in_string = false;
    let mut quote = '\0';
    let mut escaped = false;

    for (idx, ch) in spec.char_indices() {
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
                let left = &spec[..idx];
                let right = &spec[idx + ch.len_utf8()..];
                return (left, Some(right.trim()));
            }
            _ => {}
        }
    }

    (spec, None)
}
