//! Legado URL-rule compilation and request preparation.

use super::{BodyJs, RequestSpec, DEFAULT_USER_AGENT};
use crate::model::book_source::BookSource;
use crate::parser::js_url::{
    eval_js_url_option_with_headers, eval_js_url_template_with_headers, eval_js_url_with_bindings,
    eval_js_url_with_headers, with_js_lib,
};
use crate::runtime::session::current_active_session;
use crate::util::text::find_template_close;
use encoding_rs::{Encoding, UTF_8};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::LazyLock as Lazy;
use ureq::http::header::{CONTENT_TYPE, USER_AGENT};
use ureq::http::Method;

#[derive(Debug, Clone, Default)]
pub struct UrlRuleContext {
    pub book_variable: Option<String>,
    pub chapter_variable: Option<String>,
    pub book_name: Option<String>,
    pub chapter_title: Option<String>,
    pub book_fields: HashMap<String, String>,
    pub chapter_fields: serde_json::Map<String, Value>,
}

impl UrlRuleContext {
    fn variable_map(raw: Option<&str>) -> serde_json::Map<String, Value> {
        raw.and_then(|value| serde_json::from_str::<Value>(value).ok())
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default()
    }

    fn bindings(&self) -> HashMap<String, Value> {
        let book_variables = Self::variable_map(self.book_variable.as_deref());
        let mut book = serde_json::Map::new();
        for (key, value) in &self.book_fields {
            book.insert(key.clone(), Value::String(value.clone()));
        }
        book.insert("variableMap".to_string(), Value::Object(book_variables));
        if let Some(name) = self.book_name.as_deref() {
            book.insert("name".to_string(), Value::String(name.to_string()));
            book.insert("bookName".to_string(), Value::String(name.to_string()));
        }

        let chapter_variables = Self::variable_map(self.chapter_variable.as_deref());
        let mut chapter = chapter_variables.clone();
        chapter.extend(self.chapter_fields.clone());
        chapter.insert("variableMap".to_string(), Value::Object(chapter_variables));
        if let Some(title) = self.chapter_title.as_deref() {
            chapter.insert("title".to_string(), Value::String(title.to_string()));
        }

        HashMap::from([
            ("book".to_string(), Value::Object(book)),
            ("chapter".to_string(), Value::Object(chapter)),
            (
                "title".to_string(),
                Value::String(self.chapter_title.clone().unwrap_or_default()),
            ),
        ])
    }

    fn get(&self, key: &str) -> Option<String> {
        if let Some(prop) = key.strip_prefix("book.") {
            if let Some(val) = self.book_fields.get(prop) {
                return Some(val.clone());
            }
            let values = Self::variable_map(self.book_variable.as_deref());
            if let Some(val) = values.get(prop).and_then(value_to_string) {
                return Some(val);
            }
        }
        let lookup = |raw: Option<&str>| {
            let values = Self::variable_map(raw);
            values.get(key).and_then(value_to_string)
        };
        match key {
            "bookName" => self
                .book_name
                .clone()
                .or_else(|| self.book_fields.get("name").cloned()),
            "title" => self.chapter_title.clone(),
            _ => lookup(self.chapter_variable.as_deref())
                .or_else(|| lookup(self.book_variable.as_deref()))
                .or_else(|| self.book_fields.get(key).cloned())
                .or_else(|| {
                    current_active_session()
                        .and_then(|session| session.get_variable(key))
                        .and_then(|value| value_to_string(&value))
                }),
        }
    }
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
    analyze_url_with_context(raw_rule, key, page, base_url, source, None)
}

pub fn analyze_url_with_context(
    raw_rule: &str,
    key: &str,
    page: i32,
    base_url: &str,
    source: &BookSource,
    context: Option<&UrlRuleContext>,
) -> Result<RequestSpec, String> {
    with_js_lib(source.js_lib.as_deref(), || {
        compile_url_request(raw_rule, key, page, base_url, source, context, None)
    })
}

pub(crate) fn analyze_url_with_headers(
    raw_rule: &str,
    key: &str,
    page: i32,
    base_url: &str,
    source: &BookSource,
    headers: Option<Vec<(String, String)>>,
) -> Result<RequestSpec, String> {
    with_js_lib(source.js_lib.as_deref(), || {
        compile_url_request(raw_rule, key, page, base_url, source, None, headers)
    })
}

fn compile_url_request(
    raw_rule: &str,
    key: &str,
    page: i32,
    base_url: &str,
    source: &BookSource,
    context: Option<&UrlRuleContext>,
    initial_headers: Option<Vec<(String, String)>>,
) -> Result<RequestSpec, String> {
    let raw_rule = raw_rule.trim();
    if raw_rule.is_empty() {
        return Err("URL rule is empty".to_string());
    }

    // Stage 1: initialize headers and pull transport proxy out of them.
    // Legado's AnalyzeUrl uses headerMapF instead of source/login headers when
    // JsExtensions.connect(url, header) supplies an explicit header map.
    let has_initial_headers = initial_headers.is_some();
    let mut headers = match initial_headers {
        Some(headers) => headers,
        None => source_headers(source)?,
    };
    let mut proxy = take_proxy_header(&mut headers).filter(|value| !value.trim().is_empty());
    if !has_initial_headers {
        if let Some(active) = current_active_session() {
            if let Some(login_header) = active.get_login_header() {
                merge_headers(&mut headers, headers_from_value(&login_header));
            }
        }
    }
    ensure_user_agent(&mut headers);

    let base = strip_url_options(base_url).trim();

    // Stages 2-4: URL JS segments, embedded JS templates, legacy placeholders, page choices.
    let bindings = context.map(UrlRuleContext::bindings);
    let mut rule = eval_url_rule_js_segments(
        raw_rule,
        key,
        page,
        source,
        base,
        bindings.as_ref(),
        &mut headers,
    )?;
    rule = expand_url_templates(
        &rule,
        key,
        page,
        source,
        base,
        context,
        bindings.as_ref(),
        &mut headers,
    )?;
    rule = replace_legacy_placeholders(&rule, key, page);
    rule = replace_page_choices(&rule, page);

    // Stage 5: split the final URL rule and parse optional JSON.
    let (url_part, options_text) = split_url_options(&rule);
    let options = match options_text {
        Some(text) => parse_url_options(text)?,
        None => Value::Null,
    };

    // Stage 6: resolve URL and apply options that modify the request context.
    let mut url = absolute_url(base, url_part.trim());
    // Android merges URL-option headers before running option JS against java.headerMap.
    if let Some(extra) = options.get("headers") {
        merge_headers(&mut headers, headers_from_value(extra));
    }
    if let Some(script) = options
        .get("js")
        .and_then(Value::as_str)
        .filter(|script| !script.trim().is_empty())
    {
        let rewritten = eval_js_url_option_with_headers(
            script,
            &url,
            key,
            page,
            &source.book_source_url,
            base,
            bindings.as_ref(),
            &mut headers,
        )
        .map_err(|error| format!("URL option JavaScript failed: {error}"))?;
        url = absolute_url(base, &rewritten);
    }
    if !url.starts_with("data:") {
        validate_http_url(&url)?;
    }

    if let Some(raw_proxy) = options
        .get("proxy")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        proxy = Some(raw_proxy.to_string());
    }
    ensure_user_agent(&mut headers);

    let raw_method = options.get("method");
    let requested_method = raw_method
        .and_then(Value::as_str)
        .map(str::trim)
        .map(str::to_ascii_uppercase);
    if raw_method.is_some() && !matches!(requested_method.as_deref(), Some("GET" | "POST" | "HEAD"))
    {
        if let Some(active) = current_active_session() {
            active.note_unknown_method_fallback();
        }
    }
    let method = match requested_method.as_deref() {
        Some("POST") => Method::POST,
        Some("HEAD") => Method::HEAD,
        _ => Method::GET,
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
        .map(str::to_owned);
    let body_js = options
        .get("bodyJs")
        .and_then(Value::as_str)
        .filter(|script| !script.trim().is_empty())
        .map(|script| BodyJs {
            script: script.to_string(),
            key: key.to_string(),
            page,
            source_key: source.book_source_url.clone(),
            js_lib: source.js_lib.clone(),
            bindings: bindings.clone(),
        });
    let body = prepare_request_body(
        method == Method::POST,
        body,
        &mut headers,
        charset.as_deref(),
    );

    // AnalyzeUrl sends stored cookies even when automatic response storage is off.
    // Direct java.get/post bypass this compiler and retain their explicit-header policy.
    if source.enabled_cookie_jar == Some(false) {
        if let Some(stored) = current_active_session().and_then(|active| active.get_cookie(&url)) {
            let explicit = headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("cookie"))
                .map(|(_, value)| value.as_str());
            let pairs: HashMap<_, _> = std::iter::once(stored.as_str())
                .chain(explicit)
                .flat_map(|cookie| cookie.split(';'))
                .filter_map(|pair| pair.trim().split_once('='))
                .map(|(name, value)| (name.trim(), value.trim()))
                .filter(|(name, _)| !name.is_empty())
                .collect();
            let cookie = pairs
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            headers.retain(|(name, _)| !name.eq_ignore_ascii_case("cookie"));
            headers.push(("Cookie".to_string(), cookie));
        }
    }

    Ok(RequestSpec {
        url: encode_get_query(&url, charset.as_deref()),
        method,
        headers,
        body,
        charset,
        retry,
        proxy,
        response_type,
        render_with_rakers: match options.get("webView") {
            None | Some(Value::Null) | Some(Value::Bool(false)) => false,
            Some(Value::String(value)) => !matches!(value.as_str(), "" | "false"),
            Some(_) => true,
        },
        body_js,
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
    bindings: Option<&HashMap<String, Value>>,
    headers: &mut Vec<(String, String)>,
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
        result = eval_js_url_with_headers(
            script,
            &result,
            key,
            page,
            &source.book_source_url,
            base_url,
            bindings,
            headers,
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
    context: Option<&UrlRuleContext>,
    bindings: Option<&HashMap<String, Value>>,
    headers: &mut Vec<(String, String)>,
) -> Result<String, String> {
    let mut output = String::with_capacity(rule.len());
    let mut cursor = 0;
    while let Some(relative_start) = rule[cursor..].find("{{") {
        let start = cursor + relative_start;
        output.push_str(&rule[cursor..start]);
        let expression_start = start + 2;
        let Some(relative_end) = find_template_close(&rule[expression_start..]) else {
            output.push_str(&rule[start..]);
            return Ok(output);
        };
        let end = expression_start + relative_end;
        let expression = rule[expression_start..end].trim();
        let replacement = if let Some(variable) = expression
            .strip_prefix("@get:{")
            .and_then(|value| value.strip_suffix('}'))
        {
            context
                .and_then(|context| context.get(variable.trim()))
                .unwrap_or_default()
        } else if let Some(val) = context.and_then(|c| c.get(expression)) {
            val
        } else {
            eval_js_url_template_with_headers(
                expression,
                rule,
                key,
                page,
                &source.book_source_url,
                base_url,
                bindings,
                headers,
            )
            .map_err(|error| format!("URL template JavaScript failed: {error}"))?
        };
        output.push_str(&replacement);
        cursor = end + 2;
    }
    output.push_str(&rule[cursor..]);
    Ok(output)
}

fn replace_legacy_placeholders(rule: &str, key: &str, page: i32) -> String {
    let encoded_key = urlencoding::encode(key);
    let page = page.max(1).to_string();
    rule.replace("{key}", &encoded_key).replace("{page}", &page)
}

fn replace_page_choices(rule: &str, page: i32) -> String {
    let Ok(re) = regex::Regex::new(r"<(.*?)>") else {
        return rule.to_string();
    };
    re.replace_all(rule, |captures: &regex::Captures| {
        let choices = captures[1].split(',').map(str::trim).collect::<Vec<_>>();
        choices
            .get(page.saturating_sub(1) as usize)
            .or_else(|| choices.last())
            .copied()
            .unwrap_or_default()
            .to_string()
    })
    .into_owned()
}

pub(crate) fn split_url_options(rule: &str) -> (&str, Option<&str>) {
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

pub(crate) fn strip_url_options(rule: &str) -> &str {
    split_url_options(rule).0
}

fn parse_url_options(raw: &str) -> Result<Value, String> {
    serde_json::from_str(raw)
        .or_else(|_| serde_json::from_str(&escape_control_chars_in_json_strings(raw)))
        .or_else(|_| {
            serde_json::from_str(&escape_control_chars_in_json_strings(
                &normalize_legacy_url_options(raw),
            ))
        })
        .map_err(|error| format!("invalid URL options: {error}"))
}

// Normalize only legacy quoting, then let serde_json validate the structure.
// This is not JavaScript evaluation or a general JSON5 parser.
fn normalize_legacy_url_options(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\'' | '"' => {
                let quote = ch;
                output.push('"');
                while let Some(ch) = chars.next() {
                    match ch {
                        '\\' => {
                            if let Some(escaped) = chars.next() {
                                if escaped != '\'' || quote != '\'' {
                                    output.push('\\');
                                }
                                output.push(escaped);
                            } else {
                                output.push('\\');
                            }
                        }
                        ch if ch == quote => {
                            output.push('"');
                            break;
                        }
                        '"' => output.push_str("\\\""),
                        other => output.push(other),
                    }
                }
            }
            ch if ch.is_whitespace() || "{}[],:".contains(ch) => output.push(ch),
            other => {
                let mut token = String::from(other);
                while let Some(&next) = chars.peek() {
                    if next.is_whitespace() || "{}[],:\"'".contains(next) {
                        break;
                    }
                    token.push(chars.next().unwrap());
                }
                let mut lookahead = chars.clone();
                if lookahead.find(|ch| !ch.is_whitespace()) == Some(':') {
                    output.push_str(&serde_json::to_string(&token).unwrap());
                } else {
                    output.push_str(&token);
                }
            }
        }
    }
    output
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
        // Android BaseSource.getHeaderMap evaluates the rule with the source
        // binding, not the current book/chapter AnalyzeUrl bindings.
        eval_js_url_with_bindings(
            script,
            "",
            "",
            0,
            &source.book_source_url,
            &source.book_source_url,
            None,
        )
        .map_err(|error| format!("source header JavaScript failed: {error}"))?
    } else {
        raw.to_string()
    };
    Ok(parse_source_headers(&raw))
}

pub(super) fn parse_source_headers(raw: &str) -> Vec<(String, String)> {
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(raw) {
        return map
            .iter()
            .filter(|(name, _)| !name.trim().is_empty())
            .map(|(name, value)| (name.clone(), value_to_string(value).unwrap_or_default()))
            .collect();
    }

    let normalized = raw.trim().trim_start_matches('{').trim_end_matches('}');
    crate::parser::rule_analyzer::split_top_level(normalized, &[","])
        .parts
        .into_iter()
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
    if raw_url.starts_with("data:")
        || raw_url.starts_with("http://")
        || raw_url.starts_with("https://")
    {
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
    if raw_url.starts_with("data:") {
        return raw_url.to_string();
    }
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
            let mut pieces = part.splitn(2, '=');
            let name =
                encode_form_component(pieces.next().unwrap_or_default(), encoding, escape_mode);
            match pieces.next() {
                Some(value) => format!(
                    "{name}={}",
                    encode_form_component(value, encoding, escape_mode)
                ),
                None => name,
            }
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
