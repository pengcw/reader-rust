//! `reader_execute` 的书源执行层。
//!
//! FFI 只负责 C 字符串边界；这里负责请求协议校验、HTTP、分页和
//! `RuleEngine` 调用，并将所有业务失败转换成稳定的 JSON envelope。

use crate::crawler::{
    analyze_url, with_active_session, ExecuteSession, FetchError, HttpResponse, HttpSession,
};
use crate::model::book_source::{book_source_from_value, BookSource};
use crate::model::replace_rule::ReplaceRule;
use crate::parser::js::{eval_js, eval_js_with_bindings, with_js_http_client, with_js_lib};
use crate::parser::rule_engine::{apply_legado_regex, RuleEngine};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};

const DEFAULT_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_MAX_PAGES: usize = 100;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TIMEOUT_MS: u64 = 120_000;
const MAX_PAGES: usize = 100;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct ExecuteOptions {
    timeout_ms: u64,
    max_pages: usize,
    max_response_bytes: usize,
    debug: bool,
}

impl Default for ExecuteOptions {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_pages: DEFAULT_MAX_PAGES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            debug: false,
        }
    }
}

#[derive(Debug, Clone)]
struct ValidatedOptions {
    timeout_ms: u64,
    max_pages: usize,
    max_response_bytes: usize,
    debug: bool,
}

#[derive(Debug)]
struct ExecuteError {
    kind: &'static str,
    message: String,
    status: Option<u16>,
    url: Option<String>,
    auth: Option<Value>,
}

type ExecuteResult<T> = Result<T, ExecuteError>;

impl ExecuteError {
    fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            kind: "invalid_request",
            message: message.into(),
            status: None,
            url: None,
            auth: None,
        }
    }

    fn invalid_source(message: impl Into<String>) -> Self {
        Self {
            kind: "invalid_source",
            message: message.into(),
            status: None,
            url: None,
            auth: None,
        }
    }

    fn url_rule(message: impl Into<String>) -> Self {
        Self {
            kind: "url_rule",
            message: message.into(),
            status: None,
            url: None,
            auth: None,
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            kind: "internal",
            message: message.into(),
            status: None,
            url: None,
            auth: None,
        }
    }

    fn parse(message: impl Into<String>) -> Self {
        Self {
            kind: "parse",
            message: message.into(),
            status: None,
            url: None,
            auth: None,
        }
    }

    fn into_json(self) -> Value {
        let mut error = serde_json::Map::new();
        error.insert("kind".to_string(), Value::String(self.kind.to_string()));
        error.insert("message".to_string(), Value::String(self.message));
        if let Some(status) = self.status {
            error.insert("status".to_string(), json!(status));
        }
        if let Some(url) = self.url {
            error.insert("url".to_string(), Value::String(url));
        }
        if let Some(auth) = self.auth {
            error.insert("auth".to_string(), auth);
        }
        json!({"ok": false, "error": error})
    }
}

impl From<FetchError> for ExecuteError {
    fn from(error: FetchError) -> Self {
        match error {
            FetchError::InvalidUrl(message) => Self::url_rule(message),
            FetchError::Network(message) => Self {
                kind: "network",
                message,
                status: None,
                url: None,
                auth: None,
            },
            FetchError::Timeout { url, message } => Self {
                kind: "timeout",
                message,
                status: None,
                url,
                auth: None,
            },
            FetchError::HttpStatus { status, url } => Self {
                kind: "http_status",
                message: format!("HTTP {status}"),
                status: Some(status),
                url: Some(url),
                auth: None,
            },
            FetchError::ResponseTooLarge { url, limit } => Self {
                kind: "response_too_large",
                message: format!("response exceeds {limit} bytes"),
                status: None,
                url: Some(url),
                auth: None,
            },
            FetchError::AuthChallenge {
                kind,
                message,
                status,
                url,
                mode,
                login_url,
                action_url,
            } => {
                let mut auth = serde_json::Map::new();
                auth.insert("mode".to_string(), json!(mode));
                if let Some(login_url) = login_url {
                    auth.insert("loginUrl".to_string(), json!(login_url));
                }
                if let Some(action_url) = action_url {
                    auth.insert("actionUrl".to_string(), json!(action_url));
                }
                Self {
                    kind,
                    message,
                    status,
                    url: Some(url),
                    auth: Some(Value::Object(auth)),
                }
            }
        }
    }
}

/// 执行 ABI v2 JSON 请求。该函数不跨 FFI，便于单元测试。
pub fn execute(source_json: &str, request_json: &str) -> String {
    let value = match execute_inner(source_json, request_json) {
        Ok(value) => value,
        Err(error) => error.into_json(),
    };
    // `Value::to_string()` 不会失败；JSON 字符串会转义潜在 NUL，适于 C 字符串 ABI。
    value.to_string()
}

fn execute_inner(source_json: &str, request_json: &str) -> ExecuteResult<Value> {
    let source = parse_source(source_json)?;
    let (operation, params, options, request_session) = parse_request(request_json)?;
    let engine = RuleEngine::new().map_err(|error| ExecuteError::internal(error.to_string()))?;

    let (result, session_delta) = with_active_session(
        request_session.as_ref(),
        &source.book_source_url,
        |_active_session| {
            let http_session = HttpSession::new(&source, options.timeout_ms)?;
            with_js_http_client(http_session.client(), || match operation.as_str() {
                "search" => execute_search(&source, &engine, &http_session, &params, &options),
                "explore" => execute_explore(&source, &engine, &http_session, &params, &options),
                "info" => execute_info(&source, &engine, &http_session, &params, &options),
                "toc" => execute_toc(&source, &engine, &http_session, &params, &options),
                "content" => execute_content(&source, &engine, &http_session, &params, &options),
                "login_ui" => execute_login_ui(&source),
                "login" => execute_login(&source, &http_session, &params, &options),
                // `parse_request` guards this too; keep this branch in case a future caller bypasses it.
                _ => Err(ExecuteError::invalid_request(format!(
                    "unsupported op: {operation}"
                ))),
            })
        },
    );
    let mut response = result?;
    if let Some(object) = response.as_object_mut() {
        object.insert("session".to_string(), json!(session_delta));
    }
    Ok(response)
}

fn parse_source(raw: &str) -> ExecuteResult<BookSource> {
    let value = serde_json::from_str::<Value>(raw)
        .map_err(|error| ExecuteError::invalid_source(format!("invalid source JSON: {error}")))?;
    let source = book_source_from_value(value)
        .map_err(|error| ExecuteError::invalid_source(format!("invalid source: {error}")))?;
    if source.book_source_url.trim().is_empty() {
        return Err(ExecuteError::invalid_source("bookSourceUrl is required"));
    }
    Ok(source)
}

fn parse_request(
    raw: &str,
) -> ExecuteResult<(String, Value, ValidatedOptions, Option<ExecuteSession>)> {
    let value = serde_json::from_str::<Value>(raw)
        .map_err(|error| ExecuteError::invalid_request(format!("invalid request JSON: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| ExecuteError::invalid_request("request must be a JSON object"))?;

    if object.get("api").and_then(Value::as_u64) != Some(2) {
        return Err(ExecuteError::invalid_request("api must be 2"));
    }
    let operation = object
        .get("op")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ExecuteError::invalid_request("op is required"))?
        .to_string();
    if !matches!(
        operation.as_str(),
        "search" | "explore" | "info" | "toc" | "content" | "login_ui" | "login"
    ) {
        return Err(ExecuteError::invalid_request(format!(
            "unsupported op: {operation}"
        )));
    }
    let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
    if !params.is_object() {
        return Err(ExecuteError::invalid_request(
            "params must be a JSON object",
        ));
    }
    let raw_options = object.get("options").cloned().unwrap_or_else(|| json!({}));
    let raw_options = serde_json::from_value::<ExecuteOptions>(raw_options)
        .map_err(|error| ExecuteError::invalid_request(format!("invalid options: {error}")))?;
    let options = validate_options(raw_options)?;
    let session = match object.get("session") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            serde_json::from_value::<ExecuteSession>(value.clone()).map_err(|error| {
                ExecuteError::invalid_request(format!("invalid session: {error}"))
            })?,
        ),
    };
    Ok((operation, params, options, session))
}

fn validate_options(options: ExecuteOptions) -> ExecuteResult<ValidatedOptions> {
    let timeout_ms = if options.timeout_ms == 0 {
        DEFAULT_TIMEOUT_MS
    } else {
        options.timeout_ms
    };
    let max_pages = if options.max_pages == 0 {
        DEFAULT_MAX_PAGES
    } else {
        options.max_pages
    };
    let max_response_bytes = if options.max_response_bytes == 0 {
        DEFAULT_MAX_RESPONSE_BYTES
    } else {
        options.max_response_bytes
    };
    if timeout_ms > MAX_TIMEOUT_MS {
        return Err(ExecuteError::invalid_request(format!(
            "timeoutMs must be at most {MAX_TIMEOUT_MS}"
        )));
    }
    if max_pages > MAX_PAGES {
        return Err(ExecuteError::invalid_request(format!(
            "maxPages must be at most {MAX_PAGES}"
        )));
    }
    if max_response_bytes > MAX_RESPONSE_BYTES {
        return Err(ExecuteError::invalid_request(format!(
            "maxResponseBytes must be at most {MAX_RESPONSE_BYTES}"
        )));
    }
    Ok(ValidatedOptions {
        timeout_ms,
        max_pages,
        max_response_bytes,
        debug: options.debug,
    })
}

fn execute_search(
    source: &BookSource,
    engine: &RuleEngine,
    session: &HttpSession,
    params: &Value,
    options: &ValidatedOptions,
) -> ExecuteResult<Value> {
    let key = required_string(params, "key")?;
    let page = optional_page(params)?;
    let rule = source
        .search_url
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ExecuteError::url_rule("searchUrl is required"))?;
    let response = fetch_rule(
        session,
        source,
        rule,
        &key,
        page,
        &source.book_source_url,
        options,
    )?;
    let data = serde_json::to_value(engine.search_books(source, &response.body, &response.url))
        .map_err(|error| ExecuteError::internal(error.to_string()))?;
    Ok(success(data, 1, false, &response, options))
}

fn execute_explore(
    source: &BookSource,
    engine: &RuleEngine,
    session: &HttpSession,
    params: &Value,
    options: &ValidatedOptions,
) -> ExecuteResult<Value> {
    let rule = required_string(params, "url")?;
    let page = optional_page(params)?;
    let response = fetch_rule(
        session,
        source,
        &rule,
        "",
        page,
        &source.book_source_url,
        options,
    )?;
    let data = serde_json::to_value(engine.explore_books(source, &response.body, &response.url))
        .map_err(|error| ExecuteError::internal(error.to_string()))?;
    Ok(success(data, 1, false, &response, options))
}

fn execute_info(
    source: &BookSource,
    engine: &RuleEngine,
    session: &HttpSession,
    params: &Value,
    options: &ValidatedOptions,
) -> ExecuteResult<Value> {
    let book_url = required_string(params, "url")?;
    let response = fetch_rule(
        session,
        source,
        &book_url,
        "",
        1,
        &source.book_source_url,
        options,
    )?;
    let data =
        serde_json::to_value(engine.book_info(source, &response.body, &response.url, &book_url))
            .map_err(|error| ExecuteError::internal(error.to_string()))?;
    Ok(success(data, 1, false, &response, options))
}

fn execute_toc(
    source: &BookSource,
    engine: &RuleEngine,
    session: &HttpSession,
    params: &Value,
    options: &ValidatedOptions,
) -> ExecuteResult<Value> {
    let initial_url = required_string(params, "url")?;
    let detail_response = fetch_rule(
        session,
        source,
        &initial_url,
        "",
        1,
        &source.book_source_url,
        options,
    )?;
    let book_info = engine.book_info(
        source,
        &detail_response.body,
        &detail_response.url,
        &initial_url,
    );
    let toc_url = book_info
        .toc_url
        .filter(|url| !url.trim().is_empty())
        .unwrap_or(initial_url);
    let mut pending = VecDeque::from([toc_url]);
    let mut visited_pages = HashSet::new();
    let mut seen_chapters = HashSet::new();
    let mut chapters = Vec::new();
    let mut final_response = None;
    let mut truncated = false;

    while let Some(url) = pending.pop_front() {
        if visited_pages.contains(&url) {
            continue;
        }
        if visited_pages.len() >= options.max_pages {
            truncated = true;
            break;
        }
        let response = fetch_rule(
            session,
            source,
            &url,
            "",
            1,
            &source.book_source_url,
            options,
        )?;
        visited_pages.insert(url);
        let (page_chapters, next_urls) = engine.chapter_list(source, &response.body, &response.url);
        for mut chapter in page_chapters {
            if seen_chapters.insert(chapter.url.clone()) {
                chapter.index = chapters.len() as i32;
                chapters.push(chapter);
            }
        }
        for next_url in next_urls {
            if !next_url.trim().is_empty() && !visited_pages.contains(&next_url) {
                pending.push_back(next_url);
            }
        }
        final_response = Some(response);
    }

    let response =
        final_response.ok_or_else(|| ExecuteError::url_rule("toc URL produced no request"))?;
    Ok(success(
        json!({"chapters": chapters, "pages": visited_pages.len(), "truncated": truncated}),
        visited_pages.len(),
        truncated,
        &response,
        options,
    ))
}

fn execute_content(
    source: &BookSource,
    engine: &RuleEngine,
    session: &HttpSession,
    params: &Value,
    options: &ValidatedOptions,
) -> ExecuteResult<Value> {
    let initial_url = required_string(params, "url")?;
    let replace_rules = parse_replace_rules(params.get("replaceRules"))?;
    let mut current_url = initial_url.clone();
    let mut visited_urls = HashSet::new();
    let mut fragments = Vec::new();
    let mut initial_response_url = None;
    let mut final_response = None;
    let mut truncated = false;

    while !visited_urls.contains(&current_url) {
        if visited_urls.len() >= options.max_pages {
            truncated = true;
            break;
        }
        let response = fetch_rule(
            session,
            source,
            &current_url,
            "",
            1,
            &source.book_source_url,
            options,
        )?;
        visited_urls.insert(current_url.clone());
        let response_url = response.url.clone();
        let chapter_url = initial_response_url.get_or_insert_with(|| response_url.clone());
        let content = engine.content(source, &response.body, &response.url);
        if !content.is_empty() {
            fragments.push(content);
        }
        let next_url = engine.next_content_url(source, &response.body, &response.url);
        final_response = Some(response);

        match next_url {
            Some(next_url)
                if should_follow_content_page(chapter_url, &response_url, &next_url)
                    && !visited_urls.contains(&next_url) =>
            {
                current_url = next_url;
            }
            Some(_) | None => break,
        }
    }

    let response =
        final_response.ok_or_else(|| ExecuteError::url_rule("content URL produced no request"))?;
    let content = apply_replace_rules(&fragments.join("\n"), &replace_rules);
    Ok(success(
        json!({"content": content, "pages": visited_urls.len(), "truncated": truncated}),
        visited_urls.len(),
        truncated,
        &response,
        options,
    ))
}

fn execute_login_ui(source: &BookSource) -> ExecuteResult<Value> {
    let raw = source.login_ui.as_deref().unwrap_or("").trim();
    let ui = if raw.is_empty() {
        json!([])
    } else if let Ok(value) = serde_json::from_str::<Value>(raw) {
        value
    } else {
        let script = strip_js_prefix(raw).unwrap_or(raw);
        let output = with_js_lib(source.js_lib.as_deref(), || {
            eval_js(script, "", &source.book_source_url)
        })
        .map_err(|error| ExecuteError::parse(format!("loginUi JavaScript failed: {error}")))?;
        serde_json::from_str::<Value>(&output).map_err(|error| {
            ExecuteError::parse(format!("loginUi must return a JSON array: {error}"))
        })?
    };
    if !ui.is_array() {
        return Err(ExecuteError::parse("loginUi must be an array"));
    }
    Ok(success_without_http(ui))
}

fn execute_login(
    source: &BookSource,
    _session: &HttpSession,
    params: &Value,
    _options: &ValidatedOptions,
) -> ExecuteResult<Value> {
    let values = params.get("values").cloned().unwrap_or_else(|| json!({}));
    if !values.is_object() {
        return Err(ExecuteError::invalid_request(
            "params.values must be an object",
        ));
    }
    let action = match params.get("action") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if !value.trim().is_empty() => Some(value.trim()),
        Some(_) => {
            return Err(ExecuteError::invalid_request(
                "params.action must be a non-empty string",
            ))
        }
    };
    if action.is_some_and(is_absolute_http_url) {
        return Err(web_login_error(
            source,
            action.unwrap_or_default(),
            "登录按钮需要通过外部浏览器打开；浏览器 Cookie 不会自动导入书源会话".to_string(),
        ));
    }

    let login_url = source.login_url.as_deref().unwrap_or("").trim();
    let login_script = strip_js_prefix(login_url);
    if login_script.is_none() && !login_url.is_empty() {
        let url = absolute_login_url(source).unwrap_or_else(|| login_url.to_string());
        return Err(web_login_error(
            source,
            &url,
            "该书源使用网页登录；当前解析器不提供内嵌 WebView，外部浏览器 Cookie 不会自动同步"
                .to_string(),
        ));
    }

    if login_script.is_some() || action.is_some() {
        let mut script = login_script.unwrap_or_default().to_string();
        if let Some(action) = action {
            script.push_str("\n;\n");
            script.push_str(action);
        } else if login_script.is_some() {
            script.push_str("\n;\nlogin();");
        }
        let bindings = login_bindings(&values);
        let output = with_js_lib(source.js_lib.as_deref(), || {
            eval_js_with_bindings(&script, "", &source.book_source_url, &bindings)
        })
        .map_err(|error| {
            auth_required_error(
                source,
                None,
                &source.book_source_url,
                format!("login script failed: {error}"),
            )
        })?;
        if is_login_failure(&output) {
            return Err(auth_required_error(
                source,
                None,
                &source.book_source_url,
                "login script reported authentication failure".to_string(),
            ));
        }
        return Ok(success_without_http(json!({
            "result": output,
            "message": "登录脚本执行成功",
        })));
    }

    Err(ExecuteError::invalid_request(
        "source.loginUrl or params.action is required",
    ))
}

fn login_bindings(values: &Value) -> HashMap<String, Value> {
    let mut bindings = HashMap::new();
    bindings.insert("loginInfo".to_string(), values.clone());
    bindings.insert("values".to_string(), values.clone());
    bindings.insert("result".to_string(), values.clone());
    bindings
}

fn is_absolute_http_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|parsed| matches!(parsed.scheme(), "http" | "https"))
}

fn strip_js_prefix(rule: &str) -> Option<&str> {
    rule.strip_prefix("@js:")
        .or_else(|| rule.strip_prefix("js:"))
        .or_else(|| {
            rule.strip_prefix("<js>")
                .and_then(|body| body.strip_suffix("</js>"))
        })
}

fn login_check_failed_text(value: &str) -> bool {
    let lower = value.to_lowercase();
    [
        "请先登录",
        "请登录后",
        "尚未登录",
        "未登录",
        "登录失效",
        "登录过期",
        "需要登录",
        "login required",
        "please login",
        "not logged in",
        "unauthorized",
        "authentication required",
    ]
    .iter()
    .any(|marker| lower.contains(&marker.to_lowercase()))
}

fn is_login_failure(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("false") || login_check_failed_text(value)
}

fn auth_required_error(
    source: &BookSource,
    status: Option<u16>,
    url: &str,
    message: String,
) -> ExecuteError {
    map_fetch_error(
        FetchError::AuthChallenge {
            kind: "auth_required",
            message,
            status,
            url: url.to_string(),
            mode: "script".to_string(),
            login_url: None,
            action_url: None,
        },
        source,
    )
}

fn web_login_error(source: &BookSource, url: &str, message: String) -> ExecuteError {
    ExecuteError::from(FetchError::AuthChallenge {
        kind: "auth_required",
        message,
        status: None,
        url: source.book_source_url.clone(),
        mode: "web".to_string(),
        login_url: url::Url::parse(url)
            .ok()
            .filter(|parsed| matches!(parsed.scheme(), "http" | "https"))
            .map(|parsed| parsed.to_string()),
        action_url: None,
    })
}

fn success_without_http(data: Value) -> Value {
    json!({
        "ok": true,
        "data": data,
        "meta": {"pages": 0, "truncated": false}
    })
}

fn fetch_rule(
    session: &HttpSession,
    source: &BookSource,
    rule: &str,
    key: &str,
    page: i32,
    base_url: &str,
    options: &ValidatedOptions,
) -> ExecuteResult<HttpResponse> {
    let spec = analyze_url(rule, key, page, base_url, source).map_err(ExecuteError::url_rule)?;
    let response = session
        .fetch(&spec, options.max_response_bytes)
        .map_err(|error| map_fetch_error(error, source))?;
    validate_login_response(source, response)
}

fn validate_login_response(
    source: &BookSource,
    response: HttpResponse,
) -> ExecuteResult<HttpResponse> {
    let Some(script) = source
        .login_check_js
        .as_deref()
        .map(str::trim)
        .filter(|script| !script.is_empty())
    else {
        return Ok(response);
    };

    let mut response_headers = serde_json::Map::new();
    for (name, value) in &response.headers {
        response_headers.insert(name.clone(), json!(value));
    }
    let mut bindings = HashMap::new();
    bindings.insert(
        "result".to_string(),
        json!({
            "__ffiStrResponse": true,
            "raw": null,
            "body": response.body.clone(),
            "url": response.url.clone(),
            "code": response.status,
            "headers": response_headers,
            "isSuccessful": (200..300).contains(&response.status),
        }),
    );
    let output = with_js_lib(source.js_lib.as_deref(), || {
        eval_js_with_bindings(script, "", &response.url, &bindings)
    })
    .map_err(|error| {
        auth_required_error(
            source,
            Some(response.status),
            &response.url,
            format!("loginCheckJs failed: {error}"),
        )
    })?;

    let trimmed = output.trim();
    if trimmed.eq_ignore_ascii_case("false") || login_check_failed_text(trimmed) {
        return Err(auth_required_error(
            source,
            Some(response.status),
            &response.url,
            "loginCheckJs reports that authentication is required".to_string(),
        ));
    }
    if trimmed.eq_ignore_ascii_case("true") {
        return Ok(response);
    }

    let value = serde_json::from_str::<Value>(&output).map_err(|_| {
        auth_required_error(
            source,
            Some(response.status),
            &response.url,
            "loginCheckJs must return a StrResponse".to_string(),
        )
    })?;
    response_from_login_check(value, response).ok_or_else(|| {
        auth_required_error(
            source,
            None,
            &source.book_source_url,
            "loginCheckJs must return a StrResponse".to_string(),
        )
    })
}

fn response_from_login_check(value: Value, original: HttpResponse) -> Option<HttpResponse> {
    let object = value.as_object()?;
    let status = object
        .get("code")
        .or_else(|| object.get("status"))
        .and_then(Value::as_u64)
        .and_then(|status| u16::try_from(status).ok())
        .unwrap_or(original.status);
    let is_successful = object
        .get("isSuccessful")
        .and_then(Value::as_bool)
        .unwrap_or((200..300).contains(&status));
    if !is_successful {
        return None;
    }
    let body = match object.get("body") {
        Some(Value::String(body)) => body.clone(),
        Some(Value::Null) | None => original.body,
        Some(body) => body.to_string(),
    };
    let url = object
        .get("url")
        .and_then(Value::as_str)
        .filter(|url| !url.trim().is_empty())
        .unwrap_or(&original.url)
        .to_string();
    let headers = object
        .get("headers")
        .and_then(Value::as_object)
        .map(|headers| {
            headers
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .as_str()
                        .map(|value| (name.to_ascii_lowercase(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or(original.headers);
    Some(HttpResponse {
        url,
        status,
        headers,
        body,
    })
}

fn login_ui_configured(raw: &str) -> bool {
    let raw = raw.trim();
    if raw.is_empty() {
        return false;
    }
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Array(rows)) => !rows.is_empty(),
        Ok(Value::Null) => false,
        _ => true,
    }
}

fn map_fetch_error(error: FetchError, source: &BookSource) -> ExecuteError {
    match error {
        FetchError::AuthChallenge {
            kind,
            message,
            status,
            url,
            mode,
            login_url,
            action_url,
        } => {
            let has_login_ui = source.login_ui.as_deref().is_some_and(login_ui_configured);
            let has_login_config = has_login_ui
                || source
                    .login_url
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty());

            if kind == "auth_required" && status == Some(403) && !has_login_config {
                return ExecuteError::from(FetchError::HttpStatus { status: 403, url });
            }

            let mode = if kind == "auth_required" {
                if has_login_ui {
                    "form".to_string()
                } else if source
                    .login_url
                    .as_deref()
                    .is_some_and(|value| strip_js_prefix(value.trim()).is_some())
                {
                    "script".to_string()
                } else if absolute_login_url(source).is_some() {
                    "web".to_string()
                } else {
                    "script".to_string()
                }
            } else {
                mode
            };
            let login_url = login_url.or_else(|| absolute_login_url(source));
            ExecuteError::from(FetchError::AuthChallenge {
                kind,
                message,
                status,
                url,
                mode,
                login_url,
                action_url,
            })
        }
        other => ExecuteError::from(other),
    }
}

fn absolute_login_url(source: &BookSource) -> Option<String> {
    let raw = source.login_url.as_deref()?.trim();
    if raw.is_empty() || strip_js_prefix(raw).is_some() {
        return None;
    }
    let url = url::Url::parse(raw)
        .or_else(|_| url::Url::parse(&source.book_source_url)?.join(raw))
        .ok()?;
    matches!(url.scheme(), "http" | "https").then(|| url.to_string())
}

fn required_string(params: &Value, key: &str) -> ExecuteResult<String> {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| ExecuteError::invalid_request(format!("params.{key} is required")))
}

fn optional_page(params: &Value) -> ExecuteResult<i32> {
    let page = params.get("page").and_then(Value::as_i64).unwrap_or(1);
    if !(1..=i32::MAX as i64).contains(&page) {
        return Err(ExecuteError::invalid_request(
            "params.page must be a positive integer",
        ));
    }
    Ok(page as i32)
}

fn parse_replace_rules(value: Option<&Value>) -> ExecuteResult<Vec<ReplaceRule>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    serde_json::from_value(value.clone()).map_err(|error| {
        ExecuteError::invalid_request(format!("invalid params.replaceRules: {error}"))
    })
}

fn apply_replace_rules(content: &str, rules: &[ReplaceRule]) -> String {
    let mut content = content.to_string();
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
            content = apply_legado_regex(&content, &expression);
        } else {
            content = content.replace(&rule.pattern, &rule.replacement);
        }
    }
    content
}

fn success(
    data: Value,
    pages: usize,
    truncated: bool,
    response: &HttpResponse,
    options: &ValidatedOptions,
) -> Value {
    let mut meta = serde_json::Map::new();
    meta.insert("pages".to_string(), json!(pages));
    meta.insert("truncated".to_string(), json!(truncated));
    meta.insert("finalUrl".to_string(), json!(response.url));
    meta.insert("status".to_string(), json!(response.status));
    if options.debug {
        meta.insert(
            "debug".to_string(),
            json!({"responseBytes": response.body.len()}),
        );
    }
    json!({"ok": true, "data": data, "meta": meta})
}

// 复用主分支 BookService 的启发式，避免把章节翻页规则误判为下一章。
fn should_follow_content_page(chapter_url: &str, current_url: &str, next_url: &str) -> bool {
    let chapter_url = strip_fragment(chapter_url);
    let current_url = strip_fragment(current_url);
    let next_url = strip_fragment(next_url);
    if next_url == chapter_url || next_url == current_url {
        return false;
    }

    match (
        url::Url::parse(chapter_url),
        url::Url::parse(current_url),
        url::Url::parse(next_url),
    ) {
        (Ok(chapter), Ok(current), Ok(next)) => {
            if chapter.scheme() != next.scheme()
                || chapter.host_str() != next.host_str()
                || chapter.port_or_known_default() != next.port_or_known_default()
            {
                return false;
            }
            let chapter_base = content_path_base(chapter.path(), false);
            let current_base = content_path_base(current.path(), false);
            let next_base = content_path_base(next.path(), false);
            let next_page_base = content_path_base(next.path(), true);
            next_base == chapter_base
                || next_base == current_base
                || next_page_base == chapter_base
                || next_page_base == current_base
        }
        _ => false,
    }
}

fn strip_fragment(url: &str) -> &str {
    url.split_once('#').map(|(head, _)| head).unwrap_or(url)
}

fn content_path_base(path: &str, strip_page_suffix: bool) -> String {
    let (directory, filename) = path.rsplit_once('/').unwrap_or(("", path));
    let (stem, _) = filename.rsplit_once('.').unwrap_or((filename, ""));
    let stem = if strip_page_suffix {
        match stem.rsplit_once('-') {
            Some((prefix, suffix)) if suffix.chars().all(|ch| ch.is_ascii_digit()) => prefix,
            _ => stem,
        }
    } else {
        stem
    };
    if directory.is_empty() {
        stem.to_string()
    } else {
        format!("{directory}/{stem}")
    }
}

#[cfg(test)]
mod tests {
    use super::execute;
    use serde_json::Value;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn serve_once(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        format!("http://{address}")
    }

    fn serve_operation_fixture(request_count: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for _ in 0..request_count {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let bytes_read = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..bytes_read]);
                let target = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");
                let has_session_cookie = request.lines().skip(1).any(|line| {
                    line.split_once(':').is_some_and(|(name, value)| {
                        name.trim().eq_ignore_ascii_case("cookie")
                            && value.contains("reader-session=ok")
                    })
                });
                let (status, extra_headers, body) = match target.split('?').next().unwrap_or(target)
                {
                    "/explore" => (
                        "200 OK",
                        "",
                        r#"{"data":[{"name":"发现书","author":"作者","url":"/book/2"}]}"#,
                    ),
                    "/info" => (
                        "200 OK",
                        "",
                        r#"{"data":{"name":"详情书","author":"详情作者"}}"#,
                    ),
                    "/toc/1" => (
                        "200 OK",
                        "",
                        r#"{"chapters":[{"title":"第一章","url":"/chapter/1.html"}],"next":"/toc/2"}"#,
                    ),
                    "/toc/2" => (
                        "200 OK",
                        "",
                        r#"{"chapters":[{"title":"第二章","url":"/chapter/2.html"}]}"#,
                    ),
                    "/chapter/1.html" => (
                        "200 OK",
                        "Set-Cookie: reader-session=ok\r\n",
                        r#"{"content":"第一页正文","next":"/chapter/1-2.html"}"#,
                    ),
                    "/chapter/1-2.html" if has_session_cookie => {
                        ("200 OK", "", r#"{"content":"第二页正文"}"#)
                    }
                    "/chapter/1-2.html" => ("403 Forbidden", "", r#"{"error":"missing cookie"}"#),
                    _ => ("404 Not Found", "", r#"{"error":"not found"}"#),
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json; charset=utf-8\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                )
                .unwrap();
            }
        });
        format!("http://{address}")
    }

    #[test]
    fn execute_rejects_unknown_operation_with_stable_envelope() {
        let result: serde_json::Value = serde_json::from_str(&execute(
            r#"{"bookSourceName":"test","bookSourceUrl":"https://example.invalid"}"#,
            r#"{"api":2,"op":"unknown"}"#,
        ))
        .unwrap();
        assert_eq!(result["ok"], false);
        assert_eq!(result["error"]["kind"], "invalid_request");
    }

    #[test]
    fn execute_search_fetches_and_parses_in_the_so() {
        let base_url = serve_once(
            r#"{"data":[{"name":"Rust 搜索结果","author":"测试作者","url":"/book/1"}]}"#,
        );
        let source = serde_json::json!({
            "bookSourceName": "FFI test source",
            "bookSourceUrl": base_url,
            "searchUrl": "/search?keyword={{key}}&page={{page}}",
            "ruleSearch": {
                "bookList": "$.data[*]",
                "name": "$.name",
                "author": "$.author",
                "bookUrl": "$.url"
            }
        });
        let request = serde_json::json!({
            "api": 2,
            "op": "search",
            "params": {"key": "Rust", "page": 1}
        });

        let result: serde_json::Value =
            serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"][0]["name"], "Rust 搜索结果");
        assert_eq!(
            result["data"][0]["bookUrl"],
            format!("{}/book/1", source["bookSourceUrl"].as_str().unwrap())
        );
    }

    #[test]
    fn execute_supports_explore_info_toc_and_content_pagination() {
        // explore + info + two TOC pages + two content pages. The second content
        // page requires the cookie set by the first one.
        let base_url = serve_operation_fixture(7);
        let source = serde_json::json!({
            "bookSourceName": "all operation fixture",
            "bookSourceUrl": base_url,
            "ruleExplore": {
                "bookList": "$.data[*]",
                "name": "$.name",
                "author": "$.author",
                "bookUrl": "$.url"
            },
            "ruleBookInfo": {
                "name": "$.data.name",
                "author": "$.data.author"
            },
            "ruleToc": {
                "chapterList": "$.chapters[*]",
                "chapterName": "$.title",
                "chapterUrl": "$.url",
                "nextTocUrl": "$.next"
            },
            "ruleContent": {
                "content": "$.content",
                "nextContentUrl": "$.next"
            }
        });
        let call = |op: &str, url: &str| -> serde_json::Value {
            serde_json::from_str(&execute(
                &source.to_string(),
                &serde_json::json!({"api": 2, "op": op, "params": {"url": url}}).to_string(),
            ))
            .unwrap()
        };

        let explore = call("explore", "/explore");
        assert_eq!(explore["ok"], true, "{explore}");
        assert_eq!(explore["data"][0]["name"], "发现书");

        let info = call("info", "/info");
        assert_eq!(info["ok"], true, "{info}");
        assert_eq!(info["data"]["name"], "详情书");

        let toc = call("toc", "/toc/1");
        assert_eq!(toc["ok"], true, "{toc}");
        assert_eq!(toc["data"]["chapters"].as_array().unwrap().len(), 2);
        assert_eq!(toc["data"]["pages"], 2);

        let content = call("content", "/chapter/1.html");
        assert_eq!(content["ok"], true, "{content}");
        assert_eq!(content["data"]["content"], "第一页正文\n第二页正文");
        assert_eq!(content["data"]["pages"], 2);
    }

    #[test]
    fn execute_round_trips_cookie_session_between_calls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let base_url = format!("http://{address}");
        let response_body =
            r#"{"data":[{"name":"Session 书","author":"测试作者","url":"/book/1"}]}"#;
        let response_body_for_server = response_body.to_string();
        thread::spawn(move || {
            for call_index in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let bytes_read = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..bytes_read]);
                let has_cookie = request.lines().skip(1).any(|line| {
                    line.split_once(':').is_some_and(|(name, value)| {
                        name.trim().eq_ignore_ascii_case("cookie")
                            && value.contains("reader-session=roundtrip")
                    })
                });
                let (status, headers, body) = if call_index == 0 {
                    (
                        "200 OK",
                        "Set-Cookie: reader-session=roundtrip; Path=/\r\n",
                        response_body_for_server.as_str(),
                    )
                } else if has_cookie {
                    ("200 OK", "", response_body_for_server.as_str())
                } else {
                    ("403 Forbidden", "", r#"{"error":"missing cookie"}"#)
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json; charset=utf-8\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                )
                .unwrap();
            }
        });

        let source = serde_json::json!({
            "bookSourceName": "session round-trip fixture",
            "bookSourceUrl": base_url,
            "searchUrl": "/search?keyword={{key}}",
            "ruleSearch": {
                "bookList": "$.data[*]",
                "name": "$.name",
                "author": "$.author",
                "bookUrl": "$.url"
            }
        });
        let request = |session: Option<Value>| {
            let mut value = serde_json::json!({
                "api": 2,
                "op": "search",
                "params": {"key": "Rust"}
            });
            if let Some(session) = session {
                value["session"] = session;
            }
            value
        };

        let first: Value =
            serde_json::from_str(&execute(&source.to_string(), &request(None).to_string()))
                .unwrap();
        assert_eq!(first["ok"], true, "{first}");
        assert_eq!(first["session"]["cookies"], "reader-session=roundtrip");

        let second: Value = serde_json::from_str(&execute(
            &source.to_string(),
            &request(Some(first["session"].clone())).to_string(),
        ))
        .unwrap();
        assert_eq!(second["ok"], true, "{second}");
        assert_eq!(second["session"], Value::Null);
    }

    #[test]
    fn login_check_js_receives_and_can_replace_str_response() {
        let base_url = serve_once(r#"{"message":"before"}"#);
        let source = serde_json::json!({
            "bookSourceName": "login check fixture",
            "bookSourceUrl": base_url,
            "loginCheckJs": r#"if (result.code() !== 200 || result.url().indexOf('http') !== 0 || result.headers().get('content-type').indexOf('application/json') < 0) throw new Error('bad StrResponse'); var response = result.toJSON(); response.body = JSON.stringify({message: 'after'}); response"#,
            "ruleBookInfo": {"name": "$.message"}
        });
        let result: Value = serde_json::from_str(&execute(
            &source.to_string(),
            &serde_json::json!({"api": 2, "op": "info", "params": {"url": "/book/1"}}).to_string(),
        ))
        .unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"]["name"], "after");
    }

    #[test]
    fn login_script_exposes_credentials_through_source_helpers() {
        let source = serde_json::json!({
            "bookSourceName": "login script fixture",
            "bookSourceUrl": "https://login.example/",
            "loginUrl": "@js:function login() { return source.getLoginInfo().username + ':' + source.getLoginInfoMap().get('password'); }",
            "loginUi": r#"[{"name":"username","type":"text"},{"name":"password","type":"password"}]"#
        });
        let login: Value = serde_json::from_str(&execute(
            &source.to_string(),
            &serde_json::json!({
                "api": 2,
                "op": "login",
                "params": {"values": {"username": "reader", "password": "secret"}}
            })
            .to_string(),
        ))
        .unwrap();
        assert_eq!(login["ok"], true, "{login}");
        assert_eq!(login["data"]["result"], "reader:secret");

        let form: Value = serde_json::from_str(&execute(
            &source.to_string(),
            r#"{"api":2,"op":"login_ui"}"#,
        ))
        .unwrap();
        assert_eq!(form["ok"], true, "{form}");
        assert_eq!(form["data"][1]["type"], "password");
    }

    #[test]
    fn ordinary_login_url_is_reported_as_web_flow_without_http_fetch() {
        let source = serde_json::json!({
            "bookSourceName": "web login fixture",
            "bookSourceUrl": "https://catalog.example/books",
            "loginUrl": "/login"
        });
        let result: Value = serde_json::from_str(&execute(
            &source.to_string(),
            r#"{"api":2,"op":"login","params":{"values":{}}}"#,
        ))
        .unwrap();
        assert_eq!(result["ok"], false, "{result}");
        assert_eq!(result["error"]["kind"], "auth_required");
        assert_eq!(result["error"]["auth"]["mode"], "web");
        assert_eq!(
            result["error"]["auth"]["loginUrl"],
            "https://catalog.example/login"
        );
    }
}
