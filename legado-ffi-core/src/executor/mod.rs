//! `reader_execute` 的书源执行层。
//!
//! FFI 只负责 C 字符串边界；这里负责请求协议校验、HTTP、分页和
//! `RuleEngine` 调用，并将所有业务失败转换成稳定的 JSON envelope。

use crate::crawler::{
    analyze_url_with_context, strip_url_options, FetchError, HttpResponse, HttpSession,
    UrlRuleContext,
};
use crate::model::book_source::{book_source_from_value, BookSource};
use crate::parser::js::{
    eval_js, eval_js_with_bindings, with_js_http_clients, with_js_info_map, with_js_lib,
    with_login_messages, with_click_browser, InfoMapState,
};
use crate::parser::rule_engine::{
    dedupe_chapters_last_wins, normalize_list_rule, RuleEngine,
};
use crate::runtime::session::with_active_session;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};

mod protocol;
mod text_transform;

use protocol::{parse_request, ExecuteRequest, Operation};

const DEFAULT_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_MAX_PAGES: usize = 100;
pub(crate) const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
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

    fn unsupported(message: impl Into<String>) -> Self {
        Self {
            kind: "unsupported",
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
            FetchError::InvalidUrl(message) | FetchError::Rule(message) => Self::url_rule(message),
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
    if is_loc_book(source_json, request_json) {
        return Err(ExecuteError::unsupported("不支持远程本地书籍"));
    }
    let source = parse_source(source_json)?;
    let ExecuteRequest {
        operation,
        params,
        options,
        session: request_session,
        info_map: request_info_map,
    } = parse_request(request_json)?;
    let engine = RuleEngine::new().map_err(|error| ExecuteError::internal(error.to_string()))?;

    let (result, session_delta) = with_active_session(
        request_session.as_ref(),
        &source.book_source_url,
        |active_session| {
            let result = (|| -> ExecuteResult<Value> {
                let http_session = HttpSession::new(&source, options.timeout_ms)?;
                with_js_http_clients(
                    http_session.client(),
                    http_session.webview_client(),
                    &source,
                    || {
                        match operation {
                            Operation::Search => {
                                execute_search(&source, &engine, &http_session, &params, &options)
                            }
                            Operation::Explore => execute_explore(
                                &source,
                                &engine,
                                &http_session,
                                &params,
                                &options,
                                request_info_map.clone(),
                            ),
                            Operation::ExploreKinds => execute_explore_kinds_with_state(
                                &source,
                                &options,
                                request_info_map.clone(),
                            ),
                            Operation::Info => {
                                execute_info(&source, &engine, &http_session, &params, &options)
                            }
                            Operation::Toc => {
                                execute_toc(&source, &engine, &http_session, &params, &options)
                            }
                            Operation::Content => {
                                execute_content(&source, &engine, &http_session, &params, &options)
                            }
                            Operation::Click => execute_click(&source, &params),
                            Operation::LoginUi => execute_login_ui(&source),
                            Operation::Login => {
                                execute_login(&source, &http_session, &params, &options)
                            }
                        }
                    },
                )
            })();
            (result, active_session.had_unknown_method_fallback())
        },
    );
    let (result, unknown_method_fallback) = result;
    let succeeded = result.is_ok();
    let mut response = match result {
        Ok(response) => response,
        Err(error) if unknown_method_fallback => error.into_json(),
        Err(error) => return Err(error),
    };
    if succeeded {
        if let Some(object) = response.as_object_mut() {
            object.insert("session".to_string(), json!(session_delta));
        }
    }
    if unknown_method_fallback {
        let meta = response
            .as_object_mut()
            .expect("execution response is an object")
            .entry("meta")
            .or_insert_with(|| json!({}));
        meta["diagnostics"] = json!(["unknown_method_fallback_get"]);
    }
    Ok(response)
}

fn is_loc_book(source_json: &str, request_json: &str) -> bool {
    let is_loc = |s: Option<&str>| {
        s.map(str::trim)
            .is_some_and(|v| v.eq_ignore_ascii_case("loc_book"))
    };

    if source_json.trim().eq_ignore_ascii_case("loc_book") {
        return true;
    }

    if let Ok(val) = serde_json::from_str::<Value>(source_json) {
        if is_loc(val.get("bookSourceUrl").and_then(Value::as_str))
            || is_loc(val.get("origin").and_then(Value::as_str))
        {
            return true;
        }
    }

    if let Ok(req) = serde_json::from_str::<Value>(request_json) {
        if is_loc(req.get("origin").and_then(Value::as_str)) {
            return true;
        }
        if let Some(params) = req.get("params") {
            if is_loc(params.get("origin").and_then(Value::as_str))
                || is_loc(
                    params
                        .get("book")
                        .and_then(|b| b.get("origin"))
                        .and_then(Value::as_str),
                )
                || is_loc(
                    params
                        .get("chapter")
                        .and_then(|c| c.get("origin"))
                        .and_then(Value::as_str),
                )
            {
                return true;
            }
            if let Some(url) = params.get("url").and_then(Value::as_str) {
                let trimmed = url.trim();
                if trimmed.eq_ignore_ascii_case("loc_book") || trimmed.starts_with("content://") {
                    return true;
                }
            }
        }
        if let Some(url) = req.get("url").and_then(Value::as_str) {
            let trimmed = url.trim();
            if trimmed.eq_ignore_ascii_case("loc_book") || trimmed.starts_with("content://") {
                return true;
            }
        }
    }

    false
}

fn parse_source(raw: &str) -> ExecuteResult<BookSource> {
    let value = serde_json::from_str::<Value>(raw)
        .map_err(|error| ExecuteError::invalid_source(format!("invalid source JSON: {error}")))?;
    let source = book_source_from_value(value)
        .map_err(|error| ExecuteError::invalid_source(format!("invalid source: {error}")))?;
    if source.book_source_url.trim().is_empty() {
        return Err(ExecuteError::invalid_source("bookSourceUrl is required"));
    }
    if source
        .book_source_url
        .trim()
        .eq_ignore_ascii_case("loc_book")
    {
        return Err(ExecuteError::unsupported("不支持远程本地书籍"));
    }
    Ok(source)
}

fn load_info_map_state(supplied: Option<InfoMapState>) -> ExecuteResult<InfoMapState> {
    if let Some(state) = supplied {
        return Ok(state);
    }
    let response = crate::host_services::call("info_map.load", &json!({}));
    if response["ok"] == true {
        return InfoMapState::from_value(response["data"].clone()).map_err(|error| {
            ExecuteError::internal(format!("invalid infoMap load response: {error}"))
        });
    }
    if matches!(
        response["error"]["kind"].as_str(),
        Some("unavailable" | "unsupported")
    ) {
        return Ok(InfoMapState::default());
    }
    Err(ExecuteError::internal(
        response["error"]["message"]
            .as_str()
            .unwrap_or("infoMap load failed"),
    ))
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
    supplied: Option<InfoMapState>,
) -> ExecuteResult<Value> {
    let rule = required_string(params, "url")?;
    let page = optional_page(params)?;
    let state = load_info_map_state(supplied)?;
    // URL stages and loginCheckJs share the Map; independent list fields do not.
    let (response, state) = with_js_info_map(state, || {
        fetch_rule(
            session,
            source,
            &rule,
            "",
            page,
            &source.book_source_url,
            options,
        )
    });
    let response = response?;
    let data = serde_json::to_value(engine.explore_books(source, &response.body, &response.url))
        .map_err(|error| ExecuteError::internal(error.to_string()))?;
    let mut result = success(data, 1, false, &response, options);
    publish_info_map_state(&mut result, state, false)?;
    Ok(result)
}

// Classification flushes pending saves; exploration only carries state forward.
fn execute_explore_kinds_with_state(
    source: &BookSource,
    options: &ValidatedOptions,
    supplied: Option<InfoMapState>,
) -> ExecuteResult<Value> {
    let state = load_info_map_state(supplied)?;
    let (result, state) = with_js_info_map(state, || execute_explore_kinds(source, options));
    let mut response = result?;
    publish_info_map_state(&mut response, state, true)?;
    Ok(response)
}

fn publish_info_map_state(
    response: &mut Value,
    state: InfoMapState,
    flush: bool,
) -> ExecuteResult<()> {
    let committed =
        crate::host_services::call("info_map.commit", &json!({"state": state, "flush": flush}));
    if committed["ok"] == true {
        response["infoMap"] = committed["data"]["state"].clone();
        if let Some(error) = committed["data"].get("persistenceError") {
            response["infoMapError"] = error.clone();
        }
    } else if matches!(
        committed["error"]["kind"].as_str(),
        Some("unavailable" | "unsupported")
    ) {
        response["infoMap"] = json!(state);
    } else {
        return Err(ExecuteError::internal(
            committed["error"]["message"]
                .as_str()
                .unwrap_or("infoMap commit failed"),
        ));
    }
    Ok(())
}

fn execute_explore_kinds(source: &BookSource, options: &ValidatedOptions) -> ExecuteResult<Value> {
    let raw = source.explore_url.as_deref().unwrap_or("").trim();
    let script = if raw
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("@js:"))
    {
        Some(&raw[4..])
    } else if raw
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("<js>"))
    {
        let end = raw.len().saturating_sub(5);
        if !raw
            .get(end..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case("</js>"))
        {
            return Err(ExecuteError::parse("exploreUrl is missing </js>"));
        }
        Some(&raw[4..end])
    } else {
        None
    };
    let text = match script {
        Some(script) => with_js_lib(source.js_lib.as_deref(), || {
            eval_js(script, "", &source.book_source_url)
        })
        .map_err(|error| ExecuteError::parse(format!("exploreUrl JavaScript failed: {error}")))?,
        None => raw.to_string(),
    };
    if text.len() > options.max_response_bytes {
        return Err(ExecuteError::parse(
            "exploreUrl output exceeds maxResponseBytes",
        ));
    }
    let text = text.trim();
    let kinds: Vec<crate::model::book_source::ExploreKind> = if text.starts_with('[') {
        serde_json::from_str(text).map_err(|error| {
            ExecuteError::parse(format!("invalid explore categories JSON: {error}"))
        })?
    } else {
        let mut entries = vec![text.to_string()];
        for delimiter in ["&&", "\r\n", "\n"] {
            entries = entries
                .into_iter()
                .flat_map(|entry| {
                    crate::parser::rule_analyzer::split_top_level(&entry, &[delimiter]).parts
                })
                .collect();
        }
        entries
            .into_iter()
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                let (title, url) = entry.split_once("::").unwrap_or((&entry, ""));
                crate::model::book_source::ExploreKind {
                    title: title.trim().to_string(),
                    url: (!url.trim().is_empty()).then(|| url.trim().to_string()),
                    style: None,
                }
            })
            .collect()
    };
    let kinds = kinds
        .into_iter()
        .filter(|kind| !kind.title.trim().is_empty())
        .collect::<Vec<_>>();
    let data =
        serde_json::to_value(kinds).map_err(|error| ExecuteError::internal(error.to_string()))?;
    Ok(success_without_http(data))
}

fn serialized_variable(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(serialized) => Some(serialized.clone()),
        Value::Object(_) => serde_json::to_string(value?).ok(),
        _ => None,
    }
}

fn input_book_state(params: &Value) -> (Option<String>, Option<String>) {
    let book = params.get("book").and_then(Value::as_object);
    let variable = serialized_variable(
        book.and_then(|value| value.get("variable").or_else(|| value.get("variableMap")))
            .or_else(|| params.get("variable").or_else(|| params.get("variableMap"))),
    );
    let name = book
        .and_then(|value| value.get("name"))
        .or_else(|| params.get("bookName"))
        .or_else(|| params.get("name"))
        .and_then(Value::as_str)
        .map(str::to_string);
    (variable, name)
}

fn input_book_fields(params: &Value) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    if let Some(book) = params.get("book").and_then(Value::as_object) {
        for (k, v) in book {
            if let Some(s) = match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                Value::Bool(b) => Some(b.to_string()),
                _ => None,
            } {
                fields.insert(k.clone(), s);
            }
        }
    }
    fields
}

fn input_chapter_state(params: &Value) -> (Option<String>, Option<String>) {
    let chapter = params.get("chapter").and_then(Value::as_object);
    let variable = serialized_variable(
        chapter
            .and_then(|value| value.get("variable").or_else(|| value.get("variableMap")))
            .or_else(|| params.get("chapterVariable")),
    );
    let title = chapter
        .and_then(|value| value.get("title"))
        .or_else(|| params.get("title"))
        .and_then(Value::as_str)
        .map(str::to_string);
    (variable, title)
}

fn url_rule_context(
    book_variable: Option<&str>,
    chapter_variable: Option<&str>,
    book_name: Option<&str>,
    chapter_title: Option<&str>,
) -> UrlRuleContext {
    url_rule_context_with_fields(
        book_variable,
        chapter_variable,
        book_name,
        chapter_title,
        None,
    )
}

fn url_rule_context_with_fields(
    book_variable: Option<&str>,
    chapter_variable: Option<&str>,
    book_name: Option<&str>,
    chapter_title: Option<&str>,
    book_fields: Option<&HashMap<String, String>>,
) -> UrlRuleContext {
    UrlRuleContext {
        book_variable: book_variable.map(str::to_string),
        chapter_variable: chapter_variable.map(str::to_string),
        book_name: book_name.map(str::to_string),
        chapter_title: chapter_title.map(str::to_string),
        book_fields: book_fields.cloned().unwrap_or_default(),
        chapter_fields: serde_json::Map::new(),
    }
}

fn input_chapter_fields(params: &Value, url: &str) -> serde_json::Map<String, Value> {
    let mut fields = params
        .get("chapter")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    fields.entry("url").or_insert_with(|| json!(url));
    if let Some(is_volume) = params.get("isVolume") {
        fields
            .entry("isVolume")
            .or_insert_with(|| is_volume.clone());
    }
    fields
}

fn input_chapter_is_volume(params: &Value) -> bool {
    params
        .get("chapter")
        .and_then(|chapter| chapter.get("isVolume"))
        .or_else(|| params.get("isVolume"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn execute_info(
    source: &BookSource,
    engine: &RuleEngine,
    session: &HttpSession,
    params: &Value,
    options: &ValidatedOptions,
) -> ExecuteResult<Value> {
    let book_url = required_string(params, "url")?;
    let (variable, name) = input_book_state(params);
    let mut book_fields = input_book_fields(params);
    if let Some(name_str) = &name {
        book_fields
            .entry("name".to_string())
            .or_insert_with(|| name_str.clone());
    }
    let request_context = url_rule_context_with_fields(
        variable.as_deref(),
        None,
        name.as_deref(),
        None,
        Some(&book_fields),
    );
    let response = fetch_rule_with_context(
        session,
        source,
        &book_url,
        "",
        1,
        &source.book_source_url,
        options,
        Some(&request_context),
    )?;
    let data = serde_json::to_value(engine.book_info_with_context(
        source,
        &response.body,
        &response.url,
        &book_url,
        variable.as_deref(),
        name.as_deref(),
        Some(&book_fields),
    ))
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
    let (variable, name) = input_book_state(params);
    let mut book_fields = input_book_fields(params);
    if let Some(name_str) = &name {
        book_fields
            .entry("name".to_string())
            .or_insert_with(|| name_str.clone());
    }
    let detail_context = url_rule_context_with_fields(
        variable.as_deref(),
        None,
        name.as_deref(),
        None,
        Some(&book_fields),
    );
    let detail_response = fetch_rule_with_context(
        session,
        source,
        &initial_url,
        "",
        1,
        &source.book_source_url,
        options,
        Some(&detail_context),
    )?;
    let book_info = engine.book_info_with_context(
        source,
        &detail_response.body,
        &detail_response.url,
        &initial_url,
        variable.as_deref(),
        name.as_deref(),
        Some(&book_fields),
    );
    let toc_url = book_info
        .toc_url
        .as_ref()
        .filter(|url| !url.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| initial_url.clone());

    if !book_info.name.is_empty() {
        book_fields.insert("name".to_string(), book_info.name.clone());
        book_fields.insert("bookName".to_string(), book_info.name.clone());
    }
    if !book_info.author.is_empty() {
        book_fields.insert("author".to_string(), book_info.author.clone());
    }
    if let Some(kind) = &book_info.kind {
        book_fields.insert("kind".to_string(), kind.clone());
    }
    if let Some(word_count) = &book_info.word_count {
        book_fields.insert("wordCount".to_string(), word_count.clone());
        book_fields.insert("word_count".to_string(), word_count.clone());
    }
    if let Some(intro) = &book_info.intro {
        book_fields.insert("intro".to_string(), intro.clone());
    }
    if let Some(cover_url) = &book_info.cover_url {
        book_fields.insert("coverUrl".to_string(), cover_url.clone());
        book_fields.insert("cover_url".to_string(), cover_url.clone());
    }
    if let Some(toc_url) = &book_info.toc_url {
        book_fields.insert("tocUrl".to_string(), toc_url.clone());
        book_fields.insert("toc_url".to_string(), toc_url.clone());
    }
    if let Some(latest) = &book_info.latest_chapter_title {
        book_fields.insert("lastChapter".to_string(), latest.clone());
        book_fields.insert("latestChapterTitle".to_string(), latest.clone());
    }

    let mut book_variable = book_info.variable.clone();
    let reuse_detail_response = same_resource_url(&toc_url, &initial_url)
        || same_resource_url(&toc_url, &detail_response.url);
    let mut detail_toc_response = reuse_detail_response.then(|| detail_response.clone());
    let (_, reverse) = normalize_list_rule(
        source
            .rule_toc
            .as_ref()
            .and_then(|rule| rule.chapter_list.as_deref())
            .unwrap_or(""),
    );
    // Formatting belongs to the final TOC, after global deduplication and ordering.
    let mut page_source = source.clone();
    if let Some(rule) = &mut page_source.rule_toc {
        rule.format_js = None;
    }
    let mut pending = VecDeque::from([toc_url.clone()]);
    let mut visited_pages = HashSet::new();
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
        let toc_context = url_rule_context_with_fields(
            book_variable.as_deref(),
            None,
            Some(&book_info.name),
            None,
            Some(&book_fields),
        );
        let response = if same_resource_url(&url, &toc_url) {
            if let Some(response) = detail_toc_response.take() {
                response
            } else {
                fetch_rule_with_context(
                    session,
                    source,
                    &url,
                    "",
                    1,
                    &source.book_source_url,
                    options,
                    Some(&toc_context),
                )?
            }
        } else {
            fetch_rule_with_context(
                session,
                source,
                &url,
                "",
                1,
                &source.book_source_url,
                options,
                Some(&toc_context),
            )?
        };
        visited_pages.insert(url);
        let mut page = engine.chapter_list_page_with_context(
            &page_source,
            &response.body,
            &response.url,
            book_variable.as_deref(),
            Some(&book_info.name),
            Some(&book_fields),
        );
        book_variable = page.book_variable;
        // Keep the single-page parser contract; reverse the complete TOC below.
        if reverse {
            page.chapters.reverse();
        }
        chapters.extend(page.chapters);
        for next_url in page.next_urls {
            if !next_url.trim().is_empty() && !visited_pages.contains(&next_url) {
                pending.push_back(next_url);
            }
        }
        final_response = Some(response);
    }

    let response =
        final_response.ok_or_else(|| ExecuteError::url_rule("toc URL produced no request"))?;
    let mut chapters = dedupe_chapters_last_wins(chapters);
    if reverse {
        chapters.reverse();
        for (index, chapter) in chapters.iter_mut().enumerate() {
            chapter.index = index as i32;
        }
    }
    engine.format_chapter_list_with_context(
        source,
        &mut chapters,
        &toc_url,
        book_variable.as_deref(),
        Some(&book_info.name),
        Some(&book_fields),
    );
    let mut titles = chapters
        .iter()
        .map(|chapter| chapter.title.clone())
        .collect::<Vec<_>>();
    text_transform::apply_from_params(&mut titles, params);
    for (chapter, title) in chapters.iter_mut().zip(titles) {
        chapter.title = title;
    }
    let mut data =
        json!({"chapters": chapters, "pages": visited_pages.len(), "truncated": truncated});
    if let Some(variable) = book_variable {
        data["variable"] = json!(variable);
    }
    Ok(success(
        data,
        visited_pages.len(),
        truncated,
        &response,
        options,
    ))
}

fn same_resource_url(left: &str, right: &str) -> bool {
    let Some(mut left) = url::Url::parse(left).ok() else {
        return left == right;
    };
    let Some(mut right) = url::Url::parse(right).ok() else {
        return false;
    };
    left.set_fragment(None);
    right.set_fragment(None);
    left == right
}

fn js_code_only(script: &str) -> String {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Code,
        Quote(char),
        LineComment,
        BlockComment,
    }

    let chars = script.chars().collect::<Vec<_>>();
    let mut output = String::with_capacity(script.len());
    let mut state = State::Code;
    let mut escaped = false;
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();
        match state {
            State::Code if ch == '/' && next == Some('/') => {
                output.push_str("  ");
                state = State::LineComment;
                index += 2;
                continue;
            }
            State::Code if ch == '/' && next == Some('*') => {
                output.push_str("  ");
                state = State::BlockComment;
                index += 2;
                continue;
            }
            State::Code if matches!(ch, '\'' | '"' | '\u{60}') => {
                output.push(' ');
                state = State::Quote(ch);
                escaped = false;
            }
            State::Code => output.push(ch),
            State::Quote(quote) => {
                output.push(' ');
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == quote {
                    state = State::Code;
                }
            }
            State::LineComment => {
                output.push(if ch == '\n' { '\n' } else { ' ' });
                if ch == '\n' {
                    state = State::Code;
                }
            }
            State::BlockComment if ch == '*' && next == Some('/') => {
                output.push_str("  ");
                state = State::Code;
                index += 2;
                continue;
            }
            State::BlockComment => output.push(if ch == '\n' { '\n' } else { ' ' }),
        }
        index += 1;
    }
    output
}

fn js_has_call(code: &str, name: &str) -> bool {
    let mut rest = code;
    while let Some(index) = rest.find(name) {
        let after = &rest[index + name.len()..];
        if after.trim_start().starts_with('(') {
            return true;
        }
        rest = after;
    }
    false
}

fn uses_js_ajax_content_rule(source: &BookSource) -> bool {
    source
        .rule_content
        .as_ref()
        .and_then(|rule| rule.content.as_deref())
        .is_some_and(|rule| {
            let rule = rule.trim();
            let lower_rule = rule.to_ascii_lowercase();
            let is_js = lower_rule.starts_with("@js:")
                || lower_rule.starts_with("js:")
                || lower_rule.starts_with("<js>");
            if !is_js {
                return false;
            }

            let code = js_code_only(rule);
            let references = |name: &str| {
                code.split(|character: char| {
                    !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
                })
                .any(|identifier| identifier == name)
            };
            js_has_call(&code, "java.ajax")
                && references("baseUrl")
                && !references("input")
                && !references("result")
                && !references("src")
        })
}

fn execute_content(
    source: &BookSource,
    engine: &RuleEngine,
    session: &HttpSession,
    params: &Value,
    options: &ValidatedOptions,
) -> ExecuteResult<Value> {
    let initial_url = required_string(params, "url")?;
    let (mut book_variable, book_name) = input_book_state(params);
    let mut book_fields = input_book_fields(params);
    if let Some(name_str) = &book_name {
        book_fields
            .entry("name".to_string())
            .or_insert_with(|| name_str.clone());
    }
    let (mut chapter_variable, mut chapter_title) = input_chapter_state(params);
    let is_volume = input_chapter_is_volume(params);

    let self_fetch = uses_js_ajax_content_rule(source)
        && !strip_url_options(&initial_url).trim().starts_with("data:");

    // Source replaceRegex is applied once after all content fragments are joined.
    let mut page_source = source.clone();
    if let Some(rule) = &mut page_source.rule_content {
        rule.replace_regex = None;
    }
    let chapter_fields = input_chapter_fields(params, &initial_url);
    let mut pending = VecDeque::from([(initial_url.clone(), true)]);
    let mut visited_urls = HashSet::new();
    let mut fragments = Vec::new();
    let mut initial_response_url = None;
    let mut first_page = None;
    let mut final_response = None;
    let mut final_url = initial_url.clone();
    let mut title = None;
    let mut sub_requests = 0;
    let text_book = params
        .get("book")
        .and_then(|book| book.get("type"))
        .and_then(Value::as_i64)
        .map(|kind| kind == 0 || kind & 8 != 0 && kind & 256 == 0)
        .unwrap_or_else(|| source.book_source_type.unwrap_or(0) == 0);
    let mut truncated = false;

    while let Some((current_url, follow_next)) = pending.pop_front() {
        if visited_urls.contains(&current_url) {
            continue;
        }
        if visited_urls.len() >= options.max_pages {
            truncated = true;
            break;
        }
        let response = if self_fetch {
            None
        } else {
            let mut request_context = url_rule_context_with_fields(
                book_variable.as_deref(),
                chapter_variable.as_deref(),
                book_name.as_deref(),
                chapter_title.as_deref(),
                Some(&book_fields),
            );
            request_context.chapter_fields = chapter_fields.clone();
            Some(fetch_rule_with_context(
                session,
                source,
                &current_url,
                "",
                1,
                &source.book_source_url,
                options,
                Some(&request_context),
            )?)
        };
        let body = response
            .as_ref()
            .map_or("", |response| response.body.as_str());
        let response_url = response
            .as_ref()
            .map_or_else(|| current_url.clone(), |response| response.url.clone());
        visited_urls.insert(current_url.clone());
        let is_first_page = first_page.is_none();
        if is_first_page {
            first_page = Some((body.to_string(), response_url.clone()));
        }
        let chapter_url = initial_response_url.get_or_insert_with(|| response_url.clone());
        let page = if is_first_page {
            engine.content_first_page_with_context(
                &page_source,
                body,
                &response_url,
                book_variable.as_deref(),
                chapter_variable.as_deref(),
                book_name.as_deref(),
                chapter_title.as_deref(),
                Some(&book_fields),
                Some(&chapter_fields),
                follow_next,
            )
        } else {
            engine.content_page_with_context_follow(
                &page_source,
                body,
                &response_url,
                book_variable.as_deref(),
                chapter_variable.as_deref(),
                book_name.as_deref(),
                chapter_title.as_deref(),
                Some(&book_fields),
                Some(&chapter_fields),
                follow_next,
            )
        };
        if !page.content.is_empty() {
            fragments.push(page.content);
        }
        if let Some(parsed_title) = page.title.as_ref() {
            chapter_title = Some(parsed_title.clone());
            title = Some(parsed_title.clone());
        }
        book_variable = page.book_variable;
        chapter_variable = page.chapter_variable;
        final_url = response_url.clone();
        final_response = response;

        let recursive = page.next_urls.len() == 1;
        for next_url in page.next_urls {
            let allowed =
                !recursive || should_follow_content_page(chapter_url, &response_url, &next_url);
            if allowed
                && !visited_urls.contains(&next_url)
                && !pending.iter().any(|(url, _)| url == &next_url)
            {
                if pending.len() + visited_urls.len() >= options.max_pages {
                    truncated = true;
                    break;
                }
                pending.push_back((next_url, recursive));
            }
        }
    }

    if !self_fetch && final_response.is_none() {
        return Err(ExecuteError::url_rule("content URL produced no request"));
    }
    if text_book && !self_fetch {
        if let Some((body, url)) = first_page.as_ref() {
            if let Some(sub_content) = engine.sub_content_with_context(
                source,
                body,
                url,
                book_variable.as_deref(),
                chapter_variable.as_deref(),
                book_name.as_deref(),
                chapter_title.as_deref(),
                Some(&book_fields),
                Some(&chapter_fields),
            ) {
                let sub_content = if sub_content.to_ascii_lowercase().starts_with("http") {
                    if visited_urls.len() >= options.max_pages {
                        truncated = true;
                        String::new()
                    } else {
                        sub_requests += 1;
                        let sub_context = url_rule_context_with_fields(
                            book_variable.as_deref(),
                            None,
                            book_name.as_deref(),
                            None,
                            Some(&book_fields),
                        );
                        fetch_rule_with_context(
                            session,
                            source,
                            &sub_content,
                            "",
                            1,
                            url,
                            options,
                            Some(&sub_context),
                        )?
                        .body
                    }
                } else {
                    sub_content
                };
                if !sub_content.trim().is_empty() {
                    fragments.push(sub_content);
                }
            }
        }
    }
    let mut replacement_context = url_rule_context_with_fields(
        book_variable.as_deref(),
        chapter_variable.as_deref(),
        book_name.as_deref(),
        chapter_title.as_deref(),
        Some(&book_fields),
    );
    replacement_context.chapter_fields = chapter_fields;
    let mut content = engine.replace_content_with_context(
        source,
        &fragments.join("\n"),
        &final_url,
        &replacement_context,
    );
    text_transform::apply_from_params(std::slice::from_mut(&mut content), params);
    if content.is_empty() && !is_volume {
        return Err(ExecuteError::parse("content is empty"));
    }
    let mut data = json!({"content": content});
    if !self_fetch {
        data["pages"] = json!(visited_urls.len() + sub_requests);
        data["truncated"] = json!(truncated);
    }
    if let Some(variable) = book_variable {
        data["bookVariable"] = json!(variable);
    }
    if let Some(variable) = chapter_variable {
        data["variable"] = json!(variable);
    }
    if let Some(title) = title {
        data["title"] = json!(title);
    }
    match final_response {
        Some(response) => Ok(success(
            data,
            visited_urls.len() + sub_requests,
            truncated,
            &response,
            options,
        )),
        None => {
            let mut response = success_without_http(data);
            response["meta"]["truncated"] = json!(truncated);
            Ok(response)
        }
    }
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
            "需使用外部浏览器登录，Cookie 不支持同步".to_string(),
        ));
    }

    let login_url = source.login_url.as_deref().unwrap_or("").trim();
    let login_script = login_script(source);
    if login_script.is_none() && !login_url.is_empty() {
        let url = absolute_login_url(source).unwrap_or_else(|| login_url.to_string());
        return Err(web_login_error(
            source,
            &url,
            "需使用外部浏览器进行网页登录，Cookie 不支持同步".to_string(),
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
        let (output, messages, preview) = with_login_messages(|| with_js_lib(source.js_lib.as_deref(), || {
            eval_js_with_bindings(&script, "", &source.book_source_url, &bindings)
        }));
        let output = output.map_err(|error| {
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
            "preview": preview,
            // 原生书源用 toast/longToast 反馈状态；仅展示，不推断认证结果。
            "message": if messages.is_empty() { "登录脚本执行成功".to_string() } else { messages.join("\n") },
        })));
    }

    Err(ExecuteError::invalid_request(
        "source.loginUrl or params.action is required",
    ))
}

fn execute_click(source: &BookSource, params: &Value) -> ExecuteResult<Value> {
    let action = params.get("action").and_then(Value::as_str)
        .filter(|action| !action.trim().is_empty() && action.len() <= 64 * 1024)
        .ok_or_else(|| ExecuteError::invalid_request("click action must be a nonempty string up to 64 KiB"))?;
    let mut bindings = HashMap::new();
    for name in ["book", "chapter"] {
        if let Some(value) = params.get(name) {
            if !value.is_object() { return Err(ExecuteError::invalid_request(format!("{name} must be an object"))); }
            bindings.insert(name.to_string(), value.clone());
        }
    }
    let (output, browser) = with_click_browser(|| with_js_lib(source.js_lib.as_deref(), || {
        eval_js_with_bindings(action, "", &source.book_source_url, &bindings)
    }));
    output.map_err(|error| ExecuteError::invalid_request(format!("click script failed: {error}")))?;
    let browser = browser.ok_or_else(|| ExecuteError::invalid_request("click did not open a browser"))?;
    let url = browser.get("url").and_then(Value::as_str).unwrap_or_default();
    let html = browser.get("html").and_then(Value::as_str).unwrap_or_default();
    if !url.is_empty() && !is_absolute_http_url(url) {
        return Err(ExecuteError::invalid_request("click browser URL must be HTTP(S)"));
    }
    if url.is_empty() && html.is_empty() {
        return Err(ExecuteError::invalid_request("click browser URL and HTML are empty"));
    }
    Ok(success_without_http(json!({"browser":browser})))
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

// Legado 的原生表单使用 getLoginJs()：无前缀的 loginUrl 也可作为脚本。
// 无表单的相对网页登录 URL 保持原行为，明确的 HTTP URL 不当作脚本执行。
fn login_script(source: &BookSource) -> Option<&str> {
    let rule = source.login_url.as_deref()?.trim();
    strip_js_prefix(rule).or_else(|| {
        (!rule.is_empty()
            && !is_absolute_http_url(rule)
            && source.login_ui.as_deref().is_some_and(login_ui_configured))
        .then_some(rule)
    })
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
    fetch_rule_with_context(session, source, rule, key, page, base_url, options, None)
}

fn fetch_rule_with_context(
    session: &HttpSession,
    source: &BookSource,
    rule: &str,
    key: &str,
    page: i32,
    base_url: &str,
    options: &ValidatedOptions,
    context: Option<&UrlRuleContext>,
) -> ExecuteResult<HttpResponse> {
    let spec = analyze_url_with_context(rule, key, page, base_url, source, context)
        .map_err(ExecuteError::url_rule)?;
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
    .map_err(|error| ExecuteError::parse(format!("loginCheckJs failed: {error}")))?;

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

    let value = serde_json::from_str::<Value>(&output)
        .map_err(|_| ExecuteError::parse("loginCheckJs must return a StrResponse"))?;
    if !value.is_object() {
        return Err(ExecuteError::parse(
            "loginCheckJs must return a StrResponse",
        ));
    }
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
    if raw.is_empty() || login_script(source).is_some() {
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
    let chapter_url = strip_fragment(strip_url_options(chapter_url));
    let current_url = strip_fragment(strip_url_options(current_url));
    let next_url = strip_fragment(strip_url_options(next_url));
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
    use super::{
        execute, input_book_state, input_chapter_state, uses_js_ajax_content_rule, BookSource,
    };
    use base64::Engine;
    use serde_json::Value;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::thread;
    use std::time::{Duration, Instant};

    fn accept_with_timeout(listener: &TcpListener) -> (TcpStream, SocketAddr) {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, address)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    return (stream, address);
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("test HTTP server did not receive request: {error}"),
            }
        }
    }

    fn serve_once(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
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
                let (mut stream, _) = accept_with_timeout(&listener);
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
                        r#"{"chapters":[{"title":"第一章（更新）","url":"/chapter/1.html"},{"title":"第二章","url":"/chapter/2.html"}]}"#,
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
    fn execute_state_inputs_accept_serialized_and_map_variables() {
        let params = serde_json::json!({
            "book": {"name": "Book", "variable": r#"{"bid":"B"}"#},
            "chapter": {"title": "Chapter", "variableMap": {"cid": "C"}}
        });
        let (book_variable, book_name) = input_book_state(&params);
        let (chapter_variable, chapter_title) = input_chapter_state(&params);
        assert_eq!(book_variable.as_deref(), Some(r#"{"bid":"B"}"#));
        assert_eq!(book_name.as_deref(), Some("Book"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(chapter_variable.as_deref().unwrap())
                .unwrap()["cid"],
            "C"
        );
        assert_eq!(chapter_title.as_deref(), Some("Chapter"));
    }

    #[test]
    fn execute_rejects_empty_content_except_for_volume_chapters() {
        let source_for = |base_url: String| {
            serde_json::json!({
                "bookSourceName": "empty content fixture",
                "bookSourceUrl": base_url,
                "ruleContent": {"content": "$.content"}
            })
        };
        let empty_body = r#"{"content":""}"#;
        let base_url = serve_once(empty_body);
        let source = source_for(base_url.clone());
        let result: serde_json::Value = serde_json::from_str(&execute(
            &source.to_string(),
            &serde_json::json!({
                "api": 2,
                "op": "content",
                "params": {"url": base_url, "chapter": {"isVolume": false}}
            })
            .to_string(),
        ))
        .unwrap();
        assert_eq!(result["ok"], false);
        assert_eq!(result["error"]["kind"], "parse");
        assert_eq!(result["error"]["message"], "content is empty");

        let base_url = serve_once(empty_body);
        let source = source_for(base_url.clone());
        let result: serde_json::Value = serde_json::from_str(&execute(
            &source.to_string(),
            &serde_json::json!({
                "api": 2,
                "op": "content",
                "params": {"url": base_url, "chapter": {"isVolume": true}}
            })
            .to_string(),
        ))
        .unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"]["content"], "");
    }

    #[test]
    fn execute_toc_text_transform_runs_after_format_js() {
        let base_url = serve_once(r#"{"chapters":[{"title":"old","url":"/chapter/1"}]}"#);
        let source = serde_json::json!({
            "bookSourceName": "TOC text transform fixture",
            "bookSourceUrl": base_url,
            "ruleToc": {
                "chapterList": "$.chapters[*]",
                "chapterName": "$.title",
                "chapterUrl": "$.url",
                "formatJs": "'fmt-' + title"
            }
        });
        let request = serde_json::json!({
            "api": 2,
            "op": "toc",
            "params": {
                "url": source["bookSourceUrl"],
                "textTransformDialect": "legado",
                "textTransformRules": [{
                    "pattern": "fmt-",
                    "replacement": "final-",
                    "isRegex": false
                }]
            }
        });

        let result: Value =
            serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"]["chapters"][0]["title"], "final-old");
    }

    #[test]
    fn execute_toc_js_reads_book_scoped_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let base_url = format!("http://{address}");
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut request = [0u8; 4096];
                let bytes_read = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..bytes_read]).into_owned();
                let target = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or_default()
                    .to_string();
                let has_rule_header = request.lines().any(|line| {
                    line.split_once(':').is_some_and(|(name, value)| {
                        name.trim().eq_ignore_ascii_case("x-test") && value.trim() == "present"
                    })
                });
                let body = if target == "/book" {
                    r#"{"data":{"book":{"id":"book-id-7","name":"Book"}}}"#
                } else {
                    r#"{"data":{"chapter_lists":[{"title":"Chapter","id":"chapter-id-42"}]}}"#
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
                requests.push((target, has_rule_header));
            }
            requests
        });

        let toc_rule = format!(
            r#"@js: var id = JSON.parse(input).id; "{base_url}/toc?bid=" + id + "," + java.get("headers")"#
        );
        let source = serde_json::json!({
            "bookSourceName": "TOC scoped variable fixture",
            "bookSourceUrl": base_url,
            "ruleBookInfo": {
                "init": "data.book",
                "name": "$.name",
                "tocUrl": toc_rule
            },
            "ruleToc": {
                "chapterList": "data.chapter_lists",
                "chapterName": "title",
                "chapterUrl": "id"
            }
        });
        let request = serde_json::json!({
            "api": 2,
            "op": "toc",
            "params": {
                "url": "/book",
                "book": {
                    "name": "Book",
                    "variable": {
                        "headers": r#"{"headers":{"X-Test":"present"}}"#
                    }
                }
            }
        });

        let result: Value =
            serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
        let requests = server.join().unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(
            result["data"]["chapters"].as_array().unwrap().len(),
            1,
            "result={result} requests={requests:?}"
        );
        assert_eq!(requests[0].0, "/book");
        assert_eq!(requests[1].0, "/toc?bid=book-id-7");
        assert!(requests[1].1);
    }

    #[test]
    fn js_self_fetch_detection_ignores_strings_and_comments() {
        let source = |content: &str| -> BookSource {
            serde_json::from_value(serde_json::json!({
                "bookSourceName": "self-fetch detection",
                "bookSourceUrl": "https://example.com",
                "ruleContent": {"content": content}
            }))
            .unwrap()
        };

        assert!(!uses_js_ajax_content_rule(&source(
            r#"@js: const note = "java.ajax(baseUrl)"; baseUrl"#
        )));
        assert!(!uses_js_ajax_content_rule(&source(
            "@js: /* java.ajax(baseUrl) */ baseUrl"
        )));
        assert!(!uses_js_ajax_content_rule(&source(
            "@js: java.ajax(baseUrl); input"
        )));
        assert!(uses_js_ajax_content_rule(&source(
            "@js: java.ajax(baseUrl)"
        )));
    }

    #[test]
    fn android_request_methods_and_unknown_fallback_are_observable() {
        for (requested, expected, fallback) in [
            (serde_json::json!("get"), "GET", false),
            (serde_json::json!("post"), "POST", false),
            (serde_json::json!("head"), "HEAD", false),
            (serde_json::json!("PATCH"), "GET", true),
            (serde_json::json!(42), "GET", true),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = thread::spawn(move || {
                let (mut stream, _) = accept_with_timeout(&listener);
                let first_line = crate::util::test_http::consume_request(&mut stream);
                let method = first_line.split_whitespace().next().unwrap().to_string();
                let body = if method == "HEAD" {
                    ""
                } else {
                    r#"{"data":[]}"#
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
                method
            });
            let source = serde_json::json!({"bookSourceName":"method fixture", "bookSourceUrl":base,
                "searchUrl": format!("/search,{}", serde_json::json!({"method":requested})),
                "ruleSearch":{"bookList":"$.data[*]","name":"$.name"}});
            let request = serde_json::json!({"api":2,"op":"search","params":{"key":"test"}});
            let result: Value =
                serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
            assert_eq!(result["ok"], true, "{result}");
            assert_eq!(server.join().unwrap(), expected);
            if fallback {
                assert_eq!(
                    result["meta"]["diagnostics"],
                    serde_json::json!(["unknown_method_fallback_get"])
                );
            } else {
                assert!(result["meta"].get("diagnostics").is_none(), "{result}");
            }
        }
    }

    #[test]
    fn method_fallback_diagnostic_survives_a_failed_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut buf = [0u8; 1024];
            let size = stream.read(&mut buf).unwrap();
            let request = String::from_utf8_lossy(&buf[..size]).to_string();
            write!(
                stream,
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            request
        });
        let source = serde_json::json!({"bookSourceName":"fallback failure","bookSourceUrl":base,
            "searchUrl":"/search,{\"method\":\"DELETE\"}","ruleSearch":{"bookList":"$.data[*]"}});
        let request = serde_json::json!({"api":2,"op":"search","params":{"key":"test"}});
        let result: Value =
            serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
        assert_eq!(result["ok"], false, "{result}");
        assert_eq!(result["error"]["status"], 404);
        assert_eq!(
            result["meta"]["diagnostics"],
            serde_json::json!(["unknown_method_fallback_get"])
        );
        assert!(server.join().unwrap().starts_with("GET /search"));
    }

    #[test]
    fn content_title_uses_original_response_after_pagination() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            for index in 0..2 {
                let (mut stream, _) = accept_with_timeout(&listener);
                crate::util::test_http::consume_request(&mut stream);
                let body = if index == 0 {
                    r#"{"content":"first","title":"Original","next":"/chapter/1-2"}"#
                } else {
                    r#"{"content":"second","title":"Other"}"#
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        let source = serde_json::json!({"bookSourceName":"chapter title", "bookSourceUrl":base,
            "ruleContent":{"content":"$.content","nextContentUrl":"$.next","title":"$.title"}});
        let request = serde_json::json!({"api":2,"op":"content","params":{"url":format!("{base}/chapter/1")}});
        let result: Value =
            serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"]["title"], "Original");
        assert_eq!(result["data"]["content"], "first\nsecond");
        server.join().unwrap();
    }

    #[test]
    fn empty_or_invalid_title_rule_does_not_add_a_title_field() {
        for title_rule in ["$.title", "@js: throw new Error('title unavailable')"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = thread::spawn(move || {
                let (mut stream, _) = accept_with_timeout(&listener);
                crate::util::test_http::consume_request(&mut stream);
                let body = r#"{"content":"main","title":"   "}"#;
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            });
            let source = serde_json::json!({"bookSourceName":"optional title", "bookSourceUrl":base,
                "ruleContent":{"content":"$.content","title":title_rule}});
            let request = serde_json::json!({"api":2,"op":"content","params":{"url":format!("{base}/chapter")}});
            let result: Value =
                serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
            assert_eq!(result["ok"], true, "{result}");
            assert!(result["data"].get("title").is_none(), "{result}");
            assert_eq!(result["data"]["content"], "main");
            server.join().unwrap();
        }
    }

    #[test]
    fn multiple_next_content_urls_preserve_order_without_recursing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut paths = Vec::new();
            for _ in 0..3 {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut buf = [0u8; 2048];
                let size = stream.read(&mut buf).unwrap();
                let path = String::from_utf8_lossy(&buf[..size])
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_string();
                let body = match path.as_str() {
                    "/chapter/1" => {
                        r#"{"content":"first","next":["/part-two","/part-three","/part-two","/chapter/1"]}"#
                    }
                    "/part-two" => r#"{"content":"second","next":["/part-four"]}"#,
                    "/part-three" => r#"{"content":"third","next":["/part-four"]}"#,
                    _ => panic!("unexpected page: {path}"),
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
                paths.push(path);
            }
            paths
        });
        let source = serde_json::json!({"bookSourceName":"multi-page", "bookSourceUrl":base,
            "ruleContent":{"content":"$.content","nextContentUrl":"$.next[*]"}});
        let request = serde_json::json!({"api":2,"op":"content","params":{"url":format!("{base}/chapter/1")}});
        let result: Value =
            serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"]["content"], "first\nsecond\nthird");
        assert_eq!(result["data"]["pages"], 3);
        assert_eq!(
            server.join().unwrap(),
            ["/chapter/1", "/part-two", "/part-three"]
        );
    }

    #[test]
    fn multiple_next_content_urls_allow_cross_origin_pages() {
        let primary = TcpListener::bind("127.0.0.1:0").unwrap();
        let primary_base = format!("http://{}", primary.local_addr().unwrap());
        let secondary = TcpListener::bind("127.0.0.1:0").unwrap();
        let secondary_url = format!("http://{}/part-three", secondary.local_addr().unwrap());

        let primary_server = thread::spawn({
            let secondary_url = secondary_url.clone();
            move || {
                let mut paths = Vec::new();
                for index in 0..2 {
                    let (mut stream, _) = accept_with_timeout(&primary);
                    let mut buf = [0u8; 2048];
                    let size = stream.read(&mut buf).unwrap();
                    let path = String::from_utf8_lossy(&buf[..size])
                        .split_whitespace()
                        .nth(1)
                        .unwrap()
                        .to_string();
                    let body = if index == 0 {
                        serde_json::json!({
                            "content":"first",
                            "next":["/part-two", secondary_url]
                        })
                        .to_string()
                    } else {
                        r#"{"content":"second"}"#.to_string()
                    };
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                    paths.push(path);
                }
                paths
            }
        });
        let secondary_server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&secondary);
            let mut buf = [0u8; 2048];
            let size = stream.read(&mut buf).unwrap();
            let path = String::from_utf8_lossy(&buf[..size])
                .split_whitespace()
                .nth(1)
                .unwrap()
                .to_string();
            let body = r#"{"content":"third"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            path
        });

        let source = serde_json::json!({"bookSourceName":"cross-origin pages","bookSourceUrl":primary_base,
            "ruleContent":{"content":"$.content","nextContentUrl":"$.next[*]"}});
        let request = serde_json::json!({"api":2,"op":"content","params":{"url":format!("{primary_base}/chapter/1")}});
        let result: Value =
            serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();

        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"]["content"], "first\nsecond\nthird");
        assert_eq!(result["data"]["pages"], 3);
        assert_eq!(primary_server.join().unwrap(), ["/chapter/1", "/part-two"]);
        assert_eq!(secondary_server.join().unwrap(), "/part-three");
    }

    #[test]
    fn next_content_rule_preserves_css_and_js_url_lists() {
        let engine = crate::parser::rule_engine::RuleEngine::new().unwrap();
        let base = "https://example.com/chapter/1";
        for (rule, body) in [
            ("@css:.pages a@href", "<div class='pages'><a href='/chapter/1-2'>two</a><a href='/chapter/1-3'>three</a></div>"),
            ("@js:JSON.stringify(['/chapter/1-2','/chapter/1-3'])", "<p>main</p>"),
        ] {
            let source: BookSource = serde_json::from_value(serde_json::json!({
                "bookSourceName":"list rules", "bookSourceUrl":base,
                "ruleContent":{"content":"body@text", "nextContentUrl":rule}
            })).unwrap();
            let page = engine.content_page_with_variables(&source, body, base, None, None, None, None);
            assert_eq!(page.next_urls, ["https://example.com/chapter/1-2", "https://example.com/chapter/1-3"], "{rule}");
        }
    }

    #[test]
    fn failed_content_sibling_stops_remaining_pages() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            for index in 0..2 {
                let (mut stream, _) = accept_with_timeout(&listener);
                crate::util::test_http::consume_request(&mut stream);
                let (status, body) = if index == 0 {
                    (
                        "200 OK",
                        r#"{"content":"first","next":["/chapter/1-2","/chapter/1-3"]}"#,
                    )
                } else {
                    ("404 Not Found", "missing")
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        let source = serde_json::json!({"bookSourceName":"failed sibling", "bookSourceUrl":base,
            "ruleContent":{"content":"$.content","nextContentUrl":"$.next[*]"}});
        let request = serde_json::json!({"api":2,"op":"content","params":{"url":format!("{base}/chapter/1")}});
        let result: Value =
            serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
        assert_eq!(result["ok"], false, "{result}");
        assert_eq!(result["error"]["status"], 404);
        server.join().unwrap();
    }

    #[test]
    fn multiple_content_pages_share_a_total_page_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut paths = Vec::new();
            for index in 0..2 {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut buf = [0u8; 2048];
                let size = stream.read(&mut buf).unwrap();
                paths.push(
                    String::from_utf8_lossy(&buf[..size])
                        .split_whitespace()
                        .nth(1)
                        .unwrap()
                        .to_string(),
                );
                let body = if index == 0 {
                    r#"{"content":"first","next":["/chapter/1-2","/chapter/1-3"]}"#
                } else {
                    r#"{"content":"second"}"#
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
            paths
        });
        let source = serde_json::json!({"bookSourceName":"bounded pages", "bookSourceUrl":base,
            "ruleContent":{"content":"$.content","nextContentUrl":"$.next[*]"}});
        let request = serde_json::json!({"api":2,"op":"content","params":{
            "url":format!("{base}/chapter/1")},"options":{"maxPages":2}});
        let result: Value =
            serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"]["content"], "first\nsecond");
        assert_eq!(result["data"]["truncated"], true);
        assert_eq!(server.join().unwrap(), ["/chapter/1", "/chapter/1-2"]);
    }

    #[test]
    fn sub_content_uses_original_page_after_pagination_and_fetches_once() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let append_url = format!("{base}/append");
        let server = thread::spawn(move || {
            let mut paths = Vec::new();
            for _ in 0..3 {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut request = [0u8; 2048];
                let size = stream.read(&mut request).unwrap();
                let path = String::from_utf8_lossy(&request[..size])
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_string();
                let body = match path.as_str() {
                    "/chapter/1" => serde_json::json!({
                        "content":"first","next":"/chapter/1-2",
                        "append":format!(r#"{append_url},{{"js":"result + '?name=' + book.name"}}"#)
                    })
                    .to_string(),
                    "/chapter/1-2" => r#"{"content":"second","append":"ignored"}"#.to_string(),
                    "/append?name=Book" => "supplement".to_string(),
                    _ => panic!("unexpected path {path}"),
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
                paths.push(path);
            }
            paths
        });
        let source = serde_json::json!({
            "bookSourceName":"sub content fixture","bookSourceUrl":base,
            "ruleContent":{"content":"$.content","nextContentUrl":"$.next","subContent":"$.append"}
        });
        let request = serde_json::json!({"api":2,"op":"content","params":{
            "url":format!("{base}/chapter/1"),"book":{"name":"Book"}}});
        let result: Value =
            serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"]["content"], "first\nsecond\nsupplement");
        assert_eq!(result["data"]["pages"], 3);
        assert_eq!(
            server.join().unwrap(),
            ["/chapter/1", "/chapter/1-2", "/append?name=Book"]
        );
    }

    #[test]
    fn sub_content_url_respects_page_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            crate::util::test_http::consume_request(&mut stream);
            let body = r#"{"content":"main","append":"http://127.0.0.1:1/should-not-fetch"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let source = serde_json::json!({"bookSourceName":"budget", "bookSourceUrl":base,
            "ruleContent":{"content":"$.content","subContent":"$.append"}});
        let request = serde_json::json!({"api":2,"op":"content","params":{
            "url":format!("{base}/chapter")},"options":{"maxPages":1}});
        let result: Value =
            serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"]["content"], "main");
        assert_eq!(result["data"]["truncated"], true);
        server.join().unwrap();
    }

    #[test]
    fn sub_content_inline_applies_only_to_text_and_uses_original_response() {
        for (kind, expected) in [(8, "main\nextra"), (32, "main")] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = thread::spawn(move || {
                let (mut stream, _) = accept_with_timeout(&listener);
                crate::util::test_http::consume_request(&mut stream);
                let body = r#"{"content":"main","append":"extra"}"#;
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            });
            let source = serde_json::json!({"bookSourceName":"inline", "bookSourceUrl":base,
                "ruleContent":{"content":"$.content","subContent":"$.append"}});
            let request = serde_json::json!({"api":2,"op":"content","params":{
                "url":format!("{base}/chapter"),"book":{"type":kind}}});
            let result: Value =
                serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
            assert_eq!(result["ok"], true, "{result}");
            assert_eq!(result["data"]["content"], expected);
            server.join().unwrap();
        }
    }

    #[test]
    fn content_url_js_receives_chapter_fields_without_changing_source_header_scope() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut request = [0u8; 4096];
            let size = stream.read(&mut request).unwrap();
            let head = String::from_utf8_lossy(&request[..size]).into_owned();
            let body = r#"{"data":{"content":"chapter text"}}"#;
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            head
        });
        let source = serde_json::json!({
            "bookSourceName":"chapter context",
            "bookSourceUrl":base,
            "header":"@js: JSON.stringify({'X-Source': source.getKey()})",
            "ruleContent":{"content":"$.data.content"}
        });
        let request = serde_json::json!({
            "api":2,"op":"content","params":{
                "url":format!(r#"{base}/chapter,{{"js":"result + '?id=' + chapter.index + '&volume=' + chapter.isVolume + '&url=' + encodeURIComponent(chapter.url) + '&book=' + book.name + '&token=' + chapter.variableMap.token"}}"#),
                "book":{"name":"Book"},
                "chapter":{"url":"/chapter/42","index":7,"isVolume":false,"title":"Chapter","variableMap":{"token":"T"}}
            }
        });
        let result: Value =
            serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"]["content"], "chapter text");
        let head = server.join().unwrap();
        assert!(
            head.contains("GET /chapter?id=7&volume=false&url=%2Fchapter%2F42&book=Book&token=T "),
            "{head}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains(&format!("x-source: {base}")),
            "{head}"
        );
    }

    #[test]
    fn execute_js_content_can_fetch_with_a_non_url_chapter_id() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let base_url = format!("http://{address}");
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut request = [0u8; 4096];
            let bytes_read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..bytes_read]).into_owned();
            let target = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or_default()
                .to_string();
            let has_rule_header = request.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("x-test") && value.trim() == "present"
                })
            });
            let body = r#"{"data":{"content":"正文 from API"}}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            (target, has_rule_header)
        });

        let content_rule = format!(
            r#"@js: var url = "{base_url}/chapter?bid=" + java.get("bid") + "&cid=" + baseUrl.split("/").pop(); JSON.parse(java.ajax(url + "," + java.get("headers"))).data.content"#
        );
        let source = serde_json::json!({
            "bookSourceName": "JS self-fetch fixture",
            "bookSourceUrl": base_url,
            "ruleContent": {"content": content_rule}
        });
        let request = serde_json::json!({
            "api": 2,
            "op": "content",
            "params": {
                "url": "chapter-id-42",
                "book": {
                    "name": "Book",
                    "variable": {
                        "bid": "book-id-7",
                        "headers": r#"{"headers":{"X-Test":"present"}}"#
                    }
                },
                "chapter": {"title": "Chapter"}
            }
        });

        let result: Value =
            serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
        let (target, has_rule_header) = server.join().unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"]["content"], "正文 from API");
        assert!(target.starts_with("/chapter?bid=book-id-7&cid=chapter-id-42"));
        assert!(has_rule_header);
    }

    #[test]
    fn execute_js_content_self_fetches_from_full_chapter_url() {
        let key = "242ccb8230d709e1";
        let iv = "0123456789abcdef";
        let plaintext = "正文：JavaImporter AES 兼容";
        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(
                crate::parser::js::eval_js(
                    &format!(
                        "java.aesBase64Encode({plaintext:?}, {key:?}, 'AES/CBC/PKCS5Padding', {iv:?})"
                    ),
                    "",
                    "",
                )
                .unwrap(),
            )
            .unwrap();
        let mut payload = iv.as_bytes().to_vec();
        payload.extend(encrypted);
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let base_url = format!("http://{address}");
        let server = thread::spawn(move || {
            let (mut stream, _) = accept_with_timeout(&listener);
            let mut request = [0u8; 4096];
            let bytes_read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..bytes_read]).into_owned();
            let target = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or_default()
                .to_string();
            let has_rule_header = request.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("x-test") && value.trim() == "present"
                })
            });
            let body = serde_json::json!({"data": {"content": encoded}}).to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            (target, has_rule_header)
        });

        let content_rule = format!(
            r#"@js:
                var javaImport = new JavaImporter();
                javaImport.importPackage(Packages.java.lang, Packages.javax.crypto.spec,
                    Packages.javax.crypto, Packages.java.util);
                with (javaImport) {{
                    function decode(content) {{
                        var ivEncData = Base64.getDecoder().decode(String(content));
                        var key = SecretKeySpec(String("{key}").getBytes(), "AES");
                        var iv = IvParameterSpec(Arrays.copyOfRange(ivEncData, 0, 16));
                        var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipher.init(2, key, iv);
                        return String(cipher.doFinal(Arrays.copyOfRange(ivEncData, 16, ivEncData.length)));
                    }}
                }}
                var chapterId = baseUrl.split("/").pop();
                var url = "{base_url}/content?bid=" + java.get("bid") + "&cid=" + chapterId;
                decode(JSON.parse(java.ajax(url + "," + java.get("headers"))).data.content)
            "#
        );
        let source = serde_json::json!({
            "bookSourceName": "JavaImporter self-fetch fixture",
            "bookSourceUrl": base_url,
            "ruleContent": {"content": content_rule}
        });
        let request = serde_json::json!({
            "api": 2,
            "op": "content",
            "params": {
                "url": format!("{base_url}/chapter/chapter-id-42"),
                "book": {
                    "name": "Book",
                    "variable": {
                        "bid": "book-id-7",
                        "headers": r#"{"headers":{"X-Test":"present"}}"#
                    }
                },
                "chapter": {"title": "Chapter"}
            }
        });

        let result: Value =
            serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
        let (target, has_rule_header) = server.join().unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"]["content"], plaintext);
        assert_eq!(target, "/content?bid=book-id-7&cid=chapter-id-42");
        assert!(has_rule_header);
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
        // explore + info + TOC detail/reuse + next TOC page + two content pages.
        // The second content page requires the cookie set by the first one.
        let base_url = serve_operation_fixture(6);
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
        assert_eq!(toc["data"]["chapters"][0]["title"], "第一章（更新）");
        assert_eq!(toc["data"]["chapters"][1]["title"], "第二章");
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
                let (mut stream, _) = accept_with_timeout(&listener);
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
    fn login_header_and_cookie_follow_the_ffi_session_lifecycle() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..4 {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut request = [0u8; 4096];
                let size = stream.read(&mut request).unwrap();
                requests.push(String::from_utf8_lossy(&request[..size]).to_ascii_lowercase());
                let body = r#"{"data":[{"name":"Book","url":"/book"}]}"#;
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            requests
        });
        let source = serde_json::json!({
            "bookSourceName": "login session fixture",
            "bookSourceUrl": base,
            "searchUrl": "/search?key={{key}}",
            "ruleSearch": {"bookList":"$.data[*]","name":"$.name","bookUrl":"$.url"}
        });
        let login = serde_json::json!({
            "api":2,"op":"login","params":{"values":{},"action":format!(
                "source.putLoginHeader(JSON.stringify({{Authorization:'Bearer secret',Cookie:'sid=secret'}})); java.ajax('{base}/during'); 'ok'"
            )}
        });
        let first: Value =
            serde_json::from_str(&execute(&source.to_string(), &login.to_string())).unwrap();
        assert_eq!(first["ok"], true, "{first}");
        assert_eq!(first["session"]["cookies"], "sid=secret");
        assert_eq!(first["session"]["header"]["Authorization"], "Bearer secret");
        let search = serde_json::json!({"api":2,"op":"search","params":{"key":"test"},"session":first["session"]});
        let found: Value =
            serde_json::from_str(&execute(&source.to_string(), &search.to_string())).unwrap();
        assert_eq!(found["ok"], true, "{found}");
        assert_eq!(found["session"], Value::Null);

        let clear = serde_json::json!({
            "api":2,"op":"login","params":{"values":{},"action":format!(
                "source.removeLoginHeader(); java.ajax('{base}/cleared'); 'ok'"
            )},"session":first["session"]
        });
        let cleared: Value =
            serde_json::from_str(&execute(&source.to_string(), &clear.to_string())).unwrap();
        assert_eq!(cleared["ok"], true, "{cleared}");
        assert!(
            cleared["session"].is_object(),
            "clearing state must emit a delta: {cleared}"
        );
        assert!(cleared["session"]["cookies"].is_null());
        assert!(cleared["session"]["header"].is_null());
        let mut after = search;
        after["session"] = cleared["session"].clone();
        let final_result: Value =
            serde_json::from_str(&execute(&source.to_string(), &after.to_string())).unwrap();
        assert_eq!(final_result["ok"], true, "{final_result}");

        let requests = server.join().unwrap();
        for (index, path) in ["/during", "/search", "/cleared", "/search"]
            .iter()
            .enumerate()
        {
            assert!(
                requests[index].starts_with(&format!("get {path}")),
                "{}",
                requests[index]
            );
            let authenticated = index < 2;
            assert_eq!(
                requests[index].contains("authorization: bearer secret"),
                authenticated
            );
            assert_eq!(
                requests[index].contains("cookie: sid=secret"),
                authenticated
            );
        }
    }

    #[test]
    fn login_cookie_on_another_host_survives_next_ffi_call() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let login_host = format!("http://{address}");
        let source = serde_json::json!({
            "bookSourceName":"two hosts",
            "bookSourceUrl":format!("http://127.0.0.2:{}", address.port())
        });
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for index in 0..2 {
                let (mut stream, _) = accept_with_timeout(&listener);
                let mut buf = [0u8; 4096];
                let size = stream.read(&mut buf).unwrap();
                requests.push(String::from_utf8_lossy(&buf[..size]).to_ascii_lowercase());
                let cookie = if index == 0 {
                    "Set-Cookie: token=remote; Path=/private\r\n"
                } else {
                    ""
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\n{cookie}Content-Length: 2\r\nConnection: close\r\n\r\nok"
                )
                .unwrap();
            }
            requests
        });
        let call = |path: &str, session: Value| {
            let request = serde_json::json!({
                "api":2,"op":"login","params":{"values":{},"action":format!(
                    "java.ajax('{login_host}{path}'); 'ok'"
                )},"session":session
            });
            let result: Value =
                serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
            assert_eq!(result["ok"], true, "{result}");
            result
        };
        let first = call("/private/login", Value::Null);
        assert!(first["session"]["cookies"].is_null());
        assert!(first["session"]["cookieJar"].is_array());
        let second = call("/private/next", first["session"].clone());
        assert_eq!(second["session"], Value::Null);
        let requests = server.join().unwrap();
        assert!(!requests[0].contains("cookie: token=remote"));
        assert!(
            requests[1].contains("cookie: token=remote"),
            "{}",
            requests[1]
        );
    }

    #[test]
    fn execute_round_trips_js_cache_without_cross_user_leakage() {
        let source = serde_json::json!({
            "bookSourceName": "cache session fixture",
            "bookSourceUrl": "https://cache-session.example/",
            "loginUi": "@js:JSON.stringify([{name:cache.get('private-token')||'missing'}])"
        });
        let login_request = serde_json::json!({
            "api":2,"op":"login",
            "params":{"values":{},"action":"cache.put('private-token','user-a',60); 'ok'"}
        });
        let first: Value =
            serde_json::from_str(&execute(&source.to_string(), &login_request.to_string()))
                .unwrap();
        assert_eq!(first["ok"], true, "{first}");
        assert!(first["session"]["variables"]["__reader_js_cache_v1"].is_object());

        let ui_request = serde_json::json!({"api":2,"op":"login_ui","params":{}});
        let other: Value =
            serde_json::from_str(&execute(&source.to_string(), &ui_request.to_string())).unwrap();
        assert_eq!(other["data"][0]["name"], "missing", "{other}");
        let mut restored_request = ui_request;
        restored_request["session"] = first["session"].clone();
        let restored: Value =
            serde_json::from_str(&execute(&source.to_string(), &restored_request.to_string()))
                .unwrap();
        assert_eq!(restored["data"][0]["name"], "user-a", "{restored}");
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
            "loginUrl": "@js:function login() { return JSON.parse(source.getLoginInfo()).username + ':' + source.getLoginInfoMap().get('password'); }",
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

    #[test]
    fn execute_rejects_loc_book_with_unsupported_error() {
        let source_loc = serde_json::json!({
            "bookSourceName": "Local book",
            "bookSourceUrl": "loc_book"
        });
        let req_toc = serde_json::json!({
            "api": 2,
            "op": "toc",
            "params": {"url": "https://example.com/toc"}
        });
        let res1: Value =
            serde_json::from_str(&execute(&source_loc.to_string(), &req_toc.to_string())).unwrap();
        assert_eq!(res1["ok"], false, "{res1}");
        assert_eq!(res1["error"]["kind"], "unsupported");
        assert_eq!(res1["error"]["message"], "不支持远程本地书籍");

        let normal_source = serde_json::json!({
            "bookSourceName": "Normal",
            "bookSourceUrl": "https://example.com"
        });
        let req_with_loc_origin = serde_json::json!({
            "api": 2,
            "op": "toc",
            "params": {
                "url": "content://com.android.externalstorage.documents/test.epub",
                "origin": "loc_book"
            }
        });
        let res2: Value = serde_json::from_str(&execute(
            &normal_source.to_string(),
            &req_with_loc_origin.to_string(),
        ))
        .unwrap();
        assert_eq!(res2["ok"], false, "{res2}");
        assert_eq!(res2["error"]["kind"], "unsupported");
        assert_eq!(res2["error"]["message"], "不支持远程本地书籍");

        let req_with_content_url = serde_json::json!({
            "api": 2,
            "op": "content",
            "params": {
                "url": "content://com.android.externalstorage.documents/document/123"
            }
        });
        let res3: Value = serde_json::from_str(&execute(
            &normal_source.to_string(),
            &req_with_content_url.to_string(),
        ))
        .unwrap();
        assert_eq!(res3["ok"], false, "{res3}");
        assert_eq!(res3["error"]["kind"], "unsupported");
        assert_eq!(res3["error"]["message"], "不支持远程本地书籍");
    }
}
