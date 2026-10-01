use crate::executor;
use crate::model::book_source::book_source_from_value;
use crate::model::replace_rule::ReplaceRule;
use crate::model::search::SearchBook;
use crate::parser::js::eval_js;
use crate::parser::rule_engine::{apply_legado_regex, RuleEngine};
use safer_ffi::prelude::*;
use serde_json::{json, Value};

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
}
