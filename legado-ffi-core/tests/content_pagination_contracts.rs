//! Source replaceRegex is a whole-chapter phase in the business executor.
use reader_parser::executor::execute;
use reader_parser::model::book_source::BookSource;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

fn source(base: &str, replacement: &str, content_rule: &str) -> Value {
    json!({"bookSourceUrl": base, "bookSourceName": "content pagination fixture",
        "ruleContent": {"content": content_rule, "nextContentUrl": "$.next", "replaceRegex": replacement}})
}

fn run(pages: Vec<Value>, replacement: &str, content_rule: &str) -> Value {
    run_with_context(pages, replacement, content_rule, None, Value::Null)
}

fn run_with_context(
    pages: Vec<Value>,
    replacement: &str,
    content_rule: &str,
    js_lib: Option<&str>,
    book: Value,
) -> Value {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let expected_pages = pages.len();
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        for body in pages {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "fixture request timed out");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                header.push(byte[0]);
                assert!(header.len() <= 8192, "fixture header exceeds budget");
            }
            let header = String::from_utf8(header).unwrap();
            assert!(header.starts_with("GET "));
            requests.push(header.split_whitespace().nth(1).unwrap().to_string());
            let body = body.to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
        requests
    });
    let mut source = source(&base, replacement, content_rule);
    if let Some(script) = js_lib {
        source["jsLib"] = json!(script);
    }
    let response: Value = serde_json::from_str(&execute(&source.to_string(),
        &json!({"api": 2, "op": "content", "params": {"url": format!("{base}/chapter/1"), "book": book}, "options": {"timeoutMs": 1000}}).to_string())).unwrap();
    let requests = server.join().unwrap();
    assert_eq!(response["ok"], true, "{response}");
    assert_eq!(response["data"]["pages"], expected_pages);
    assert_eq!(response["data"]["truncated"], false);
    assert_eq!(
        requests,
        (1..=expected_pages)
            .map(|page| if page == 1 {
                "/chapter/1".to_string()
            } else {
                format!("/chapter/1?p={page}")
            })
            .collect::<Vec<_>>()
    );
    response
}

fn two_pages(first: &str, second: &str) -> Vec<Value> {
    vec![
        json!({"content": first, "next": "/chapter/1?p=2"}),
        json!({"content": second, "next": ""}),
    ]
}

#[test]
fn pure_js_source_replacement_receives_the_complete_string_once() {
    for rule in ["@js: '[' + result + ']'", "<js>'[' + result + ']'</js>"] {
        let result = run(two_pages("A", "B"), rule, "$.content");
        assert_eq!(result["data"]["content"], "[A\nB]");
    }
}

#[test]
fn js_hash_markers_are_script_text_not_regex_separators() {
    for rule in [
        "@js: result + '##literal##suffix'",
        "<js>result + '##literal##suffix'</js>",
    ] {
        let result = run(two_pages("A", "B"), rule, "$.content");
        assert_eq!(result["data"]["content"], "A\nB##literal##suffix");
    }
}

#[test]
fn js_source_replacement_keeps_library_book_and_final_chapter_variables() {
    let result = run_with_context(vec![
        json!({"content": "A", "cid": "c1", "next": "/chapter/1?p=2"}),
        json!({"content": "B", "cid": "c2", "next": ""}),
    ], "@js: decorate(result, book.variableMap.bid, chapter.variableMap.cid, book.name)",
        "$.content@put:{cid:$.cid}",
        Some("function decorate(text, bid, cid, name) { return 'lib:' + bid + '/' + cid + '/' + name + ':' + text; }"),
        json!({"name": "Book", "variableMap": {"bid": "book-1"}}));
    assert_eq!(result["data"]["content"], "lib:book-1/c2/Book:A\nB");
}

#[test]
fn failing_js_source_replacement_keeps_the_complete_stage_input() {
    for rule in [
        "@js: throw new Error('synthetic failure')",
        "<js>throw new Error('synthetic failure')</js>",
        "@js: (syntax error",
    ] {
        let result = run(two_pages("A", "B"), rule, "$.content");
        assert_eq!(result["data"]["content"], "A\nB");
    }
}

#[test]
fn single_page_js_source_replacement_uses_its_direct_result() {
    for (script, expected) in [
        ("result.toLowerCase()", "a"),
        ("null", ""),
        ("undefined", ""),
        ("''", ""),
    ] {
        let source: BookSource = serde_json::from_value(source(
            "https://content-js.test/",
            &format!("@js:{script}"),
            "$.content",
        ))
        .unwrap();
        let result = RuleEngine::new().unwrap().content(
            &source,
            "{\"content\":\"A\"}",
            "https://content-js.test/1",
        );
        assert_eq!(result, expected, "{script}");
    }
}

#[test]
fn source_replacement_can_match_across_page_boundaries() {
    let result = run(two_pages("A", "B"), "##A\\nB##merged", "$.content");
    assert_eq!(result["data"]["content"], "merged");
}

#[test]
fn anchored_replacement_runs_once_on_the_complete_chapter() {
    let result = run(two_pages("A", "A"), "##^A##X", "$.content");
    assert_eq!(result["data"]["content"], "X\nA");
}

#[test]
fn source_replacement_uses_final_page_variables() {
    let result = run(
        vec![
            json!({"content": "A", "pattern": "unused", "next": "/chapter/1?p=2"}),
            json!({"content": "B", "pattern": "A\\nB", "next": ""}),
        ],
        "##{{@get:{pattern}}}##X",
        "$.content@put:{pattern:$.pattern}",
    );
    assert_eq!(result["data"]["content"], "X");
}

#[test]
fn multi_link_pages_keep_order_and_do_not_follow_child_links() {
    let result = run(
        vec![
            json!({"content": "A", "next": ["/chapter/1?p=2", "/chapter/1?p=3"]}),
            json!({"content": "B", "next": "/must-not-fetch"}),
            json!({"content": "C", "next": "/must-not-fetch"}),
        ],
        "##A\\nB\\nC##X",
        "$.content",
    );
    assert_eq!(result["data"]["content"], "X");
}

#[test]
fn single_page_parser_keeps_its_existing_replacement_phase() {
    let source: BookSource =
        serde_json::from_value(source("https://content-phase.test/", "##A##X", "$.content"))
            .unwrap();
    let result = RuleEngine::new().unwrap().content(
        &source,
        "{\"content\":\"A\"}",
        "https://content-phase.test/chapter/1",
    );
    assert_eq!(result, "X");
}
