use reader_parser::ffi::{reader_eval, reader_free_string};
use safer_ffi::prelude::*;
use serde_json::Value;
use std::ffi::CString;
use std::thread;

fn call_reader_eval(input: &str, rule: &str) -> String {
    let c_input = CString::new(input).unwrap();
    let c_rule = CString::new(rule).unwrap();
    let result = reader_eval(
        char_p::Ref::try_from(c_input.as_c_str()).unwrap(),
        char_p::Ref::try_from(c_rule.as_c_str()).unwrap(),
    );
    let output = result.to_str().to_string();
    reader_free_string(Some(result));
    output
}

#[test]
fn ffi_eval_built_in_directives_and_transforms() {
    let version = call_reader_eval("", "@version");
    assert!(!version.is_empty(), "version must not be empty");
    assert_eq!(version, env!("CARGO_PKG_VERSION"));

    let uuid1 = call_reader_eval("", "@uuid");
    let uuid2 = call_reader_eval("", "@uuid");
    assert_eq!(uuid1.len(), 36, "uuid must be 36 characters");
    assert_ne!(uuid1, uuid2, "subsequent uuids must differ");

    let aid = call_reader_eval("", "@android_id");
    assert_eq!(aid.len(), 16, "android id must be 16 hex chars");
    assert!(aid.chars().all(|c| c.is_ascii_hexdigit()));

    let encoded = call_reader_eval("hello world?query=1&b=2", "@encode");
    assert_eq!(encoded, "hello%20world%3Fquery%3D1%26b%3D2");

    let decoded = call_reader_eval(&encoded, "@decode");
    assert_eq!(decoded, "hello world?query=1&b=2");

    let clean = call_reader_eval(
        "<p>Hello<script>alert(1)</script><style>.a{}</style> World</p>",
        "@clean",
    );
    assert!(!clean.contains("<script>"), "clean must remove scripts");
    assert!(!clean.contains("<style>"), "clean must remove styles");

    let text = call_reader_eval("<div><p>Line 1</p><p>Line 2</p></div>", "@text");
    assert!(text.contains("Line 1") && text.contains("Line 2"));
}

#[test]
fn ffi_eval_content_extraction_html_and_xpath_returns_json_arrays() {
    // ABI v1 contract: reader_eval returns a JSON-serialized array of strings for HTML and XPath.
    let html = r#"<div class="book"><h1 class="title">My Title</h1><span class="author">Author A</span></div>"#;
    let title_json = call_reader_eval(html, ".book h1@text");
    let title_val: Value = serde_json::from_str(&title_json).unwrap();
    assert_eq!(title_val, serde_json::json!(["My Title"]));

    let author_json = call_reader_eval(html, ".author@text");
    let author_val: Value = serde_json::from_str(&author_json).unwrap();
    assert_eq!(author_val, serde_json::json!(["Author A"]));

    let xml = r#"<?xml version="1.0"?><catalog><book id="bk101"><title>XML Developer</title></book></catalog>"#;
    let xml_json = call_reader_eval(xml, "//book/title");
    let xml_val: Value = serde_json::from_str(&xml_json).unwrap();
    assert_eq!(xml_val, serde_json::json!(["XML Developer"]));
}

#[test]
fn ffi_eval_jsonpath_missing_in_eval_defect() {
    // DEFECT DISCOVERY IN reader_eval:
    // reader_eval handles directives (@...), regex (##...), JS (@js:), and XPath (//...).
    // But for JSON inputs with `$.field` rules, reader_eval lacks a
    // JsonPath dispatch branch! It falls through to parse_document (HTML parser),
    // treating "$.title" as a CSS selector, which produces an empty array "[]".
    let json_data = r#"{"title":"Rust Deep Dive","author":"Ferris"}"#;
    let title_out = call_reader_eval(json_data, "$.title");
    assert_eq!(
        title_out, "[]",
        "Documents current defect: reader_eval lacks JsonPath branch and returns empty array"
    );
}

#[test]
fn ffi_eval_multithread_concurrency_stress() {
    let thread_count = 8;
    let iterations_per_thread = 50;
    let mut handles = Vec::with_capacity(thread_count);

    for t in 0..thread_count {
        let handle = thread::spawn(move || {
            for i in 0..iterations_per_thread {
                let id = format!("t{t}_i{i}");

                // 1. HTML CSS extraction
                let html_input = format!(r#"<div class="item" id="node_{id}">content_{id}</div>"#);
                let html_out = call_reader_eval(&html_input, ".item@text");
                let parsed_html: Value = serde_json::from_str(&html_out).unwrap();
                assert_eq!(
                    parsed_html,
                    serde_json::json!([format!("content_{id}")]),
                    "Thread {t} CSS mismatch at iteration {i}"
                );

                // 2. JS evaluation
                let js_rule = format!(r#"@js:"eval_" + "{id}""#);
                let js_out = call_reader_eval("", &js_rule);
                assert_eq!(
                    js_out,
                    format!("eval_{id}"),
                    "Thread {t} JS mismatch at iteration {i}"
                );

                // 3. XPath extraction
                let xml_input = format!(r#"<root><item id="{id}">val_{id}</item></root>"#);
                let xpath_out = call_reader_eval(&xml_input, "//item");
                let parsed_xpath: Value = serde_json::from_str(&xpath_out).unwrap();
                assert_eq!(
                    parsed_xpath,
                    serde_json::json!([format!("val_{id}")]),
                    "Thread {t} XPath mismatch at iteration {i}"
                );

                // 4. Regex replacement
                let regex_out = call_reader_eval(&format!("raw_{id}"), "##raw##baked");
                assert_eq!(
                    regex_out,
                    format!("baked_{id}"),
                    "Thread {t} regex mismatch at iteration {i}"
                );

                // 5. Built-in directive
                let uuid = call_reader_eval("", "@uuid");
                assert_eq!(uuid.len(), 36);
            }
        });
        handles.push(handle);
    }

    for (t, handle) in handles.into_iter().enumerate() {
        handle
            .join()
            .unwrap_or_else(|e| panic!("Thread {t} panicked: {e:?}"));
    }
}

#[test]
fn ffi_eval_syntax_error_resilience() {
    // Malformed XPath should return empty array without crashing
    let broken_xpath = call_reader_eval("<html><body>test</body></html>", "//[broken");
    assert_eq!(broken_xpath, "[]");

    // JS error throw should return JSON error without aborting
    let js_throw = call_reader_eval("", r#"@js:throw new Error("intentional test error");"#);
    assert!(
        js_throw.contains("JS Eval Failed"),
        "Expected JS Eval Failed error message, got: {js_throw}"
    );

    // Subsequent normal calls must succeed cleanly
    let recovery = call_reader_eval("<h1>Recovered</h1>", "h1@text");
    let recovery_val: Value = serde_json::from_str(&recovery).unwrap();
    assert_eq!(recovery_val, serde_json::json!(["Recovered"]));
}

#[test]
fn ffi_eval_large_input_payload() {
    // Generate a ~1.8MB HTML document
    let mut items = Vec::new();
    for i in 0..50_000 {
        items.push(format!(r#"<li class="book-item">Title Number {i}</li>"#));
    }
    let large_html = format!(r#"<html><body><ul id="list">{}</ul></body></html>"#, items.join("\n"));
    assert!(large_html.len() > 1_500_000, "Payload should exceed 1.5MB");

    let count_out = call_reader_eval(&large_html, "@js:result.length");
    assert_eq!(count_out, large_html.len().to_string());
}
