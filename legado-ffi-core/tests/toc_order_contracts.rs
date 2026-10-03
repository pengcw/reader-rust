//! TOC direction contracts with bounded local HTTP fixtures, never external I/O.
use reader_parser::executor::execute;
use reader_parser::model::book_source::BookSource;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

fn page(items: &[(u32, &str)], next: &str) -> Value {
    json!({"chapters": items.iter().map(|(id, title)| json!({"title": title, "url": format!("/chapter/{id}")})).collect::<Vec<_>>(), "next": next})
}

fn source(base: &str, prefix: &str) -> Value {
    json!({"bookSourceUrl": base, "bookSourceName": "TOC order fixture",
        "ruleToc": {"chapterList": format!("{prefix}$.chapters[*]"), "chapterName": "$.title", "chapterUrl": "$.url", "nextTocUrl": "$.next"}})
}

fn run(prefix: &str, pages: Vec<Value>) -> Value {
    run_with_format(prefix, pages, None)
}

fn run_with_format(prefix: &str, pages: Vec<Value>, format_js: Option<&str>) -> Value {
    run_with_context(prefix, pages, format_js, None, Value::Null)
}

fn run_with_context(
    prefix: &str,
    pages: Vec<Value>,
    format_js: Option<&str>,
    js_lib: Option<&str>,
    book: Value,
) -> Value {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut paths = Vec::new();
        for body in pages {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "fixture request timed out");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() <= 8192, "fixture header exceeds budget");
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET "));
            paths.push(request.split_whitespace().nth(1).unwrap().to_string());
            let body = body.to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
        paths
    });
    let mut source = source(&base, prefix);
    if let Some(script) = format_js {
        source["ruleToc"]["formatJs"] = json!(script);
    }
    if let Some(script) = js_lib {
        source["jsLib"] = json!(script);
    }
    let result: Value = serde_json::from_str(&execute(
        &source.to_string(),
        &json!({"api": 2, "op": "toc", "params": {"url": format!("{base}/toc/1"), "book": book}})
            .to_string(),
    ))
    .unwrap();
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(server.join().unwrap(), ["/toc/1", "/toc/2"]);
    assert_eq!(result["data"]["pages"], 2);
    assert_eq!(result["data"]["truncated"], false);
    for (index, chapter) in result["data"]["chapters"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        assert_eq!(chapter["index"], index);
    }
    result["data"]["chapters"].clone()
}

fn titles(chapters: &Value) -> Vec<&str> {
    chapters
        .as_array()
        .unwrap()
        .iter()
        .map(|chapter| chapter["title"].as_str().unwrap())
        .collect()
}

#[test]
fn final_formatter_keeps_library_book_and_retained_chapter_variables() {
    let mut first = page(&[(3, "Three"), (2, "Two old")], "/toc/2");
    first["chapters"][0]["variable"] = json!("{\"cid\":\"c3\"}");
    first["chapters"][1]["variable"] = json!("{\"cid\":\"old-c2\"}");
    let mut second = page(&[(2, "Two updated"), (1, "One")], "");
    second["chapters"][0]["variable"] = json!("{\"cid\":\"new-c2\"}");
    second["chapters"][1]["variable"] = json!("{\"cid\":\"c1\"}");
    let chapters = run_with_context("-", vec![first, second],
        Some("gInt++; stamp([index, gInt, book.name, book.author, book.variableMap.bid, chapter.variableMap.cid, title])"),
        Some("function stamp(parts) { return 'lib:' + parts.join('/'); }"),
        json!({"name": "Book", "author": "Author", "variableMap": {"bid": "book-7"}}));
    assert_eq!(
        titles(&chapters),
        [
            "lib:1/1/Book/Author/book-7/c1/One",
            "lib:2/2/Book/Author/book-7/new-c2/Two updated",
            "lib:3/3/Book/Author/book-7/c3/Three",
        ]
    );
    let variables: Vec<Value> = chapters
        .as_array()
        .unwrap()
        .iter()
        .map(|chapter| serde_json::from_str(chapter["variable"].as_str().unwrap()).unwrap())
        .collect();
    assert_eq!(
        variables,
        [
            json!({"cid": "c1"}),
            json!({"cid": "new-c2"}),
            json!({"cid": "c3"})
        ]
    );
}

#[test]
fn final_formatter_library_and_book_context_do_not_leak_between_calls() {
    for marker in ["first", "second"] {
        let library = format!("function stamp(title) {{ return '{marker}/' + title; }}");
        let chapters = run_with_context(
            "",
            vec![page(&[(1, "One")], "/toc/2"), page(&[(2, "Two")], "")],
            Some("stamp(book.variableMap.bid + '/' + title)"),
            Some(&library),
            json!({"variableMap": {"bid": marker}}),
        );
        assert_eq!(
            titles(&chapters),
            [
                format!("{marker}/{marker}/One"),
                format!("{marker}/{marker}/Two")
            ]
        );
        assert_eq!(
            reader_parser::parser::js::eval_js("typeof stamp", "", "https://outside-context.test/")
                .unwrap(),
            "undefined"
        );
    }
}

#[test]
fn format_js_numbers_the_complete_toc_without_page_resets() {
    let chapters = run_with_format(
        "",
        vec![
            page(&[(1, "One"), (2, "Two")], "/toc/2"),
            page(&[(3, "Three"), (4, "Four")], ""),
        ],
        Some("gInt++; [gInt, index, chapter.index, title].join(':')"),
    );
    assert_eq!(
        titles(&chapters),
        ["1:1:0:One", "2:2:1:Two", "3:3:2:Three", "4:4:3:Four"]
    );
}

#[test]
fn format_js_runs_only_on_retained_chapters_in_final_reverse_order() {
    let chapters = run_with_format(
        "-",
        vec![
            page(&[(3, "Three"), (2, "Two old")], "/toc/2"),
            page(&[(2, "Two updated"), (1, "One")], ""),
        ],
        Some("gInt++; [gInt, index, chapter.index, title].join(':')"),
    );
    assert_eq!(
        titles(&chapters),
        ["1:1:0:One", "2:2:1:Two updated", "3:3:2:Three"]
    );
}

#[test]
fn format_js_errors_keep_titles_and_do_not_stop_later_pages() {
    let chapters = run_with_format("", vec![
        page(&[(1, "One"), (2, "Two")], "/toc/2"),
        page(&[(3, "Three")], ""),
    ], Some("if (title === 'Two') throw new Error('synthetic formatting error'); `${index}:${title}`"));
    assert_eq!(titles(&chapters), ["1:One", "Two", "3:Three"]);
}

#[test]
fn negative_list_rule_reverses_the_complete_paginated_toc() {
    let chapters = run(
        "-",
        vec![
            page(&[(4, "Four"), (3, "Three")], "/toc/2"),
            page(&[(2, "Two"), (1, "One")], ""),
        ],
    );
    assert_eq!(titles(&chapters), ["One", "Two", "Three", "Four"]);
}

#[test]
fn pagination_and_page_order_are_preserved_without_negative_prefix() {
    for prefix in ["", "+"] {
        for items in [vec![(1, "One"), (2, "Two")], vec![(2, "Two"), (1, "One")]] {
            let chapters = run(
                prefix,
                vec![page(&items, "/toc/2"), page(&[(3, "Three")], "")],
            );
            assert_eq!(titles(&chapters), [items[0].1, items[1].1, "Three"]);
        }
    }
}

#[test]
fn global_reverse_keeps_last_fetched_duplicate_metadata() {
    let chapters = run(
        "-",
        vec![
            page(&[(3, "Three"), (2, "Two old")], "/toc/2"),
            page(&[(2, "Two updated"), (1, "One")], ""),
        ],
    );
    assert_eq!(titles(&chapters), ["One", "Two updated", "Three"]);
}

#[test]
fn single_page_parser_keeps_its_existing_reverse_contract() {
    let source: BookSource =
        serde_json::from_value(source("https://toc-order.test/", "-")).unwrap();
    let (chapters, _) = RuleEngine::new().unwrap().chapter_list(
        &source,
        &page(&[(2, "Two"), (1, "One")], "").to_string(),
        "https://toc-order.test/toc/1",
    );
    assert_eq!(
        chapters
            .iter()
            .map(|chapter| chapter.title.as_str())
            .collect::<Vec<_>>(),
        ["One", "Two"]
    );
    assert_eq!(
        chapters
            .iter()
            .map(|chapter| chapter.index)
            .collect::<Vec<_>>(),
        [0, 1]
    );
}
