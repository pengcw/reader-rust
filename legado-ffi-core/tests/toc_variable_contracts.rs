//! Book variables survive TOC pagination; chapter writes stay chapter-local.
use reader_parser::executor::execute;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

fn run(initial: Value, pages: Vec<Value>) -> Value {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let page_count = pages.len();
    let server = thread::spawn(move || {
        for (index, page) in pages.into_iter().enumerate() {
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
                assert!(request.len() <= 8192);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with(&format!("GET /toc/{} ", index + 1)),
                "{request}"
            );
            if index > 0 {
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("x-token: updated\r\n"),
                    "{request}"
                );
            }
            let body = page.to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
    });
    let source = json!({"bookSourceUrl": base, "bookSourceName": "TOC variable fixture",
        "ruleToc": {"init": "@put:{token:$.token}", "chapterList": "$.chapters[*]",
            "chapterName": "@get:{token}", "chapterUrl": "$.url@put:{chapterOnly:$.id}",
            "nextTocUrl": "$.next", "formatJs": "title + '/' + book.variableMap.token"}});
    let result: Value = serde_json::from_str(&execute(&source.to_string(),
        &json!({"api": 2, "op": "toc", "params": {"url": format!("{base}/toc/1"), "book": {"variable": initial.to_string()}},
            "options": {"maxPages": page_count}}).to_string())).unwrap();
    server.join().unwrap();
    assert_eq!(result["ok"], true, "{result}");
    result["data"].clone()
}

#[test]
fn toc_book_writes_reach_next_request_page_and_final_formatter() {
    let data = run(
        json!({"keep": "original", "token": "old"}),
        vec![
            json!({"token": "updated", "chapters": [{"url": "/chapter/1", "id": "one"}],
            "next": "/toc/2,{\"headers\":{\"X-Token\":\"{{book.variableMap.token}}\"}}"}),
            json!({"token": "final", "chapters": [{"url": "/chapter/2", "id": "two"}], "next": ""}),
        ],
    );
    assert_eq!(data["pages"], 2);
    assert_eq!(data["chapters"][0]["title"], "updated/final");
    assert_eq!(data["chapters"][1]["title"], "final/final");
    let variable: Value = serde_json::from_str(data["variable"].as_str().unwrap()).unwrap();
    assert_eq!(variable, json!({"keep": "original", "token": "final"}));
    for (index, expected) in ["one", "two"].iter().enumerate() {
        let variable: Value =
            serde_json::from_str(data["chapters"][index]["variable"].as_str().unwrap()).unwrap();
        assert_eq!(variable, json!({"chapterOnly": expected}));
    }
}

#[test]
fn toc_single_page_keeps_existing_book_state_separate_from_chapter_writes() {
    let data = run(
        json!({"keep": "original"}),
        vec![
            json!({"token": "single", "chapters": [{"url": "/chapter/1", "id": "one"}, {"url": "/chapter/2", "id": "two"}], "next": ""}),
        ],
    );
    let variable: Value = serde_json::from_str(data["variable"].as_str().unwrap()).unwrap();
    assert_eq!(variable, json!({"keep": "original", "token": "single"}));
    assert_eq!(data["chapters"][1]["title"], "single/single");
}
