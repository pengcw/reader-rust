//! Self-fetch JS shares page traversal, but never triggers an extra native fetch.
use reader_parser::executor::execute;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

fn server(paths: Vec<&'static str>) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for (index, path) in paths.iter().enumerate() {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "fixture timed out");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("{error}"),
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
            assert!(request.starts_with(&format!("GET {path} ")), "{request}");
            requests.push(request);
            let body = if index == 0 { "first" } else { "second" };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        requests
    });
    (base, handle)
}
fn run(base: &str, rule: Value, max_pages: usize, params: Value) -> Value {
    let source = json!({"bookSourceUrl":base, "enabledCookieJar":false,"ruleContent":rule});
    let mut params = params;
    params["url"] = json!(format!("{base}/chapter/1"));
    let response = execute(
        &source.to_string(),
        &json!({"api":2,"op":"content","params":params,
        "options":{"maxPages":max_pages,"timeoutMs":2000}})
        .to_string(),
    );
    let response: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(response["ok"], true, "{response}");
    assert_eq!(
        response["meta"]["pages"], 0,
        "JS requests are not native fetches"
    );
    assert!(response["data"].get("pages").is_none());
    response
}
const NEXT: &str = "@js:baseUrl.endsWith('/chapter/1') ? source.getKey() + '/chapter/1-2' : ''";

#[test]
fn self_fetch_follows_next_page_and_applies_full_text_replacement_once() {
    let (base, handle) = server(vec!["/chapter/1", "/chapter/1-2"]);
    let response = run(
        &base,
        json!({
            "content":r#"@js:java.ajax(baseUrl+',{"headers":{"X-Token":"'+chapter.getVariable('token')+'"}}')"#,
            "title":"@put:{token:\"{{'start'}}\",titles:\"{{Number(chapter.getVariable('titles') || 0) + 1}}\"}@js:'Chapter'",
            "nextContentUrl":format!("@put:{{token:\"{{{{'next'}}}}\",steps:\"{{{{Number(chapter.getVariable('steps') || 0) + 1}}}}\"}}{NEXT}"),
            "replaceRegex":r#"@js:result === 'first\nsecond' ? 'complete' : 'wrong stage'"#
        }),
        2,
        json!({"book":{"variable":"{\"keep\":\"book\"}"},"chapter":{"variable":"{\"keep\":\"chapter\"}"}}),
    );
    assert_eq!(response["data"]["content"], "complete");
    assert_eq!(response["data"]["title"], "Chapter");
    assert_eq!(response["meta"]["truncated"], false);
    let book: Value =
        serde_json::from_str(response["data"]["bookVariable"].as_str().unwrap()).unwrap();
    let chapter: Value =
        serde_json::from_str(response["data"]["variable"].as_str().unwrap()).unwrap();
    assert_eq!(book, json!({"keep":"book"}));
    assert_eq!(
        chapter,
        json!({"keep":"chapter","token":"next","titles":"1","steps":"2"})
    );
    let requests = handle.join().unwrap();
    assert!(requests[0]
        .lines()
        .any(|line| line.eq_ignore_ascii_case("X-Token: start")));
    assert!(requests[1]
        .lines()
        .any(|line| line.eq_ignore_ascii_case("X-Token: next")));
}

#[test]
fn self_fetch_page_budget_prevents_second_request_and_reports_truncation() {
    let (base, handle) = server(vec!["/chapter/1"]);
    let response = run(
        &base,
        json!({"content":"@js:java.ajax(baseUrl)","nextContentUrl":NEXT}),
        1,
        json!({}),
    );
    assert_eq!(response["data"]["content"], "first");
    assert_eq!(response["meta"]["truncated"], true);
    assert_eq!(handle.join().unwrap().len(), 1);
}

#[test]
fn self_fetch_duplicate_and_single_page_rules_do_not_replay_requests() {
    for next in ["@js:baseUrl", "@js:''"] {
        let (base, handle) = server(vec!["/chapter/1"]);
        let response = run(
            &base,
            json!({"content":"@js:java.ajax(baseUrl)","nextContentUrl":next}),
            3,
            json!({}),
        );
        assert_eq!(response["data"]["content"], "first");
        assert_eq!(response["meta"]["truncated"], false);
        assert_eq!(handle.join().unwrap().len(), 1);
    }
}
