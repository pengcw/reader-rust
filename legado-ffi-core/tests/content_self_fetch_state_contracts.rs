//! JS self-fetch returns the same book/chapter snapshots as normal content paths.
use reader_parser::executor::execute;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn self_fetch_keeps_final_chapter_state_and_book_scope_without_replaying_http() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        for id in ["one", "two"] {
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
            assert!(
                request.starts_with(&format!("GET /chapter?id={id} ")),
                "{request}"
            );
            requests.push(request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nBody"
            )
            .unwrap();
        }
        requests
    });
    let source = json!({"bookSourceUrl":base, "enabledCookieJar":false, "ruleContent":{
        "title":"@put:{token:\"{{'final'}}\",titleCount:\"{{Number(chapter.getVariable('titleCount') || 0) + 1}}\"}@js:'Chapter'",
        "content":r#"@js:var endpoint = source.getKey() + '/chapter?id=' + baseUrl; var text = java.ajax(endpoint + ',{"headers":{"X-Token":"' + chapter.getVariable('token') + '"}}'); text + '/' + book.getVariable('bid');"#,
        "nextContentUrl":"@put:{late:\"{{'after'}}\"}@js:''"
    }});
    for id in ["one", "two"] {
        let book = json!({"bid":format!("book-{id}"),"keep":"book"});
        let chapter = json!({"bid":format!("chapter-{id}"),"token":"old","keep":"chapter"});
        let request = json!({"api":2,"op":"content","params":{"url":id,
            "book":{"variable":book.to_string()},"chapter":{"variable":chapter.to_string()}},
            "options":{"timeoutMs":2000}});
        let result: Value =
            serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"]["content"], format!("Body/book-{id}"));
        assert_eq!(result["data"]["title"], "Chapter");
        let final_book: Value =
            serde_json::from_str(result["data"]["bookVariable"].as_str().unwrap()).unwrap();
        let final_chapter: Value =
            serde_json::from_str(result["data"]["variable"].as_str().unwrap()).unwrap();
        assert_eq!(final_book, book);
        assert_eq!(
            final_chapter,
            json!({"bid":format!("chapter-{id}"),"token":"final","keep":"chapter","titleCount":"1","late":"after"})
        );
    }
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|request| request.to_ascii_lowercase().contains("x-token: final\r\n")));
}

#[test]
fn self_fetch_without_variables_keeps_optional_state_absent() {
    let source = json!({"bookSourceUrl":"https://fixture.invalid","ruleContent":{
        "content":"@js:if (false) java.ajax(baseUrl); 'Body'"}});
    let request = json!({"api":2,"op":"content","params":{"url":"chapter-id"}});
    let result: Value =
        serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["data"]["content"], "Body");
    assert!(result["data"].get("bookVariable").is_none());
    assert!(result["data"].get("variable").is_none());
}
