//! Final content variables must survive State Out, without crossing book/chapter scopes.
use reader_parser::executor::execute;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn chapter_token_reaches_next_page_and_final_response_without_changing_book_variables() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        for (token, text, next) in [
            ("middle", "A", "/chapter/1?p=2,{\"headers\":{\"X-Book\":\"{{book.variableMap.bid}}\",\"X-Chapter\":\"{{chapter.variableMap.pageToken}}\"}}"),
            ("final", "B", ""),
        ] {
            let deadline = Instant::now()+Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream,_)) => break stream,
                    Err(e) if e.kind()==std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now()<deadline,"fixture timed out");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut request=Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte=[0]; stream.read_exact(&mut byte).unwrap(); request.push(byte[0]);
                assert!(request.len()<=8192);
            }
            requests.push(String::from_utf8(request).unwrap());
            let body=json!({"token":token,"content":text,"next":next}).to_string();
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        }
        requests
    });
    let source = json!({"bookSourceUrl":base,"enabledCookieJar":false,"ruleContent":{
        "content":"$.content@put:{pageToken:$.token}","nextContentUrl":"$.next",
        "replaceRegex":"@js:result + '/' + book.variableMap.bid + '/' + chapter.variableMap.pageToken"}});
    let result: Value = serde_json::from_str(&execute(
        &source.to_string(),
        &json!({"api":2,"op":"content",
        "params":{"url":format!("{base}/chapter/1"),"book":{"variable":"{\"bid\":\"book\"}"},
            "chapter":{"variable":"{\"pageToken\":\"old\",\"keep\":\"original\"}"}}})
        .to_string(),
    ))
    .unwrap();
    let requests = server.join().unwrap();
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["data"]["pages"], 2);
    assert!(requests[1].starts_with("GET /chapter/1?p=2 "));
    assert!(requests[1]
        .to_ascii_lowercase()
        .contains("x-book: book\r\n"));
    assert!(requests[1]
        .to_ascii_lowercase()
        .contains("x-chapter: middle\r\n"));
    assert_eq!(result["data"]["content"], "A\nB/book/final");
    let book: Value =
        serde_json::from_str(result["data"]["bookVariable"].as_str().unwrap()).unwrap();
    let chapter: Value =
        serde_json::from_str(result["data"]["variable"].as_str().unwrap()).unwrap();
    assert_eq!(book, json!({"bid":"book"}));
    assert_eq!(chapter, json!({"pageToken":"final","keep":"original"}));
}
