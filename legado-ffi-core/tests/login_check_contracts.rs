//! loginCheckJs failures must not masquerade as expired authentication.
use reader_parser::executor::execute;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

fn check(script: &str) -> Value {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "fixture request timed out");
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
        let body = r#"{"name":"Original"}"#;
        write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
    });
    let source = json!({"bookSourceUrl":base, "enabledCookieJar":false,
        "loginCheckJs":script,"ruleBookInfo":{"name":"$.name"}});
    let result = serde_json::from_str(&execute(
        &source.to_string(),
        &json!({"api":2,"op":"info","params":{"url":format!("{base}/book")}}).to_string(),
    ))
    .unwrap();
    server.join().unwrap();
    result
}

#[test]
fn script_exceptions_are_parse_errors_without_login_guidance() {
    for script in ["throw new Error('bad rule')", "const = invalid"] {
        let result = check(script);
        assert_eq!(result["ok"], false, "{result}");
        assert_eq!(result["error"]["kind"], "parse", "{result}");
        assert!(result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("loginCheckJs"));
        assert!(result["error"].get("auth").is_none(), "{result}");
    }
}

#[test]
fn invalid_return_types_are_parse_errors_not_authentication_failures() {
    for script in ["null", "''", "'plain body'", "42", "[]"] {
        let result = check(script);
        assert_eq!(result["ok"], false, "script={script}: {result}");
        assert_eq!(
            result["error"]["kind"], "parse",
            "script={script}: {result}"
        );
        assert!(result["error"].get("auth").is_none());
    }
}

#[test]
fn existing_boolean_and_response_compatibility_stays_intact() {
    // The shared JS bridge preserves `result` for undefined completion values.
    for script in ["true", "result", "undefined", "let localValue = 1"] {
        let result = check(script);
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"]["name"], "Original");
    }
    let modified = check("var response = result.toJSON(); response.body = JSON.stringify({name:'Changed'}); response");
    assert_eq!(modified["ok"], true, "{modified}");
    assert_eq!(modified["data"]["name"], "Changed");
    for script in [
        "false",
        "var response = result.toJSON(); response.isSuccessful = false; response",
    ] {
        let result = check(script);
        assert_eq!(result["ok"], false, "{result}");
        assert_eq!(result["error"]["kind"], "auth_required", "{result}");
    }
}
