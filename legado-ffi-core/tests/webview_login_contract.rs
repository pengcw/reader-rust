//! Offline script-driven WebView login, not an interactive browser contract.
use reader_parser::executor::execute;
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};

#[test]
fn webview_login_posts_and_restores_cookie_session() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        for path in ["/login", "/auth", "/private"] {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "request timeout: {path}");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(err) => panic!("{err}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut header = String::new();
            let mut body_len = 0;
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        body_len = value.trim().parse::<usize>().unwrap();
                    }
                }
                header.push_str(&line);
            }
            let mut request_body = vec![0; body_len];
            reader.read_exact(&mut request_body).unwrap();
            let (body, cookie) = match path {
                "/login" => {
                    assert!(header.starts_with("GET /login "));
                    (
                        r#"<html><body><script>fetch('/auth', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'user=fixture&password=fixture'}).then(function(r){return r.text();}).then(function(t){document.body.innerHTML=t;});</script></body></html>"#,
                        "",
                    )
                }
                "/auth" => {
                    assert!(header.starts_with("POST /auth "));
                    assert_eq!(request_body, b"user=fixture&password=fixture");
                    (
                        "authenticated",
                        "Set-Cookie: fixture_sid=ok; Path=/; HttpOnly\r\n",
                    )
                }
                _ => {
                    assert!(header.starts_with("GET /private "));
                    assert!(
                        header.lines().any(|line| line.split_once(':').is_some_and(
                            |(name, value)| {
                                name.eq_ignore_ascii_case("cookie")
                                    && value.contains("fixture_sid=ok")
                            }
                        )),
                        "missing restored cookie"
                    );
                    // Rakers 的模拟 DOM 不从静态 HTML 初始化 body；用页面脚本给出标记。
                    ("<html><body><script>document.body.innerHTML='private-ok';</script></body></html>", "")
                }
            };
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n{cookie}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
    });
    let source = json!({
        "bookSourceUrl": base,
        "bookSourceName": "offline webview login",
        "loginUrl": format!("@js:function login() {{ return java.webView('', '{base}/login', 'document.body.innerHTML'); }}")
    });
    let first: Value = serde_json::from_str(&execute(
        &source.to_string(),
        &json!({
            "api": 2, "op": "login", "params": {"values": {}}
        })
        .to_string(),
    ))
    .unwrap();
    assert_eq!(first["ok"], true, "{first}");
    assert_eq!(first["data"]["result"], "authenticated", "{first}");
    assert_eq!(first["session"]["cookies"], "fixture_sid=ok", "{first}");
    assert!(!first["session"]["cookieJar"].is_null(), "{first}");
    let second: Value = serde_json::from_str(&execute(&source.to_string(), &json!({
        "api": 2, "op": "login", "session": first["session"],
        "params": {"values": {}, "action": format!("java.webView('', '{base}/private', 'document.body.innerHTML')")}
    }).to_string())).unwrap();
    assert_eq!(second["ok"], true, "{second}");
    assert_eq!(second["data"]["result"], "private-ok", "{second}");
    assert_eq!(second["session"], Value::Null, "{second}");
    server.join().unwrap();
}
