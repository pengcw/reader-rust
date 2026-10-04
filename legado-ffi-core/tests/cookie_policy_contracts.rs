//! Source-backed CookieJar=false contracts; all traffic stays on loopback.
use reader_parser::crawler::{analyze_url, with_active_session, HttpSession};
use reader_parser::executor::execute;
use reader_parser::model::book_source::BookSource;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

fn fixture(count: usize) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut cookies = Vec::new();
        for _ in 0..count {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "fixture timed out");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("{e}"),
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
            let cookie = request
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("cookie")
                        .then(|| value.trim().to_string())
                })
                .unwrap_or_default();
            cookies.push(cookie);
            write!(stream, "HTTP/1.1 200 OK\r\nSet-Cookie: automatic=unwanted; Path=/\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
        }
        cookies
    });
    (base, server)
}

#[test]
fn disabled_jar_native_sends_manually_stored_cookies_but_rejects_response_cookies() {
    let (base, server) = fixture(2);
    let source = BookSource {
        book_source_url: base.clone(),
        enabled_cookie_jar: Some(false),
        ..Default::default()
    };
    with_active_session(None, &base, |active| {
        active.set_cookie(&base, "manual=kept");
        let session = HttpSession::new(&source, 2000).unwrap();
        for _ in 0..2 {
            let spec = analyze_url("/page", "", 1, &base, &source).unwrap();
            session.fetch(&spec, 1024).unwrap();
        }
        assert_eq!(active.get_cookie(&base).as_deref(), Some("manual=kept"));
    });
    assert_eq!(server.join().unwrap(), ["manual=kept", "manual=kept"]);
}

fn js_requests(script: &str) -> Vec<String> {
    let (base, server) = fixture(2);
    let source = json!({"bookSourceUrl": base, "enabledCookieJar": false});
    let action = format!(
        "cookie.setCookie({}, 'manual=kept'); {script}; 'ok'",
        json!(base)
    );
    let action = action.replace("URL", &json!(format!("{base}/page")).to_string());
    let result: Value = serde_json::from_str(&execute(
        &source.to_string(),
        &json!({"api":2,"op":"login","params":{"action":action},"options":{"timeoutMs":2000}})
            .to_string(),
    ))
    .unwrap();
    let cookies = server.join().unwrap();
    assert_eq!(result["ok"], true, "{result}");
    cookies
}

#[test]
fn disabled_jar_ajax_uses_analyze_url_cookie_policy() {
    assert_eq!(
        js_requests("java.ajax(URL); java.ajax(URL)"),
        ["manual=kept", "manual=kept"]
    );
}

#[test]
fn disabled_jar_direct_js_get_only_sends_explicit_cookie_headers() {
    assert_eq!(
        js_requests("java.get(URL, {}); java.get(URL, {Cookie:'explicit=sent'})"),
        ["", "explicit=sent"]
    );
}

#[test]
fn disabled_jar_url_options_override_same_named_stored_cookie() {
    let (base, server) = fixture(1);
    let source = BookSource {
        book_source_url: base.clone(),
        enabled_cookie_jar: Some(false),
        ..Default::default()
    };
    with_active_session(None, &base, |active| {
        active.set_cookie(&base, "manual=stored; keep=other");
        let spec = analyze_url(
            r#"/page,{"headers":{"Cookie":"manual=explicit"}}"#,
            "",
            1,
            &base,
            &source,
        )
        .unwrap();
        HttpSession::new(&source, 2000)
            .unwrap()
            .fetch(&spec, 1024)
            .unwrap();
    });
    let cookies = server.join().unwrap();
    assert!(cookies[0].split(';').any(|v| v.trim() == "manual=explicit"));
    assert!(cookies[0].split(';').any(|v| v.trim() == "keep=other"));
    assert!(!cookies[0].contains("manual=stored"));
}

#[test]
fn disabled_jar_preserves_empty_cookie_override_and_equals_in_values() {
    let base = "https://cookie-scope.test/private/page";
    let source = BookSource {
        book_source_url: base.into(),
        enabled_cookie_jar: Some(false),
        ..Default::default()
    };
    with_active_session(None, base, |active| {
        active.set_cookie(base, "manual=stored; keep=a=b");
        let spec = analyze_url(
            r#"/private/page,{"headers":{"Cookie":"manual="}}"#,
            "",
            1,
            base,
            &source,
        )
        .unwrap();
        let cookie = &spec
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("cookie"))
            .unwrap()
            .1;
        assert!(cookie.split(';').any(|v| v.trim() == "manual="));
        assert!(cookie.split(';').any(|v| v.trim() == "keep=a=b"));
        let spec = analyze_url("https://other.test/private/page", "", 1, base, &source).unwrap();
        assert!(!spec
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("cookie")));
    });
}
