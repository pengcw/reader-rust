//! Rakers Headless DOM & JavaScript Rendering Contracts
//!
//! Verifies the headless browser environment powered by QuickJS and DOM manipulation
//! exposed via `reader_eval(input, "@rakers_render")`.
//!
//! Contracts:
//! 1. Headless DOM manipulation & script execution (document, innerHTML, createElement).
//! 2. SPA novel review list client-side hydration (inline data & DOM rendering).
//! 3. External script resolution and execution via baseUrl and loopback HTTP server.
//! 4. Promise microtask and timer queue (setTimeout/then) flushing.
//! 5. Synchronous and asynchronous page HTTP requests through the shared Rakers transport.
//! 6. Real `window.fetch` body/status/JSON hydration.
//! 7. Security limits, payload bounds, and syntax error resilience.
//! 8. Full URL direct fetch with cookie continuity across page subrequests.

use reader_parser::ffi::{reader_eval, reader_free_string};
use safer_ffi::prelude::*;
use serde_json::{json, Value};
use std::ffi::CString;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::thread;

fn call_rakers_render(input: &str) -> String {
    let c_input = CString::new(input).unwrap();
    let c_rule = CString::new("@rakers_render").unwrap();
    let result = reader_eval(
        char_p::Ref::try_from(c_input.as_c_str()).unwrap(),
        char_p::Ref::try_from(c_rule.as_c_str()).unwrap(),
    );
    let output = result.to_str().to_string();
    reader_free_string(Some(result));
    output
}

#[test]
fn rakers_headless_dom_and_script_execution() {
    let raw_html = r#"
        <!DOCTYPE html>
        <html>
        <head><title>Test Page</title></head>
        <body>
            <h1 id="title">Static Header</h1>
            <div id="container">Placeholder to replace</div>
            <script>
                var container = document.getElementById("container");
                var newEl = document.createElement("p");
                newEl.className = "dynamic-p";
                newEl.innerHTML = "Hydrated by Rakers";
                container.appendChild(newEl);
            </script>
        </body>
        </html>
    "#;

    let rendered = call_rakers_render(raw_html);

    assert!(rendered.contains("Hydrated by Rakers"), "Must execute DOM creation script");
    assert!(rendered.contains("dynamic-p"), "Must retain injected classes");
    assert!(rendered.contains("Static Header"), "Must preserve static sibling nodes outside container");
    assert!(!rendered.contains("Placeholder to replace"), "Must replace mount container placeholder");
}

#[test]
fn rakers_spa_novel_review_hydration() {
    // Simulates an SPA novel review widget loaded in KOReader:
    // Initial HTML only contains a skeleton. Inline JS hydrates it from a JSON data model.
    let spa_html = r#"
        <html>
        <body>
            <h2>本章段评</h2>
            <div id="reviews-root">
                <div class="loading">正在加载评论...</div>
            </div>
            <script>
                var rawComments = [
                    {"author": "书友墨客", "content": "这章伏笔写的绝了！", "likes": 42},
                    {"author": "追更狂魔", "content": "生产队的驴都不敢这么歇，快更新！", "likes": 18}
                ];
                var root = document.getElementById("reviews-root");
                root.innerHTML = ""; // Clear loading
                for (var i = 0; i < rawComments.length; i++) {
                    var item = rawComments[i];
                    var div = document.createElement("div");
                    div.className = "review-card";
                    div.innerHTML = "<span class='author'>" + item.author + "</span>: " +
                                    "<span class='text'>" + item.content + "</span> " +
                                    "<span class='badge'>" + item.likes + "赞</span>";
                    root.appendChild(div);
                }
            </script>
        </body>
        </html>
    "#;

    let rendered = call_rakers_render(spa_html);

    assert!(!rendered.contains("正在加载评论..."), "Loading placeholder must be removed");
    assert!(rendered.contains("书友墨客"), "First author must be rendered");
    assert!(rendered.contains("这章伏笔写的绝了！"), "First comment content must be rendered");
    assert!(rendered.contains("42赞"), "Likes count must be rendered");
    assert!(rendered.contains("追更狂魔"), "Second author must be rendered");
    assert!(rendered.contains("生产队的驴都不敢这么歇，快更新！"), "Second comment content must be rendered");
}

#[test]
fn rakers_external_script_resolution_with_base_url() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();

        assert!(request_line.starts_with("GET /static/remote_render.js "), "Must request external script");

        // Drain headers
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                break;
            }
        }

        let js_body = "document.getElementById('external-target').innerHTML = '<span class=\"success\">Remote JS Injected Successfully</span>';";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{js_body}",
            js_body.len()
        ).unwrap();
    });

    let input_req = json!({
        "html": "<html><body><div id='external-target'>Pending</div><script src='/static/remote_render.js'></script></body></html>",
        "baseUrl": format!("{base_url}/chapter/1001.html")
    }).to_string();

    let rendered = call_rakers_render(&input_req);
    server.join().unwrap();

    assert!(rendered.contains("Remote JS Injected Successfully"), "Rendered HTML must reflect external script execution");
    assert!(!rendered.contains("Pending"), "Pending placeholder must be replaced");
}

#[test]
fn rakers_timer_and_promise_microtask_flushing() {
    // Tests that rakers's event loop executes microtasks and setTimeout callbacks
    // before serializing the final DOM snapshot.
    let html = r#"
        <html><body>
            <div id="out">0</div>
            <script>
                var el = document.getElementById("out");
                Promise.resolve().then(function() {
                    el.innerHTML = "MicrotaskDone";
                });
                setTimeout(function() {
                    el.innerHTML += "+TimeoutDone";
                }, 0);
            </script>
        </body></html>
    "#;

    let rendered = call_rakers_render(html);
    assert!(rendered.contains("MicrotaskDone+TimeoutDone"), "Must flush Promise microtasks and setTimeout before snapshot, got: {rendered}");
}

#[test]
fn rakers_xhr_sync_fetch_runtime_support() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();

        assert!(request_line.starts_with("GET /api/comments.json "), "Must request comments API");

        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                break;
            }
        }

        let json_body = r#"{"title":"XHR测试","count":99}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json_body}",
            json_body.len()
        ).unwrap();
    });

    let input_req = json!({
        "html": format!(r#"
            <html><body>
                <div id="result">Initial</div>
                <script>
                    var xhr = new XMLHttpRequest();
                    xhr.open("GET", "{base_url}/api/comments.json", false);
                    xhr.send();
                    var data = JSON.parse(xhr.responseText);
                    document.getElementById("result").innerHTML = data.title + ":" + data.count;
                </script>
            </body></html>
        "#),
        "baseUrl": base_url
    }).to_string();

    let rendered = call_rakers_render(&input_req);
    server.join().unwrap();

    assert!(rendered.contains("XHR测试:99"), "Must fetch and render data via synchronous XHR, got: {rendered}");
}

#[test]
fn rakers_fetch_real_json_hydration() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        assert!(request_line.starts_with("GET /api/data "), "fetch must perform the real GET");
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" { break; }
        }
        let body = r#"{"title":"Fetch Hydrated","count":7}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ).unwrap();
    });

    let input = json!({
        "html": r#"<html><body><div id="fetch-status">Pending</div><script>
            fetch('/api/data')
                .then(function(res) { return res.json(); })
                .then(function(data) {
                    document.getElementById('fetch-status').innerHTML = data.title + ':' + data.count;
                });
        </script></body></html>"#,
        "baseUrl": format!("{base_url}/chapter/1")
    }).to_string();

    let rendered = call_rakers_render(&input);
    server.join().unwrap();
    assert!(rendered.contains("Fetch Hydrated:7"), "fetch JSON must hydrate DOM, got: {rendered}");
}

#[test]
fn rakers_fetch_post_preserves_method_headers_body_and_status() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        assert!(request_line.starts_with("POST /submit "));
        let mut content_length = 0usize;
        let mut saw_test_header = false;
        let mut saw_script_cookie = false;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" { break; }
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("content-length:") {
                content_length = line.split_once(':').unwrap().1.trim().parse().unwrap();
            }
            if lower.starts_with("x-rakers-test:") && line.contains("yes") {
                saw_test_header = true;
            }
            if lower.starts_with("cookie:") && line.contains("script_cookie=forbidden") {
                saw_script_cookie = true;
            }
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).unwrap();
        assert_eq!(String::from_utf8(body).unwrap(), "payload");
        assert!(saw_test_header, "fetch request header must reach transport");
        assert!(!saw_script_cookie, "page JavaScript must not inject a raw Cookie header");

        let response = "accepted";
        write!(
            stream,
            "HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
            response.len()
        ).unwrap();
    });

    let input = json!({
        "html": r#"<html><body><div id="out">Pending</div><script>
            fetch('/submit', {method:'POST', headers:{'X-Rakers-Test':'yes','Cookie':'script_cookie=forbidden'}, body:'payload'})
                .then(function(r){ var status=r.status; return r.text().then(function(t){ return status + ':' + t; }); })
                .then(function(v){ document.getElementById('out').innerHTML=v; });
        </script></body></html>"#,
        "baseUrl": format!("{base_url}/page")
    }).to_string();

    let rendered = call_rakers_render(&input);
    server.join().unwrap();
    assert!(rendered.contains("201:accepted"), "POST fetch must expose real status/body, got: {rendered}");
}

#[test]
fn rakers_direct_url_reuses_cookie_session_for_fetch() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let page_url = format!("http://127.0.0.1:{port}/page");

    let server = thread::spawn(move || {
        let (mut page_stream, _) = listener.accept().unwrap();
        let mut page_reader = BufReader::new(page_stream.try_clone().unwrap());
        let mut request_line = String::new();
        page_reader.read_line(&mut request_line).unwrap();
        assert!(request_line.starts_with("GET /page "));
        let mut saw_seed_cookie = false;
        loop {
            let mut line = String::new();
            if page_reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" { break; }
            if line.to_ascii_lowercase().starts_with("cookie:") && line.contains("sid=seeded") {
                saw_seed_cookie = true;
            }
        }
        assert!(saw_seed_cookie, "input Cookie header must reach the main page request");
        let html = r#"<html><body><div id="out">Pending</div><script>
            fetch('/api').then(function(r){return r.text();})
                .then(function(t){document.getElementById('out').innerHTML=t;});
        </script></body></html>"#;
        write!(
            page_stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: server_cookie=updated; Path=/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html}",
            html.len()
        ).unwrap();

        let (mut api_stream, _) = listener.accept().unwrap();
        let mut api_reader = BufReader::new(api_stream.try_clone().unwrap());
        let mut api_line = String::new();
        api_reader.read_line(&mut api_line).unwrap();
        assert!(api_line.starts_with("GET /api "));
        let mut saw_seed_cookie = false;
        let mut saw_response_cookie = false;
        loop {
            let mut line = String::new();
            if api_reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" { break; }
            if line.to_ascii_lowercase().starts_with("cookie:") {
                saw_seed_cookie |= line.contains("sid=seeded");
                saw_response_cookie |= line.contains("server_cookie=updated");
            }
        }
        assert!(saw_seed_cookie, "initial Cookie header must remain in the shared jar");
        assert!(saw_response_cookie, "page Set-Cookie must be reused by JS fetch");
        let body = "cookie-ok";
        write!(
            api_stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ).unwrap();
    });

    let input = json!({
        "url": page_url,
        "headers": {"Cookie": "sid=seeded"}
    }).to_string();
    let rendered = call_rakers_render(&input);
    server.join().unwrap();
    assert!(rendered.contains("cookie-ok"), "shared cookie session must hydrate DOM, got: {rendered}");
}

#[test]
fn rakers_fetch_set_cookie_is_reused_by_next_subrequest() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");

    let server = thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        let mut first_reader = BufReader::new(first.try_clone().unwrap());
        let mut line = String::new();
        first_reader.read_line(&mut line).unwrap();
        assert!(line.starts_with("GET /session/start "));
        loop {
            line.clear();
            if first_reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" { break; }
        }
        let body = "seeded";
        write!(
            first,
            "HTTP/1.1 200 OK\r\nSet-Cookie: api_sid=from_fetch; Path=/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ).unwrap();

        let (mut second, _) = listener.accept().unwrap();
        let mut second_reader = BufReader::new(second.try_clone().unwrap());
        line.clear();
        second_reader.read_line(&mut line).unwrap();
        assert!(line.starts_with("GET /session/check "));
        let mut saw_cookie = false;
        loop {
            line.clear();
            if second_reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" { break; }
            if line.to_ascii_lowercase().starts_with("cookie:") && line.contains("api_sid=from_fetch") {
                saw_cookie = true;
            }
        }
        assert!(saw_cookie, "Set-Cookie from one fetch must be reused by the next fetch");
        let body = "subrequest-cookie-ok";
        write!(
            second,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ).unwrap();
    });

    let input = json!({
        "html": r#"<html><body><div id="out">Pending</div><script>
            fetch('/session/start').then(function(){ return fetch('/session/check'); })
                .then(function(r){ return r.text(); })
                .then(function(t){ document.getElementById('out').innerHTML=t; });
        </script></body></html>"#,
        "baseUrl": format!("{base_url}/page")
    }).to_string();

    let rendered = call_rakers_render(&input);
    server.join().unwrap();
    assert!(rendered.contains("subrequest-cookie-ok"), "fetch cookie jar must persist within one render, got: {rendered}");
}

#[test]
fn rakers_security_limits_and_syntax_error_resilience() {
    // 1. Broken JavaScript syntax must not panic the engine
    let broken_syntax = r#"
        <html><body>
            <div id="safe">Still Alive</div>
            <script>
                var a = {{{; // Syntax error
            </script>
        </body></html>
    "#;
    let rendered_broken = call_rakers_render(broken_syntax);
    assert!(rendered_broken.contains("Still Alive"), "Syntax error must not crash or wipe DOM");

    // 2. Input exceeding MAX_RAKERS_EVAL_JSON_BYTES (16MB)
    let huge_input = "a".repeat(17 * 1024 * 1024);
    let huge_res = call_rakers_render(&huge_input);
    let error_val: Value = serde_json::from_str(&huge_res).unwrap();
    assert_eq!(error_val["error"], "Rakers render input exceeds 16 MiB");

    // 3. Mutually exclusive input (providing both url and html)
    let invalid_both = json!({
        "url": "http://example.com",
        "html": "<html></html>"
    }).to_string();
    let both_res = call_rakers_render(&invalid_both);
    let both_err: Value = serde_json::from_str(&both_res).unwrap();
    assert_eq!(both_err["error"], "provide either url or html, not both");
}

#[test]
fn rakers_direct_url_full_pipeline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_url = format!("http://127.0.0.1:{port}/review_page");

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();

        assert!(request_line.starts_with("GET /review_page "), "Must request page via HTTP");

        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                break;
            }
        }

        let page_html = r#"
            <!DOCTYPE html>
            <html><body>
                <div id="content">Server Response</div>
                <script>
                    document.getElementById("content").innerHTML = "Headless Hydrated";
                </script>
            </body></html>
        "#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page_html}",
            page_html.len()
        ).unwrap();
    });

    let rendered = call_rakers_render(&server_url);
    server.join().unwrap();

    assert!(rendered.contains("Headless Hydrated"), "Full URL fetch & render pipeline must succeed, got: {rendered}");
}

#[test]
fn rakers_fanqie_h5_spa_fetch_hydrates() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        assert!(request_line.starts_with("GET /api/fanqie/comment/chapter/list "));
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" { break; }
        }
        let body = r#"{"items":[{"content":"真实评论数据"}]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ).unwrap();
    });

    let input = json!({
        "html": r#"<!DOCTYPE html><html><body>
            <div class="main-tabs"><button class="active">本章说</button></div>
            <div class="loading" id="loading">加载中...</div>
            <div class="main-container" id="contentArea"></div>
            <script>
                const API = { chapterList: '/api/fanqie/comment/chapter/list' };
                async function loadComments() {
                    var resp = await fetch(API.chapterList);
                    var data = await resp.json();
                    if (data && data.items && data.items.length) {
                        document.getElementById('contentArea').innerHTML = '<div>Comments Loaded:' + data.items[0].content + '</div>';
                    }
                }
                loadComments();
            </script>
        </body></html>"#,
        "baseUrl": format!("{base_url}/comments/page")
    }).to_string();

    let rendered = call_rakers_render(&input);
    server.join().unwrap();
    assert!(rendered.contains("本章说"));
    assert!(rendered.contains("Comments Loaded:真实评论数据"), "fetch-based SPA must hydrate, got: {rendered}");
}
