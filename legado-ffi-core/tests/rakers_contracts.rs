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
//! 5. Synchronous XHR (XMLHttpRequest) data fetching via native `_r_fetch_sync`.
//! 6. `window.fetch` stub safe non-crashing contract.
//! 7. Security limits, payload bounds, and syntax error resilience.
//! 8. Full URL direct fetch and headless render pipeline.

use reader_parser::ffi::{reader_eval, reader_free_string};
use safer_ffi::prelude::*;
use serde_json::{json, Value};
use std::ffi::CString;
use std::io::{BufRead, BufReader, Write};
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
fn rakers_fetch_stub_safe_resolution() {
    // Tests that window.fetch resolves without throwing exceptions in SPA code
    let html = r#"
        <html><body>
            <div id="fetch-status">Pending</div>
            <script>
                fetch('/dummy-endpoint')
                    .then(function(res) {
                        return res.json();
                    })
                    .then(function(data) {
                        // In rakers, fetch resolves with null
                        if (data === null) {
                            document.getElementById("fetch-status").innerHTML = "FetchStubHandledSafely";
                        }
                    })
                    .catch(function(err) {
                        document.getElementById("fetch-status").innerHTML = "FetchFailed";
                    });
            </script>
        </body></html>
    "#;

    let rendered = call_rakers_render(html);
    assert!(rendered.contains("FetchStubHandledSafely"), "window.fetch must resolve cleanly without crashing runtime, got: {rendered}");
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
fn rakers_fanqie_h5_spa_fetch_limitation_and_bypass_verification() {
    // Verifies the exact boundary of Rakers when encountering modern SPA comment pages (such as Dahuilang's fanqie_comment H5):
    // 1. Rakers executes safely without crashing/panicking, preserving the overall HTML structure.
    // 2. However, because window.fetch is a stub returning null, the SPA cannot hydrate its dynamic comments, leaving contentArea empty.
    let spa_html = r#"
        <!DOCTYPE html><html><body>
            <div class="main-tabs"><button class="active">本章说</button></div>
            <div class="loading" id="loading">加载中...</div>
            <div class="main-container" id="contentArea"></div>
            <script>
                const API = { chapterList: '/api/fanqie/comment/chapter/list' };
                async function loadComments() {
                    try {
                        var resp = await fetch(API.chapterList);
                        var data = await resp.json();
                        if (data && data.items) {
                            document.getElementById("contentArea").innerHTML = "<div>Comments Loaded</div>";
                            document.getElementById("loading").style.display = "none";
                        }
                    } catch(e) {}
                }
                loadComments();
            </script>
        </body></html>
    "#;

    let rendered = call_rakers_render(spa_html);

    // Documents Rakers limitation on modern fetch-based SPAs:
    assert!(rendered.contains("本章说"), "DOM static structure is intact");
    assert!(rendered.contains("id=\"contentArea\""), "Container element exists");
    assert!(!rendered.contains("Comments Loaded"), "Documents Rakers limitation: fetch stub returning null prevents SPA async hydration");
}
