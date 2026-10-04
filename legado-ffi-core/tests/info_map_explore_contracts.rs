//! URL-only infoMap scope over bounded local HTTP fixtures.
use reader_parser::executor::execute;
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
        let mut requests = Vec::new();
        for _ in 0..count {
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
            requests.push(String::from_utf8(request).unwrap());
            let body = r#"{"items":[{"name":"Book","url":"/book"}]}"#;
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
        requests
    });
    (base, server)
}

fn source(base: &str) -> Value {
    json!({"bookSourceUrl":base, "bookSourceName":"explore state",
        "exploreUrl":"@js: infoMap.put('tag','rank'); [{title:'分类',url:'/list?tag={{tag()}}&page={{page}}'}];",
        "jsLib":"function tag(){return infoMap.get('tag');}",
        "ruleExplore":{"bookList":"$.items[*]","name":"$.name@js:typeof infoMap + ':' + result","bookUrl":"$.url"},
        "ruleSearch":{"bookList":"$.items[*]","name":"$.name@js:typeof infoMap + ':' + result","bookUrl":"$.url"}})
}

fn run(source: &Value, op: &str, params: Value, state: Option<Value>) -> Value {
    let mut request = json!({"api":2,"op":op,"params":params});
    if let Some(state) = state {
        request["infoMap"] = state;
    }
    serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap()
}

#[test]
fn classification_state_reaches_templates_library_login_checks_and_later_pages() {
    let (base, server) = fixture(2);
    let mut source = source(&base);
    source["loginCheckJs"] = json!("if(infoMap.get('tag') !== 'rank') throw new Error('lost state'); infoMap.put('checks',String(Number(infoMap.get('checks')||0)+1)); result;");
    let categories = run(&source, "explore_kinds", json!({}), None);
    assert_eq!(categories["ok"], true, "{categories}");
    let url = categories["data"][0]["url"].clone();
    let mut state = categories["infoMap"].clone();
    for page in [1, 2] {
        let response = run(
            &source,
            "explore",
            json!({"url":url,"page":page}),
            Some(state),
        );
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(response["data"][0]["name"], "undefined:Book");
        assert_eq!(response["infoMap"]["values"]["checks"], page.to_string());
        state = response["infoMap"].clone();
    }
    let requests = server.join().unwrap();
    assert!(requests[0].starts_with("GET /list?tag=rank&page=1 "));
    assert!(requests[1].starts_with("GET /list?tag=rank&page=2 "));
}

#[test]
fn option_javascript_and_body_javascript_share_state_but_list_fields_do_not() {
    let (base, server) = fixture(1);
    let source = source(&base);
    let state = json!({"values":{"tag":"rank"},"needSave":false,"saveTime":0});
    let options = json!({"js":"java.headerMap.put('X-Category',infoMap.get('tag')); infoMap.put('option','yes'); result+'?tag='+infoMap.get('tag');",
        "bodyJs":"JSON.stringify({items:[{name:infoMap.get('tag'),url:'/book'}]})"});
    let response = run(
        &source,
        "explore",
        json!({"url":format!("/options,{options}")}),
        Some(state),
    );
    assert_eq!(response["ok"], true, "{response}");
    assert_eq!(response["data"][0]["name"], "undefined:rank");
    assert_eq!(response["infoMap"]["values"]["option"], "yes");
    let requests = server.join().unwrap();
    assert!(requests[0].starts_with("GET /options?tag=rank "));
    assert!(requests[0]
        .to_ascii_lowercase()
        .contains("x-category: rank\r\n"));
}

#[test]
fn normal_search_does_not_receive_supplied_exploration_state() {
    let (base, server) = fixture(1);
    let mut source = source(&base);
    source["searchUrl"] = json!("/search?map={{typeof infoMap}}");
    let response = run(
        &source,
        "search",
        json!({"key":"book"}),
        Some(json!({"values":{"secret":"private"},"needSave":true,"saveTime":0})),
    );
    assert_eq!(response["ok"], true, "{response}");
    assert_eq!(response["data"][0]["name"], "undefined:Book");
    assert!(response.get("infoMap").is_none());
    assert!(server.join().unwrap()[0].starts_with("GET /search?map=undefined "));
}

#[test]
fn direct_url_javascript_reads_and_updates_the_same_map() {
    let (base, server) = fixture(1);
    let source = source(&base);
    let response = run(
        &source,
        "explore",
        json!({"url":"@js:infoMap.put('counter','1'); source.key+'/direct?tag='+tag();"}),
        Some(json!({"values":{"tag":"rank"},"needSave":false,"saveTime":0})),
    );
    assert_eq!(response["ok"], true, "{response}");
    assert_eq!(response["infoMap"]["values"]["counter"], "1");
    assert!(server.join().unwrap()[0].starts_with("GET /direct?tag=rank "));
}

#[test]
fn failed_url_javascript_does_not_publish_unsaved_state() {
    let source = source("https://never-request.test");
    let response = run(
        &source,
        "explore",
        json!({"url":"@js:infoMap.put('tag','bad'); throw new Error('stop before HTTP');"}),
        Some(json!({"values":{"tag":"rank"},"needSave":false,"saveTime":0})),
    );
    assert_eq!(response["ok"], false, "{response}");
    assert!(response.get("infoMap").is_none());
}
