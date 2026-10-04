//! Android's typed data-URI byte carrier, not a general data-to-text protocol.
use base64::{engine::general_purpose::STANDARD, Engine};
use reader_parser::crawler::{analyze_url, FetchError, HttpSession};
use reader_parser::executor::execute;
use reader_parser::model::book_source::BookSource;
use serde_json::{json, Value};

const BASE: &str = "https://fixture.invalid";
fn carrier(bytes: &[u8]) -> String {
    format!(
        "data:;base64,{},{{\"type\":\"qingtian\"}}",
        STANDARD.encode(bytes)
    )
}
fn source() -> BookSource {
    BookSource {
        book_source_url: BASE.into(),
        ..Default::default()
    }
}

#[test]
fn typed_carrier_returns_hex_without_network_proxy_or_rendering() {
    let source = source();
    for (payload, expected) in [
        ("AAH/", "0001ff"),
        ("YQ", "61"),
        ("Y Q==\n", "61"),
        ("", ""),
    ] {
        let raw = format!("data:application/octet-stream;base64,{payload},{{\"type\":\"\",\"proxy\":\"invalid proxy\",\"webView\":true,\"bodyJs\":\"throw Error('must not run')\"}}");
        let spec = analyze_url(&raw, "", 1, BASE, &source).unwrap();
        let response = HttpSession::new(&source, 100)
            .unwrap()
            .fetch(&spec, 3)
            .unwrap();
        assert_eq!(response.body, expected);
        assert_eq!(response.status, 200);
        assert!(response.url.starts_with("data:"));
    }
}

#[test]
fn malformed_untyped_and_oversized_carriers_do_not_become_text() {
    let source = source();
    let session = HttpSession::new(&source, 100).unwrap();
    for raw in [
        "data:;base64,YQ==",
        "data:;base64,YQ==,{\"type\":null}",
        "data:,plain,{\"type\":\"bin\"}",
        "data:;base64,!!!!,{\"type\":\"bin\"}",
    ] {
        let succeeded = analyze_url(raw, "", 1, BASE, &source)
            .map(|spec| session.fetch(&spec, 3).is_ok())
            .unwrap_or(false);
        assert!(!succeeded, "{raw}");
    }
    let spec = analyze_url(&carrier(b"abcd"), "", 1, BASE, &source).unwrap();
    assert!(matches!(
        session.fetch(&spec, 3),
        Err(FetchError::ResponseTooLarge { limit: 3, .. })
    ));
}

#[test]
fn typed_content_reaches_rule_and_source_bound_ajax() {
    let inner = carrier("正文".as_bytes());
    let source = json!({"bookSourceUrl":BASE, "ruleContent":{
        "content": format!("@js:java.hexDecodeToString(result) + '/' + java.hexDecodeToString(java.ajax({}))", serde_json::to_string(&inner).unwrap())
    }});
    let request = json!({"api":2,"op":"content","params":{"url":carrier(b"initial")}});
    let result: Value =
        serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["data"]["content"], "initial/正文");
}

#[test]
fn carriers_survive_search_info_toc_and_content_offline() {
    let chapter_url = carrier(json!({"content":"完整正文"}).to_string().as_bytes());
    let toc_url = carrier(
        json!({"chapters":[{"title":"第一章","url":chapter_url}]})
            .to_string()
            .as_bytes(),
    );
    let book_url = carrier(
        json!({"name":"载体书籍","tocUrl":toc_url})
            .to_string()
            .as_bytes(),
    );
    let search_url = carrier(
        json!({"books":[{"name":"载体书籍","url":book_url}]})
            .to_string()
            .as_bytes(),
    );
    let source = json!({"bookSourceUrl":BASE, "searchUrl":search_url,
        "ruleSearch":{"bookList":"<js>java.hexDecodeToString(result)</js>$.books[*]","name":"$.name","bookUrl":"$.url"},
        "ruleBookInfo":{"init":"@js:java.hexDecodeToString(result)","name":"$.name","tocUrl":"$.tocUrl"},
        "ruleToc":{"chapterList":"<js>java.hexDecodeToString(result)</js>$.chapters[*]","chapterName":"$.title","chapterUrl":"$.url"},
        "ruleContent":{"content":"@js:JSON.parse(java.hexDecodeToString(result)).content"}});
    let call = |op: &str, params: Value| -> Value {
        let result: Value = serde_json::from_str(&execute(
            &source.to_string(),
            &json!({"api":2,"op":op,"params":params,"options":{"timeoutMs":100}}).to_string(),
        ))
        .unwrap();
        assert_eq!(result["ok"], true, "{op}: {result}");
        result["data"].clone()
    };
    let books = call("search", json!({"key":"载体"}));
    assert_eq!(books[0]["name"], "载体书籍");
    assert_eq!(books[0]["bookUrl"], book_url);
    let info = call("info", json!({"url":books[0]["bookUrl"]}));
    assert_eq!(info["name"], "载体书籍");
    assert_eq!(info["tocUrl"], toc_url);
    let toc = call("toc", json!({"url":info["tocUrl"]}));
    assert_eq!(toc["chapters"][0]["title"], "第一章");
    assert_eq!(toc["chapters"][0]["url"], chapter_url);
    let content = call("content", json!({"url":toc["chapters"][0]["url"]}));
    assert_eq!(content["content"], "完整正文");
}

#[test]
fn option_js_runs_before_data_decoding() {
    let source = source();
    let target = "data:;base64,Yg==";
    let raw = format!(
        "data:;base64,YQ==,{}",
        json!({"type":"bin","js":serde_json::to_string(target).unwrap()})
    );
    let spec = analyze_url(&raw, "", 1, BASE, &source).unwrap();
    assert_eq!(spec.url, target);
    let response = HttpSession::new(&source, 100)
        .unwrap()
        .fetch(&spec, 1)
        .unwrap();
    assert_eq!(response.body, "62");
}

#[test]
fn json_returning_info_init_runs_once_and_preserves_state() {
    let source = json!({"bookSourceUrl":BASE, "ruleBookInfo":{
        "init":"@js:java.put('initCount', String(Number(java.get('initCount') || 0) + 1)); JSON.stringify({name:'Book'})",
        "name":"$.name", "author":"@js:java.get('initCount')"}});
    let request = json!({"api":2,"op":"info","params":{"url":carrier(b"raw")}});
    let result: Value =
        serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["data"]["name"], "Book");
    assert_eq!(result["data"]["author"], "1");
}

#[test]
fn info_init_decodes_raw_carrier_before_trailing_jsonpath_once() {
    let source = json!({"bookSourceUrl":BASE, "ruleBookInfo":{
        "init":"<js>java.put('initCount', String(Number(java.get('initCount') || 0) + 1)); java.hexDecodeToString(result)</js>$.data",
        "name":"$.name", "author":"@js:java.get('initCount')"}});
    let request = json!({"api":2,"op":"info","params":{"url":carrier(br#"{"data":{"name":"Book"},"name":"Wrong outer scope"}"#)}});
    let result: Value =
        serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["data"]["name"], "Book");
    assert_eq!(result["data"]["author"], "1");
}

#[test]
fn content_init_decodes_raw_carrier_before_trailing_jsonpath_once() {
    let source = json!({"bookSourceUrl":BASE,"ruleContent":{
        "content":"<js>java.put('count', String(Number(java.get('count') || 0) + 1)); JSON.stringify({content:JSON.parse(java.hexDecodeToString(result)).content + '/' + java.get('count')})</js>$.content"}});
    let request =
        json!({"api":2,"op":"content","params":{"url":carrier(br#"{"content":"Body"}"#)}});
    let result: Value =
        serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["data"]["content"], "Body/1");
}
