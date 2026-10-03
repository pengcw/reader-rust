use reader_parser::parser::js::{eval_js, eval_js_with_bindings};
use serde_json::json;
use std::collections::HashMap;

fn make_str_response(
    body: &str,
    url: &str,
    code: u16,
    headers: &[(&str, &str)],
) -> HashMap<String, serde_json::Value> {
    let mut header_map = serde_json::Map::new();
    for (k, v) in headers {
        header_map.insert(k.to_string(), json!(v));
    }
    let mut bindings = HashMap::new();
    bindings.insert(
        "result".to_string(),
        json!({
            "__ffiStrResponse": true,
            "raw": null,
            "body": body,
            "url": url,
            "code": code,
            "headers": header_map,
            "isSuccessful": (200..300).contains(&code),
        }),
    );
    bindings
}

#[test]
fn java_aes_base64_decode_to_string_decrypts_legado_paths() {
    let encrypted = "UhQTfQq/qXGCKPd5D+cjxB7Y0AzwiFMYBmcN5nIm2PboUavKiWEIVaAPIhDXbkox";
    let result = eval_js(
        r#"java.aesBase64DecodeToString(result, "f041c49714d39908", "AES/CBC/PKCS5Padding", "0123456789abcdef")"#,
        encrypted,
        "http://api.jmlldsc.com",
    )
    .unwrap();

    assert_eq!(result, "http://api.lemiyigou.com/655/655791/70398.json");
}

#[test]
fn str_response_callable_method_returns_body_text() {
    let bindings = make_str_response(
        r#"{"status":"ok","count":42}"#,
        "https://api.example.com/data",
        200,
        &[("content-type", "application/json")],
    );
    let output =
        eval_js_with_bindings(r#"result.body()"#, "", "https://api.example.com", &bindings)
            .unwrap();
    assert_eq!(output, r#"{"status":"ok","count":42}"#);
}

#[test]
fn str_response_property_access_and_string_methods() {
    // In Legado (Kotlin/Rhino), StrResponse has `val body: String` and `fun body(): String`.
    // Book source scripts frequently treat `result.body` as a String property:
    // e.g. `result.body.indexOf('ok')`, `JSON.parse(result.body)`, `result.body.length`.
    let body = r#"{"status":"ok","count":42}"#;
    let bindings = make_str_response(
        body,
        "https://api.example.com/data",
        200,
        &[("content-type", "application/json")],
    );
    let output = eval_js_with_bindings(
        r#"
        JSON.stringify({
            index: result.body.indexOf("ok"),
            length: result.body.length,
            parsedCount: JSON.parse(result.body).count,
            strConcat: ("" + result.body).startsWith('{"status"')
        })
        "#,
        "",
        "https://api.example.com",
        &bindings,
    )
    .unwrap();

    let val: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(
        val["index"],
        body.find("ok").unwrap(),
        "result.body.indexOf should find substring index"
    );
    assert_eq!(
        val["length"],
        body.encode_utf16().count(),
        "result.body.length should match string length, not 0"
    );
    assert_eq!(
        val["parsedCount"], 42,
        "JSON.parse(result.body) should parse JSON correctly"
    );
    assert_eq!(
        val["strConcat"], true,
        "String coercion of result.body should yield body string"
    );
}

#[test]
fn str_response_body_preserves_unicode_and_callable_coercion() {
    let bindings = make_str_response("书😀", "https://example.test", 200, &[]);
    let output = eval_js_with_bindings(
        r#"JSON.stringify([result.body(), String(result.body), result.body.length,
            result.body.substring(1), result.body, result.body[0], result.headers().get('missing')])"#,
        "",
        "https://example.test",
        &bindings,
    ).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&output).unwrap(),
        json!(["书😀", "书😀", 3, "😀", "书😀", "书", null])
    );
}

#[test]
fn str_response_header_shorthand_method() {
    // Legado's StrResponse delegates header queries to OkHttp Response.header(name).
    // Booksources commonly write `result.header('content-type')` instead of `result.headers().get(...)`.
    let bindings = make_str_response(
        "{}",
        "https://api.example.com/data",
        200,
        &[
            ("Content-Type", "application/json; charset=utf-8"),
            ("X-Token", "xyz"),
        ],
    );
    let output = eval_js_with_bindings(
        r#"
        JSON.stringify({
            ct: result.header('content-type'),
            token: result.header('x-token'),
            missing: result.header('nonexistent')
        })
        "#,
        "",
        "https://api.example.com",
        &bindings,
    )
    .unwrap();

    let val: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(val["ct"], "application/json; charset=utf-8");
    assert_eq!(val["token"], "xyz");
    assert!(val["missing"].is_null());
}

#[test]
fn packages_org_jsoup_parse_resolves_abs_urls_and_collection_methods() {
    // Referenced from Tlegado source_runtime.rs lines 238-244 & Legado Rhino compatibility:
    // `Packages.org.jsoup.Jsoup.parse(html, baseUri)` must be callable,
    // and elements must support `.attr('abs:href')`, `.hasAttr()`, `.isEmpty()`.
    let html = r#"<nav><a href="/next">Hello &amp; World</a></nav>"#;
    let script = r#"
        const doc = Packages.org.jsoup.Jsoup.parse(
            '<nav><a href="/next">Hello &amp; World</a></nav>',
            'https://example.test/base'
        );
        const links = doc.select('nav').first().select('a');
        JSON.stringify([
            links.length,
            links.first().text(),
            links.attr('abs:href'),
            links.first().hasAttr('href'),
            links.isEmpty()
        ]);
    "#;
    let output = eval_js(script, html, "https://example.test").unwrap();
    let val: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(val[0], 1, "link count");
    assert_eq!(val[1], "Hello & World", "html unescaped text");
    assert_eq!(
        val[2], "https://example.test/next",
        "abs:href resolution with baseUri"
    );
    assert_eq!(val[3], true, "hasAttr('href')");
    assert_eq!(val[4], false, "isEmpty()");
}

#[test]
fn org_jsoup_document_convenience_methods() {
    // Legado rules frequently use Jsoup document methods:
    // doc.title(), doc.selectFirst(), doc.body()
    let html = r#"<!DOCTYPE html><html><head><title>My Book</title></head><body><div id="content"><h1>Chapter 1</h1><p>Text</p></div></body></html>"#;
    let script = r#"
        const doc = org.jsoup.Jsoup.parse(result);
        JSON.stringify({
            title: doc.title(),
            firstH1: doc.selectFirst('h1').text(),
            hasBody: doc.body() != null
        });
    "#;
    let output = eval_js(script, html, "https://example.test").unwrap();
    let val: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(val["title"], "My Book");
    assert_eq!(val["firstH1"], "Chapter 1");
    assert_eq!(val["hasBody"], true);
}

#[test]
fn jsoup_abs_attributes_keep_query_fragment_and_missing_attribute_semantics() {
    let output = eval_js(
        r#"
        const doc = org.jsoup.Jsoup.parse(
            '<a></a><a href="../next?q=书#part" disabled></a>',
            'https://example.test/books/current');
        const links = doc.select('a');
        const link = links.get(1);
        JSON.stringify([Packages.org.jsoup === org.jsoup, links.attr('abs:href'),
            link.hasAttr('disabled'), link.attr('disabled'),
            links.first().hasAttr('href'), links.first().attr('abs:href'),
            doc.select('missing').isEmpty(), doc.select('missing').attr('href'),
            doc.selectFirst('missing')]);
        "#,
        "",
        "https://unused.test",
    )
    .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&output).unwrap(),
        json!([
            true,
            "https://example.test/next?q=%E4%B9%A6#part",
            true,
            "",
            false,
            "",
            true,
            "",
            null
        ])
    );
}

#[test]
fn jsoup_document_methods_observe_removal_and_do_not_leak_base_uri() {
    let output = eval_js(
        r#"
        const doc = org.jsoup.Jsoup.parse('<title>Old</title><a href="/next">Next</a>', 'https://example.test');
        doc.select('title').remove();
        const other = org.jsoup.Jsoup.parse('<a href="/next">Next</a>');
        JSON.stringify([doc.title(), doc.body().selectFirst('a').attr('abs:href'),
            other.selectFirst('a').attr('abs:href'), other.selectFirst('a').hasAttr('abs:href')]);
        "#,
        "",
        "https://unused.test",
    ).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&output).unwrap(),
        json!(["", "https://example.test/next", "", false])
    );
}

#[test]
fn java_crypto_and_digest_utilities() {
    let script = r#"
        JSON.stringify({
            md5: java.md5Encode("hello"),
            md5_16: java.md5Encode16("hello"),
            b64Enc: java.base64Encode("hello world"),
            b64Dec: java.base64Decode("aGVsbG8gd29ybGQ=")
        });
    "#;
    let output = eval_js(script, "", "https://example.test").unwrap();
    let val: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(val["md5"], "5d41402abc4b2a76b9719d911017c592");
    assert_eq!(val["md5_16"], "bc4b2a76b9719d91");
    assert_eq!(val["b64Enc"], "aGVsbG8gd29ybGQ=");
    assert_eq!(val["b64Dec"], "hello world");
}

#[test]
fn java_pure_time_format_and_chapter_utilities() {
    let script = r#"
        JSON.stringify({
            utc: java.timeFormatUTC(0, "yyyy-MM-dd", 0),
            toNum: java.toNumChapter("第123章")
        });
    "#;
    let output = eval_js(script, "", "https://example.test").unwrap();
    let val: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(val["utc"], "1970-01-01");
    assert_eq!(val["toNum"], "第123章");
}

#[test]
fn java_chinese_convert_requires_registered_host_services() {
    // In Legado, chinese convert (t2s/s2t) relies on OpenCC / Android dictionary.
    // In reader-rust FFI, it delegates to host_services.
    // Without registered host service in the current process, calling t2s throws an explicit error.
    let script = r#"
        try {
            java.t2s("簡體字轉換");
            "ok";
        } catch (e) {
            e.message;
        }
    "#;
    let output = eval_js(script, "", "https://example.test").unwrap();
    assert!(
        output.contains("host services are not registered"),
        "Expected host services missing error, got: {output}"
    );
}
