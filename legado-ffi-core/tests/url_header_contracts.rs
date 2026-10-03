//! Regression tests for URL rule compilation, header parsing resilience,
//! option handling, and encoding contracts.
use reader_parser::crawler::analyze_url;
use reader_parser::model::book_source::BookSource;
use serde_json::json;
use ureq::http::Method;

const BASE: &str = "https://fixture.test";

fn source_with_header(header: &str) -> BookSource {
    serde_json::from_value(json!({
        "bookSourceName": "Header resilience fixture",
        "bookSourceUrl": BASE,
        "header": header
    }))
    .unwrap()
}

#[test]
fn single_quote_header_preserves_commas_in_user_agent() {
    let source = source_with_header(
        "{'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64), CustomBot/1.0', 'X-Tag': 'ok'}",
    );
    let spec = analyze_url("/page", "", 1, BASE, &source).unwrap();

    let ua = spec
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .map(|(_, v)| v.as_str());
    assert_eq!(
        ua,
        Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64), CustomBot/1.0"),
        "User-Agent containing comma must not be fragmented by loose parsing"
    );

    let tag = spec
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-tag"))
        .map(|(_, v)| v.as_str());
    assert_eq!(tag, Some("ok"));
}

#[test]
fn single_quote_header_preserves_url_scheme_and_multiple_colons() {
    let source = source_with_header(
        "{'Referer': 'https://example.com/books', 'X-Token': 'token:part1:part2'}",
    );
    let spec = analyze_url("/page", "", 1, BASE, &source).unwrap();

    let referer = spec
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("referer"))
        .map(|(_, v)| v.as_str());
    assert_eq!(
        referer,
        Some("https://example.com/books"),
        "URL in header value must not lose its scheme prefix due to colon splitting"
    );

    let token = spec
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-token"))
        .map(|(_, v)| v.as_str());
    assert_eq!(
        token,
        Some("token:part1:part2"),
        "Header value with multiple colons must be preserved completely"
    );
}

#[test]
fn proxy_in_headers_is_extracted_and_removed_from_request_headers() {
    let source = source_with_header(
        r#"{"User-Agent": "Bot/1.0", "proxy": "http://127.0.0.1:8888", "X-Key": "v"}"#,
    );
    let spec = analyze_url("/page", "", 1, BASE, &source).unwrap();

    assert_eq!(
        spec.proxy.as_deref(),
        Some("http://127.0.0.1:8888"),
        "proxy header should be extracted to proxy field"
    );
    let has_proxy_header = spec
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("proxy"));
    assert!(
        !has_proxy_header,
        "proxy should be removed from HTTP request headers"
    );
}

#[test]
fn dynamic_page_choices_stay_at_last_choice_when_page_exceeds_bounds() {
    let source = source_with_header("");
    let rule = "/books?page=<1,2,3>";

    let p1 = analyze_url(rule, "", 1, BASE, &source).unwrap();
    assert_eq!(p1.url, format!("{BASE}/books?page=1"));

    let p2 = analyze_url(rule, "", 2, BASE, &source).unwrap();
    assert_eq!(p2.url, format!("{BASE}/books?page=2"));

    let p3 = analyze_url(rule, "", 3, BASE, &source).unwrap();
    assert_eq!(p3.url, format!("{BASE}/books?page=3"));

    let p4 = analyze_url(rule, "", 4, BASE, &source).unwrap();
    assert_eq!(
        p4.url,
        format!("{BASE}/books?page=3"),
        "page beyond choice count must stay at last choice"
    );

    let p10 = analyze_url(rule, "", 10, BASE, &source).unwrap();
    assert_eq!(
        p10.url,
        format!("{BASE}/books?page=3"),
        "large page index must stay at last choice"
    );
}

#[test]
fn url_options_with_raw_unescaped_control_characters_in_json() {
    let source = source_with_header("");
    // Note: raw newline byte 0x0A and tab byte 0x09 embedded inside json string
    let rule = "/api,{\"method\":\"POST\",\"body\":\"first\nsecond\tthird\",\"headers\":{\"X-Custom\":\"value\"}}";

    let spec = analyze_url(rule, "", 1, BASE, &source);
    assert!(
        spec.is_ok(),
        "URL options containing unescaped raw newlines/tabs should not cause parsing rejection: {:?}",
        spec.err()
    );
    let spec = spec.unwrap();
    assert_eq!(spec.method, Method::POST);
    // Without Content-Type, non-JSON/XML bodies follow form encoding.
    assert_eq!(spec.body.as_deref(), Some("first%0Asecond%09third"));
    assert!(spec
        .headers
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("content-type")
            && value == "application/x-www-form-urlencoded"));
    let custom = spec
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-custom"))
        .map(|(_, v)| v.as_str());
    assert_eq!(custom, Some("value"));
}

#[test]
fn url_js_segments_and_templates_evaluate_with_bindings() {
    let source = source_with_header("");
    let rule = "/search/<js>key + '-p' + page</js>/list?q={{key}}";

    let spec = analyze_url(rule, "novel", 2, BASE, &source).unwrap();
    // Ordinary suffixes overwrite the JS result unless they use @result.
    assert_eq!(spec.url, format!("{BASE}/list?q=novel"));
}

#[test]
fn url_inline_templates_preserve_surrounding_path() {
    let source = source_with_header("");
    let rule = "/search/{{key + '-p' + page}}/list?q={{key}}";
    let spec = analyze_url(rule, "novel", 2, BASE, &source).unwrap();
    assert_eq!(spec.url, format!("{BASE}/search/novel-p2/list?q=novel"));
}

#[test]
fn url_js_segments_compose_through_explicit_result() {
    let source = source_with_header("");
    let rule = "/search/<js>result + key + '-p' + page</js>@result/list?q={{key}}";
    let spec = analyze_url(rule, "novel", 2, BASE, &source).unwrap();
    assert_eq!(spec.url, format!("{BASE}/search/novel-p2/list?q=novel"));
}

#[test]
fn explicit_content_type_preserves_raw_control_characters() {
    let source = source_with_header("");
    let options = json!({
        "method": "POST",
        "body": "first\nsecond\tthird",
        "headers": {"Content-Type": "text/plain; charset=utf-8"}
    });
    let spec = analyze_url(&format!("/api,{options}"), "", 1, BASE, &source).unwrap();
    assert_eq!(spec.body.as_deref(), Some("first\nsecond\tthird"));
    assert!(spec
        .headers
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("content-type")
            && value == "text/plain; charset=utf-8"));
}

#[test]
fn form_body_encodes_raw_control_characters_in_values() {
    let source = source_with_header("");
    let options = json!({"method": "POST", "body": "text=first\nsecond\tthird"});
    let spec = analyze_url(&format!("/api,{options}"), "", 1, BASE, &source).unwrap();
    assert_eq!(spec.body.as_deref(), Some("text=first%0Asecond%09third"));
}

#[test]
fn form_encoding_distinguishes_bare_keys_empty_values_and_equals_in_values() {
    let source = source_with_header("");
    for (body, expected) in [
        ("裸字段", "%E8%A3%B8%E5%AD%97%E6%AE%B5"),
        ("裸字段=", "%E8%A3%B8%E5%AD%97%E6%AE%B5="),
        (
            "裸字段=一=二",
            "%E8%A3%B8%E5%AD%97%E6%AE%B5=%E4%B8%80%3D%E4%BA%8C",
        ),
        (
            "裸字段&empty=&value=a=b",
            "%E8%A3%B8%E5%AD%97%E6%AE%B5&empty=&value=a%3Db",
        ),
    ] {
        let options = json!({"method": "POST", "body": body});
        let spec = analyze_url(&format!("/api,{options}"), "", 1, BASE, &source).unwrap();
        assert_eq!(spec.body.as_deref(), Some(expected), "{body}");
    }
}

#[test]
fn legacy_url_options_support_nested_keys_quotes_and_control_characters() {
    let source = source_with_header("");
    let rule = r#"/api,{method:'POST', headers:{'Content-Type':'text/plain', 'X-Note':'book, "quoted": it\'s'}, body:'中文\nline\tend\\path', retry:1}"#;
    let spec = analyze_url(rule, "", 1, BASE, &source).unwrap();
    assert_eq!(spec.method, Method::POST);
    assert_eq!(spec.body.as_deref(), Some("中文\nline\tend\\path"));
    assert!(spec
        .headers
        .iter()
        .any(|(name, value)| name == "X-Note" && value == "book, \"quoted\": it's"));
    let spec = analyze_url(
        "/api,{method:'POST',body:'first\nsecond\tthird'}",
        "",
        1,
        BASE,
        &source,
    )
    .unwrap();
    assert_eq!(spec.body.as_deref(), Some("first%0Asecond%09third"));
}

#[test]
fn shuba69_single_quote_search_options_encode_gbk_post_body() {
    let source = source_with_header("");
    let rule = "/modules/article/search.php,{'charset':'gbk','body':'searchkey={{key}}&searchtype=all','method':'POST'}";
    let spec = analyze_url(rule, "诡秘之主", 1, "https://69shuba.cx", &source).unwrap();
    assert_eq!(spec.url, "https://69shuba.cx/modules/article/search.php");
    assert_eq!(spec.method, Method::POST);
    assert_eq!(
        spec.body.as_deref(),
        Some("searchkey=%B9%EE%C3%D8%D6%AE%D6%F7&searchtype=all")
    );
}

#[test]
fn legacy_url_options_reject_trailing_commas_and_executable_values() {
    let source = source_with_header("");
    for options in [
        "{method:'POST',}",
        "{headers:{'X-Note':'ok',}}",
        "{body:'unterminated}",
        "{method:'POST' body:'missing comma'}",
        "{method:(function(){return 'POST'})()}",
        "{method:'POST'} trailing",
    ] {
        assert!(
            analyze_url(&format!("/api,{options}"), "", 1, BASE, &source).is_err(),
            "{options}"
        );
    }
}

#[test]
fn non_utf8_charset_gbk_encodes_chinese_query_parameters() {
    let source = source_with_header("");
    let rule = "/search?key={{key}},{\"charset\":\"gbk\"}";

    let spec = analyze_url(rule, "小说", 1, BASE, &source).unwrap();
    // In GBK: 小 = 0xD0 0xA1 (%D0%A1), 说 = 0xCB 0xB5 (%CB%B5)
    assert!(
        spec.url.contains("%D0%A1%CB%B5") || spec.url.contains("%d0%a1%cb%b5"),
        "q parameter with charset gbk should be percent-encoded as GBK bytes, got: {}",
        spec.url
    );
}
