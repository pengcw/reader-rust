use reader_parser::crawler::analyze_url;
use reader_parser::model::book::Book;
use reader_parser::model::book_source::{book_source_from_value, BookSource};
use reader_parser::model::rule::{SearchRule, TocRule};
use reader_parser::parser::rule_engine::RuleEngine;
use reader_parser::parser::{html, jsonpath};
use serde_json::json;
use ureq::http::Method;

#[test]
fn book_source_deserializes_stringified_rule_objects() {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceName": "String rules",
        "bookSourceUrl": "https://example.test",
        "ruleSearch": "{\"bookList\":\".item\",\"name\":\".title@text\"}"
    }))
    .unwrap();

    let rule = source.rule_search.unwrap();
    assert_eq!(rule.book_list.as_deref(), Some(".item"));
    assert_eq!(rule.name.as_deref(), Some(".title@text"));
}

#[test]
fn legacy_book_source_fields_are_migrated_to_current_shape() {
    let source = book_source_from_value(json!({
        "bookSourceName": "Legacy",
        "bookSourceUrl": "https://legacy.example",
        "httpUserAgent": "LegacyUA",
        "ruleSearchUrl": "/search?keyword=searchKey&page=searchPage@Header:{\"X-Legacy\":\"1\"}",
        "ruleSearchList": ".item",
        "ruleSearchName": ".name@text",
        "ruleSearchAuthor": ".author@text",
        "ruleBookName": "h1@text",
        "ruleChapterList": "a",
        "ruleChapterName": "a@text",
        "ruleContentUrl": "a@href",
        "ruleBookContent": "#content@text"
    }))
    .unwrap();

    assert_eq!(
        source.header.as_deref(),
        Some("{\"User-Agent\":\"LegacyUA\"}")
    );
    assert_eq!(
        source.search_url.as_deref(),
        Some("/search?keyword={{key}}&page={{page}},{\"headers\":{\"X-Legacy\":\"1\"}}")
    );
    assert_eq!(
        source
            .rule_search
            .as_ref()
            .and_then(|rule| rule.book_list.as_deref()),
        Some(".item")
    );
    assert_eq!(
        source
            .rule_book_info
            .as_ref()
            .and_then(|rule| rule.name.as_deref()),
        Some("h1@text")
    );
    assert_eq!(
        source
            .rule_toc
            .as_ref()
            .and_then(|rule| rule.chapter_url.as_deref()),
        Some("a@href")
    );
    assert_eq!(
        source
            .rule_content
            .as_ref()
            .and_then(|rule| rule.content.as_deref()),
        Some("#content@text")
    );
}

#[test]
fn book_source_accepts_numeric_metadata_as_strings() {
    let source = book_source_from_value(json!({
        "bookSourceName": "String metadata",
        "bookSourceUrl": "https://metadata.example",
        "lastUpdateTime": "1778603539900",
        "respondTime": "180000"
    }))
    .unwrap();

    assert_eq!(source.last_update_time, Some(1_778_603_539_900));
    assert_eq!(source.respond_time, Some(180_000));
}

#[test]
fn optional_i64_metadata_accepts_float_encoded_integers() {
    // Some 32-bit hosts serialize millisecond timestamps with a decimal/exponent.
    let source = book_source_from_value(serde_json::from_str(r#"{
        "bookSourceUrl": "https://metadata.example",
        "lastUpdateTime": 1.7786035399e12,
        "respondTime": 180000.0
    }"#).unwrap()).unwrap();
    assert_eq!(source.last_update_time, Some(1_778_603_539_900));
    assert_eq!(source.respond_time, Some(180_000));

    let book: Book = serde_json::from_str(
        r#"{"durChapterTime":1.7786035399e12,"lastCheckTime":180000.0,"group":4.0}"#,
    ).unwrap();
    assert_eq!(book.dur_chapter_time, Some(1_778_603_539_900));
    assert_eq!(book.last_check_time, Some(180_000));
    assert_eq!(book.group, Some(4));
}

#[test]
fn optional_i64_metadata_does_not_wrap_or_saturate_invalid_numbers() {
    let source = book_source_from_value(json!({
        "bookSourceUrl": "https://metadata.example",
        "lastUpdateTime": u64::MAX,
        "respondTime": 1e200
    })).unwrap();
    assert_eq!(source.last_update_time, None);
    assert_eq!(source.respond_time, None);

    let book: Book = serde_json::from_value(json!({
        "durChapterTime": -1e200,
        "lastCheckTime": u64::MAX,
        "group": 1.25
    })).unwrap();
    assert_eq!(book.dur_chapter_time, None);
    assert_eq!(book.last_check_time, None);
    assert_eq!(book.group, None);
}

#[test]
fn url_analyzer_supports_inline_js_page_choices_headers_and_response_type() {
    let source = BookSource {
        book_source_name: "URL compat".to_string(),
        book_source_url: "https://a.test/root/".to_string(),
        header: Some("@js:JSON.stringify({'X-Token':'ok'})".to_string()),
        ..Default::default()
    };

    let spec = analyze_url(
        "/search?q={{key}}&page=<1,2,3>,{\"headers\":{\"Referer\":\"https://a.test\"},\"retry\":3,\"type\":\"hex\"}",
        "斗破",
        2,
        &source.book_source_url,
        &source,
    )
    .unwrap();

    assert_eq!(spec.method, Method::GET);
    assert_eq!(
        spec.url,
        "https://a.test/search?q=%E6%96%97%E7%A0%B4&page=2"
    );
    assert_eq!(spec.retry, 3);
    assert_eq!(spec.response_type.as_deref(), Some("hex"));
    assert!(spec
        .headers
        .iter()
        .any(|(name, value)| name == "X-Token" && value == "ok"));
    assert!(spec
        .headers
        .iter()
        .any(|(name, value)| name == "Referer" && value == "https://a.test"));
    assert!(spec
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("user-agent")));
}

#[test]
fn url_analyzer_encodes_get_query_with_declared_charset() {
    let source = BookSource {
        book_source_name: "GBK query".to_string(),
        book_source_url: "https://b.faloo.com".to_string(),
        ..Default::default()
    };

    let spec = analyze_url(
        "/l/0/1.html?t=1&k={{key}},{\"charset\":\"gbk\"}",
        "斗破",
        1,
        &source.book_source_url,
        &source,
    )
    .unwrap();

    assert_eq!(spec.charset.as_deref(), Some("gbk"));
    assert!(
        spec.url.ends_with("/l/0/1.html?t=1&k=%B6%B7%C6%C6"),
        "{}",
        spec.url
    );
}

#[test]
fn url_analyzer_accepts_raw_newlines_in_option_strings() {
    let source = BookSource {
        book_source_name: "Relaxed options".to_string(),
        book_source_url: "https://options.example".to_string(),
        ..Default::default()
    };

    let spec = analyze_url(
        r#"https://options.example/post,{
  "method": "POST",
  "headers": {"Content-Type": "text/plain"},
  "body": "line1
line2"
}"#,
        "",
        1,
        &source.book_source_url,
        &source,
    )
    .unwrap();

    assert_eq!(spec.method, Method::POST);
    assert_eq!(spec.body.as_deref(), Some("line1\nline2"));
}

#[test]
fn url_analyzer_supports_single_brace_key_and_page_placeholders() {
    let source = BookSource {
        book_source_name: "Legacy placeholders".to_string(),
        book_source_url: "https://m.cuoceng.com".to_string(),
        ..Default::default()
    };

    let spec = analyze_url(
        "/book/so/{key}/{page}.html",
        "星门",
        3,
        &source.book_source_url,
        &source,
    )
    .unwrap();

    assert_eq!(
        spec.url,
        "https://m.cuoceng.com/book/so/%E6%98%9F%E9%97%A8/3.html"
    );
}

#[test]
fn html_rule_split_ignores_delimiters_inside_attribute_selectors() {
    let doc = html::parse_document(r#"<div data-x="a&&b">Bad</div><span>Good</span>"#);

    assert_eq!(
        html::select_text_list(&doc, r#"div[data-x="a&&b"]@text||span@text"#),
        vec!["Bad".to_string()]
    );
}

#[test]
fn jsonpath_supports_embedded_path_templates() {
    let value = json!({"data":{"name":"书名","author":"作者"}});

    assert_eq!(
        jsonpath::jsonpath_first_string(&value, "作者：{$.data.author}"),
        Some("作者：作者".to_string())
    );
}

#[test]
fn chapter_list_strips_css_mode_prefix() {
    let engine = RuleEngine::new().unwrap();
    let source = BookSource {
        book_source_name: "TOC".to_string(),
        book_source_url: "https://toc.example".to_string(),
        rule_toc: Some(TocRule {
            chapter_list: Some("@css:.dirList li a".to_string()),
            chapter_name: Some("text".to_string()),
            chapter_url: Some("href".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let (chapters, _) = engine.chapter_list(
        &source,
        r#"<ul class="dirList"><li><a href="/c1.html">第一章</a></li></ul>"#,
        "https://toc.example/book/",
    );

    assert_eq!(chapters.len(), 1);
    assert_eq!(chapters[0].title, "第一章");
    assert_eq!(chapters[0].url, "https://toc.example/c1.html");
}

#[test]
fn all_in_one_regex_keeps_group_zero_literal() {
    let source = BookSource {
        book_source_name: "Regex".to_string(),
        book_source_url: "https://regex.example".to_string(),
        rule_search: Some(SearchRule {
            book_list: Some(r#":<a href="([^"]+)">([^<]+)</a>"#.to_string()),
            name: Some("$0".to_string()),
            book_url: Some("$1".to_string()),
            author: Some("$2".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let results = RuleEngine::new().unwrap().search_books(
        &source,
        r#"<li><a href="/1">第一章</a></li>"#,
        "https://regex.example",
    );

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "$0");
    assert_eq!(results[0].book_url, "https://regex.example/1");
    assert_eq!(results[0].author, "第一章");
}

#[test]
fn explore_books_falls_back_to_search_rule_when_rule_explore_is_empty() {
    let source = BookSource {
        book_source_name: "Explore fallback".to_string(),
        book_source_url: "https://fallback.example".to_string(),
        rule_explore: Some(SearchRule::default()),
        rule_search: Some(SearchRule {
            book_list: Some("$.data[*]".to_string()),
            name: Some("$.novelName".to_string()),
            author: Some("$.authorName".to_string()),
            book_url: Some("/novel/{{$.novelId}}".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let books = RuleEngine::new().unwrap().explore_books(
        &source,
        r#"{"data":[{"novelName":"书海结果","authorName":"作者","novelId":"abc"}]}"#,
        "https://fallback.example",
    );

    assert_eq!(books.len(), 1);
    assert_eq!(books[0].name, "书海结果");
    assert_eq!(books[0].book_url, "https://fallback.example/novel/abc");
}
