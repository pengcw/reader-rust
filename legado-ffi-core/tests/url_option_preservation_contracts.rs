//! Preserve request options on extracted links, without contaminating the base URL.
use reader_parser::crawler::analyze_url;
use reader_parser::model::book_source::BookSource;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::json;

const BASE: &str = "https://fixture.test/books/one/";

fn source() -> BookSource {
    serde_json::from_value(
        json!({"bookSourceUrl":"https://fixture.test", "bookSourceName":"URL option fixture",
        "ruleSearch":{"bookList":"a", "name":"text", "bookUrl":"href"},
        "ruleBookInfo":{"name":"h1@text", "tocUrl":"a@href"},
        "ruleToc":{"chapterList":"li", "chapterName":"a@text", "chapterUrl":"a@href"}}),
    )
    .unwrap()
}

#[test]
fn relative_toc_options_survive_resolution_and_url_analysis() {
    let source = source();
    let book = RuleEngine::new().unwrap().book_info(
        &source,
        r#"<h1>Book</h1><a href='/toc/1/,{"webView":true}'>TOC</a>"#,
        BASE,
        BASE,
    );
    let toc = book.toc_url.unwrap();
    assert_eq!(toc, r#"https://fixture.test/toc/1/,{"webView":true}"#);
    let spec = analyze_url(&toc, "", 1, BASE, &source).unwrap();
    assert_eq!(spec.url, "https://fixture.test/toc/1/");
}

#[test]
fn chapter_links_keep_single_quote_and_nested_options_exactly() {
    let source = source();
    let html = r#"<ul><li><a href="../chapter/1, {'webView':true,'headers':{'X-Note':'a,b:c'}}">Chapter</a></li></ul>"#;
    let (chapters, _) = RuleEngine::new().unwrap().chapter_list(&source, html, BASE);
    assert_eq!(chapters.len(), 1);
    assert_eq!(
        chapters[0].url,
        "https://fixture.test/books/chapter/1, {'webView':true,'headers':{'X-Note':'a,b:c'}}"
    );
    let spec = analyze_url(&chapters[0].url, "", 1, BASE, &source).unwrap();
    assert_eq!(spec.url, "https://fixture.test/books/chapter/1");
    assert!(spec
        .headers
        .iter()
        .any(|(key, value)| key == "X-Note" && value == "a,b:c"));
}

#[test]
fn relative_search_urls_keep_non_webview_options_and_ignore_base_options() {
    let source = source();
    let books = RuleEngine::new().unwrap().search_books(
        &source,
        r#"<a href='../detail/1?x=a,b#part,{"method":"POST","body":"x=1"}'>Book</a>"#,
        &format!("{BASE},{{\"webView\":true}}"),
    );
    assert_eq!(books.len(), 1);
    assert_eq!(
        books[0].book_url,
        r#"https://fixture.test/books/detail/1?x=a,b#part,{"method":"POST","body":"x=1"}"#
    );
}

#[test]
fn ordinary_commas_queries_and_encoded_braces_are_not_options() {
    let source = source();
    let books = RuleEngine::new().unwrap().search_books(
        &source,
        "<a href='../detail/a,b?q=a,b%2C%7Bvalue%7D#part'>Book</a>",
        BASE,
    );
    assert_eq!(
        books[0].book_url,
        "https://fixture.test/books/detail/a,b?q=a,b%2C%7Bvalue%7D#part"
    );
}

#[test]
fn absolute_and_scheme_relative_targets_keep_options() {
    for target in [
        r#"https://other.test/chapter,{"webView":true}"#,
        r#"//other.test/chapter,{"webView":true}"#,
    ] {
        let html = format!("<li><a href='{target}'>Chapter</a></li>");
        let (chapters, _) = RuleEngine::new()
            .unwrap()
            .chapter_list(&source(), &html, BASE);
        assert_eq!(
            chapters[0].url,
            r#"https://other.test/chapter,{"webView":true}"#
        );
    }
}

#[test]
fn data_metadata_url_keeps_payload_and_options_without_resolution() {
    let target = r#"data:;base64,eyJpZCI6MX0=,{"type":"virtual","webView":true}"#;
    let html = format!("<a href='{target}'>Virtual book</a>");
    let books = RuleEngine::new()
        .unwrap()
        .search_books(&source(), &html, BASE);
    assert_eq!(books[0].book_url, target);
}

#[test]
fn regexp_appended_options_survive_toc_and_chapter_extraction() {
    let mut source = source();
    source.rule_book_info.as_mut().unwrap().toc_url =
        Some(r#"a@href##$##,{"webView":true}"#.into());
    source.rule_toc.as_mut().unwrap().chapter_url = Some(r#"a@href##$##,{"webView":true}"#.into());
    let engine = RuleEngine::new().unwrap();
    let book = engine.book_info(
        &source,
        "<h1>Book</h1><a href='/toc/1/'>TOC</a>",
        BASE,
        BASE,
    );
    assert_eq!(
        book.toc_url.as_deref(),
        Some(r#"https://fixture.test/toc/1/,{"webView":true}"#)
    );
    let (chapters, _) =
        engine.chapter_list(&source, "<li><a href='/chapter/1/'>Chapter</a></li>", BASE);
    assert_eq!(
        chapters[0].url,
        r#"https://fixture.test/chapter/1/,{"webView":true}"#
    );
}
