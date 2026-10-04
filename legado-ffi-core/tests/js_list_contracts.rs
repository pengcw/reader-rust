//! Pure JS list dispatch and HTML-node field extraction through public APIs.
use reader_parser::model::book_source::BookSource;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::json;

const BASE: &str = "https://fixture.test";
const BODY: &str =
    "<ol><li><a href='/one'><h4>One</h4></a></li><li><a href='/two'><h4>Two</h4></a></li></ol>";

#[test]
fn pure_js_json_lists_use_all_supported_prefixes() {
    for list in [
        "@js:JSON.parse(result).items",
        "js:JSON.parse(result).items",
        "<js>JSON.parse(result).items</js>",
    ] {
        let source: BookSource = serde_json::from_value(json!({
            "bookSourceUrl": BASE, "bookSourceName": "JS list",
            "ruleSearch": {"bookList": list, "name": "name", "bookUrl": "url"}
        }))
        .unwrap();
        let books = RuleEngine::new().unwrap().search_books(
            &source,
            r#"{"items":[{"name":"One","url":"/one"}]}"#,
            BASE,
        );
        assert_eq!(books.len(), 1, "{list}");
        assert_eq!(books[0].name, "One", "{list}");
        assert_eq!(books[0].book_url, format!("{BASE}/one"), "{list}");
    }
}

#[test]
fn pure_js_html_node_lists_keep_css_field_context() {
    for list in [
        "@js:java.getElements('li')",
        "js:java.getElements('li')",
        "<js>java.getElements('li')</js>",
    ] {
        let source: BookSource = serde_json::from_value(json!({
            "bookSourceUrl": BASE, "bookSourceName": "JS nodes",
            "ruleSearch": {"bookList": list, "name": "h4@text", "bookUrl": "a@href"}
        }))
        .unwrap();
        let books = RuleEngine::new().unwrap().search_books(&source, BODY, BASE);
        assert_eq!(
            books.iter().map(|b| b.name.as_str()).collect::<Vec<_>>(),
            ["One", "Two"],
            "{list}"
        );
        assert_eq!(
            books
                .iter()
                .map(|b| b.book_url.as_str())
                .collect::<Vec<_>>(),
            ["https://fixture.test/one", "https://fixture.test/two"],
            "{list}"
        );
    }
}

#[test]
fn single_and_reordered_nodes_preserve_methods_and_item_identity() {
    for (list, expected) in [
        ("@js:java.getElement('li')", vec!["One"]),
        ("@js:java.getElements('li').reverse()", vec!["Two", "One"]),
        (
            "@js:java.getElements('li').filter(x => x.text() === 'Two')",
            vec!["Two"],
        ),
        ("@js:java.getElement('missing')", vec![]),
    ] {
        let source: BookSource = serde_json::from_value(json!({
            "bookSourceUrl": BASE, "bookSourceName": "JS nodes",
            "ruleSearch": {"bookList": list, "name": "h4@text", "bookUrl": "a@href"}
        }))
        .unwrap();
        let books = RuleEngine::new().unwrap().search_books(&source, BODY, BASE);
        assert_eq!(
            books.iter().map(|b| b.name.as_str()).collect::<Vec<_>>(),
            expected,
            "{list}"
        );
    }
}

#[test]
fn js_toc_nodes_keep_order_fields_and_next_page() {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE, "bookSourceName": "JS TOC",
        "ruleToc": {"chapterList": "@js:java.getElements('li').reverse()",
            "chapterName": "h4@text", "chapterUrl": "a@href", "nextTocUrl": "a.next@href"}
    }))
    .unwrap();
    let body = format!("{BODY}<a class='next' href='/next'>Next</a>");
    let (chapters, next) = RuleEngine::new()
        .unwrap()
        .chapter_list(&source, &body, BASE);
    assert_eq!(
        chapters
            .iter()
            .map(|c| c.title.as_str())
            .collect::<Vec<_>>(),
        ["Two", "One"]
    );
    assert_eq!(chapters.iter().map(|c| c.index).collect::<Vec<_>>(), [0, 1]);
    assert_eq!(chapters[0].url, format!("{BASE}/two"));
    assert_eq!(next, [format!("{BASE}/next")]);
}
