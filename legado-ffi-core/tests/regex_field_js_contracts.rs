//! AllInOne capture fields share JS evaluation in TOC and search rules.
use reader_parser::model::book_source::BookSource;
use reader_parser::parser::js::eval_js;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::json;

const BASE: &str = "https://regex-fields.test/book/42/";

#[test]
fn java_put_accepts_regex_match_array_as_string_value() {
    let result = eval_js(
        "var bid = baseUrl.match(/\\d+/); java.put('regex_field_bid', bid); java.get('regex_field_bid')",
        "", BASE,
    ).expect("String-valued java.put must accept the match array used by Qidian");
    assert_eq!(result, "42");
}

#[test]
fn explicit_regex_mode_wins_over_valid_json_body() {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "Explicit regex over JSON",
        "ruleToc": {
            "chapterList": ":\"id\":(\\d+),\"name\":\"([^\"]+)\"",
            "chapterName": "$2",
            "chapterUrl": "/read/$1"
        }
    }))
    .unwrap();
    let (chapters, _) =
        RuleEngine::new()
            .unwrap()
            .chapter_list(&source, r#"[{"id":7,"name":"甲"}]"#, BASE);
    assert_eq!(chapters.len(), 1);
    assert_eq!(chapters[0].title, "甲");
    assert_eq!(chapters[0].url, "https://regex-fields.test/read/7");
}

#[test]
fn toc_pure_js_receives_capture_array_and_trailing_js_receives_text() {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "Capture stage inputs",
        "ruleToc": {
            "chapterList": ":(\\d+)\\|([^\\n]+)",
            "chapterName": "$2@js:result + '章'",
            "chapterUrl": "@js:'/read/' + result[1]",
            "updateTime": "<js>result[0]</js>",
            "isVip": "$1@js:result === '7'"
        }
    }))
    .unwrap();
    let (chapters, _) = RuleEngine::new()
        .unwrap()
        .chapter_list(&source, "7|甲\n8|乙", BASE);
    assert_eq!(chapters.len(), 2);
    assert_eq!(chapters[0].title, "甲章");
    assert_eq!(chapters[0].url, "https://regex-fields.test/read/7");
    assert_eq!(chapters[0].tag.as_deref(), Some("7|甲"));
    assert!(chapters[0].is_vip);
    assert!(!chapters[1].is_vip);
}

#[test]
fn js_output_replacement_group_is_not_a_toc_capture() {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "Capture and replacement namespaces",
        "ruleToc": {
            "chapterList": ":(\\d+)\\|([^\\n]+)",
            "chapterName": "$2@js:result + '尾部'##(尾部)##[$1]",
            "chapterUrl": "/read/$1"
        }
    }))
    .unwrap();
    let (chapters, _) = RuleEngine::new()
        .unwrap()
        .chapter_list(&source, "7|甲", BASE);
    assert_eq!(chapters.len(), 1);
    assert_eq!(chapters[0].title, "甲[尾部]");
    assert_eq!(chapters[0].url, "https://regex-fields.test/read/7");
}

#[test]
fn regex_search_fields_use_same_capture_js_pipeline() {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "Regex search JS",
        "ruleSearch": {
            "bookList": ":(\\d+)\\|([^\\n]+)",
            "name": "$2@js:result + '书'",
            "bookUrl": "@js:'/book/' + result[1]",
            "author": "$0"
        }
    }))
    .unwrap();
    let books = RuleEngine::new()
        .unwrap()
        .search_books(&source, "7|甲", BASE);
    assert_eq!(books.len(), 1);
    assert_eq!(books[0].name, "甲书");
    assert_eq!(books[0].book_url, "https://regex-fields.test/book/7");
    assert_eq!(books[0].author, "$0", "Literal $0 remains compatible");
}

#[test]
fn non_js_capture_fields_keep_existing_replacement_behavior() {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "Regex capture compatibility",
        "ruleToc": {
            "chapterList": ":(\\d+)\\|([^\\n]+)",
            "chapterName": "$2##甲##乙",
            "chapterUrl": "/read/$1"
        }
    }))
    .unwrap();
    let (chapters, _) = RuleEngine::new()
        .unwrap()
        .chapter_list(&source, "7|甲", BASE);
    assert_eq!(chapters.len(), 1);
    assert_eq!(chapters[0].title, "乙");
    assert_eq!(chapters[0].url, "https://regex-fields.test/read/7");
}
