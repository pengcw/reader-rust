//! Minimal regression contracts isolating JS pipeline & execution issues:
//! - BUG-13: AllInOne regex TOC mode ignores field `@js:` scripts, treating them as relative URLs
//! - BUG-17: JSON fields must execute the selector after a leading JS stage;
//!   list prefixes have a separate, already-supported transformation path.
//! - Cross-rule variable propagation via `java.put` and `java.get`

use reader_parser::model::book_source::BookSource;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::json;

const BASE: &str = "https://vipreader.qidian.test/book/1234567/";

#[test]
fn all_in_one_regex_toc_evaluates_field_js_script_with_captures() {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "AllInOne JS Fixture",
        "ruleToc": {
            "chapterList": ":\"id\":(\\d+),.*?\"name\":\"(.*?)\"",
            "chapterName": "$2",
            "chapterUrl": "@js:var bid = baseUrl.match(/\\d+/)[0]; 'https://vipreader.qidian.test/chapter/' + bid + '/$1/'"
        }
    })).unwrap();

    let engine = RuleEngine::new().unwrap();
    let body = r#"
        window.chapters = [
            {"id":1001,"name":"第1章 穿越异界"},
            {"id":1002,"name":"第2章 绑定金手指"}
        ];
    "#;

    let (chapters, _) = engine.chapter_list(&source, body, BASE);
    assert_eq!(chapters.len(), 2, "Must extract 2 chapters via regex");
    assert_eq!(chapters[0].title, "第1章 穿越异界");
    assert_eq!(
        chapters[0].url,
        "https://vipreader.qidian.test/chapter/1234567/1001/",
        "Field rule chapterUrl with @js: must be evaluated as JavaScript instead of being resolved as a relative URL"
    );
    assert_eq!(
        chapters[1].url,
        "https://vipreader.qidian.test/chapter/1234567/1002/"
    );
}

#[test]
fn all_in_one_regex_toc_state_propagation_via_java_put_get() {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "AllInOne State Fixture",
        "ruleToc": {
            "chapterList": ":\"id\":(\\d+),.*?\"isVip\":(\\d+),.*?\"name\":\"(.*?)\"",
            "chapterName": "$3",
            "chapterUrl": "@js:java.put('last_vip', '$2'); '/chapter/$1'",
            "isVip": "@js:java.get('last_vip') === '1'"
        }
    }))
    .unwrap();

    let engine = RuleEngine::new().unwrap();
    let body = r#"
        [{"id":2001,"isVip":1,"name":"VIP章节"}]
    "#;

    let (chapters, _) = engine.chapter_list(&source, body, BASE);
    assert_eq!(chapters.len(), 1);
    assert_eq!(
        chapters[0].is_vip, true,
        "isVip must read state put by chapterUrl"
    );
}

#[test]
fn toc_list_rule_with_js_prefix_preserves_trailing_jsonpath_selector() {
    // In Qimao and similar sources:
    // chapterList: <js>java.put('agent', '1'); result</js>\n$.data.chapter_lists
    // `extract_js` must NOT discard `$.data.chapter_lists` after the </js> closing tag.
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "TOC JS Prefix Fixture",
        "ruleToc": {
            "chapterList": "<js>java.put('agent_mode', JSON.parse(result).data.mode); result</js>\n$.data.chapter_lists",
            "chapterName": "$.title",
            "chapterUrl": "@js:'https://api.test/read/' + java.get('agent_mode') + '/' + '{{$.cid}}'"
        }
    })).unwrap();

    let engine = RuleEngine::new().unwrap();
    let body = r#"{
        "data": {
            "mode": "fast",
            "chapter_lists": [
                {"cid": "c1", "title": "第1章 宗门大比"},
                {"cid": "c2", "title": "第2章 一鸣惊人"}
            ]
        }
    }"#;

    let (chapters, _) = engine.chapter_list(&source, body, BASE);
    assert_eq!(
        chapters.len(),
        2,
        "Rule with <js>...</js> prefix must not discard trailing JSONPath $.data.chapter_lists"
    );
    assert_eq!(chapters[0].title, "第1章 宗门大比");
    assert_eq!(chapters[0].url, "https://api.test/read/fast/c1");
    assert_eq!(chapters[1].url, "https://api.test/read/fast/c2");
}

#[test]
fn search_book_list_rule_with_js_prefix_preserves_trailing_css_selector() {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "Search JS Prefix Fixture",
        "ruleSearch": {
            "bookList": "<js>java.put('source_tag', 'verified'); result</js>\nclass.book-item",
            "name": "class.title@text",
            "bookUrl": "a@href"
        }
    }))
    .unwrap();

    let engine = RuleEngine::new().unwrap();
    let body = r#"
        <div class="container">
            <div class="book-item"><a href="/book/1"><span class="title">遮天</span></a></div>
            <div class="book-item"><a href="/book/2"><span class="title">完美世界</span></a></div>
        </div>
    "#;
    let books = engine.search_books(&source, body, BASE);
    assert_eq!(
        books.len(),
        2,
        "Search rule with <js>...</js> prefix must not discard trailing CSS class.book-item"
    );
    assert_eq!(books[0].name, "遮天");
    assert_eq!(books[1].name, "完美世界");
}

#[test]
fn qimao_toc_rule_without_crashing_js_lib_verifies_prefix_js_and_variable_put_get() {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "Qimao Rule Only",
        "ruleToc": {
            "chapterList": "<js>java.put('qm_agent', String(JSON.parse(String(result)).data.reader_type) == '4' ? '1' : '0'); result</js>\n$.data.chapter_lists",
            "chapterName": "title",
            "chapterUrl": "@js:'https://api.test/read/' + java.get('qm_agent') + '/' + '{{$.id}}'"
        }
    })).unwrap();

    let engine = RuleEngine::new().unwrap();
    let toc_json = r#"{
        "data": {
            "reader_type": 4,
            "chapter_lists": [
                {
                    "id": "c1001",
                    "title": "第1章 隐世神医",
                    "content_md5": "abc123md5",
                    "words": 3000
                }
            ]
        }
    }"#;
    let (chapters, _) = engine.chapter_list(&source, toc_json, BASE);
    assert_eq!(
        chapters.len(),
        1,
        "Must extract 1 chapter from $.data.chapter_lists"
    );
    assert_eq!(chapters[0].title, "第1章 隐世神医");
    assert_eq!(chapters[0].url, "https://api.test/read/1/c1001");
}

#[test]
fn field_rule_with_js_prefix_preserves_trailing_jsonpath_selector() {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "Field JS Prefix Fixture",
        "ruleToc": {
            "chapterList": "$.chapters",
            "chapterName": "<js>java.put('seen', '1'); result</js>$.title",
            "chapterUrl": "$.url"
        }
    }))
    .unwrap();

    let engine = RuleEngine::new().unwrap();
    let body = r#"{
        "chapters": [
            {"title": "第一章 剑起", "url": "/read/1"}
        ]
    }"#;

    let (chapters, _) = engine.chapter_list(&source, body, BASE);
    assert_eq!(chapters.len(), 1);
    assert_eq!(
        chapters[0].title, "第一章 剑起",
        "Field rule with <js> prefix should not have its selector truncated"
    );
}
