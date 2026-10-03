//! JSON pure field scripts receive typed values with local string coercion.
use reader_parser::model::book_chapter::BookChapter;
use reader_parser::model::book_source::BookSource;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::{json, Value};

const BASE: &str = "https://json-field-value.test/";

fn chapters(rule: &str, item: Value) -> Vec<BookChapter> {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "JSON field values",
        "ruleToc": {
            "chapterList": "$.chapters", "chapterName": rule, "chapterUrl": "/read/1"
        }
    }))
    .unwrap();
    RuleEngine::new()
        .unwrap()
        .chapter_list(&source, &json!({"chapters": [item]}).to_string(), BASE)
        .0
}

#[test]
fn rule_local_names_do_not_shadow_the_coercion_setup() {
    let chapters = chapters(
        "@js:let result = '局部标题'; let Object = {}; let Symbol = {}; let JSON = {}; result",
        json!({"title": "原始标题"}),
    );
    assert_eq!(chapters.len(), 1);
    assert_eq!(chapters[0].title, "局部标题");
}

#[test]
fn both_pure_js_forms_receive_the_current_object() {
    for rule in ["@js:result.title", "<js>result.title</js>"] {
        let chapters = chapters(rule, json!({"title": "真实标题"}));
        assert_eq!(chapters.len(), 1);
        assert_eq!(chapters[0].title, "真实标题");
    }
}

#[test]
fn object_property_access_json_parse_and_string_coercion_agree() {
    let chapters = chapters(
        r#"<js>JSON.stringify({
        type: typeof result,
        direct: result.title,
        parsed: JSON.parse(result).title,
        stringified: String(result),
        keys: Object.keys(result)
    })</js>"#,
        json!({"title": "中文标题"}),
    );
    assert_eq!(chapters.len(), 1);
    let value: Value = serde_json::from_str(&chapters[0].title).unwrap();
    assert_eq!(
        value,
        json!({
            "type": "object", "direct": "中文标题", "parsed": "中文标题",
            "stringified": "{\"title\":\"中文标题\"}", "keys": ["title"]
        })
    );
}

#[test]
fn arrays_keep_array_identity_and_json_parse_compatibility() {
    let chapters = chapters("@js:JSON.stringify([Array.isArray(result), result[0], JSON.parse(result)[1], String(result)])", json!(["甲", "乙"]));
    assert_eq!(chapters.len(), 1);
    let value: Value = serde_json::from_str(&chapters[0].title).unwrap();
    assert_eq!(value, json!([true, "甲", "乙", "[\"甲\",\"乙\"]"]));
}

#[test]
fn primitive_json_values_keep_their_native_types() {
    for (item, expected) in [
        (json!("文本"), json!(["string", "文本"])),
        (json!(42), json!(["number", 42])),
        (json!(true), json!(["boolean", true])),
        (Value::Null, json!(["object", Value::Null])),
    ] {
        let chapters = chapters("@js:JSON.stringify([typeof result, result])", item);
        assert_eq!(chapters.len(), 1);
        let value: Value = serde_json::from_str(&chapters[0].title).unwrap();
        assert_eq!(value, expected);
    }
}

#[test]
fn typed_field_js_output_still_runs_inline_replacement() {
    let chapters = chapters(
        "<js>result.title + '尾部'</js>##尾部##修正",
        json!({"title": "正文"}),
    );
    assert_eq!(chapters.len(), 1);
    assert_eq!(chapters[0].title, "正文修正");
}

#[test]
fn combined_selector_js_keeps_string_input() {
    for (rule, expected) in [
        (
            "$.title&&$.author@js:typeof result + ':' + result",
            "string:标题\n作者",
        ),
        (
            "$.missing||$.title<js>typeof result + ':' + result</js>",
            "string:标题",
        ),
    ] {
        let chapters = chapters(rule, json!({"title": "标题", "author": "作者"}));
        assert_eq!(chapters.len(), 1);
        assert_eq!(chapters[0].title, expected);
    }
}

#[test]
fn trailing_selector_js_keeps_string_input() {
    let chapters = chapters(
        "$.title<js>typeof result + ':' + result</js>",
        json!({"title": "标题"}),
    );
    assert_eq!(chapters.len(), 1);
    assert_eq!(chapters[0].title, "string:标题");
}

#[test]
fn failing_pure_js_does_not_turn_original_json_into_a_chapter_title() {
    let chapters = chapters(
        "<js>throw new Error('field failed')</js>",
        json!({"title": "不可回退为JSON"}),
    );
    // JSON TOC parsing intentionally retains entries with an empty title.
    assert_eq!(chapters.len(), 1);
    assert_eq!(chapters[0].title, "");
}

#[test]
fn virtual_search_url_preserves_metadata_from_current_item() {
    use base64::Engine;
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "Virtual metadata",
        "ruleSearch": {
            "bookList": "$.data", "name": "$.name",
            "bookUrl": "<js>'data:;base64,' + java.base64Encode(JSON.stringify({book_id: result.book_id, sources: result.source, tab: '小说', url: ''})) + ',{\"type\":\"qingtian\"}'</js>"
        }
    })).unwrap();
    let books = RuleEngine::new().unwrap().search_books(
        &source,
        &json!({"data":[{
            "name": "天渊", "book_id": "b1001", "source": "番茄"
        }]})
        .to_string(),
        BASE,
    );
    assert_eq!(books.len(), 1);
    let url = &books[0].book_url;
    let (encoded, options) = url
        .strip_prefix("data:;base64,")
        .unwrap()
        .split_once(',')
        .unwrap();
    assert_eq!(options, r#"{"type":"qingtian"}"#);
    let payload = base64::prelude::BASE64_STANDARD.decode(encoded).unwrap();
    let value: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(
        value,
        json!({"book_id": "b1001", "sources": "番茄", "tab": "小说", "url": ""})
    );
}
