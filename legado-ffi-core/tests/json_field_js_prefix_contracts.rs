//! JSON field JS stages must feed their output into the following selector.
use reader_parser::model::book_source::BookSource;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::{json, Value};

fn chapter_title(rule: &str, item: Value) -> String {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": "https://field-prefix.test/",
        "bookSourceName": "JSON field stages",
        "ruleToc": {
            "chapterList": "$.chapters",
            "chapterName": rule,
            "chapterUrl": "$.url"
        }
    }))
    .unwrap();
    let body = json!({"chapters": [item]}).to_string();
    let engine = RuleEngine::new().unwrap();
    let (chapters, _) = engine.chapter_list(&source, &body, "https://field-prefix.test/");
    assert_eq!(chapters.len(), 1);
    assert_eq!(chapters[0].url, "https://field-prefix.test/read/1");
    chapters[0].title.clone()
}

fn item() -> Value {
    json!({"title": "原始标题", "url": "/read/1"})
}

#[test]
fn prefix_js_receives_json_object_then_selects_field() {
    assert_eq!(
        chapter_title("<js>result.title = '修改标题'; result</js>$.title", item()),
        "修改标题"
    );
}

#[test]
fn consecutive_prefix_stages_consume_previous_output() {
    assert_eq!(
        chapter_title(
            "<js>({nested: result})</js><js>result.nested</js>$.title",
            item()
        ),
        "原始标题"
    );
}

#[test]
fn prefix_returned_json_string_can_feed_jsonpath() {
    assert_eq!(
        chapter_title(
            "<js>JSON.stringify({title: '字符串输出'})</js>$.title",
            item()
        ),
        "字符串输出"
    );
}

#[test]
fn prefix_then_selector_trailing_js_and_replacement_keep_order() {
    assert_eq!(
        chapter_title(
            "<js>({title: '阶段'})</js>$.title<js>result + '尾部'</js>##尾部##替换",
            item()
        ),
        "阶段替换"
    );
}

#[test]
fn existing_pure_js_field_keeps_string_input_contract() {
    assert_eq!(
        chapter_title("@js:JSON.parse(result).title", item()),
        "原始标题"
    );
}

#[test]
fn existing_selector_then_js_field_is_unchanged() {
    assert_eq!(
        chapter_title("$.title<js>result + '后缀'</js>", item()),
        "原始标题后缀"
    );
}
