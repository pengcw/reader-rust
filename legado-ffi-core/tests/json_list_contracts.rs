//! JSON list combinations through public search and explore APIs.
use reader_parser::model::book_source::BookSource;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::{json, Value};

const BASE: &str = "https://fixture.test";

fn source(list: &str) -> BookSource {
    serde_json::from_value(json!({
        "bookSourceUrl": BASE, "bookSourceName": "JSON list fixture",
        "ruleSearch": {"bookList": list, "name": "name", "bookUrl": "url"},
        "ruleExplore": {"bookList": list, "name": "name", "bookUrl": "url"}
    }))
    .unwrap()
}

fn assert_names(list: &str, body: Value, expected: &[&str]) {
    let engine = RuleEngine::new().unwrap();
    let source = source(list);
    let body = body.to_string();
    for books in [
        engine.search_books(&source, &body, BASE),
        engine.explore_books(&source, &body, BASE),
    ] {
        assert_eq!(
            books
                .iter()
                .map(|book| book.name.as_str())
                .collect::<Vec<_>>(),
            expected,
            "{list}"
        );
    }
}

fn body() -> Value {
    json!({"a": [{"name":"A1","url":"/a1"},{"name":"A2","url":"/a2"}],
        "b": [{"name":"B1","url":"/b1"},{"name":"B2","url":"/b2"},{"name":"B3","url":"/b3"}]})
}

#[test]
fn json_list_and_appends_in_branch_order() {
    assert_names("$.a&&$.b", body(), &["A1", "A2", "B1", "B2", "B3"]);
}

#[test]
fn json_list_or_falls_back_on_empty_but_keeps_first_nonempty_group() {
    assert_names("$.missing||$.a||$.b", body(), &["A1", "A2"]);
    assert_names(
        "$.empty||$.b",
        json!({"empty":[], "b":[{"name":"B","url":"/b"}]}),
        &["B"],
    );
}

#[test]
fn json_list_interleave_uses_first_nonempty_group_length() {
    assert_names("$.a%%$.b", body(), &["A1", "B1", "A2", "B2"]);
    assert_names("$.b%%$.a", body(), &["B1", "A1", "B2", "A2", "B3"]);
    assert_names("$.missing%%$.a%%$.b", body(), &["A1", "B1", "A2", "B2"]);
}

#[test]
fn json_list_interleave_skips_null_items_before_trailing_js() {
    assert_names(
        "$.a%%$.b@js:result.map(item => ({name: item.name + '-' + result.length, url: item.url}))",
        json!({"a":[null,{"name":"A2","url":"/a2"}], "b":[{"name":"B1","url":"/b1"},{"name":"B2","url":"/b2"}]}),
        &["B1-3", "A2-3", "B2-3"],
    );
}

#[test]
fn json_list_operators_inside_quoted_paths_are_not_delimiters() {
    assert_names(
        "$['a&&b']||$.missing",
        json!({"a&&b":[{"name":"Quoted","url":"/q"}]}),
        &["Quoted"],
    );
}

#[test]
fn json_list_trailing_js_sees_complete_list_once_before_final_book_deduplication() {
    assert_names("$.a&&$.a@js:result.map((item, i) => ({name: item.name + '-' + result.length, url: item.url + '/' + i}))",
        json!({"a":[{"name":"A","url":"/a"}]}), &["A-2", "A-2"]);
}

#[test]
fn json_list_or_short_circuits_before_item_field_validation() {
    assert_names(
        "$.a||$.b@js:result.map(item => ({name: item.name || 'Chosen A', url: item.url}))",
        json!({"a":[{"name":"","url":"/a"}], "b":[{"name":"B","url":"/b"}]}),
        &["Chosen A"],
    );
}

#[test]
fn json_list_prefix_reverse_and_scalar_paths_remain_supported() {
    assert_names(
        "-@json:$.a&&@json:$.b",
        body(),
        &["B3", "B2", "B1", "A2", "A1"],
    );
    assert_names("$.a", body(), &["A1", "A2"]);
    assert_names("$.a[0]", body(), &["A1"]);
}
