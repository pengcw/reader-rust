use reader_parser::ffi::{reader_eval, reader_free_string};
use safer_ffi::prelude::*;
use serde_json::{json, Value};
use std::ffi::CString;

fn evaluate(input: &str, rule: &str) -> Value {
    let input = CString::new(input).unwrap();
    let rule = CString::new(rule).unwrap();
    let result = reader_eval(
        char_p::Ref::try_from(input.as_c_str()).unwrap(),
        char_p::Ref::try_from(rule.as_c_str()).unwrap(),
    );
    let output = result.to_str().to_owned();
    reader_free_string(Some(result));
    serde_json::from_str(&output).unwrap()
}

#[test]
fn normalization_exposes_legacy_urls_rules_and_unknown_fields_without_dto_loss() {
    let raw = json!({
        "bookSourceUrl":"https://example.com", "bookSourceName":"old",
        "ruleSearchUrl":"/search?q=searchKey&p=searchPage+1",
        "ruleFindUrl":"一::/one?p=searchPage&&二::/two?p=searchPage-1",
        "ruleSearchList":".book", "ruleSearchName":".title@text",
        "vendorConfig":{"customFlag":true}, "error":"opaque custom field"
    });
    let response = evaluate(&raw.to_string(), "@normalize_source");
    assert_eq!(response["ok"], true);
    let data = &response["data"];
    assert_eq!(data["searchUrl"], "/search?q={{key}}&p={{page+1}}");
    assert_eq!(
        data["exploreUrl"],
        "一::/one?p={{page}}\n二::/two?p={{page-1}}"
    );
    assert_eq!(data["ruleSearch"]["bookList"], ".book");
    assert_eq!(data["vendorConfig"], raw["vendorConfig"]);
    assert_eq!(data["error"], raw["error"]);
    assert!(data.get("ruleSearchUrl").is_none());
    assert_eq!(
        evaluate(&data.to_string(), "@normalize_source")["data"],
        *data
    );
}

#[test]
fn normalization_does_not_execute_modern_scripts_or_rewrite_rule_strings() {
    let raw = json!({
        "bookSourceUrl":"https://example.com", "bookSourceName":"modern",
        "searchUrl":"@js: throw new Error('must not execute');",
        "exploreUrl":"<js>throw new Error('must not execute');</js>",
        "jsLib":"throw new Error('must not load');",
        "loginUrl":"searchKey|charset=gbk@body:{a,b}",
        "ruleSearch":"{\"bookList\":\".book\"}",
        "customConfig":{"nested":{"value":"kept"}}
    });
    assert_eq!(evaluate(&raw.to_string(), "@normalize_source")["data"], raw);
}

#[test]
fn normalization_rejects_non_object_input_with_a_structured_error() {
    for raw in ["", "{broken", "[]", "null", "42", "\"text\""] {
        let response = evaluate(raw, "@normalize_source");
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["kind"], "invalid_argument");
        assert!(response.get("data").is_none());
    }
}

#[test]
fn existing_validate_directive_keeps_its_original_contract() {
    let response = evaluate(
        &json!({"bookSourceUrl":"https://example.com","bookSourceName":"valid"}).to_string(),
        "@validate",
    );
    assert_eq!(response, json!({"valid":true,"errors":[]}));
}
