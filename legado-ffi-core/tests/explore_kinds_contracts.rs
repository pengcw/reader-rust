use reader_parser::executor::execute;
use serde_json::{json, Value};

fn run(source: Value, session: Value, options: Value) -> Value {
    serde_json::from_str(&execute(
        &source.to_string(),
        &json!({
            "api":2,"op":"explore_kinds","params":{},"session":session,"options":options
        })
        .to_string(),
    ))
    .unwrap()
}
fn source(rule: &str) -> Value {
    json!({"bookSourceUrl":"https://example.com","bookSourceName":"categories","exploreUrl":rule})
}

#[test]
fn static_category_json_preserves_styles_and_does_not_evaluate_js_lib() {
    let mut source = source(
        r#"[{"title":"推荐","url":"/rank","style":{"layout_flexGrow":1}},{"title":"分组"}]"#,
    );
    source["jsLib"] = json!("throw new Error('must not run for static categories');");
    let response = run(source, Value::Null, json!({}));
    assert_eq!(response["ok"], true);
    assert_eq!(response["data"][0]["style"], json!({"layout_flexGrow":1}));
    assert!(response["data"][1]["url"].is_null());
    assert_eq!(response["meta"]["pages"], 0);
}

#[test]
fn legacy_text_categories_are_normalized_and_options_stay_per_item() {
    let response = run(
        json!({
            "bookSourceUrl":"https://example.com","bookSourceName":"old categories",
            "ruleFindUrl":"一::/one?p=searchPage@Header:{\"X-Value\":\"left&&right\"}&&二::/two?p=searchPage+1"
        }),
        Value::Null,
        json!({}),
    );
    assert_eq!(response["ok"], true);
    assert_eq!(response["data"].as_array().unwrap().len(), 2);
    assert_eq!(response["data"][0]["title"], "一");
    assert!(response["data"][0]["url"]
        .as_str()
        .unwrap()
        .contains("left&&right"));
    assert_eq!(response["data"][1]["url"], "/two?p={{page+1}}");
}

#[test]
fn javascript_categories_use_js_lib_source_and_session_and_return_variable_changes() {
    let mut source = source("@js: const label=categoryName(source.getVariable()); source.setVariable('changed'); [{title:label,url:source.key+'/list'}];");
    source["jsLib"] = json!("function categoryName(value){return '分类:'+value;}");
    for variable in ["first", "second"] {
        let response = run(
            source.clone(),
            json!({"variables":{"variable":variable}}),
            json!({}),
        );
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(response["data"][0]["title"], format!("分类:{variable}"));
        assert_eq!(response["data"][0]["url"], "https://example.com/list");
        assert_eq!(response["session"]["variables"]["variable"], "changed");
    }
}

#[test]
fn javascript_forms_accept_json_arrays_and_text_without_executing_at_import() {
    for rule in [
        "@JS: JSON.stringify([{title:'一',url:'/one'}]);",
        "<JS>[{title:'一',url:'/one'}];</JS>",
        "<js>'一::/one';</js>",
    ] {
        let response = run(source(rule), Value::Null, json!({}));
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(response["data"][0]["title"], "一");
        assert_eq!(response["data"][0]["url"], "/one");
    }
}

#[test]
fn invalid_json_missing_js_closure_and_script_errors_are_explicit() {
    for rule in [
        "[{broken]",
        "<js>'unclosed'",
        "@js:throw new Error('category failed');",
    ] {
        let response = run(source(rule), Value::Null, json!({}));
        assert_eq!(response["ok"], false, "{response}");
        assert_eq!(response["error"]["kind"], "parse");
    }
    let response = run(
        source("@js:'x'.repeat(100);"),
        Value::Null,
        json!({"maxResponseBytes":32}),
    );
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["kind"], "parse");
}

#[test]
fn empty_categories_are_successful_and_do_not_require_a_network_request() {
    for rule in ["", "[]", "\n&&\n"] {
        let response = run(source(rule), Value::Null, json!({}));
        assert_eq!(response["ok"], true);
        assert_eq!(response["data"], json!([]));
        assert_eq!(response["meta"]["pages"], 0);
    }
}
