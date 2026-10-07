use reader_parser::executor::execute;
use serde_json::{json, Value};

fn click(source: Value, action: &str) -> Value {
    let request = json!({"api":2,"op":"click","params":{
        "action":action,"book":{"name":"fixture"},"chapter":{"index":8}
    }});
    serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap()
}

#[test]
fn click_runs_source_library_not_login_and_captures_without_fetching() {
    let source = json!({
        "bookSourceUrl":"https://fixture.invalid", "bookSourceName":"click fixture",
        "loginUrl":"throw new Error('login must not execute');",
        "jsLib":"function customReview(){java.startBrowser('https://fixture.invalid/review?chapter='+chapter.index,book.name);}",
    });
    let result = click(source, "customReview()");
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["data"]["browser"]["url"], "https://fixture.invalid/review?chapter=8");
    assert_eq!(result["data"]["browser"]["title"], "fixture");
    assert!(result["data"].get("preview").is_none());
}

#[test]
fn click_browser_aliases_and_latest_target_contract() {
    let source = json!({"bookSourceUrl":"https://fixture.invalid"});
    for method in ["startBrowser", "showReadingBrowser", "startBrowserDp"] {
        let result = click(source.clone(), &format!("java.{method}('https://fixture.invalid/review','评论')"));
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["data"]["browser"]["title"], "评论");
    }
    let result = click(source, "java.startBrowser('https://fixture.invalid/first','first');java.showBrowser('https://fixture.invalid/last','<p>review</p>','window.java=java;')");
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["data"]["browser"]["url"], "https://fixture.invalid/last");
    assert_eq!(result["data"]["browser"]["html"], "<p>review</p>");
}

#[test]
fn capture_scope_does_not_leak_after_success_or_exception() {
    let source = json!({"bookSourceUrl":"https://fixture.invalid"});
    assert_eq!(click(source.clone(), "java.startBrowser('https://fixture.invalid/review','ok')")["ok"], true);
    assert_eq!(click(source.clone(), "throw new Error('fixture')")["ok"], false);
    assert_eq!(click(source.clone(), "42")["ok"], false);
    assert_eq!(click(source.clone(), "java.startBrowser('javascript:evil()','bad')")["ok"], false);
    assert_eq!(click(source, "java.startBrowser('https://fixture.invalid/review','again')")["ok"], true);
}
