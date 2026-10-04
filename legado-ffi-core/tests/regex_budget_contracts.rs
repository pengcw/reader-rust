//! Step exhaustion never publishes a partially replaced field.
use reader_parser::model::book_source::BookSource;
use reader_parser::parser::{js::eval_js, rule_engine::RuleEngine};
use serde_json::json;

#[test]
fn js_reports_budget_exhaustion_and_the_next_call_has_a_fresh_budget() {
    let result = eval_js(r#"
        const text = ('a'.repeat(16) + '!').repeat(12);
        let rejected = false;
        try { regex_replace(text, '(a+)+b|.', 'X'); }
        catch (error) { rejected = error instanceof TypeError && /budget exceeded/.test(error.message); }
        [rejected, regex_replace('ab', '.', 'X')].join('|')
    "#, "", "https://fixture.test").unwrap();
    assert_eq!(result, "true|XX");
}

#[test]
fn field_replacement_keeps_the_entire_input_on_budget_exhaustion() {
    let input = format!("{}!", "a".repeat(16)).repeat(12);
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl":"https://fixture.test", "ruleSearch":{
            "bookList":"$.items[*]", "name":"$.name", "bookUrl":"$.url",
            "author":"$.author##(a+)+b|.##X"}}))
    .unwrap();
    let body = json!({"items":[{"name":"Book", "url":"/book", "author":input}]}).to_string();
    let books = RuleEngine::new()
        .unwrap()
        .search_books(&source, &body, "https://fixture.test");
    assert_eq!(books.len(), 1);
    assert_eq!(books[0].author, input);
}
