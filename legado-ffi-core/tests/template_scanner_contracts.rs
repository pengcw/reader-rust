//! URL and field templates share closing-delimiter semantics; no HTTP traffic.
use reader_parser::crawler::analyze_url;
use reader_parser::model::book_source::BookSource;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::json;
use ureq::http::Method;

const BASE: &str = "https://fixture.test";

#[test]
fn url_and_field_templates_agree_on_comments_quotes_and_braces() {
    for (expression, expected) in [
        ("1 /* }} { */ + 2", "3"),
        ("1 // }} {\n + 2", "3"),
        (r#"({a:{b:'value'}}).a.b"#, "value"),
        (r#"'it\'s }}'"#, "it's }}"),
        (r#""中文}}""#, "中文}}"),
        ("`text }}`", "text }}"),
        ("8 / 2", "4"),
    ] {
        let name_rule = ["前{{", expression, "}}后"].concat();
        let source: BookSource = serde_json::from_value(json!({
            "bookSourceUrl": BASE,
            "ruleSearch": {"bookList":"li", "name":name_rule, "bookUrl":"a@href"}
        }))
        .unwrap();
        let rule = ["/book/{{", expression, "}}/end"].concat();
        let spec = analyze_url(&rule, "", 1, BASE, &source).unwrap();
        let path = spec.url.strip_prefix(BASE).unwrap();
        assert_eq!(
            urlencoding::decode(path).unwrap(),
            format!("/book/{expected}/end"),
            "{expression}"
        );
        let books = RuleEngine::new().unwrap().search_books(
            &source,
            "<ul><li><a href='/one'>Original</a></li></ul>",
            BASE,
        );
        assert_eq!(books.len(), 1, "{expression}");
        assert_eq!(books[0].name, format!("前{expected}后"), "{expression}");
        assert_eq!(books[0].book_url, format!("{BASE}/one"), "{expression}");
    }
}

#[test]
fn successive_url_templates_preserve_request_options() {
    let source = BookSource {
        book_source_url: BASE.into(),
        ..Default::default()
    };
    let options = json!({"method":"POST", "body":"unchanged", "headers":{"Content-Type":"text/plain", "X-Keep":"kept"}});
    let rule = format!("{},{}", "/book/{{1 /* }} { */ + 2}}/{{8 / 2}}", options);
    let spec = analyze_url(&rule, "", 1, BASE, &source).unwrap();
    assert_eq!(spec.url, format!("{BASE}/book/3/4"));
    assert_eq!(spec.method, Method::POST);
    assert_eq!(spec.body.as_deref(), Some("unchanged"));
    assert!(spec
        .headers
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("X-Keep") && value == "kept"));
}

#[test]
fn unclosed_url_templates_remain_unexpanded() {
    let source = BookSource {
        book_source_url: BASE.into(),
        ..Default::default()
    };
    for expression in [
        "'unterminated }}",
        "/* unterminated }}",
        "{unclosed }}",
        "1 // }}",
    ] {
        let rule = ["/book/{{", expression].concat();
        let spec = analyze_url(&rule, "", 1, BASE, &source).unwrap();
        let path = spec.url.strip_prefix(BASE).unwrap();
        assert_eq!(urlencoding::decode(path).unwrap(), rule, "{expression}");
    }
}
