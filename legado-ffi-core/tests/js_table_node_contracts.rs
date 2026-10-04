//! JS-returned table fragments retain the selected element, not its wrapper.
use reader_parser::model::book_source::BookSource;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::json;

const BASE: &str = "https://fixture.test";
fn books(body: &str, list: &str, name: &str, url: &str) -> Vec<(String, String)> {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "ruleSearch": {"bookList":list,"name":name,"bookUrl":url}
    }))
    .unwrap();
    RuleEngine::new()
        .unwrap()
        .search_books(&source, body, BASE)
        .into_iter()
        .map(|book| (book.name, book.book_url))
        .collect()
}

#[test]
fn js_table_rows_preserve_order_fields_and_single_node_identity() {
    let body = "<table><tr data-name='One'><td><a href='/one'>One</a></td></tr><tr data-name='Two'><td><a href='/two'>Two</a></td></tr></table>";
    let expected = vec![
        ("One".into(), format!("{BASE}/one")),
        ("Two".into(), format!("{BASE}/two")),
    ];
    assert_eq!(books(body, "tr", "td@text", "a@href"), expected);
    for list in [
        "@js:java.getElements('tr')",
        "js:java.getElements('tr')",
        "<js>java.getElements('tr')</js>",
        "@js:JSON.stringify(java.getElements('tr'))",
    ] {
        assert_eq!(books(body, list, "td@text", "a@href"), expected, "{list}");
    }
    let mut reversed = expected.clone();
    reversed.reverse();
    assert_eq!(
        books(
            body,
            "@js:java.getElements('tr').reverse()",
            "@data-name",
            "a@href"
        ),
        reversed
    );
    assert_eq!(
        books(body, "@js:java.getElement('tr')", "@data-name", "a@href"),
        expected[..1]
    );
}

#[test]
fn all_table_fragment_types_keep_root_attributes_and_relative_children() {
    for (tag, contents) in [
        ("tr", "<td><a href='/one'>One</a></td>"),
        ("td", "<a href='/one'>One</a>"),
        ("th", "<a href='/one'>One</a>"),
        ("tbody", "<tr><td><a href='/one'>One</a></td></tr>"),
        ("thead", "<tr><th><a href='/one'>One</a></th></tr>"),
        ("tfoot", "<tr><td><a href='/one'>One</a></td></tr>"),
        ("caption", "<a href='/one'>One</a>"),
        ("colgroup", "<col>"),
        ("col", ""),
    ] {
        let element = if tag == "col" {
            "<col data-name='One' data-url='/one'>".to_string()
        } else {
            format!("<{tag} data-name='One' data-url='/one'>{contents}</{tag}>")
        };
        let body = match tag {
            "td" | "th" => format!("<table><tr>{element}</tr></table>"),
            "col" => format!("<table><colgroup>{element}</colgroup></table>"),
            _ => format!("<table>{element}</table>"),
        };
        let list = format!("@js:java.getElements('{tag}')");
        let expected = vec![("One".into(), format!("{BASE}/one"))];
        assert_eq!(
            books(&body, tag, "@data-name", "@data-url"),
            expected,
            "native {tag}"
        );
        assert_eq!(
            books(&body, &list, "@data-name", "@data-url"),
            expected,
            "JS {tag}"
        );
        if !matches!(tag, "col" | "colgroup") {
            assert_eq!(
                books(&body, &list, "a@text", "a@href"),
                expected,
                "relative {tag}"
            );
        }
    }
}

#[test]
fn js_table_toc_fields_share_the_same_element_context() {
    let source: BookSource = serde_json::from_value(json!({"bookSourceUrl":BASE,
        "ruleToc":{"chapterList":"@js:java.getElements('tr').reverse()",
            "chapterName":"td@text","chapterUrl":"a@href","nextTocUrl":"a.next@href"}
    }))
    .unwrap();
    let body = "<table><tr><td><a href='/one'>One</a></td></tr><tr><td><a href='/two'>Two</a></td></tr></table><a class='next' href='/next'>Next</a>";
    let (chapters, next) = RuleEngine::new().unwrap().chapter_list(&source, body, BASE);
    assert_eq!(
        chapters
            .iter()
            .map(|chapter| chapter.title.as_str())
            .collect::<Vec<_>>(),
        ["Two", "One"]
    );
    assert_eq!(chapters[0].url, format!("{BASE}/two"));
    assert_eq!(next, [format!("{BASE}/next")]);
}
