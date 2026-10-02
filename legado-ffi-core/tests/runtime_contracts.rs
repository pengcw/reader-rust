//! Cross-module contracts exercised only through public APIs; no external I/O.
use reader_parser::crawler::analyze_url;
use reader_parser::crawler::session::{current_active_session, with_active_session};
use reader_parser::model::book_source::BookSource;
use reader_parser::parser::js::{eval_js, with_js_lib};
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::{json, Value};
use std::panic::{catch_unwind, AssertUnwindSafe};

const BASE: &str = "https://fixture.test";

fn source(rules: Value) -> BookSource {
    let mut value = json!({"bookSourceUrl": BASE, "bookSourceName": "integration fixture"});
    value
        .as_object_mut()
        .unwrap()
        .extend(rules.as_object().unwrap().clone());
    serde_json::from_value(value).unwrap()
}

#[test]
fn xml_search_filters_original_nodes_then_evaluates_composite_fields() {
    let source = source(json!({"ruleSearch": {
        "bookList": "@xpath://Item@js:result.filter(item => item.attr('x:id') === 'keep' && item.select('./Enabled').size() === 1)",
        "name": "./Name", "author": "./A&&./B", "bookUrl": "./Url"
    }}));
    let books = RuleEngine::new().unwrap().search_books(&source,
        r#"<?xml version="1.0"?><Root xmlns:x="urn:ids"><Item x:id="drop"><Name>First</Name><Url>/1</Url></Item><Item x:id="keep"><Enabled/><Name>Second</Name><A>A</A><B>B</B><Url>/2</Url></Item></Root>"#,
        BASE);
    assert_eq!(books.len(), 1);
    assert_eq!(books[0].name, "Second");
    assert_eq!(books[0].author, "A\nB");
    assert_eq!(books[0].book_url, format!("{BASE}/2"));
}

#[test]
fn xml_toc_list_js_can_query_chapter_ancestors_before_rust_parsing() {
    let source = source(json!({"ruleToc": {
        "chapterList": "@xpath://Chapter@js:result.filter(item => java.getString('@xpath:../Flag', item) === 'keep')",
        "chapterName": "./Title", "chapterUrl": "./Url"
    }}));
    let (chapters, _) = RuleEngine::new().unwrap().chapter_list(&source,
        r#"<?xml version="1.0"?><Book><Volume><Flag>keep</Flag><Chapter><Title>One</Title><Url>/chapter/1</Url></Chapter></Volume><Volume><Flag>drop</Flag><Chapter><Title>Two</Title><Url>/chapter/2</Url></Chapter></Volume></Book>"#,
        BASE);
    assert_eq!(chapters.len(), 1);
    assert_eq!(chapters[0].title, "One");
    assert_eq!(chapters[0].url, format!("{BASE}/chapter/1"));
}

#[test]
fn json_search_combinations_short_circuit_and_keep_per_book_variables_for_details() {
    let source = source(json!({
        "ruleSearch": {
            "bookList": "$.items[*]", "name": "$.name@put:{bid:$.id}",
            "author": "$.a[*]&&$.b[*]@js:result.toUpperCase()",
            "intro": "$.missing||$.intro||$.intro@put:{skipped:$.id}",
            "bookUrl": "/book/{{$.id}}"
        },
        "ruleBookInfo": {"name": "@get:{bid}"}
    }));
    let engine = RuleEngine::new().unwrap();
    let books = engine.search_books(&source,
        r#"{"items":[{"id":"a","name":"Alpha","a":["a1","a2"],"b":["b1"],"intro":"I"},{"id":"b","name":"Beta","a":["a1","a2"],"b":["b1"],"intro":"J"}]}"#,
        BASE);
    assert_eq!(books.len(), 2);
    for (book, id, intro) in [(&books[0], "a", "I"), (&books[1], "b", "J")] {
        assert_eq!(book.author, "A1\nA2\nB1");
        assert_eq!(book.intro.as_deref(), Some(intro));
        assert_eq!(book.book_url, format!("{BASE}/book/{id}"));
        let variables: Value = serde_json::from_str(book.variable.as_deref().unwrap()).unwrap();
        assert_eq!(variables["bid"], id);
        assert!(variables.get("skipped").is_none());
        let detail = engine.book_info_with_variable(
            &source,
            "<html></html>",
            BASE,
            &book.book_url,
            book.variable.as_deref(),
            Some(&book.name),
        );
        assert_eq!(detail.name, id);
    }
}

#[test]
fn template_lexing_survives_search_fields_and_relative_url_resolution() {
    let source = source(json!({"ruleSearch": {
        "bookList": "$.items[*]", "name": "{{({label:'}}'}).label}}",
        "author": r#"{{'it\'s }}'}}"#,
        "intro": "{{1 // }}\n + 2}}",
        "bookUrl": "/book/{{1 /* }} */ + 2}}"
    }}));
    let books = RuleEngine::new()
        .unwrap()
        .search_books(&source, r#"{"items":[{}]}"#, BASE);
    assert_eq!(books.len(), 1);
    assert_eq!(books[0].name, "}}");
    assert_eq!(books[0].author, "it's }}");
    assert_eq!(books[0].intro.as_deref(), Some("3"));
    assert_eq!(books[0].book_url, format!("{BASE}/book/3"));
}

#[test]
fn quoted_jsonpath_keys_and_unequal_interleave_groups_work_in_search() {
    let source = source(json!({"ruleSearch": {
        "bookList": "$.items[*]", "name": "$.name",
        "author": "$['a&&b'][*]%%$.c[*]", "intro": "$.missing||$['intro||text']",
        "bookUrl": "/{{$.id}}"
    }}));
    let books = RuleEngine::new().unwrap().search_books(
        &source,
        r#"{"items":[{"id":"1","name":"N","a&&b":["A1","A2"],"c":["C1"],"intro||text":"I"}]}"#,
        BASE,
    );
    assert_eq!(books.len(), 1);
    assert_eq!(books[0].author, "A1\nC1\nA2");
    assert_eq!(books[0].intro.as_deref(), Some("I"));
}

#[test]
fn failed_js_auth_update_preserves_headers_for_native_url_analysis_and_state_out() {
    let source = source(json!({}));
    let ((message, spec), state) = with_active_session(None, BASE, |_| {
        let message = eval_js(
            r#"
            source.putLoginHeader('{"Authorization":"old","Cookie":"sid=old"}');
            let name = 'not rejected';
            try { source.putLoginHeader('{"Authorization":"new","Cookie":"sid=new; broken"}'); }
            catch (error) { name = error.name; }
            name
        "#,
            "",
            BASE,
        )
        .unwrap();
        (message, analyze_url("/next", "", 1, BASE, &source).unwrap())
    });
    assert_eq!(message, "TypeError");
    assert!(spec
        .headers
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("authorization") && value == "old"));
    assert!(spec
        .headers
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("cookie") && value == "sid=old"));
    let state = state.unwrap();
    let (cookie, unchanged) =
        with_active_session(Some(&state), BASE, |active| active.get_cookie(BASE));
    assert_eq!(cookie.as_deref(), Some("sid=old"));
    assert!(unchanged.is_none());
}

#[test]
fn deleted_login_cookie_does_not_reappear_after_session_roundtrip() {
    let source = source(json!({}));
    let (_, state) = with_active_session(None, BASE, |_| {
        eval_js(
            r#"
            source.putLoginHeader('{"Authorization":"token","Cookie":"sid=old"}');
            cookie.removeCookie(baseUrl);
            source.getLoginHeaderMap().has('Cookie')
        "#,
            "",
            BASE,
        )
        .map(|result| assert_eq!(result, "false"))
        .unwrap();
    });
    let state = state.unwrap();
    let (spec, unchanged) = with_active_session(Some(&state), BASE, |active| {
        assert!(active.get_cookie(BASE).is_none());
        analyze_url("/after", "", 1, BASE, &source).unwrap()
    });
    assert!(!spec
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("cookie")));
    assert!(spec
        .headers
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("authorization") && value == "token"));
    assert!(unchanged.is_none());
}

#[test]
fn nested_rust_unwind_restores_js_library_and_parent_session_together() {
    let (result, _) = with_active_session(None, BASE, |outer| {
        outer.set_variable("user", json!("Alice"));
        with_js_lib(Some("function label(){return 'outer';}"), || {
            let mut inner_result = None;
            let panic = catch_unwind(AssertUnwindSafe(|| {
                with_active_session(None, BASE, |inner| {
                    inner.set_variable("user", json!("Bob"));
                    with_js_lib(Some("function label(){return 'inner';}"), || {
                        inner_result = Some(
                            eval_js("[label(),source.getVariable('user')].join('|')", "", BASE)
                                .unwrap(),
                        );
                        panic!("fixture unwind");
                    });
                });
            }));
            assert!(panic.is_err());
            assert_eq!(inner_result.as_deref(), Some("inner|Bob"));
            eval_js("[label(),source.getVariable('user')].join('|')", "", BASE).unwrap()
        })
    });
    assert_eq!(result, "outer|Alice");
    assert!(current_active_session().is_none());
    assert_eq!(eval_js("typeof label", "", BASE).unwrap(), "undefined");
}

#[test]
fn xml_and_html_node_queries_do_not_leak_mode_or_document_pool_across_evaluations() {
    let xml = r#"<?xml version="1.0"?><Root><Item><Child class="kid">Value</Child></Item></Root>"#;
    let html = r#"<div><section><span class="kid">Value</span></section></div>"#;
    for body in [xml, html, xml] {
        let result = eval_js(
            r#"
            const item = java.getElement('//Item', result) || java.getElement('//section', result);
            [item.__readerXPathNode.documentId, java.getString('.kid@text', item),
             item.select('@xpath:parent::*').size()].join('|')
        "#,
            body,
            BASE,
        )
        .unwrap();
        assert_eq!(result, "0|Value|1");
    }
}

#[test]
fn large_xml_result_keeps_compact_nodes_and_correct_sibling_locations() {
    let items: String = (0..200)
        .map(|index| format!("<Item><Child>{index}</Child></Item>"))
        .collect();
    let body = format!(
        "<?xml version=\"1.0\"?><Root><Noise>{}</Noise>{items}</Root>",
        "x".repeat(64 * 1024)
    );
    let output = eval_js(
        r#"
        const items = java.getElements('//Item', result);
        const selected = items.get(100);
        [items.size(), new Set(items.map(item => item.__readerXPathNode.documentId)).size,
         JSON.stringify(items).length < 60000,
         java.getString('@xpath:./Child', selected),
         selected.select('@xpath:following-sibling::Item[1]/Child').first().text(),
         selected.select('@xpath:preceding-sibling::Item[1]/Child').first().text()].join('|')
    "#,
        &body,
        BASE,
    )
    .unwrap();
    assert_eq!(output, "200|1|true|100|101|99");
}
