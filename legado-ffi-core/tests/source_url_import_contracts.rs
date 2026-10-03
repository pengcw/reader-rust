use reader_parser::crawler::analyze_url;
use reader_parser::model::book_source::{book_source_from_value, migrate_legacy_book_source_value};
use serde_json::json;
use ureq::http::Method;

#[test]
fn modern_url_fields_preserve_javascript_and_legacy_looking_literals() {
    for script in [
        "@js: let searchKey = 'searchPage'; if (key) { const x = {a:1,b:2}; '/search?q=' + key; } else { '/empty'; }",
        "<js>const x = {a:1,b:2}; 'https://example.com/search?literal=searchKey';</js>",
        "  @js: const text = '@Header:{\"X\":\"1\"}|charset=gbk@body:searchPage'; '/search';",
    ] {
        let source = book_source_from_value(json!({
            "bookSourceUrl": "https://example.com", "searchUrl": script,
            "exploreUrl": script, "loginUrl": script
        })).unwrap();
        assert_eq!(source.search_url.as_deref(), Some(script));
        assert_eq!(source.explore_url.as_deref(), Some(script));
        assert_eq!(source.login_url.as_deref(), Some(script));
    }
}

#[test]
fn imported_modern_javascript_executes_instead_of_corrupting_block_braces() {
    let script = "@js: if (key) { const route = {path:'/search',label:'searchKey'}; route.path + '?q=' + key; } else { '/empty'; }";
    let source = book_source_from_value(json!({
        "bookSourceUrl":"https://example.com", "searchUrl":script
    }))
    .unwrap();
    assert_eq!(source.search_url.as_deref(), Some(script));
    let spec = analyze_url(
        source.search_url.as_deref().unwrap(),
        "reader",
        1,
        &source.book_source_url,
        &source,
    )
    .unwrap();
    assert_eq!(spec.url, "https://example.com/search?q=reader");
}

#[test]
fn modern_options_and_inline_templates_are_not_legacy_migrated() {
    let raw = r#"/search?q={{key}}&p={{page}},{"method":"POST","headers":{"X-Literal":"searchKey,searchPage"},"body":"searchKey|charset=gbk@body:{a,b}"}"#;
    let source = book_source_from_value(json!({
        "bookSourceUrl":"https://example.com", "searchUrl":raw
    }))
    .unwrap();
    assert_eq!(source.search_url.as_deref(), Some(raw));
    let spec = analyze_url(raw, "reader", 2, &source.book_source_url, &source).unwrap();
    assert_eq!(spec.method, Method::POST);
    // Import preservation must not disable existing runtime substitutions or
    // form encoding. Compare with the same rule executed without migration.
    let direct: reader_parser::model::book_source::BookSource = serde_json::from_value(json!({
        "bookSourceUrl":"https://example.com", "searchUrl":raw
    }))
    .unwrap();
    let baseline = analyze_url(raw, "reader", 2, &direct.book_source_url, &direct).unwrap();
    assert_eq!(spec.url, baseline.url);
    assert_eq!(spec.body, baseline.body);
    assert_eq!(spec.headers, baseline.headers);
}

#[test]
fn old_url_aliases_still_convert_placeholders_page_choices_and_headers() {
    let source = book_source_from_value(json!({
        "bookSourceUrl":"https://example.com",
        "ruleSearchUrl":"/search?q=searchKey&p=searchPage&choice={1,2}@Header:{\"X-Legacy\":\"yes\"}",
        "ruleFindUrl":"/list?p=searchPage|charset=gbk"
    })).unwrap();
    assert_eq!(
        source.search_url.as_deref(),
        Some("/search?q={{key}}&p={{page}}&choice=<1,2>,{\"headers\":{\"X-Legacy\":\"yes\"}}")
    );
    assert_eq!(
        source.explore_url.as_deref(),
        Some("/list?p={{page}},{\"charset\":\"gbk\"}")
    );
    let spec = analyze_url(
        source.search_url.as_deref().unwrap(),
        "reader",
        2,
        &source.book_source_url,
        &source,
    )
    .unwrap();
    assert_eq!(spec.url, "https://example.com/search?q=reader&p=2&choice=2");
    assert!(spec
        .headers
        .iter()
        .any(|(name, value)| name == "X-Legacy" && value == "yes"));
}

#[test]
fn current_fields_win_over_old_aliases_and_login_url_is_not_converted() {
    let current = "@js: const x = {a:1,b:2}; '/search?literal=searchKey';";
    let login = "/login?literal=searchKey&page=searchPage";
    let source = book_source_from_value(json!({
        "bookSourceUrl":"https://example.com", "searchUrl":current,
        "ruleSearchUrl":"/old?q=searchKey", "exploreUrl":current,
        "ruleFindUrl":"/old?p=searchPage", "loginUrl":login
    }))
    .unwrap();
    assert_eq!(source.search_url.as_deref(), Some(current));
    assert_eq!(source.explore_url.as_deref(), Some(current));
    assert_eq!(source.login_url.as_deref(), Some(login));
}

#[test]
fn migration_is_idempotent_and_does_not_convert_the_new_url_twice() {
    let source = json!({
        "bookSourceUrl":"https://example.com",
        "ruleSearchUrl":"/search?q=searchKey@body:literal=searchPage"
    });
    let once = migrate_legacy_book_source_value(source);
    let twice = migrate_legacy_book_source_value(once.clone());
    assert_eq!(once, twice);
    let (url, options) = once["searchUrl"].as_str().unwrap().split_once(',').unwrap();
    assert_eq!(url, "/search?q={{key}}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(options).unwrap(),
        json!({"method":"POST", "body":"literal=searchPage"})
    );
}

#[test]
fn legacy_explore_javascript_is_preserved_before_url_option_conversion() {
    for script in [
        "@js: const routes = {a:1,b:2}; const text = 'searchKey|charset=gbk@body:payload'; '/list';",
        "<js>const routes = {a:1,b:2}; '/list?q=searchKey';</js>",
    ] {
        let source = book_source_from_value(json!({
            "bookSourceUrl":"https://example.com", "ruleFindUrl":script
        })).unwrap();
        assert_eq!(source.explore_url.as_deref(), Some(script));
    }
}

#[test]
fn legacy_search_js_only_rewrites_equals_placeholders_as_in_original_importer() {
    let source = book_source_from_value(json!({
        "bookSourceUrl":"https://example.com",
        "ruleSearchUrl":"<js>const routes = {a:1,b:2}; const searchKeyName = 'unchanged'; '/search?q=searchKey&p=searchPage';</js>"
    })).unwrap();
    assert_eq!(source.search_url.as_deref(), Some(
        "<js>const routes = {a:1,b:2}; const searchKeyName = 'unchanged'; '/search?q={{key}}&p={{page}}';</js>"));
}

#[test]
fn old_url_templates_keep_nested_braces_and_convert_legacy_js_bindings() {
    let raw = "/search?q={{encodeURIComponent(searchKey)}}&p={{searchPage+1}}&choice={1,2}&token={{JSON.stringify({a:1,b:2})}}";
    let source = book_source_from_value(json!({
        "bookSourceUrl":"https://example.com", "ruleSearchUrl":raw
    }))
    .unwrap();
    assert_eq!(source.search_url.as_deref(), Some(
        "/search?q={{encodeURIComponent(key)}}&p={{page+1}}&choice=<1,2>&token={{JSON.stringify({a:1,b:2})}}"));
    let spec = analyze_url(
        source.search_url.as_deref().unwrap(),
        "reader",
        2,
        &source.book_source_url,
        &source,
    )
    .unwrap();
    assert!(spec.url.contains("q=reader&p=3&choice=2"), "{}", spec.url);
}

#[test]
fn legacy_option_markers_and_closing_braces_inside_templates_are_not_metadata() {
    let raw =
        r#"/search?literal={{'@Header:{"A":"1","B":"2"}|charset=gbk@body:x}}'}}&choice={1,2}"#;
    let source = book_source_from_value(json!({
        "bookSourceUrl":"https://example.com", "ruleSearchUrl":raw
    }))
    .unwrap();
    assert_eq!(
        source.search_url.as_deref(),
        Some(
            r#"/search?literal={{'@Header:{"A":"1","B":"2"}|charset=gbk@body:x}}'}}&choice=<1,2>"#
        )
    );
}

#[test]
fn template_protection_preserves_literal_dollar_indices_and_unclosed_templates() {
    for (raw, expected) in [
        (
            "/search?literal=$0&value={{searchPage}}&choice={1,2}",
            "/search?literal=$0&value={{page}}&choice=<1,2>",
        ),
        (
            "/search?value={{JSON.stringify({a:1,b:2})",
            "/search?value={{JSON.stringify({a:1,b:2})",
        ),
        (
            "/search?value={{'searchPage}}",
            "/search?value={{'searchPage}}",
        ),
        (
            "/search?value={{searchPage /* quoted }} */}}",
            "/search?value={{page /* quoted }} */}}",
        ),
    ] {
        let source = book_source_from_value(json!({
            "bookSourceUrl":"https://example.com", "ruleSearchUrl":raw
        }))
        .unwrap();
        assert_eq!(source.search_url.as_deref(), Some(expected));
    }
}
