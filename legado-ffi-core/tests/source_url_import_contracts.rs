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

#[test]
fn legacy_page_offsets_are_evaluated_after_import_in_all_original_forms() {
    for (expression, expected, page_value) in [
        ("searchPage+1", "{{page+1}}", 3),
        ("searchPage-1", "{{page-1}}", 1),
        ("<searchPage+1>", "{{page+1}}", 3),
        ("<searchPage-1>", "{{page-1}}", 1),
        ("{searchPage+1}", "{{page+1}}", 3),
        ("{searchPage-1}", "{{page-1}}", 1),
    ] {
        let raw = format!("/search?q=searchKey&p={expression}&choice={{1,2}}");
        let source = book_source_from_value(json!({
            "bookSourceUrl":"https://example.com", "ruleSearchUrl":raw,
            "ruleFindUrl":raw
        }))
        .unwrap();
        let converted = format!("/search?q={{{{key}}}}&p={expected}&choice=<1,2>");
        assert_eq!(source.search_url.as_deref(), Some(converted.as_str()));
        assert_eq!(source.explore_url, source.search_url);
        let spec = analyze_url(&converted, "reader", 2, &source.book_source_url, &source).unwrap();
        assert_eq!(
            spec.url,
            format!("https://example.com/search?q=reader&p={page_value}&choice=2")
        );
    }
}

#[test]
fn legacy_page_offsets_do_not_wrap_existing_template_expressions() {
    let source = book_source_from_value(json!({
        "bookSourceUrl":"https://example.com",
        "ruleSearchUrl":"/search?p=searchPage+1&js={{searchPage-1}}&current={{page+1}}"
    }))
    .unwrap();
    let raw = source.search_url.as_deref().unwrap();
    assert_eq!(raw, "/search?p={{page+1}}&js={{page-1}}&current={{page+1}}");
    let spec = analyze_url(raw, "", 2, &source.book_source_url, &source).unwrap();
    assert_eq!(spec.url, "https://example.com/search?p=3&js=1&current=3");
}

#[test]
fn page_offset_migration_does_not_rewrite_extracted_headers_or_post_body() {
    let source = migrate_legacy_book_source_value(json!({
        "bookSourceUrl":"https://example.com",
        "ruleSearchUrl":"/search?p=searchPage+1@Header:{\"X-Literal\":\"searchPage+1\"}@body:value=searchPage-1"
    }));
    let (url, options) = source["searchUrl"]
        .as_str()
        .unwrap()
        .split_once(',')
        .unwrap();
    assert_eq!(url, "/search?p={{page+1}}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(options).unwrap(),
        json!({
            "headers":{"X-Literal":"searchPage+1"}, "method":"POST", "body":"value=searchPage-1"
        })
    );
    assert_eq!(migrate_legacy_book_source_value(source.clone()), source);
}

#[test]
fn legacy_explore_list_migrates_each_items_options_without_cross_contamination() {
    let source = book_source_from_value(json!({
        "bookSourceUrl":"https://example.com",
        "ruleFindUrl":"排行::/rank?p=searchPage@Header:{\"X-List\":\"rank\"}&&搜索::/search?q=searchKey@body:value=searchPage\r\n分类::/category?p=searchPage|charset=gbk"
    })).unwrap();
    let lines = source
        .explore_url
        .as_deref()
        .unwrap()
        .lines()
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 3);
    let expected = [
        (
            "排行",
            "/rank?p={{page}}",
            json!({"headers":{"X-List":"rank"}}),
        ),
        (
            "搜索",
            "/search?q={{key}}",
            json!({"method":"POST","body":"value=searchPage"}),
        ),
        ("分类", "/category?p={{page}}", json!({"charset":"gbk"})),
    ];
    for (line, (title, expected_url, options)) in lines.iter().zip(expected) {
        let (actual_title, rule) = line.split_once("::").unwrap();
        assert_eq!(actual_title, title);
        let (url, raw_options) = rule.split_once(',').unwrap();
        assert_eq!(url, expected_url);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(raw_options).unwrap(),
            options
        );
        analyze_url(rule, "reader", 2, &source.book_source_url, &source).unwrap();
    }
}

#[test]
fn legacy_explore_list_normalizes_mixed_delimiters_and_ignores_empty_entries() {
    let migrated = migrate_legacy_book_source_value(json!({
        "ruleFindUrl":"\r\n&&一::/one?p=searchPage&&\n二::/two?p=searchPage+1\r\n\n&&"
    }));
    assert_eq!(
        migrated["exploreUrl"],
        "一::/one?p={{page}}\n二::/two?p={{page+1}}"
    );
    assert_eq!(migrate_legacy_book_source_value(migrated.clone()), migrated);
}

#[test]
fn explore_list_split_does_not_cut_templates_or_quoted_header_values() {
    let raw = "一::/one?q={{searchPage > 1 && searchKey ? 'a' : 'b'}}@Header:{\"X-Value\":\"left&&right\"}\n二::/two?p=searchPage";
    let source = book_source_from_value(json!({
        "bookSourceUrl":"https://example.com", "ruleFindUrl":raw
    }))
    .unwrap();
    let lines = source
        .explore_url
        .as_deref()
        .unwrap()
        .lines()
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    assert_eq!(
        lines[0],
        "一::/one?q={{page > 1 && key ? 'a' : 'b'}},{\"headers\":{\"X-Value\":\"left&&right\"}}"
    );
    assert_eq!(lines[1], "二::/two?p={{page}}");
}

#[test]
fn explore_titles_are_not_placeholders_and_bare_ipv6_urls_are_not_titles() {
    let migrated = migrate_legacy_book_source_value(json!({
        "ruleFindUrl":"searchPage榜::/list?p=searchPage\nhttp://[::1]/list?p=searchPage"
    }));
    assert_eq!(
        migrated["exploreUrl"],
        "searchPage榜::/list?p={{page}}\nhttp://[::1]/list?p={{page}}"
    );
}
