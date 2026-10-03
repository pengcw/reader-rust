//! Return-value and counter boundaries of the existing TOC formatter.
use reader_parser::model::book_source::BookSource;
use reader_parser::model::rule::TocRule;
use reader_parser::parser::rule_engine::RuleEngine;

fn titles(script: &str) -> Vec<String> {
    let source = BookSource {
        book_source_url: "https://format-result.test/".to_string(),
        rule_toc: Some(TocRule {
            chapter_list: Some("$[*]".to_string()),
            chapter_name: Some("$.title".to_string()),
            chapter_url: Some("$.url".to_string()),
            format_js: Some(script.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let (chapters, _) = RuleEngine::new().unwrap().chapter_list(
        &source,
        r#"[{"title":"One","url":"/1"},{"title":"Two","url":"/2"},{"title":"Three","url":"/3"}]"#,
        "https://format-result.test/toc",
    );
    assert_eq!(chapters.len(), 3);
    for (index, chapter) in chapters.iter().enumerate() {
        assert_eq!(chapter.index, index as i32);
        assert_eq!(
            chapter.url,
            format!("https://format-result.test/{}", index + 1)
        );
    }
    chapters.into_iter().map(|chapter| chapter.title).collect()
}

#[test]
fn empty_and_whitespace_format_results_replace_titles() {
    assert_eq!(titles("index === 2 ? ' \\t ' : ''"), ["", " \t ", ""]);
}

#[test]
fn null_and_undefined_keep_titles_but_retain_counter_changes() {
    assert_eq!(
        titles("gInt++; index === 1 ? null : index === 2 ? undefined : `${gInt}:${title}`"),
        ["One", "Two", "3:Three"]
    );
}

#[test]
fn counter_changes_before_throw_are_visible_to_the_next_chapter() {
    assert_eq!(
        titles("gInt++; if (index === 2) throw new Error('synthetic failure'); `${gInt}:${title}`"),
        ["1:One", "Two", "3:Three"]
    );
}

#[test]
fn existing_primitive_result_conversion_is_preserved() {
    // Preserve local conversions; this does not establish Rhino Number.toString parity.
    for (script, expected) in [
        ("0", "0"),
        ("12.5", "12.5"),
        ("false", "false"),
        ("true", "true"),
    ] {
        assert_eq!(titles(script), [expected, expected, expected]);
    }
}
