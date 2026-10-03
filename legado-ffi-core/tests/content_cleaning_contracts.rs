//! Isolate the stages involved in the 69shuba content-cleaning failure.
use reader_parser::model::book_source::BookSource;
use reader_parser::model::rule::ContentRule;
use reader_parser::parser::{
    html,
    rule_engine::{apply_legado_regex, RuleEngine},
};

const BODY: &str = "<div class=\"txtnav\">\n广告行1\n广告行2\n第一段正常正文内容。\n第二段正常正文内容。\n(本章完)\n最.新.小.说.发布\n</div>";
const BASE: &str = "https://69shuba.cx/txt/123/1.htm";
const PATTERN: &str =
    r"##(^(.+\n){2}(第1章 绯红.*\n)?)|(\n\uE5E5.*)+|(\n.*\(本章完\)$)|(\n最.新.小.说.+)";

#[test]
fn shuba69_end_marker_at_eof_is_removed_without_losing_paragraphs() {
    let input = "广告行1\n广告行2\n第一段正常正文内容。\n第二段正常正文内容。\n(本章完)";
    assert_eq!(
        apply_legado_regex(input, PATTERN),
        "第一段正常正文内容。\n第二段正常正文内容。"
    );
}

#[test]
fn shuba69_end_marker_before_ad_is_not_retried_after_ad_removal() {
    let input =
        "广告行1\n广告行2\n第一段正常正文内容。\n第二段正常正文内容。\n(本章完)\n最.新.小.说.发布";
    assert_eq!(
        apply_legado_regex(input, PATTERN),
        "第一段正常正文内容。\n第二段正常正文内容。\n(本章完)"
    );
}

fn source(replace_regex: Option<&str>) -> BookSource {
    BookSource {
        rule_content: Some(ContentRule {
            content: Some("class.txtnav@html".to_string()),
            replace_regex: replace_regex.map(str::to_string),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn shuba69_cleaning_stages_keep_paragraphs_before_template_replacement() {
    let extracted =
        html::select_all_text(&html::parse_document(BODY), "class.txtnav@html").unwrap();
    let formatted = html::format_keep_img(&extracted, BASE);
    let replaced = apply_legado_regex(&formatted, PATTERN);
    println!("extracted={extracted:?}\nformatted={formatted:?}\nreplaced={replaced:?}");
    assert!(extracted.contains("第一段正常正文内容。"));
    assert_eq!(
        formatted,
        "广告行1\n广告行2\n第一段正常正文内容。\n第二段正常正文内容。\n(本章完)\n最.新.小.说.发布"
    );
    assert!(replaced.contains("第一段正常正文内容。"));
    assert!(replaced.contains("第二段正常正文内容。"));
    assert!(!replaced.contains("最.新.小.说.发布"));
    // The end marker is not at EOF in this fixture, so its `$` branch cannot match.
    assert!(replaced.contains("(本章完)"));
}

#[test]
fn shuba69_compare_literal_and_template_replacement_inputs() {
    let engine = RuleEngine::new().unwrap();
    for (label, rule) in [
        ("none", None),
        ("literal", Some(PATTERN)),
        (
            "chapter_template",
            Some(
                r"##(^(.+\n){2}({{chapter.title}}.*\n)?)|(\n\uE5E5.*)+|(\n.*\(本章完\)$)|(\n最.新.小.说.+)",
            ),
        ),
        (
            "missing_book_title",
            Some(
                r"##(^(.+\n){2}({{book.durChapterTitle}}.*\n)?)|(\n\uE5E5.*)+|(\n.*\(本章完\)$)|(\n最.新.小.说.+)",
            ),
        ),
    ] {
        let output = engine.content_with_variables(
            &source(rule),
            BODY,
            BASE,
            None,
            None,
            Some("诡秘之主"),
            Some("第1章 绯红"),
        );
        println!("{label}={output:?}");
        match label {
            "none" => assert!(output.contains("广告行1\n广告行2\n第一段正常正文内容。")),
            "missing_book_title" => {
                // Diagnostic snapshot, not successful metadata propagation:
                // a missing book property expands to empty and broadens the source regex.
                assert_eq!(output, "第二段正常正文内容。\n(本章完)");
            }
            _ => assert_eq!(
                output,
                "第一段正常正文内容。\n第二段正常正文内容。\n(本章完)"
            ),
        }
    }
}
