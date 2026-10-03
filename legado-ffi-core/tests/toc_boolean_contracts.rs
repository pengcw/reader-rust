//! Chapter flags follow Legado String?.isTrue(), not generic boolean parsing.
use reader_parser::model::book_source::BookSource;
use reader_parser::model::rule::TocRule;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::json;

const BASE: &str = "https://toc-flags.test/";
const CASES: &[(&str, bool)] = &[
    ("", false),
    (" \t", false),
    ("null", false),
    ("false", false),
    ("FALSE", false),
    (" no ", false),
    ("Not", false),
    ("0", false),
    ("0.0", false),
    (" 0.0 ", false),
    ("true", true),
    ("1", true),
    ("VIP", true),
    ("none", true),
    ("off", true),
    ("NULL", true),
    (" null ", true),
    ("00", true),
    ("0.00", true),
];

fn verify(body: &str, list: &str, name: &str, url: &str, flag: &str, cases: &[(&str, bool)]) {
    let source = BookSource {
        book_source_url: BASE.to_string(),
        rule_toc: Some(TocRule {
            chapter_list: Some(list.to_string()),
            chapter_name: Some(name.to_string()),
            chapter_url: Some(url.to_string()),
            is_volume: Some(flag.to_string()),
            is_vip: Some(flag.to_string()),
            is_pay: Some(flag.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let (chapters, _) = RuleEngine::new().unwrap().chapter_list(&source, body, BASE);
    assert_eq!(chapters.len(), cases.len());
    for (index, (chapter, (value, expected))) in chapters.iter().zip(cases).enumerate() {
        assert_eq!(
            (chapter.is_volume, chapter.is_vip, chapter.is_pay),
            (*expected, *expected, *expected),
            "{list}: flag {value:?}"
        );
        assert_eq!(chapter.index, index as i32);
        assert_eq!(chapter.url, format!("{BASE}chapter/{index}"));
    }
}

fn json_rows() -> String {
    json!(CASES.iter().enumerate().map(|(index, (flag, _))|
        json!({"name": format!("Chapter {index}"), "url": format!("/chapter/{index}"), "flag": flag})
    ).collect::<Vec<_>>()).to_string()
}

#[test]
fn json_chapter_flags_follow_exact_legado_string_rules() {
    verify(&json_rows(), "$[*]", "$.name", "$.url", "$.flag", CASES);
}

#[test]
fn js_list_chapter_flags_use_the_same_shared_truthiness() {
    verify(
        &json_rows(),
        "@js:JSON.parse(result)",
        "$.name",
        "$.url",
        "$.flag",
        CASES,
    );
}

#[test]
fn html_attribute_chapter_flags_use_the_same_shared_truthiness() {
    let body = CASES
        .iter()
        .enumerate()
        .map(|(index, (flag, _))| {
            format!("<a href='/chapter/{index}' data-flag='{flag}'>Chapter {index}</a>")
        })
        .collect::<String>();
    verify(&body, "a", "text", "href", "data-flag", CASES);
}

#[test]
fn xml_attribute_chapter_flags_use_the_same_shared_truthiness() {
    // XML parsers normalize literal tabs in attributes; use a character reference.
    let body = format!("<?xml version='1.0'?><Root>{}</Root>", CASES.iter().enumerate().map(|(index, (flag, _))|
        format!("<Chapter flag='{}'><Name>Chapter {index}</Name><Url>/chapter/{index}</Url></Chapter>", flag.replace('\t', "&#9;"))
    ).collect::<String>());
    // The existing XPath scalar field evaluator trims before boolean conversion.
    // Preserve that extraction contract; padded "null" therefore becomes false.
    let cases: Vec<_> = CASES
        .iter()
        .map(|&(flag, expected)| (flag, expected && flag.trim() != "null"))
        .collect();
    verify(
        &body,
        "@xpath://Chapter",
        "./Name",
        "./Url",
        "./@flag",
        &cases,
    );
}

#[test]
fn regex_capture_chapter_flags_use_the_same_shared_truthiness() {
    let body = CASES
        .iter()
        .enumerate()
        .map(|(index, (flag, _))| format!("[{index}|{flag}]"))
        .collect::<String>();
    verify(
        &body,
        r#":\[(\d+)\|([^\]]*)\]"#,
        "Chapter $1",
        "/chapter/$1",
        "$2",
        CASES,
    );
}
