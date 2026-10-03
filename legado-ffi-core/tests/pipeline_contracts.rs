//! Regression tests for book source pipelines: TOC ordering, volume identity,
//! truthy booleans, AllInOne regex captures, and content formatting.
use reader_parser::model::book_source::BookSource;
use reader_parser::model::rule::{ContentRule, TocRule};
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::json;

const BASE: &str = "https://fixture.test";

fn empty_source() -> BookSource {
    serde_json::from_value(json!({
        "bookSourceName": "Pipeline fixture",
        "bookSourceUrl": BASE
    }))
    .unwrap()
}

#[test]
fn toc_ordering_with_and_without_minus_prefix() {
    let mut normal_source = empty_source();
    normal_source.rule_toc = Some(TocRule {
        chapter_list: Some("$.chapters[*]".to_string()),
        chapter_name: Some("$.title".to_string()),
        chapter_url: Some("$.url".to_string()),
        ..Default::default()
    });

    let mut reverse_source = empty_source();
    reverse_source.rule_toc = Some(TocRule {
        chapter_list: Some("-$.chapters[*]".to_string()),
        chapter_name: Some("$.title".to_string()),
        chapter_url: Some("$.url".to_string()),
        ..Default::default()
    });

    let body = json!({
        "chapters": [
            {"title": "Chapter 1", "url": "/c1"},
            {"title": "Chapter 2", "url": "/c2"},
            {"title": "Chapter 3", "url": "/c3"}
        ]
    })
    .to_string();

    let engine = RuleEngine::new().unwrap();
    let (normal_chapters, _) = engine.chapter_list(&normal_source, &body, BASE);
    let (reverse_chapters, _) = engine.chapter_list(&reverse_source, &body, BASE);

    let normal_titles: Vec<&str> = normal_chapters.iter().map(|c| c.title.as_str()).collect();
    let reverse_titles: Vec<&str> = reverse_chapters.iter().map(|c| c.title.as_str()).collect();

    assert_eq!(
        normal_titles,
        vec!["Chapter 1", "Chapter 2", "Chapter 3"],
        "Normal chapterList without '-' should preserve normal ascending order"
    );
    assert_eq!(
        reverse_titles,
        vec!["Chapter 3", "Chapter 2", "Chapter 1"],
        "ChapterList with '-' prefix should reverse the list"
    );
}

#[test]
fn is_volume_truthy_values_adhere_to_legado_specification() {
    let mut source = empty_source();
    source.rule_toc = Some(TocRule {
        chapter_list: Some("$.items[*]".to_string()),
        chapter_name: Some("$.title".to_string()),
        chapter_url: Some("$.url".to_string()),
        is_volume: Some("$.vol".to_string()),
        ..Default::default()
    });

    let body = json!({
        "items": [
            {"title": "Item 1", "url": "/1", "vol": "true"},
            {"title": "Item 2", "url": "/2", "vol": "1"},
            {"title": "Item 3", "url": "/3", "vol": "VIP"},
            {"title": "Item 4", "url": "/4", "vol": "false"},
            {"title": "Item 5", "url": "/5", "vol": "0"},
            {"title": "Item 6", "url": "/6", "vol": "null"},
            {"title": "Item 7", "url": "/7", "vol": "not"},
            {"title": "Item 8", "url": "/8", "vol": ""}
        ]
    })
    .to_string();

    let engine = RuleEngine::new().unwrap();
    let (chapters, _) = engine.chapter_list(&source, &body, BASE);
    assert_eq!(chapters.len(), 8);

    assert!(chapters[0].is_volume, "'true' must be truthy");
    assert!(chapters[1].is_volume, "'1' must be truthy");
    assert!(chapters[2].is_volume, "'VIP' must be truthy in Legado");
    assert!(!chapters[3].is_volume, "'false' must be falsy");
    assert!(!chapters[4].is_volume, "'0' must be falsy");
    assert!(!chapters[5].is_volume, "'null' must be falsy");
    assert!(!chapters[6].is_volume, "'not' must be falsy");
    assert!(!chapters[7].is_volume, "empty string must be falsy");
}

#[test]
fn empty_url_volume_chapter_generates_distinct_synthetic_id() {
    let mut source = empty_source();
    source.rule_toc = Some(TocRule {
        chapter_list: Some("$.items[*]".to_string()),
        chapter_name: Some("$.title".to_string()),
        chapter_url: Some("$.url".to_string()),
        is_volume: Some("$.is_vol".to_string()),
        ..Default::default()
    });

    let body = json!({
        "items": [
            {"title": "卷一 人间", "url": "", "is_vol": "true"},
            {"title": "第一章 起源", "url": "/c1", "is_vol": "false"},
            {"title": "卷二 天界", "url": "", "is_vol": "true"},
            {"title": "第二章 飞升", "url": "/c2", "is_vol": "false"}
        ]
    })
    .to_string();

    let engine = RuleEngine::new().unwrap();
    let (chapters, _) = engine.chapter_list(&source, &body, BASE);
    assert_eq!(chapters.len(), 4);

    assert!(chapters[0].is_volume);
    assert!(!chapters[0].url.is_empty(), "volume url must not be empty");
    assert!(chapters[2].is_volume);
    assert!(!chapters[2].url.is_empty());
    assert_ne!(
        chapters[0].url, chapters[2].url,
        "Distinct volume chapters must have distinct synthetic URLs"
    );
}

#[test]
fn all_in_one_regex_substitutes_numbered_groups_and_preserves_dollar_zero() {
    let mut source = empty_source();
    source.rule_toc = Some(TocRule {
        chapter_list: Some(r#":<a href="([^"]+)">([^<]+)</a>"#.to_string()),
        chapter_name: Some("$2 ($0)".to_string()),
        chapter_url: Some("$1".to_string()),
        ..Default::default()
    });

    let body = r#"
        <div class="list">
            <a href="/chap/10">第十章 决战</a>
            <a href="/chap/11">第十一章 落幕</a>
        </div>
    "#;

    let engine = RuleEngine::new().unwrap();
    let (chapters, _) = engine.chapter_list(&source, body, BASE);
    assert_eq!(chapters.len(), 2);

    assert_eq!(chapters[0].url, format!("{BASE}/chap/10"));
    assert_eq!(
        chapters[0].title, "第十章 决战 ($0)",
        "$0 in Legado AllInOne regex must remain literal '$0' rather than full match"
    );

    assert_eq!(chapters[1].url, format!("{BASE}/chap/11"));
    assert_eq!(chapters[1].title, "第十一章 落幕 ($0)");
}

#[test]
fn content_clean_and_replace_regex_pipeline() {
    let mut source = empty_source();
    source.rule_content = Some(ContentRule {
        content: Some("#content@text".to_string()),
        replace_regex: Some("##ad_block##".to_string()),
        ..Default::default()
    });

    let body = r#"
        <div id="content">
            第一行正文
            ad_block
            第二行正文
        </div>
    "#;

    let engine = RuleEngine::new().unwrap();
    let content = engine.content(&source, body, BASE);

    assert!(
        !content.contains("ad_block"),
        "replace_regex should remove ad_block from content"
    );
    assert!(
        content.contains("第一行正文"),
        "Original content line 1 should be retained"
    );
    assert!(
        content.contains("第二行正文"),
        "Original content line 2 should be retained"
    );
}

#[test]
fn html_content_replacement_preserves_paragraphs_without_online_txt_indentation() {
    let mut source = empty_source();
    source.rule_content = Some(ContentRule {
        content: Some("#content@html".to_string()),
        replace_regex: Some("##ad##".to_string()),
        ..Default::default()
    });

    let body = r#"<div id="content"><p>第一行</p><p>第二行</p></div>"#;
    let engine = RuleEngine::new().unwrap();
    let content = engine.content(&source, body, BASE);
    // Original BookContent only adds this indentation for book.isOnLineTxt.
    // HTML extraction should retain both paragraphs, without unconditional indentation.
    assert_eq!(content, "第一行\n第二行");
}
