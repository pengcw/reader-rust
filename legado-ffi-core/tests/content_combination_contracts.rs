//! Minimal regression contracts isolating content rule combinations:
//! - BUG-16: Interleaved list merging via `%%` (.line_en@text%%.line_cn@title)
//! - BUG-18: Inline regex replacement via `##` (content##regex##replacement)
//! - Negative indexing on elements (a.-1@href)

use reader_parser::model::book_source::BookSource;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::json;

const BASE: &str = "https://fixture.test/book/101/1.html";

fn content_source(
    content_rule: &str,
    replace_regex: Option<&str>,
    next_rule: Option<&str>,
) -> BookSource {
    let mut rule = json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "Content Combination Fixture",
        "ruleContent": {
            "content": content_rule,
        }
    });
    if let Some(r) = replace_regex {
        rule["ruleContent"]["replaceRegex"] = json!(r);
    }
    if let Some(n) = next_rule {
        rule["ruleContent"]["nextContentUrl"] = json!(n);
    }
    serde_json::from_value(rule).unwrap()
}

#[test]
fn content_interleaved_percent_merges_two_selectors_alternating() {
    let source = content_source(".line_en@text%%.line_cn@title", None, None);
    let engine = RuleEngine::new().unwrap();

    let html = r#"
        <div class="content">
            <p class="line_en">Chapter 1. A New Beginning.</p>
            <p class="line_cn" title="第一章 新的开始。">（点击看译文）</p>
            <p class="line_en">The morning sun shone brightly.</p>
            <p class="line_cn" title="清晨的阳光格外明媚。">（点击看译文）</p>
        </div>
    "#;

    let text = engine.content_with_variables(
        &source,
        html,
        BASE,
        None,
        None,
        Some("双语小说"),
        Some("Chapter 1"),
    );

    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(
        lines,
        vec![
            "Chapter 1. A New Beginning.",
            "第一章 新的开始。",
            "The morning sun shone brightly.",
            "清晨的阳光格外明媚。"
        ],
        "%% must alternate lines between .line_en@text and .line_cn@title"
    );
}

#[test]
fn content_interleaved_percent_with_unequal_lengths() {
    let source = content_source(".item_a@text%%.item_b@text", None, None);
    let engine = RuleEngine::new().unwrap();

    let html = r#"
        <div>
            <span class="item_a">A1</span>
            <span class="item_b">B1</span>
            <span class="item_a">A2</span>
            <span class="item_b">B2</span>
            <span class="item_a">A3</span>
        </div>
    "#;

    let text = engine.content_with_variables(&source, html, BASE, None, None, None, None);
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(
        lines,
        vec!["A1", "B1", "A2", "B2", "A3"],
        "First group has three items"
    );
    let reversed = content_source(".item_b@text%%.item_a@text", None, None);
    assert_eq!(
        engine
            .content(&reversed, html, BASE)
            .lines()
            .collect::<Vec<_>>(),
        vec!["B1", "A1", "B2", "A2"],
        "Later group is bounded by first group length"
    );
    let missing = content_source(".missing@text%%.item_b@text%%.item_a@text", None, None);
    assert_eq!(
        engine
            .content(&missing, html, BASE)
            .lines()
            .collect::<Vec<_>>(),
        vec!["B1", "A1", "B2", "A2"],
        "Empty groups do not determine the interleave length"
    );
}

#[test]
fn content_inline_regex_replacement_deletes_when_no_replacement() {
    let source = content_source("class.txtnav@text##广告行\\d+", None, None);
    let engine = RuleEngine::new().unwrap();

    let html = r#"
        <div class="txtnav">
            广告行1
            广告行2
            第一行真正的正文内容。
            第二行真正的正文内容。
        </div>
    "#;

    let text = engine.content_with_variables(&source, html, BASE, None, None, None, None);
    assert!(
        !text.contains("广告行1"),
        "Inline ## without replacement should delete matches: {text}"
    );
    assert!(
        !text.contains("广告行2"),
        "Inline ## without replacement should delete matches: {text}"
    );
    assert!(text.contains("第一行真正的正文内容"));
    assert!(text.contains("第二行真正的正文内容"));
}

#[test]
fn content_inline_regex_start_anchor_does_not_retry_after_first_deletion() {
    let source = content_source(".line@text##^广告行\\d+\\n?", None, None);
    let text = RuleEngine::new().unwrap().content(
        &source,
        "<p class='line'>广告行1</p><p class='line'>广告行2</p><p class='line'>正文</p>",
        BASE,
    );
    assert_eq!(text, "广告行2\n正文");
}

#[test]
fn content_inline_regex_replacement_spans_combined_selection_once() {
    let source = content_source(
        ".a@text&&.b@text##A\\nB##Joined",
        Some("##Joined##Final"),
        None,
    );
    let text =
        RuleEngine::new()
            .unwrap()
            .content(&source, "<p class='a'>A</p><p class='b'>B</p>", BASE);
    assert_eq!(text, "Final");
}

#[test]
fn content_combination_trailing_js_receives_complete_interleaved_result() {
    let source = content_source(
        ".a@text%%.b@text@js:result.replace(/\\n/g, '|')",
        None,
        None,
    );
    let text = RuleEngine::new().unwrap().content(
        &source,
        "<p class='a'>A1</p><p class='a'>A2</p><p class='b'>B1</p><p class='b'>B2</p>",
        BASE,
    );
    assert_eq!(text, "A1|B1|A2|B2");
}

#[test]
fn content_inline_regex_replacement_with_custom_replacement_string() {
    let source = content_source("id.content@text##笔趣阁##正版书店", None, None);
    let engine = RuleEngine::new().unwrap();

    let html = r#"<div id="content">欢迎来到笔趣阁阅读正文。</div>"#;

    let text = engine.content_with_variables(&source, html, BASE, None, None, None, None);
    assert!(
        text.contains("欢迎来到正版书店阅读正文。"),
        "Inline ##regex##replacement should substitute text, got: {text}"
    );
}

#[test]
fn content_next_page_url_negative_indexing() {
    let source = content_source("id.content@text", None, Some("class.pagebar@tag.a.-1@href"));
    let engine = RuleEngine::new().unwrap();

    let html = r#"
        <div id="content">第1页内容</div>
        <div class="pagebar">
            <a href="/page/1.html">1</a>
            <a href="/page/2.html">2</a>
            <a href="/page/3.html">下一页</a>
        </div>
    "#;

    let next_url = engine.next_content_url(&source, html, BASE);
    assert_eq!(
        next_url.as_deref(),
        Some("https://fixture.test/page/3.html"),
        "a.-1@href must select the last matching anchor"
    );
}
