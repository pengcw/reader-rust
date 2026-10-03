//! Minimal regression contracts isolating URL Option preservation:
//! - BUG-20: Relative URL resolution (`resolve_url`) strips and drops trailing URL options
//!   such as `,{"webView":true}` or `,{"headers":...}`.

use reader_parser::model::book_source::BookSource;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::json;

const BASE: &str = "https://www.pilishuwu.com/book/1001/";

#[test]
fn search_book_url_preserves_trailing_json_options_on_relative_path() {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "Search URL Option Fixture",
        "ruleSearch": {
            "bookList": "li",
            "name": "a@text",
            "bookUrl": "a@href##$##,{\"webView\":true}"
        }
    }))
    .unwrap();

    let engine = RuleEngine::new().unwrap();
    let html = r#"<ul><li><a href="/book/2001/">斗破苍穹</a></li></ul>"#;

    let books = engine.search_books(&source, html, BASE);
    assert_eq!(books.len(), 1);
    assert_eq!(
        books[0].book_url, "https://www.pilishuwu.com/book/2001/,{\"webView\":true}",
        "search_books must preserve trailing options JSON on relative paths"
    );
}

#[test]
fn search_book_url_preserves_options_with_nested_headers() {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "Search Headers Option Fixture",
        "ruleSearch": {
            "bookList": "li",
            "name": "a@text",
            "bookUrl": "a@href##$##,{\"headers\":{\"User-Agent\":\"CustomUA\"}}"
        }
    }))
    .unwrap();

    let engine = RuleEngine::new().unwrap();
    let html = r#"<ul><li><a href="/api/v1/book/1">斗罗大陆</a></li></ul>"#;

    let books = engine.search_books(&source, html, BASE);
    assert_eq!(books.len(), 1);
    assert_eq!(
        books[0].book_url,
        "https://www.pilishuwu.com/api/v1/book/1,{\"headers\":{\"User-Agent\":\"CustomUA\"}}",
        "search_books must preserve nested headers options"
    );
}

#[test]
fn book_info_toc_url_preserves_options_after_regex_replacement() {
    // In Pili Shuwu: ruleBookInfo.tocUrl: "text.章节目录@href##$##,{\"webView\":true}"
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "Pili Fixture",
        "ruleBookInfo": {
            "name": "h1@text",
            "tocUrl": "text.章节目录@href##$##,{\"webView\":true}"
        }
    }))
    .unwrap();

    let engine = RuleEngine::new().unwrap();
    let html = r#"
        <h1>吞噬星空</h1>
        <div class="actions">
            <a class="btn" href="/toc/1001/">章节目录</a>
        </div>
    "#;

    let book = engine.book_info(&source, html, BASE, BASE);
    assert_eq!(book.name, "吞噬星空");
    assert_eq!(
        book.toc_url.as_deref(),
        Some("https://www.pilishuwu.com/toc/1001/,{\"webView\":true}"),
        "BookInfo tocUrl must retain webView option after resolution"
    );
}

#[test]
fn chapter_url_preserves_options_when_relative_path_with_options() {
    let source: BookSource = serde_json::from_value(json!({
        "bookSourceUrl": BASE,
        "bookSourceName": "Chapter URL Option Fixture",
        "ruleToc": {
            "chapterList": "li",
            "chapterName": "a@text",
            "chapterUrl": "a@href##$##,{\"webView\":true}"
        }
    }))
    .unwrap();

    let engine = RuleEngine::new().unwrap();
    let html = r#"
        <ul>
            <li><a href="/chapter/1.html">第1章</a></li>
        </ul>
    "#;

    let (chapters, _) = engine.chapter_list(&source, html, BASE);
    assert_eq!(chapters.len(), 1);
    assert_eq!(
        chapters[0].url, "https://www.pilishuwu.com/chapter/1.html,{\"webView\":true}",
        "Chapter URL must retain webView option after resolution"
    );
}
