//! Jsoup selector contracts through the project adapter and RuleEngine.
//! jQuery-only aliases and negative indices are not Jsoup contracts.

use reader_parser::model::book_source::book_source_from_value;
use reader_parser::parser::html;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::json;

/// First child and first element of its type.
#[test]
fn test_tdd_jsoup_01_first_pseudo() {
    let html = r#"
        <ul class="chapters">
            <li><a href="/c1">第1章 初始</a></li>
            <li><a href="/c2">第2章 进阶</a></li>
            <li><a href="/c3">第3章 终局</a></li>
        </ul>
    "#;
    let doc = html::parse_document(html);

    // :first-child
    let res1 = html::select_text_list(&doc, "ul.chapters li:first-child a@text");
    assert_eq!(res1, vec!["第1章 初始"]);

    // :first-of-type
    let res2 = html::select_text_list(&doc, "ul.chapters li:first-of-type a@text");
    assert_eq!(res2, vec!["第1章 初始"]);
}

/// Last child and last element of its type.
#[test]
fn test_tdd_jsoup_02_last_pseudo() {
    let html = r#"
        <ul class="chapters">
            <li><a href="/c1">第1章 初始</a></li>
            <li><a href="/c2">第2章 进阶</a></li>
            <li><a href="/c3">第3章 终局</a></li>
        </ul>
    "#;
    let doc = html::parse_document(html);

    // :last-child
    let res1 = html::select_text_list(&doc, "ul.chapters li:last-child a@text");
    assert_eq!(res1, vec!["第3章 终局"]);

    // :last-of-type
    let res2 = html::select_text_list(&doc, "ul.chapters li:last-of-type a@text");
    assert_eq!(res2, vec!["第3章 终局"]);
}

/// CSS nth-child indices are one-based.
#[test]
fn test_tdd_jsoup_03_even_and_odd_pseudo() {
    let html = r#"
        <table class="grid">
            <tr class="row"><td class="num">0</td></tr>
            <tr class="row"><td class="num">1</td></tr>
            <tr class="row"><td class="num">2</td></tr>
            <tr class="row"><td class="num">3</td></tr>
        </table>
    "#;
    let doc = html::parse_document(html);

    // CSS odd 表示第 1、3 行
    let even_res = html::select_text_list(&doc, "tr.row:nth-child(odd) td.num@text");
    assert_eq!(even_res, vec!["0", "2"]);

    // CSS even 表示第 2、4 行
    let odd_res = html::select_text_list(&doc, "tr.row:nth-child(even) td.num@text");
    assert_eq!(odd_res, vec!["1", "3"]);
}

/// Empty and nonempty elements.
#[test]
fn test_tdd_jsoup_04_parent_and_empty_pseudo() {
    let html = r#"
        <div class="box" id="b1">有内容</div>
        <div class="box" id="b2"><span>子标签</span></div>
        <div class="box empty" id="b3"></div>
    "#;
    let doc = html::parse_document(html);

    // :not(:empty) 匹配非空节点
    let parent_ids = html::select_text_list(&doc, "div.box:not(:empty)@id");
    assert_eq!(parent_ids, vec!["b1", "b2"]);

    // :empty 匹配空节点
    let empty_ids = html::select_text_list(&doc, "div.box:empty@id");
    assert_eq!(empty_ids, vec!["b3"]);
}

/// 5. 测试 :eq, :lt, :gt 索引伪类（带空白与负数索引）
#[test]
fn test_tdd_jsoup_05_eq_lt_gt_pseudo() {
    let html = r#"
        <div class="list">
            <span class="item">A</span>
            <span class="item">B</span>
            <span class="item">C</span>
            <span class="item">D</span>
        </div>
    "#;
    let doc = html::parse_document(html);

    // 带空白的 :eq( 1 )
    let eq_res = html::select_text_list(&doc, "span.item:eq( 1 )@text");
    assert_eq!(eq_res, vec!["B"]);

    // Jsoup 不接受负数索引；本项目无匹配结果。
    let neg_res = html::select_text_list(&doc, "span.item:eq(-1)@text");
    assert!(neg_res.is_empty());

    // :lt(2) 匹配索引 < 2 的元素 (A, B)
    let lt_res = html::select_text_list(&doc, "span.item:lt( 2 )@text");
    assert_eq!(lt_res, vec!["A", "B"]);

    // :gt(1) 匹配索引 > 1 的元素 (C, D)
    let gt_res = html::select_text_list(&doc, "span.item:gt( 1 )@text");
    assert_eq!(gt_res, vec!["C", "D"]);
}

/// 6. 测试 :contains 与 :containsOwn 文本过滤伪类
#[test]
fn test_tdd_jsoup_06_contains_and_contains_own() {
    let html = r#"
        <div class="book-info">
            <div class="tag" id="t1">标签：<span>玄幻修真</span></div>
            <div class="tag" id="t2">纯文本玄幻</div>
            <div class="tag" id="t3">都市言情</div>
        </div>
    "#;
    let source = json!({
        "bookSourceName": "Jsoup Contains Test",
        "bookSourceUrl": "https://example.com",
        "ruleSearch": {
            "bookList": ".book-info",
            "name": ".tag:containsOwn(玄幻)@text",
            "author": ".tag:contains(修真)@text"
        }
    });
    let parsed_source = book_source_from_value(source).unwrap();
    let engine = RuleEngine::new().unwrap();

    let books = engine.search_books(&parsed_source, html, "https://example.com");
    assert_eq!(books.len(), 1);
    // containsOwn 只命中纯文本直接包含 "玄幻" 的 t2，不穿透 t1 的 span
    assert_eq!(books[0].name, "纯文本玄幻");
    // contains 穿透命中包含 "修真" 的 t1
    assert_eq!(books[0].author, "标签： 玄幻修真");
}

/// 7. 测试 :has 伪类与子代选择器及 Jsoup 复杂嵌套
#[test]
fn test_tdd_jsoup_07_has_nested_pseudo() {
    let html = r#"
        <div class="catalog">
            <div class="volume" id="v1">
                <h3>第一卷 凡人篇</h3>
                <span class="status">完结</span>
            </div>
            <div class="volume" id="v2">
                <h3>第二卷 仙界篇</h3>
                <span class="status">连载中</span>
            </div>
        </div>
    "#;
    let source = json!({
        "bookSourceName": "Jsoup Has Test",
        "bookSourceUrl": "https://example.com",
        "ruleSearch": {
            "bookList": ".volume:has(span:contains(完结))",
            "name": "h3@text"
        }
    });
    let parsed_source = book_source_from_value(source).unwrap();
    let engine = RuleEngine::new().unwrap();

    let books = engine.search_books(&parsed_source, html, "https://example.com");
    assert_eq!(books.len(), 1);
    assert_eq!(books[0].name, "第一卷 凡人篇");
}

/// 8. 测试 :contains 与兄弟组合器 (+ 与 ~) 级联查找
#[test]
fn test_tdd_jsoup_08_sibling_combinators_with_contains() {
    let html = r#"
        <dl class="meta">
            <dt>作者</dt><dd>忘语</dd>
            <dt>最新章节</dt><dd><a href="/ch999">第999章 大结局</a></dd>
            <dt>其他信息</dt><dd>字数 500 万</dd>
        </dl>
    "#;
    let source = json!({
        "bookSourceName": "Jsoup Sibling Test",
        "bookSourceUrl": "https://example.com",
        "ruleSearch": {
            "bookList": ".meta",
            "name": "dt:contains(最新章节) + dd a@text",
            "author": "dt:contains(作者) + dd@text"
        }
    });
    let parsed_source = book_source_from_value(source).unwrap();
    let engine = RuleEngine::new().unwrap();

    let books = engine.search_books(&parsed_source, html, "https://example.com");
    assert_eq!(books.len(), 1);
    assert_eq!(books[0].name, "第999章 大结局");
    assert_eq!(books[0].author, "忘语");
}

/// Nested has/contains through the chapter-list entry point.
#[test]
fn test_tdd_jsoup_09_end_to_end_chapter_list_contract() {
    let html = r#"
        <div class="chapter-wrapper">
            <ul class="list">
                <li class="chapter"><a href="/1">第1章</a></li>
                <li class="chapter vip"><a href="/2">第2章 (VIP)</a></li>
                <li class="chapter"><a href="/3">第3章</a></li>
                <li class="chapter vip"><a href="/4">第4章 (VIP)</a></li>
                <li class="chapter"><a href="/5">第5章</a></li>
            </ul>
        </div>
    "#;

    // 只提取 VIP 章节。
    let source = json!({
        "bookSourceName": "Jsoup VIP TOC Test",
        "bookSourceUrl": "https://example.com",
        "ruleToc": {
            "chapterList": "ul.list li:has(a:contains(VIP))",
            "chapterName": "a@text",
            "chapterUrl": "a@href"
        }
    });
    let parsed_source = book_source_from_value(source).unwrap();
    let engine = RuleEngine::new().unwrap();

    let (chapters, _) = engine.chapter_list(&parsed_source, html, "https://example.com");
    assert_eq!(chapters.len(), 2);
    assert_eq!(chapters[0].title, "第2章 (VIP)");
    assert_eq!(chapters[1].title, "第4章 (VIP)");
}

#[test]
fn jquery_aliases_are_not_jsoup_selectors() {
    let doc = html::parse_document("<div>A</div><div>B</div>");
    for pseudo in [
        ":first", ":first()", ":last", ":last()", ":even", ":odd", ":parent",
    ] {
        assert!(
            html::select_text_list(&doc, &format!("div{pseudo}@text")).is_empty(),
            "{pseudo}"
        );
    }
}

#[test]
fn indices_count_all_element_siblings_per_parent() {
    let doc = html::parse_document(
        "<section><i>skip</i>text<!-- comment --><b class=item>A</b><b class=item>B</b></section>         <section><b class=item>C</b><i>skip</i><b class=item>D</b></section>",
    );
    for (selector, expected) in [
        ("b.item:eq( 1 )@text", vec!["A"]),
        ("b.item:eq(0)@text", vec!["C"]),
        ("b.item:lt( 2 )@text", vec!["A", "C"]),
        ("b.item:gt( 1 )@text", vec!["B", "D"]),
    ] {
        assert_eq!(
            html::select_text_list(&doc, selector),
            expected,
            "{selector}"
        );
    }
}

#[test]
fn pseudo_text_in_attributes_is_literal() {
    let doc = html::parse_document(
        r#"<div data-rule=":eq( 1 )">index</div><div data-rule=":first">alias</div>"#,
    );
    for (selector, expected) in [
        (r#"div[data-rule=":eq( 1 )"]@text"#, "index"),
        (r#"div[data-rule=':first']@text"#, "alias"),
    ] {
        assert_eq!(html::select_text_list(&doc, selector), vec![expected]);
    }
}

#[test]
fn contains_general_sibling_does_not_cross_parent() {
    let doc = html::parse_document(
        "<dl><dt>作者</dt><dd>A</dd><dt>其他</dt><dd>B</dd></dl><dl><dd>C</dd></dl>",
    );
    assert_eq!(
        html::select_text_list(&doc, "dt:contains(作者) ~ dd@text"),
        vec!["A", "B"],
    );
}

#[test]
fn has_nested_contains_own_and_not_filters_descendants() {
    let doc = html::parse_document(
        "<article id=a><span>VIP</span></article>         <article id=b><span class=disabled>VIP</span></article>         <article id=c><span><b>VIP</b></span></article>         <article id=d><span>普通</span></article>",
    );
    assert_eq!(
        html::select_text_list(&doc, "article:has(span:not(.disabled):containsOwn(VIP))@id"),
        vec!["a"],
    );
}

#[test]
fn grouped_pseudos_deduplicate_in_document_order() {
    let doc = html::parse_document("<p id=a>Alpha</p><p id=b>Beta</p><p id=c>Alpha Beta</p>");
    assert_eq!(
        html::select_text_list(&doc, "p:contains(Beta), p:contains(Alpha)@id"),
        vec!["a", "b", "c"],
    );
    let source = book_source_from_value(json!({
        "bookSourceName": "scoped grouping", "bookSourceUrl": "https://example.com",
        "ruleSearch": {"bookList": "section", "name": "p:contains(Beta), p:contains(Alpha)@text"}
    }))
    .unwrap();
    let engine = RuleEngine::new().unwrap();
    let books = engine.search_books(&source,
        "<aside><p>Alpha outside</p></aside><section><p>Alpha</p><p>Beta</p><p>Alpha Beta</p></section>",
        "https://example.com");
    assert_eq!(books.len(), 1);
    // Scalar field extraction retains the first match in document order.
    assert_eq!(books[0].name, "Alpha");
}

#[test]
fn has_preserves_quoted_attribute_pseudo_text_and_parentheses() {
    let doc = html::parse_document(
        r#"<article id=a><span data-label=":contains(VIP), (draft)">A</span></article>
           <article id=b><span data-label="other">B</span></article>"#,
    );
    assert_eq!(
        html::select_text_list(
            &doc,
            r#"article:has(span[data-label=":contains(VIP), (draft)"])@id"#
        ),
        vec!["a"],
    );
}

#[test]
fn commas_inside_contains_and_has_are_not_outer_groups() {
    let doc = html::parse_document(
        "<article id=a><span>A,B</span></article><article id=b><a>C</a></article><article id=c><i>D</i></article>",
    );
    assert_eq!(
        html::select_text_list(&doc, "span:contains(A,B)@text"),
        vec!["A,B"]
    );
    assert_eq!(
        html::select_text_list(&doc, "article:has(span:contains(A,B), a)@id"),
        vec!["a", "b"]
    );
    assert_eq!(
        html::select_text_list(&doc, "article:has(span:contains(A,B), a), article#c@id"),
        vec!["a", "b", "c"]
    );
}

#[test]
fn contains_unescapes_parentheses_and_literal_backslashes() {
    let doc = html::parse_document(r"<p id=a>A(B)</p><p id=b>A\B</p><p id=c>other</p>");
    for (selector, expected) in [
        (r"p:contains(A\(B\))@id", "a"),
        (r"p:contains(A\\B)@id", "b"),
    ] {
        assert_eq!(
            html::select_text_list(&doc, selector),
            vec![expected],
            "{selector}"
        );
    }
}

#[test]
fn has_child_text_predicate_excludes_grandchildren() {
    let body = "<article id=a><span>VIP</span></article>\
        <article id=b><div><span>VIP</span></div></article>\
        <article id=c><span>普通</span></article>";
    let doc = html::parse_document(body);
    for selector in [
        "article:has(> span:contains(VIP))@id",
        "article:has(> span:containsOwn(VIP))@id",
        "article:has(> span:matches(^VIP$))@id",
    ] {
        assert_eq!(
            html::select_text_list(&doc, selector),
            vec!["a"],
            "{selector}"
        );
    }
    let source = book_source_from_value(json!({
        "bookSourceName":"child has", "bookSourceUrl":"https://example.com",
        "ruleSearch":{"bookList":"article:has(> span:contains(VIP))", "name":"span@text"}
    }))
    .unwrap();
    let books = RuleEngine::new()
        .unwrap()
        .search_books(&source, body, "https://example.com");
    assert_eq!(books.len(), 1);
    assert_eq!(books[0].name, "VIP");
}

#[test]
fn sibling_suffix_preserves_attribute_spaces_and_child_relationships() {
    let doc = html::parse_document(
        "<dl><dt><span>作者</span></dt><dd data-label='a b'><a>A</a><div><a>nested</a></div></dd>\
         <dd data-label='a b'><a>B</a></dd></dl><dl><dd data-label='a b'><a>outside</a></dd></dl>",
    );
    for predicate in [
        "dt:contains(作者)",
        "dt:matches(作者)",
        "dt:has(span:contains(作者))",
    ] {
        for (suffix, expected) in [
            (" + dd[data-label=\"a b\"] a@text", vec!["A", "nested"]),
            (" + dd[data-label=\"a b\"] > a@text", vec!["A"]),
            (" ~ dd[data-label=\"a b\"] > a@text", vec!["A", "B"]),
            ("+dd[data-label=\"a b\"]>a@text", vec!["A"]),
        ] {
            let rule = format!("{predicate}{suffix}");
            assert_eq!(html::select_text_list(&doc, &rule), expected, "{rule}");
        }
    }
}

#[test]
fn has_handles_individually_escaped_parentheses_and_inner_commas() {
    let doc = html::parse_document(
        "<article id=a><span>A)B,C</span></article>\
         <article id=b><span>A(B,C</span></article><article id=c><i>plain</i></article>",
    );
    for (rule, expected) in [
        (r"article:has(span:contains(A\)B,C))@id", vec!["a"]),
        (r"article:has(span:contains(A\(B,C))@id", vec!["b"]),
        (r"article:has(span:contains(A\)B,C), i)@id", vec!["a", "c"]),
        (
            r"article:has(span:contains(A\(B,C)), article#c@id",
            vec!["b", "c"],
        ),
    ] {
        assert_eq!(html::select_text_list(&doc, rule), expected, "{rule}");
    }
}
