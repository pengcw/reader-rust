//! Replacement errors and compatibility fallback through public parser APIs.
use reader_parser::model::book_source::BookSource;
use reader_parser::parser::js::eval_js;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::json;

const BASE: &str = "https://fixture.test";

#[test]
fn js_regex_replace_throws_for_invalid_references_without_exposing_partial_output() {
    let output = eval_js(
        r#"
        const replacements = ['$9', '$99', '${missing}', '${}', '${1x}', '${a_b}',
                              '${name', '$', '$x', '$$', String.fromCharCode(92),
                              'ok$1/${missing}', 'ok$1' + String.fromCharCode(92)];
        replacements.map(replacement => {
            try { return regex_replace('prefix a suffix a', '(a)', replacement); }
            catch (error) { return error instanceof TypeError ? 'rejected' : error.name; }
        }).join('|')
    "#,
        "",
        BASE,
    )
    .unwrap();
    assert_eq!(output, vec!["rejected"; 13].join("|"));
}

#[test]
fn js_regex_replace_does_not_validate_replacement_when_no_match_exists() {
    let output = eval_js(
        r#"
        ['$99', '${missing}', '$', String.fromCharCode(92)]
            .map(replacement => regex_replace('b', '(a)', replacement)).join('|')
    "#,
        "",
        BASE,
    )
    .unwrap();
    assert_eq!(output, "b|b|b|b");
}

#[test]
fn replacement_valid_groups_and_escapes_keep_java_semantics() {
    let output = eval_js(
        r#"
        [regex_replace('a', '(a)', '$0/$11'),
         regex_replace('abcdefghijk', '(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)(k)', '$11'),
         regex_replace('b', '(?<name>a)?b', '<${name}>'),
         regex_replace('a', '(a)', '\\$1'),
         regex_replace('a', '(a)', '\\q')].join('|')
    "#,
        "",
        BASE,
    )
    .unwrap();
    assert_eq!(output, "a/a1|k|<>|$1|q");
}

#[test]
fn unicode_zero_width_and_leading_zero_references_keep_java_boundaries() {
    let output = eval_js(r#"
        let rejected;
        try { regex_replace('中🙂', '', '$9'); }
        catch (error) { rejected = error.name; }
        [regex_replace('前中文🙂后中文', '(中文)', '<$0/$1>'),
         regex_replace('a', 'a', '\\🙂'),
         regex_replace('中🙂', '', 'X'), rejected,
         ['$00','$01','$09','$10'].map(replacement => regex_replace('ab', '(a)b', replacement)).join(',')].join('|')
    "#, "", BASE).unwrap();
    assert_eq!(
        output,
        "前<中文/中文>🙂后<中文/中文>|🙂|X中X🙂X|TypeError|ab,a,ab9,a0"
    );
}

#[test]
fn first_only_keeps_match_fragment_context_loss_and_original_on_invalid_replacement() {
    let output = eval_js(
        r#"
        [java.getString('##\\d+##<$0>##', 'x12y34'),
         java.getString('##(?<=chapter-)\\d+##<$0>##', 'chapter-12'),
         java.getString('##(\\d+)##$99##', 'x12y34'),
         java.getString('##z##$99##', 'abc')].join('|')
    "#,
        "",
        BASE,
    )
    .unwrap();
    assert_eq!(output, "<12>|12|x12y34|");
}

#[test]
fn invalid_pattern_keeps_each_existing_entry_point_fallback() {
    let output = eval_js(
        r#"
        [regex_replace('a[b', '[', 'X'),
         java.getString('##[##X', 'a[b'),
         java.getString('##[##X##', 'a[b')].join('|')
    "#,
        "",
        BASE,
    )
    .unwrap();
    assert_eq!(output, "a[b|aXb|X");
}

#[test]
fn invalid_replacement_preserves_the_combined_and_js_processed_field_text() {
    for (list, name, a, b, url, body) in [
        (
            "@css:.item",
            ".name@text",
            ".a@text",
            ".b@text",
            "a@href",
            r#"<div class="item"><span class="name">Book</span><i class="a">A1</i><i class="a">A2</i><i class="b">B1</i><a href="/book"></a></div>"#,
        ),
        (
            "$.items[*]",
            "$.name",
            "$.a[*]",
            "$.b[*]",
            "/book",
            r#"{"items":[{"name":"Book","a":["A1","A2"],"b":["B1"]}]}"#,
        ),
        (
            "@xpath://Item",
            "./Name",
            "./A",
            "./B",
            "./Url",
            r#"<?xml version="1.0"?><Root><Item><Name>Book</Name><A>A1</A><A>A2</A><B>B1</B><Url>/book</Url></Item></Root>"#,
        ),
    ] {
        for (operator, expected) in [("&&", "a1\na2\nb1"), ("||", "a1\na2"), ("%%", "a1\nb1\na2")] {
            let source: BookSource = serde_json::from_value(json!({
                "bookSourceUrl":BASE, "ruleSearch":{"bookList":list,"name":name,"bookUrl":url,
                    "author":format!("{a}{operator}{b}@js:result.toLowerCase()##(a)##ok$1/${{missing}}")}
            })).unwrap();
            let books = RuleEngine::new().unwrap().search_books(&source, body, BASE);
            assert_eq!(books.len(), 1, "{list} {operator}");
            assert_eq!(books[0].author, expected, "{list} {operator}");
        }
    }
}

#[test]
fn invalid_replacement_preserves_html_json_and_xpath_field_content() {
    for (list, name, author, url, body) in [
        (
            "@css:.item",
            ".name@text",
            ".author@text",
            "a@href",
            r#"<div class="item"><span class="name">Book</span><i class="author">Alice</i><a href="/book"></a></div>"#,
        ),
        (
            "$.items[*]",
            "$.name",
            "$.author",
            "/book",
            r#"{"items":[{"name":"Book","author":"Alice"}]}"#,
        ),
        (
            "@xpath://Item",
            "./Name",
            "./Author",
            "./Url",
            r#"<?xml version="1.0"?><Root><Item><Name>Book</Name><Author>Alice</Author><Url>/book</Url></Item></Root>"#,
        ),
    ] {
        let source: BookSource = serde_json::from_value(json!({
            "bookSourceUrl": BASE, "bookSourceName": "replacement fixture",
            "ruleSearch": {"bookList":list, "name":name,
                           "author":format!("{author}##(A)##${{missing}}"), "bookUrl":url}
        }))
        .unwrap();
        let books = RuleEngine::new().unwrap().search_books(&source, body, BASE);
        assert_eq!(books.len(), 1, "{list}");
        assert_eq!(books[0].name, "Book");
        assert_eq!(books[0].author, "Alice", "{list}");
        assert_eq!(books[0].book_url, format!("{BASE}/book"));
    }
}
