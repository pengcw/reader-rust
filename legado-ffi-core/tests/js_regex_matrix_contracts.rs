//! Native string/ECMAScript replacement and the Android-compatible Java bridge
//! intentionally have different replacement grammars and Unicode boundaries.
use reader_parser::parser::js::eval_js;
use serde_json::{json, Value};

fn evaluate(script: &str) -> Value {
    serde_json::from_str(&eval_js(script, "", "https://fixture.invalid/").unwrap()).unwrap()
}

#[test]
fn replacement_count_and_capture_grammar_remain_entry_point_specific() {
    let result = evaluate(
        r#"
        let invalidJava;
        try { regex_replace('a', 'a', '$&'); }
        catch (error) { invalidJava = error instanceof TypeError; }
        JSON.stringify([
            'a1a2'.replace('a', 'X'),
            'a1a2'.replace(/a/g, 'X'),
            regex_replace('a1a2', 'a', 'X'),
            'a1a2'.replace(/a/g, '<$&>'),
            regex_replace('a1a2', 'a', '<$0>'),
            'a'.replace(/(a)/, '$0/$1'),
            regex_replace('a', '(a)', '$0/$1'),
            'a'.replace('a', '$1'), invalidJava
        ]);
    "#,
    );
    assert_eq!(
        result,
        json!(["X1a2", "X1X2", "X1X2", "<a>1<a>2", "<a>1<a>2", "$0/a", "a/a", "$1", true])
    );
}

#[test]
fn emoji_and_zero_width_use_utf16_or_unicode_boundaries_as_requested() {
    let result = evaluate(
        r#"
        const units = text => Array.from({length:text.length}, (_, i) => text.charCodeAt(i));
        JSON.stringify([
            '🙂'.replace(/./g, 'X'),
            '🙂'.replace(/./gu, 'X'),
            regex_replace('🙂', '.', 'X'),
            units('中🙂'.replace('', 'X')),
            units('中🙂'.replace(/(?:)/g, 'X')),
            units('中🙂'.replace(/(?:)/gu, 'X')),
            units(regex_replace('中🙂', '', 'X')),
            '中🙂'.replace(/$/g, 'X'),
            regex_replace('中🙂', '$', 'X'),
            ''.replace(/$/g, 'X'), regex_replace('', '$', 'X')
        ]);
    "#,
    );
    assert_eq!(
        result,
        json!([
            "XX",
            "X",
            "X",
            [88, 20013, 55357, 56898],
            [88, 20013, 88, 55357, 88, 56898, 88],
            [88, 20013, 88, 55357, 56898, 88],
            [88, 20013, 88, 55357, 56898, 88],
            "中🙂X",
            "中🙂X",
            "X",
            "X"
        ])
    );
}

#[test]
fn unicode_classes_and_case_folding_do_not_become_ascii_only() {
    let result = evaluate(
        r#"
        const text = '中١A　';
        JSON.stringify([
            text.replace(/\w/g, 'X'), regex_replace(text, '\\w', 'X'),
            text.replace(/\d/g, 'X'), regex_replace(text, '\\d', 'X'),
            text.replace(/\p{L}/gu, 'X'), regex_replace(text, '\\p{L}', 'X'),
            text.replace(/\s/g, 'X'), regex_replace(text, '\\s', 'X'),
            'K'.replace(/k/gi, 'X'), 'K'.replace(/k/giu, 'X'),
            regex_replace('K', '(?i)k', 'X')
        ]);
    "#,
    );
    assert_eq!(
        result,
        json!([
            "中١X　",
            "XXX　",
            "中١A　",
            "中XA　",
            "X١X　",
            "X١X　",
            "中١AX",
            "中١AX",
            "K",
            "X",
            "X"
        ])
    );
}
