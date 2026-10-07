use crate::parser::{js::eval_js, source_regex};
use serde::Deserialize;
use serde_json::{json, Value};

// qread passes UNICODE_CHARACTER_CLASS | MULTILINE to java.util.regex.Pattern.
// Java's U flag implies Unicode case behavior; java_regex models U/u separately,
// so include both here to preserve the effective Java semantics.
const QREAD_REGEX_FLAGS: &str = "uUm";

const READER3_BATCH_JS: &str = r#"
(function() {
    var payload = JSON.parse(result);
    var values = Array.isArray(payload.values) ? payload.values : [];
    var rules = Array.isArray(payload.rules) ? payload.rules : [];
    return values.map(function(value) {
        var text = String(value);
        rules.forEach(function(rule) {
            try {
                var pattern = String(rule.pattern);
                var replacement = rule.replacement == null ? "" : String(rule.replacement);
                if (rule.isRegex === true) {
                    text = text.replace(new RegExp(pattern, "ig"), replacement);
                } else {
                    text = text.replace(pattern, replacement);
                }
            } catch (_) {
                // One malformed user rule must not abort the remaining rules.
            }
        });
        return text;
    });
})()
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextTransformDialect {
    Reader3,
    Legado,
    Qread,
}

impl TextTransformDialect {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "reader3" => Some(Self::Reader3),
            "legado" => Some(Self::Legado),
            "qread" => Some(Self::Qread),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TextTransformRule {
    pattern: String,
    #[serde(default)]
    replacement: String,
    #[serde(default, rename = "isRegex")]
    is_regex: bool,
}

pub(super) fn apply_from_params(values: &mut [String], params: &Value) {
    let Some((dialect, rules)) = parse_transform_request(params) else {
        return;
    };

    match dialect {
        TextTransformDialect::Reader3 => {
            if let Some(transformed) = apply_reader3(values, &rules) {
                for (value, transformed) in values.iter_mut().zip(transformed) {
                    *value = transformed;
                }
            }
        }
        TextTransformDialect::Legado | TextTransformDialect::Qread => {
            for value in values {
                *value = apply_java_rules(value, &rules, dialect);
            }
        }
    }
}

fn parse_transform_request(
    params: &Value,
) -> Option<(TextTransformDialect, Vec<TextTransformRule>)> {
    let dialect = params
        .get("textTransformDialect")
        .and_then(Value::as_str)
        .and_then(TextTransformDialect::parse)?;
    let raw_rules = params.get("textTransformRules")?.as_array()?;

    let rules = raw_rules
        .iter()
        .filter_map(|rule| serde_json::from_value(rule.clone()).ok())
        .collect::<Vec<_>>();
    (!rules.is_empty()).then_some((dialect, rules))
}

fn apply_reader3(values: &[String], rules: &[TextTransformRule]) -> Option<Vec<String>> {
    let rules = rules
        .iter()
        .map(|rule| {
            json!({
                "pattern": &rule.pattern,
                "replacement": &rule.replacement,
                "isRegex": rule.is_regex,
            })
        })
        .collect::<Vec<_>>();
    let payload = serde_json::to_string(&json!({
        "values": values,
        "rules": rules,
    }))
    .ok()?;

    let output = eval_js(READER3_BATCH_JS, &payload, "").ok()?;
    let transformed = serde_json::from_str::<Vec<String>>(&output).ok()?;
    (transformed.len() == values.len()).then_some(transformed)
}

fn apply_java_rules(
    input: &str,
    rules: &[TextTransformRule],
    dialect: TextTransformDialect,
) -> String {
    let mut output = input.to_string();

    for rule in rules {
        if rule.pattern.is_empty() {
            continue;
        }
        if !rule.is_regex {
            output = output.replace(&rule.pattern, &rule.replacement);
            continue;
        }
        if let Some(script) = rule.replacement.strip_prefix("@js:") {
            let flags = if dialect == TextTransformDialect::Qread {
                QREAD_REGEX_FLAGS
            } else {
                "uU"
            };
            // Preserve JS completion-value string coercion, including objects and null.
            let script = format!("String(eval({}))", json!(script));
            if let Ok(next) =
                source_regex::replace_all_with(&output, &rule.pattern, flags, |matched| {
                    eval_js(&script, matched, "")
                })
            {
                output = next;
            }
        } else {
            let result = match dialect {
                TextTransformDialect::Legado => {
                    source_regex::replace_all(&output, &rule.pattern, &rule.replacement)
                }
                TextTransformDialect::Qread => source_regex::replace_all_with_flags(
                    &output,
                    &rule.pattern,
                    &rule.replacement,
                    QREAD_REGEX_FLAGS,
                ),
                TextTransformDialect::Reader3 => unreachable!("Reader3 uses QuickJS"),
            };
            if let Ok(next) = result {
                output = next;
            }
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(dialect: &str, rules: Value) -> Value {
        json!({
            "textTransformDialect": dialect,
            "textTransformRules": rules,
        })
    }

    fn apply(input: &str, dialect: &str, rules: Value) -> String {
        let mut values = vec![input.to_string()];
        apply_from_params(&mut values, &params(dialect, rules));
        values.remove(0)
    }

    #[test]
    fn reader3_plain_replaces_first_only() {
        assert_eq!(
            apply(
                "old old",
                "reader3",
                json!([{"pattern":"old","replacement":"new","isRegex":false}]),
            ),
            "new old"
        );
    }

    #[test]
    fn reader3_regex_is_global_and_case_insensitive() {
        assert_eq!(
            apply(
                "Old old",
                "reader3",
                json!([{"pattern":"(old)","replacement":"[$1]","isRegex":true}]),
            ),
            "[Old] [old]"
        );
    }

    #[test]
    fn legado_plain_and_java_regex_preserve_order() {
        assert_eq!(
            apply(
                "a a",
                "legado",
                json!([
                    {"pattern":"a","replacement":"b","isRegex":false},
                    {"pattern":"(b)","replacement":"<$1>","isRegex":true}
                ]),
            ),
            "<b> <b>"
        );
    }

    #[test]
    fn qread_regex_is_multiline_without_forcing_case_insensitive() {
        assert_eq!(
            apply(
                "a\nA\na",
                "qread",
                json!([{"pattern":"^a","replacement":"X","isRegex":true}]),
            ),
            "X\nA\nX"
        );
    }

    #[test]
    fn invalid_java_regex_skips_only_that_rule() {
        for dialect in ["legado", "qread"] {
            assert_eq!(
                apply(
                    "a",
                    dialect,
                    json!([
                        {"pattern":"[","replacement":"bad","isRegex":true},
                        {"pattern":"a","replacement":"ok","isRegex":false}
                    ]),
                ),
                "ok",
                "{dialect}"
            );
        }
    }

    #[test]
    fn reader3_invalid_regex_skips_only_that_rule() {
        let mut values = vec!["a".to_string(), "a".to_string()];
        apply_from_params(
            &mut values,
            &params(
                "reader3",
                json!([
                    {"pattern":"[","replacement":"bad","isRegex":true},
                    {"pattern":"a","replacement":"ok","isRegex":false}
                ]),
            ),
        );
        assert_eq!(values, ["ok", "ok"]);
    }

    #[test]
    fn reader3_batch_preserves_value_and_rule_order() {
        let mut values = vec!["a a".to_string(), "a".to_string()];
        apply_from_params(
            &mut values,
            &params(
                "reader3",
                json!([
                    {"pattern":"a","replacement":"b","isRegex":false},
                    {"pattern":"b","replacement":"c","isRegex":false}
                ]),
            ),
        );
        assert_eq!(values, ["c a", "c"]);
    }

    #[test]
    fn java_js_replacement_runs_per_match_and_keeps_literal_output() {
        for dialect in ["legado", "qread"] {
            assert_eq!(
                apply(
                    "a b",
                    dialect,
                    json!([
                        {"pattern":"[ab]","replacement":r"@js:result.toUpperCase() + '$1\\'","isRegex":true}
                    ])
                ),
                "A$1\\ B$1\\"
            );
            assert_eq!(
                apply(
                    "a a",
                    dialect,
                    json!([
                        {"pattern":"a","replacement":"@js:result","isRegex":false}
                    ])
                ),
                "@js:result @js:result"
            );
        }
    }

    #[test]
    fn java_js_replacement_error_discards_partial_output_and_continues() {
        assert_eq!(
            apply(
                "a b",
                "qread",
                json!([
                    {"pattern":"[ab]","replacement":"@js:if (result === 'b') throw Error('bad'); 'changed'","isRegex":true},
                    {"pattern":"a","replacement":"ok","isRegex":false}
                ])
            ),
            "ok b"
        );
    }

    #[test]
    fn java_js_prefix_is_exact_and_results_use_js_string_conversion() {
        assert_eq!(
            apply(
                "a",
                "qread",
                json!([
                    {"pattern":"a","replacement":" @js:result","isRegex":true}
                ])
            ),
            " @js:result"
        );
        for (script, expected) in [
            ("42", "42"),
            ("null", "null"),
            ("({a:1})", "[object Object]"),
        ] {
            assert_eq!(
                apply(
                    "a",
                    "qread",
                    json!([
                        {"pattern":"a","replacement":format!("@js:{script}"),"isRegex":true}
                    ])
                ),
                expected
            );
        }
    }

    #[test]
    fn unknown_dialect_and_malformed_rules_leave_text_unchanged() {
        assert_eq!(
            apply("a", "unknown", json!([{"pattern":"a","replacement":"b"}])),
            "a"
        );
        assert_eq!(
            apply(
                "a",
                "legado",
                json!([
                    {"replacement":"missing-pattern"},
                    {"pattern":"a","replacement":"b","isRegex":false}
                ]),
            ),
            "b"
        );
    }
}
