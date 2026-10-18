use crate::parser::{js::eval_js, source_regex};
use serde::Deserialize;
use serde_json::{json, Value};

// qread passes UNICODE_CHARACTER_CLASS | MULTILINE to java.util.regex.Pattern.
// Java's U flag implies Unicode case behavior; java_regex models U/u separately,
// so include both here to preserve the effective Java semantics.
const QREAD_REGEX_FLAGS: &str = "uUm";
const MAX_TRANSFORM_DIAGNOSTICS: usize = 16;
pub(super) const TITLE_TRANSFORM_MIN_BYTES: usize = 16 * 1024;

/// Records bounded failure categories, never rule contents or exception messages.
#[derive(Debug)]
pub(super) struct TransformDiagnostics {
    enabled: bool,
    issues: Vec<TransformIssue>,
}

#[derive(Debug, PartialEq, Eq)]
struct TransformIssue {
    rule_index: Option<usize>,
    kind: &'static str,
}

impl TransformDiagnostics {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            issues: Vec::new(),
        }
    }

    fn record(&mut self, rule_index: Option<usize>, kind: &'static str) {
        if !self.enabled || self.issues.len() >= MAX_TRANSFORM_DIAGNOSTICS {
            return;
        }
        let issue = TransformIssue { rule_index, kind };
        if !self.issues.contains(&issue) {
            self.issues.push(issue);
        }
    }

    fn record_regex_error(&mut self, rule_index: usize, error: &source_regex::RegexError) {
        let kind = match error {
            source_regex::RegexError::InvalidPattern => "invalid_regex",
            source_regex::RegexError::InvalidReplacement { .. } => "invalid_replacement",
            source_regex::RegexError::BudgetExceeded => "regex_budget_exceeded",
        };
        self.record(Some(rule_index), kind);
    }

    pub(super) fn attach(&self, response: &mut Value, stage: &'static str) {
        if self.issues.is_empty() {
            return;
        }
        let diagnostics = self
            .issues
            .iter()
            .map(|issue| json!({"stage": stage, "ruleIndex": issue.rule_index, "kind": issue.kind}))
            .collect::<Vec<_>>();
        response["meta"]["debug"]["textTransformDiagnostics"] = json!(diagnostics);
    }
}

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

pub(super) fn apply_from_params(
    values: &mut [String],
    params: &Value,
    min_output_bytes: usize,
    diagnostics: &mut TransformDiagnostics,
) {
    let Some((dialect, rules)) = parse_transform_request(params, diagnostics) else {
        return;
    };

    match dialect {
        TextTransformDialect::Reader3 => {
            if let Some(transformed) = apply_reader3(values, &rules) {
                for (value, transformed) in values.iter_mut().zip(transformed) {
                    *value = transformed;
                }
            } else {
                // Reader3 catches individual rule errors inside its batch JS; do not
                // change those semantics just to surface per-rule diagnostics.
                diagnostics.record(None, "reader3_batch_failed");
            }
        }
        TextTransformDialect::Legado | TextTransformDialect::Qread => {
            for value in values {
                let max_output_bytes = value.len().max(min_output_bytes);
                *value = apply_java_rules(value, &rules, dialect, max_output_bytes, diagnostics);
            }
        }
    }
}

fn parse_transform_request(
    params: &Value,
    diagnostics: &mut TransformDiagnostics,
) -> Option<(TextTransformDialect, Vec<(usize, TextTransformRule)>)> {
    if params.get("textTransformDialect").is_none() && params.get("textTransformRules").is_none() {
        return None;
    }
    let Some(dialect) = params
        .get("textTransformDialect")
        .and_then(Value::as_str)
        .and_then(TextTransformDialect::parse)
    else {
        diagnostics.record(None, "invalid_dialect");
        return None;
    };
    let Some(raw_rules) = params.get("textTransformRules").and_then(Value::as_array) else {
        diagnostics.record(None, "invalid_rules");
        return None;
    };

    let mut rules = Vec::new();
    for (index, value) in raw_rules.iter().enumerate() {
        match serde_json::from_value::<TextTransformRule>(value.clone()) {
            Ok(rule) => rules.push((index, rule)),
            Err(_) => diagnostics.record(Some(index), "invalid_rule"),
        }
    }
    (!rules.is_empty()).then_some((dialect, rules))
}

fn apply_reader3(values: &[String], rules: &[(usize, TextTransformRule)]) -> Option<Vec<String>> {
    let rules = rules
        .iter()
        .map(|(_, rule)| {
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
    rules: &[(usize, TextTransformRule)],
    dialect: TextTransformDialect,
    max_output_bytes: usize,
    diagnostics: &mut TransformDiagnostics,
) -> String {
    let mut output = input.to_string();

    for (index, rule) in rules {
        if rule.pattern.is_empty() {
            continue;
        }
        if !rule.is_regex {
            if rule.replacement.len() > rule.pattern.len() {
                let growth_per_match = rule.replacement.len() - rule.pattern.len();
                let exceeds_limit = output
                    .matches(&rule.pattern)
                    .count()
                    .checked_mul(growth_per_match)
                    .and_then(|growth| output.len().checked_add(growth))
                    .is_none_or(|next_len| next_len > max_output_bytes);
                if exceeds_limit {
                    diagnostics.record(Some(*index), "output_limit_exceeded");
                    continue;
                }
            }
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
            match source_regex::replace_all_with(&output, &rule.pattern, flags, |matched| {
                eval_js(&script, matched, "")
            }) {
                Ok(next) => output = next,
                Err(error) => {
                    if let Some(regex_error) = error.downcast_ref::<source_regex::RegexError>() {
                        diagnostics.record_regex_error(*index, regex_error);
                    } else {
                        diagnostics.record(Some(*index), "js_error");
                    }
                }
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
            match result {
                Ok(next) => output = next,
                Err(error) => diagnostics.record_regex_error(*index, &error),
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
        apply_from_params(
            &mut values,
            &params(dialect, rules),
            usize::MAX,
            &mut TransformDiagnostics::new(false),
        );
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
            usize::MAX,
            &mut TransformDiagnostics::new(false),
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
            usize::MAX,
            &mut TransformDiagnostics::new(false),
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
    fn debug_reports_rule_indices_and_typed_failures_without_sensitive_values() {
        let mut values = vec!["a b".to_string()];
        let mut diagnostics = TransformDiagnostics::new(true);
        apply_from_params(
            &mut values,
            &params(
                "legado",
                json!([
                    {"replacement":"private input"},
                    {"pattern":"[","replacement":"bad","isRegex":true},
                    {"pattern":"a","replacement":"$9","isRegex":true},
                    {"pattern":"a","replacement":"@js:throw Error('secret token')","isRegex":true},
                    {"pattern":"[","replacement":"@js:result","isRegex":true},
                    {"pattern":"a","replacement":"ok","isRegex":false}
                ]),
            ),
            usize::MAX,
            &mut diagnostics,
        );
        assert_eq!(values, ["ok b"]);
        let mut result = json!({"meta":{"debug":{"responseBytes":3}}});
        diagnostics.attach(&mut result, "content");
        assert_eq!(result["meta"]["debug"]["responseBytes"], 3);
        assert_eq!(
            result["meta"]["debug"]["textTransformDiagnostics"],
            json!([
                {"stage":"content","ruleIndex":0,"kind":"invalid_rule"},
                {"stage":"content","ruleIndex":1,"kind":"invalid_regex"},
                {"stage":"content","ruleIndex":2,"kind":"invalid_replacement"},
                {"stage":"content","ruleIndex":3,"kind":"js_error"},
                {"stage":"content","ruleIndex":4,"kind":"invalid_regex"}
            ])
        );
        assert!(!result.to_string().contains("secret token"));
        assert!(!result.to_string().contains("private input"));
    }

    #[test]
    fn debug_deduplicates_across_titles_and_caps_number_of_entries() {
        let mut values = vec!["a".to_string(); 3];
        let rules = (0..25)
            .map(|_| json!({"pattern":"[","replacement":"bad","isRegex":true}))
            .collect::<Vec<_>>();
        let mut diagnostics = TransformDiagnostics::new(true);
        apply_from_params(
            &mut values,
            &params("qread", json!(rules)),
            usize::MAX,
            &mut diagnostics,
        );
        assert_eq!(values, ["a", "a", "a"]);
        let mut response = json!({"meta":{"debug":{}}});
        diagnostics.attach(&mut response, "toc");
        let entries = response["meta"]["debug"]["textTransformDiagnostics"]
            .as_array()
            .unwrap();
        assert_eq!(entries.len(), MAX_TRANSFORM_DIAGNOSTICS);
        for (index, entry) in entries.iter().enumerate() {
            assert_eq!(entry["stage"], "toc");
            assert_eq!(entry["ruleIndex"], index);
            assert_eq!(entry["kind"], "invalid_regex");
        }
    }

    #[test]
    fn debug_is_opt_in_and_reports_invalid_request_configuration() {
        let mut values = vec!["a".to_string()];
        let mut disabled = TransformDiagnostics::new(false);
        apply_from_params(
            &mut values,
            &params("unknown", json!([{"pattern":"a"}])),
            usize::MAX,
            &mut disabled,
        );
        let mut response = json!({"meta":{}});
        disabled.attach(&mut response, "content");
        assert_eq!(response, json!({"meta":{}}));

        let mut enabled = TransformDiagnostics::new(true);
        apply_from_params(
            &mut values,
            &params("unknown", json!([{"pattern":"a"}])),
            usize::MAX,
            &mut enabled,
        );
        enabled.attach(&mut response, "content");
        assert_eq!(values, ["a"]);
        assert_eq!(
            response["meta"]["debug"]["textTransformDiagnostics"],
            json!([{"stage":"content","ruleIndex":null,"kind":"invalid_dialect"}])
        );
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
