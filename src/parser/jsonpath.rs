use serde_json::Value;

fn has_unsupported_filter_selector(rule: &str) -> bool {
    let mut filter_depth = 0usize;
    let mut in_filter_selector = false;
    let mut quote = None;
    let mut escaped = false;
    let chars: Vec<char> = rule.chars().collect();
    let mut index = 0;

    while index < chars.len() {
        let ch = chars[index];
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == delimiter {
                quote = None;
            }
            index += 1;
            continue;
        }

        if ch == '\'' || ch == '\"' {
            if in_filter_selector {
                return true;
            }
            quote = Some(ch);
        } else if filter_depth > 0 {
            match ch {
                '[' => in_filter_selector = true,
                ']' => in_filter_selector = false,
                ':' | ',' if in_filter_selector => return true,
                '(' => filter_depth += 1,
                ')' => filter_depth -= 1,
                _ => {}
            }
        } else if ch == '?' && chars.get(index + 1) == Some(&'(') {
            filter_depth = 1;
            index += 1;
        }

        index += 1;
    }
    false
}

pub fn jsonpath_query(value: &Value, rule: &str) -> Vec<Value> {
    if let Some(rendered) = render_embedded_paths(value, rule) {
        return vec![Value::String(rendered)];
    }
    let rule = rule.trim();
    if rule.is_empty() {
        return vec![];
    }
    let normalized;
    let rule = if rule.starts_with('$') {
        rule
    } else if rule.starts_with('[') {
        normalized = format!("${rule}");
        &normalized
    } else {
        normalized = format!("$.{rule}");
        &normalized
    };
    // jsonpath_lib 0.3 panics on range, union, and named-key selectors inside filters.
    // Reject those unsupported expressions before calling it; release builds abort on panic.
    if has_unsupported_filter_selector(rule) {
        return vec![];
    }
    if let Ok(res) = jsonpath_lib::select(value, rule) {
        let mut out = Vec::new();
        for item in res {
            match item {
                Value::Array(items) => {
                    out.extend(items.iter().cloned());
                }
                other => out.push(other.clone()),
            }
        }
        out
    } else {
        vec![]
    }
}

pub fn jsonpath_first_string(value: &Value, rule: &str) -> Option<String> {
    if let Some(rendered) = render_embedded_paths(value, rule) {
        return Some(rendered);
    }
    let res = jsonpath_query(value, rule);
    res.first().and_then(value_to_string)
}

pub fn value_to_string(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Array(items) => Some(
            items
                .iter()
                .filter_map(value_to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        Value::Object(_) => Some(v.to_string()),
    }
}

fn render_embedded_paths(value: &Value, rule: &str) -> Option<String> {
    if !rule.contains('$') || !rule.contains('{') {
        return None;
    }
    let re = regex::Regex::new(r"\{\{\s*(\$[^}]+?)\s*\}\}|\{\s*(\$[^}]+?)\s*\}").unwrap();
    let mut replaced_any = false;
    let rendered = re
        .replace_all(rule, |captures: &regex::Captures| {
            replaced_any = true;
            let path = captures
                .get(1)
                .or_else(|| captures.get(2))
                .map(|m| m.as_str())
                .unwrap_or_default();
            jsonpath_first_string(value, path).unwrap_or_default()
        })
        .into_owned();
    if replaced_any {
        Some(rendered)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compat_jsonpath_direct_and_embedded_values() {
        let value = json!({"data":{"name":"书名","author":"作者"}});
        assert_eq!(
            jsonpath_first_string(&value, "$.data.name"),
            Some("书名".into())
        );
        assert_eq!(
            jsonpath_first_string(&value, "data.name"),
            Some("书名".into())
        );
        assert_eq!(
            jsonpath_first_string(&value, "作者：{$.data.author}"),
            Some("作者：作者".into())
        );
    }

    #[test]
    fn test_render_embedded_paths_double_and_single_braces() {
        let value = json!({
            "data": {
                "Content": [{
                    "Content": ["第一行\n第二行"]
                }]
            },
            "index": 1
        });

        // 双大括号模板不应残留外层花括号
        let rule_double = "<p>{{$.data.Content[0].Content}}</p>";
        assert_eq!(
            jsonpath_first_string(&value, rule_double),
            Some("<p>第一行\n第二行</p>".to_string())
        );

        // 单大括号兼容
        let rule_single = "第{$.index}章";
        assert_eq!(
            jsonpath_first_string(&value, rule_single),
            Some("第1章".to_string())
        );

        // 带空格双大括号
        let rule_spaces = "{{ $.data.Content[0].Content }}";
        assert_eq!(
            jsonpath_first_string(&value, rule_spaces),
            Some("第一行\n第二行".to_string())
        );

        // 包含 $ 与 { 但不含嵌入模板的字符串不应被误判为空字符串
        let non_template = r#"$.https://example.com/api,{"method":"POST"}"#;
        assert_eq!(jsonpath_first_string(&value, non_template), None);
        assert_eq!(render_embedded_paths(&value, non_template), None);
    }

    #[test]
    fn compat_jsonpath_matrix() {
        let value = json!({
            "books": [
                {"name":"A", "price":5, "vip":true, "tags":["x","y"]},
                {"name":"B", "price":10, "vip":false, "tags":["y"]},
                {"name":"C", "price":"10", "tags":[]}
            ],
            "items": [{"name":"one"}, {"name":"two"}]
        });

        // PASS: comparison operators and JSON type distinction.
        for (rule, expected) in [
            ("$.books[?(@.price == 10)].name", vec![json!("B")]),
            ("$.books[?(@.price == '10')].name", vec![json!("C")]),
            ("$.books[?(@.price != 10)].name", vec![json!("A")]),
            ("$.books[?(@.price < 10)].name", vec![json!("A")]),
            (
                "$.books[?(@.price <= 10)].name",
                vec![json!("A"), json!("B")],
            ),
            ("$.books[?(@.price > 5)].name", vec![json!("B")]),
            ("$.books[?(@.price >= 10)].name", vec![json!("B")]),
        ] {
            assert_eq!(jsonpath_query(&value, rule), expected, "{rule}");
        }

        // PASS: a presence predicate matches a present false-valued field.
        assert_eq!(
            jsonpath_query(&value, "$.books[?(@.vip)].name"),
            vec![json!("A"), json!("B")]
        );
        // DIFFERENT_SEMANTICS: missing-field != currently yields no match.
        assert!(jsonpath_query(&value, "$.books[?(@.missing != 1)].name").is_empty());

        // PASS: negative index, stepped slice, recursive descent, and root arrays.
        assert_eq!(jsonpath_query(&value, "$.books[-1].name"), vec![json!("C")]);
        assert_eq!(
            jsonpath_query(&value, "$.books[0:3:2].name"),
            vec![json!("A"), json!("C")]
        );
        assert_eq!(
            jsonpath_query(&value, "$..name"),
            vec![
                json!("A"),
                json!("B"),
                json!("C"),
                json!("one"),
                json!("two")
            ]
        );
        let root_array = json!([{"direct":"ok"}]);
        assert_eq!(
            jsonpath_query(&root_array, "$[*].direct"),
            vec![json!("ok")]
        );

        // UNSUPPORTED: regex, membership, size, and reverse slices are parse errors.
        for rule in [
            "$.books[?(@.name =~ /A|B/)].name",
            "$.books[?(@.name in ['A','C'])].name",
            "$.books[?(@.name nin ['A','C'])].name",
            "$.books[?(@.tags size 0)].name",
            "$.books[::-1].name",
        ] {
            assert!(jsonpath_lib::select(&value, rule).is_err(), "{rule}");
            assert!(jsonpath_query(&value, rule).is_empty(), "{rule}");
        }

        // UNSUPPORTED selectors inside filters panic in jsonpath_lib 0.3; reject safely.
        for rule in [
            "$.books[?(@.tags[0:1])].name",
            "$.books[?(@.tags[0,1])].name",
            "$.books[?(@['name'])].name",
        ] {
            assert!(has_unsupported_filter_selector(rule), "{rule}");
            assert!(jsonpath_query(&value, rule).is_empty(), "{rule}");
        }

        // PASS: malformed and deep paths fail closed rather than panicking.
        assert!(jsonpath_query(&value, "$.books[").is_empty());
        assert!(jsonpath_query(&value, "$.books[?(@.price >)]").is_empty());
        let deep_path = format!("$.{}", vec!["missing"; 64].join("."));
        assert!(jsonpath_query(&value, &deep_path).is_empty());
    }
}
