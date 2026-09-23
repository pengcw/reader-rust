use serde_json::Value;

pub fn jsonpath_query(value: &Value, rule: &str) -> Vec<Value> {
    if let Some(rendered) = render_embedded_paths(value, rule) {
        return vec![Value::String(rendered)];
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
        Some(String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    }
}

