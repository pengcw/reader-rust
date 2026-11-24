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

// A deliberately narrow Jayway extension: one current-item dotted-path =~ predicate.
// All ordinary JSONPath evaluation remains with jsonpath_lib.
fn regex_filter_query(value: &Value, rule: &str) -> Option<Option<Vec<Value>>> {
    let mut quote = None;
    let mut escaped = false;
    let mut start = None;
    for (index, ch) in rule.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"') {
            quote = Some(ch);
        } else if rule[index..].starts_with("[?(") {
            start = Some(index);
            break;
        }
    }
    let start = start?;
    let expression = &rule[start + 3..];
    let mut quote = None;
    let mut escaped = false;
    let mut operator = None;
    for (index, ch) in expression.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"') {
            quote = Some(ch);
        } else if ch == ')' {
            break;
        } else if expression[index..].starts_with("=~") {
            operator = Some(index);
            break;
        }
    }
    let operator = operator?;
    let (left, literal) = (&expression[..operator], &expression[operator + 2..]);
    static CURRENT_PATH: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^@(?:\.[\p{L}_$][\p{L}\p{N}_$]*)*$").unwrap()
    });
    if !CURRENT_PATH.is_match(left.trim()) {
        return Some(None);
    }
    let literal = literal.trim_start();
    let Some(pattern_start) = literal.strip_prefix('/') else {
        return Some(None);
    };
    let mut escaped = false;
    let mut end = None;
    for (index, ch) in pattern_start.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
        } else if ch == '/' {
            end = Some(index);
            break;
        }
    }
    let Some(end) = end else {
        return Some(None);
    };
    let tail = &pattern_start[end + 1..];
    let flags_end = tail
        .find(|ch: char| !ch.is_ascii_alphabetic())
        .unwrap_or(tail.len());
    // Jayway ignores unknown literal flags; use the supported Java flag set.
    let flags: String = tail[..flags_end]
        .chars()
        .filter(|ch| "dixmsuU".contains(*ch))
        .collect();
    let Some(suffix) = tail[flags_end..]
        .trim_start()
        .strip_prefix(')')
        .and_then(|tail| tail.trim_start().strip_prefix(']'))
    else {
        return Some(None);
    };
    let prefix = &rule[..start];
    if prefix.contains("[?(") || suffix.contains("[?(") {
        return Some(None);
    }
    let pattern = pattern_start[..end].replace(r"\/", "/");
    let pattern = if flags.is_empty() {
        pattern
    } else {
        format!("(?{flags}){pattern}")
    };
    if !super::source_regex::is_valid(&pattern) {
        return Some(None);
    }
    let prefix = normalize_bracket_steps(prefix);
    let Ok(parents) = jsonpath_lib::select(value, &prefix) else {
        return Some(None);
    };
    let path = format!("${}", &left.trim()[1..]);
    let matches = |item: &Value| {
        let values = jsonpath_lib::select(item, &path).unwrap_or_default();
        // A missing definite path becomes Jayway's UNDEFINED node, whose regex input is empty.
        if values.is_empty() {
            return super::source_regex::is_full_match(&pattern, "");
        }
        let scalar_matches = |value: &Value| {
            let input = match value {
                Value::String(text) => text.clone(),
                Value::Number(_) | Value::Bool(_) => value.to_string(),
                // Jayway RegexpEvaluator.getInput uses an empty string otherwise.
                _ => String::new(),
            };
            super::source_regex::is_full_match(&pattern, &input)
        };
        values.into_iter().any(|value| match value {
            Value::Array(items) => items.iter().any(scalar_matches),
            other => scalar_matches(other),
        })
    };
    let mut output = Vec::new();
    for parent in parents {
        let candidates: &[Value] = match parent {
            Value::Array(items) => items,
            other => std::slice::from_ref(other),
        };
        for item in candidates.iter().filter(|item| matches(item)) {
            if suffix.is_empty() {
                output.push(item.clone());
            } else {
                output.extend(jsonpath_query(item, &format!("${suffix}")));
            }
        }
    }
    Some(Some(output))
}

// jsonpath_lib clamps underflowing negative indexes to zero. A one-item slice
// uses the same bounds but becomes empty on underflow, without replacing its evaluator.
fn normalize_bracket_steps(rule: &str) -> std::borrow::Cow<'_, str> {
    let mut quote = None;
    let mut escaped = false;
    let mut parentheses = 0usize;
    let mut output = String::new();
    let mut copied = 0;
    for (index, ch) in rule.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => parentheses += 1,
            ')' => parentheses = parentheses.saturating_sub(1),
            '[' if parentheses == 0 => {
                let Some(end) = rule[index..].find(']').map(|end| index + end) else {
                    continue;
                };
                let step = rule[index + 1..end].trim();
                let position = step.parse::<isize>().ok();
                let needs_dot = (position.is_some() || step == "*")
                    && rule[end + 1..].starts_with(|ch: char| ch.is_ascii_alphabetic() || ch == '_');
                if let Some(position) = position.filter(|&n| n < 0) {
                    output.push_str(&rule[copied..index]);
                    if position == -1 {
                        output.push_str("[-1:]");
                    } else {
                        output.push_str(&format!("[{position}:{}]", position + 1));
                    }
                } else if needs_dot {
                    output.push_str(&rule[copied..=end]);
                } else {
                    continue;
                }
                if needs_dot {
                    output.push('.');
                }
                copied = end + 1;
            }
            _ => {}
        }
    }
    if copied == 0 {
        return std::borrow::Cow::Borrowed(rule);
    }
    output.push_str(&rule[copied..]);
    std::borrow::Cow::Owned(output)
}

pub fn jsonpath_query(value: &Value, rule: &str) -> Vec<Value> {
    jsonpath_query_with_arrays(value, rule, true)
}

pub(crate) fn jsonpath_object_value(value: &Value, rule: &str) -> Option<Value> {
    let indefinite = jsonpath_is_indefinite(rule);
    let mut values = jsonpath_query_checked(value, rule, false)?;
    if values.is_empty() && !indefinite {
        return None;
    }
    if indefinite || values.len() > 1 {
        Some(Value::Array(values))
    } else {
        values.pop()
    }
}

pub(crate) fn jsonpath_is_indefinite(rule: &str) -> bool {
    let chars: Vec<char> = rule.chars().collect();
    let mut quote = None;
    let mut escaped = false;
    let mut bracket_depth = 0usize;
    let mut index = 0usize;

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

        match ch {
            '\'' | '"' => quote = Some(ch),
            '.' if bracket_depth == 0 && chars.get(index + 1) == Some(&'.') => return true,
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '*' => return true,
            '?' | ':' | ',' if bracket_depth > 0 => return true,
            _ => {}
        }
        index += 1;
    }
    false
}

fn jsonpath_query_with_arrays(value: &Value, rule: &str, flatten_arrays: bool) -> Vec<Value> {
    jsonpath_query_checked(value, rule, flatten_arrays).unwrap_or_default()
}

// Jayway compares string and number nodes across types. jsonpath_lib also drops
// missing and null fields for !=. Limit this adapter to simple source predicates.
fn simple_comparison<'a>(root: &'a Value, rule: &str) -> Option<Vec<&'a Value>> {
    if !rule.contains("!=") && !rule.contains("==") {
        return None;
    }
    static FILTER: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r#"^\$(?:\.([A-Za-z_]\w*))?\.?\[\?\(\s*@\.([A-Za-z_]\w*)\s*(==|!=)\s*(?:([0-9]+)|'([A-Za-z_]\w*)'|"([A-Za-z_]\w*)")\s*\)\](?:\.([A-Za-z_]\w*))?$"#).unwrap()
    });
    let parts = FILTER.captures(rule)?;
    let parent = match parts.get(1) {
        Some(key) => root.get(key.as_str())?,
        None => root,
    };
    let rows: &[Value] = match parent {
        Value::Array(items) => items,
        Value::Object(_) => std::slice::from_ref(parent),
        _ => return None,
    };
    let equality = &parts[3] == "==";
    let integer = parts.get(4).map(|m| m.as_str().parse::<u32>()).transpose().ok()?;
    let literal = parts.get(5).or(parts.get(6)).or(parts.get(4))?.as_str();
    if integer.is_some() && literal.len() > 1 && literal.starts_with('0') {
        return None;
    }
    let mut result = Vec::new();
    for row in rows {
        let equal = match row.get(&parts[2]) {
            Some(Value::String(s)) => s == literal,
            Some(Value::Number(n)) => integer.is_some_and(|i| n.as_f64() == Some(f64::from(i))),
            _ => false,
        };
        if equal == equality {
            if let Some(value) = parts.get(7).map_or(Some(row), |key| row.get(key.as_str())) {
                result.push(value);
            }
        }
    }
    Some(result)
}

fn jsonpath_query_checked(value: &Value, rule: &str, flatten_arrays: bool) -> Option<Vec<Value>> {
    if let Some(rendered) = render_embedded_paths(value, rule) {
        return Some(vec![Value::String(rendered)]);
    }
    let rule = rule.trim();
    if rule.is_empty() {
        return None;
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
    if let Some(result) = regex_filter_query(value, rule) {
        return result;
    }
    // jsonpath_lib 0.3 panics on range, union, and named-key selectors inside filters.
    // Reject those unsupported expressions before calling it; release builds abort on panic.
    if has_unsupported_filter_selector(rule) {
        return None;
    }
    let rule = normalize_bracket_steps(rule);
    if let Some(field) = rule.strip_prefix("$..[?(@.").and_then(|s| s.strip_suffix(")]")) {
        if !field.is_empty() && field.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            let mut matches = Vec::new();
            collect_with_field(value, field, &mut matches);
            return Some(matches);
        }
    }
    if let Some(res) = simple_comparison(value, &rule).or_else(|| jsonpath_lib::select(value, &rule).ok()) {
        let mut out = Vec::new();
        for item in res {
            match item {
                Value::Array(items) if flatten_arrays => {
                    out.extend(items.iter().cloned());
                }
                other => out.push(other.clone()),
            }
        }
        Some(out)
    } else {
        None
    }
}

// Jayway scans each subtree before the next sibling (笔趣阁 / 晋江).
fn collect_with_field(value: &Value, field: &str, matches: &mut Vec<Value>) {
    match value {
        Value::Object(map) => {
            if map.contains_key(field) {
                matches.push(value.clone());
            }
            for child in map.values() {
                collect_with_field(child, field, matches);
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_with_field(child, field, matches);
            }
        }
        _ => {}
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
    fn p471_source_filters_keep_missing_and_null_and_compare_numeric_text() {
        let rows = json!([{"id":"missing"},{"type":null,"id":"null"},{"type":1,"id":"number"},
            {"type":"1","id":"text"},{"type":"01","id":"leading"},{"type":2,"id":"two"}]);
        let data = json!({"data":rows});
        assert_eq!(jsonpath_query(&data, "$.data[?(@.type != 1)].id"),
            vec![json!("missing"), json!("null"), json!("leading"), json!("two")]);
        let toc = json!([{"source":null,"_id":"abc"},{"source":"zhuishuvip","_id":"skip"}]);
        assert_eq!(jsonpath_query(&toc, "$.[?(@.source!='zhuishuvip')]._id"), vec![json!("abc")]);
    }

    #[test]
    fn p473_biquge_content_accepts_text_or_numeric_one() {
        let data = json!({"data":[{"hasContent":"1","content":"文本标记"},
            {"hasContent":1,"content":"数字标记"},{"hasContent":"01","content":"前导零"},
            {"hasContent":false,"content":"关闭"},{"content":"缺失"}]});
        assert_eq!(jsonpath_query(&data, "$.data[?(@.hasContent==1)].content"),
            vec![json!("文本标记"), json!("数字标记")]);
    }

    #[test]
    fn p476_biquge_volume_children_precede_the_next_chapter() {
        let child = json!({"id":2,"hasContent":false});
        let sibling = json!({"id":3,"hasContent":true});
        let parent = json!({"id":1,"hasContent":null,"child":child});
        let rule = "$..[?(@.hasContent)]";
        assert_eq!(jsonpath_query(&json!([parent,sibling]), rule),
            vec![parent, child.clone(), sibling.clone()]);
        assert_eq!(jsonpath_query(&json!([{"list":[child]},sibling]), rule),
            vec![child, sibling]);
    }

    #[test]
    fn p475_recursive_presence_includes_matching_root_before_children() {
        let child = json!({"name":"child","hasContent":false});
        let root = json!({"name":"root","hasContent":null,"rows":[child,child]});
        let rule = "$..[?(@.hasContent)]";
        assert_eq!(jsonpath_query(&root, rule), vec![root.clone(), child.clone(), child.clone()]);
        assert_eq!(jsonpath_query(&json!([child]), rule), vec![child]);
        assert!(jsonpath_query(&root, "$..[?(@.other)]").is_empty());
    }

    #[test]
    fn p474_biquge_filter_checks_single_object_itself() {
        let path = "$.data[?(@.hasContent==1)].content";
        for (flag, expected) in [(json!("1"), true), (json!(1), true), (json!(0), false)] {
            let data = json!({"data":{"hasContent":flag,"content":"正文",
                "child":{"hasContent":1,"content":"子节点"}}});
            assert_eq!(jsonpath_query(&data, path),
                if expected { vec![json!("正文")] } else { vec![] });
        }
    }

    #[test]
    fn p470_last_chapter_after_array_index() {
        let data = json!({"tracks":{"list":[{"title":"旧"},{"title":"新"}]},
            "ep_list":[{"short_title":"第一话"}], "[0]title":"literal"});
        for (rule, expected) in [
            ("$.tracks.list[-1]title", "新"),
            ("$..ep_list[0]short_title", "第一话"),
            ("$.tracks.list[*]title", "旧"),
            ("$['[0]title']", "literal"),
        ] {
            assert_eq!(jsonpath_first_string(&data, rule).as_deref(), Some(expected), "{rule}");
        }
        assert!(jsonpath_query(&data, "$.tracks.list[-3]title").is_empty());
    }

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
    fn object_value_distinguishes_empty_queries_from_errors() {
        let value = json!({"items": []});
        assert_eq!(jsonpath_object_value(&value, "$.items[*]"), Some(json!([])));
        assert_eq!(
            jsonpath_object_value(&value, "$.items[?(@.id == 1)]"),
            Some(json!([]))
        );
        assert_eq!(jsonpath_object_value(&value, "$.missing"), None);
        assert_eq!(jsonpath_object_value(&value, "$.items["), None);
        assert_eq!(
            jsonpath_object_value(&value, "$.items[?(@.id =~ /[/)]"),
            None
        );
        assert_eq!(
            jsonpath_object_value(&value, "$.items[?(@.id =~ /x/)]"),
            Some(json!([]))
        );
    }

    #[test]
    fn object_value_preserves_definite_arrays_and_indefinite_results() {
        let value = json!({"data":[{"name":"one"}]});
        assert_eq!(
            jsonpath_object_value(&value, "$.data"),
            Some(json!([{"name":"one"}]))
        );
        assert_eq!(
            jsonpath_object_value(&value, "$.data[0].name"),
            Some(json!("one"))
        );
        assert_eq!(
            jsonpath_object_value(&value, "$.data[*]"),
            Some(json!([{"name":"one"}]))
        );
        assert_eq!(
            jsonpath_object_value(&value, "$.data[*].name"),
            Some(json!(["one"]))
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
            ("$.books[?(@.price == 10)].name", vec![json!("B"), json!("C")]),
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
        // Jayway compares an absent field as UNDEFINED, distinct from 1.
        assert_eq!(jsonpath_query(&value, "$.books[?(@.missing != 1)].name"),
            vec![json!("A"), json!("B"), json!("C")]);

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

        assert_eq!(
            jsonpath_query(&value, "$.books[?(@.name =~ /A|B/)].name"),
            vec![json!("A"), json!("B")]
        );
        // UNSUPPORTED: membership, size, and reverse slices are parse errors.
        for rule in [
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
