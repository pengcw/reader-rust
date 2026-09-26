#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitResult {
    pub parts: Vec<String>,
    pub delimiter: Option<String>,
}

pub fn split_top_level(rule: &str, delimiters: &[&str]) -> SplitResult {
    let Some((_, delimiter)) = find_next_delimiter(rule, delimiters, 0) else {
        return SplitResult {
            parts: vec![rule.trim().to_string()],
            delimiter: None,
        };
    };

    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut search_from = 0usize;
    while let Some((idx, _)) = find_next_delimiter(rule, &[delimiter], search_from) {
        parts.push(rule[start..idx].trim().to_string());
        start = idx + delimiter.len();
        search_from = start;
    }
    parts.push(rule[start..].trim().to_string());

    SplitResult {
        parts,
        delimiter: Some(delimiter.to_string()),
    }
}

pub fn interleave_result_groups<T>(groups: Vec<Vec<T>>) -> Vec<T> {
    let Some(first_len) = groups.first().map(Vec::len) else {
        return Vec::new();
    };
    let mut iterators = groups
        .into_iter()
        .map(|group| group.into_iter())
        .collect::<Vec<_>>();
    let mut result = Vec::new();

    for _ in 0..first_len {
        for iterator in &mut iterators {
            if let Some(item) = iterator.next() {
                result.push(item);
            }
        }
    }

    result
}

fn find_next_delimiter<'a>(
    rule: &'a str,
    delimiters: &[&'a str],
    from: usize,
) -> Option<(usize, &'a str)> {
    let mut square_depth = 0i32;
    let mut paren_depth = 0i32;
    let mut brace_depth = 0i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for (idx, ch) in rule.char_indices().filter(|(idx, _)| *idx >= from) {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == active_quote {
                quote = None;
            }
            continue;
        }

        match ch {
            '"' | '\'' => {
                quote = Some(ch);
                continue;
            }
            '[' => square_depth += 1,
            ']' => square_depth -= 1,
            '(' => paren_depth += 1,
            ')' => paren_depth -= 1,
            '{' => brace_depth += 1,
            '}' => brace_depth -= 1,
            '\\' => {
                escaped = true;
                continue;
            }
            _ => {}
        }

        if square_depth == 0 && paren_depth == 0 && brace_depth == 0 {
            if let Some(delimiter) = delimiters.iter().find(|delimiter| {
                rule[idx..].starts_with(**delimiter)
                    && !(**delimiter == "@" && rule[idx..].starts_with("@@"))
            }) {
                return Some((idx, *delimiter));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_ignores_delimiters_inside_attribute_selector() {
        let result = split_top_level(r#"div[a="x&&y"]&&span"#, &["&&", "||", "%%"]);

        assert_eq!(result.delimiter.as_deref(), Some("&&"));
        assert_eq!(result.parts, vec![r#"div[a="x&&y"]"#, "span"]);
    }

    #[test]
    fn interleave_uses_first_group_length_and_all_groups_per_index() {
        assert_eq!(
            interleave_result_groups(vec![
                vec!["A1", "A2"],
                vec!["B1", "B2", "B3"],
                vec!["C1"],
            ]),
            vec!["A1", "B1", "C1", "A2", "B2"]
        );
    }
}
