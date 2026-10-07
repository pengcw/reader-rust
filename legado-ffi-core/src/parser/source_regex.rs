use java_regex::{MatchInfo, Regex};
use std::cell::RefCell;
use std::collections::HashMap;

const SOURCE_REGEX_CACHE_CAPACITY: usize = 128;

thread_local! {
    static SOURCE_REGEX_CACHE: RefCell<HashMap<String, Regex>> =
        RefCell::new(HashMap::with_capacity(SOURCE_REGEX_CACHE_CAPACITY));
}

fn get_cached_regex_with_flags(pattern: &str, flags: &str) -> Option<Regex> {
    let key = format!("{flags}\0{pattern}");
    SOURCE_REGEX_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(regex) = cache.get(&key) {
            return Some(regex.clone());
        }

        let regex = Regex::with_flags(pattern, flags).ok()?;
        if cache.len() >= SOURCE_REGEX_CACHE_CAPACITY {
            cache.clear();
        }
        cache.insert(key, regex.clone());
        Some(regex)
    })
}

fn get_cached_regex(pattern: &str) -> Option<Regex> {
    // Android's java.util.regex.Pattern is ICU-backed and always uses Unicode
    // character classes/case handling. java_regex targets OpenJDK, so enable
    // the equivalent Java U/u flags by default at this compatibility boundary.
    get_cached_regex_with_flags(pattern, "uU")
}

fn match_captures(info: MatchInfo) -> Vec<Option<String>> {
    let mut captures = Vec::with_capacity(info.groups.len() + 1);
    captures.push(Some(info.matched_text));
    captures.extend(info.groups);
    captures
}

pub(crate) fn is_valid(pattern: &str) -> bool {
    get_cached_regex(pattern).is_some()
}

pub(crate) fn is_full_match(pattern: &str, input: &str) -> bool {
    get_cached_regex(pattern).is_some_and(|regex| regex.matches(input))
}

fn collect_matches(regex: &Regex, input: &str) -> Result<Vec<MatchInfo>, RegexError> {
    let mut matches = regex.find_iter(input);
    let found = matches.by_ref().collect();
    if matches.budget_exhausted() {
        Err(RegexError::BudgetExceeded)
    } else {
        Ok(found)
    }
}

pub(crate) fn find_all(pattern: &str, input: &str) -> Option<Vec<String>> {
    let regex = get_cached_regex(pattern)?;
    Some(
        collect_matches(&regex, input)
            .ok()?
            .into_iter()
            .map(|found| found.matched_text)
            .collect(),
    )
}

pub(crate) fn captures_first(pattern: &str, input: &str) -> Option<Vec<Option<String>>> {
    let regex = get_cached_regex(pattern)?;
    regex.find_iter(input).next().map(match_captures)
}

pub(crate) fn captures_all(pattern: &str, input: &str) -> Option<Vec<Vec<Option<String>>>> {
    let regex = get_cached_regex(pattern)?;
    Some(
        collect_matches(&regex, input)
            .ok()?
            .into_iter()
            .map(match_captures)
            .collect(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RegexError {
    InvalidPattern,
    BudgetExceeded,
    InvalidReplacement { offset: usize, reason: &'static str },
}

impl std::fmt::Display for RegexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPattern => f.write_str("invalid regex pattern"),
            Self::BudgetExceeded => f.write_str("regex execution budget exceeded"),
            Self::InvalidReplacement { offset, reason } => {
                write!(f, "invalid replacement at byte {offset}: {reason}")
            }
        }
    }
}

#[derive(Debug)]
enum ReplacementToken {
    Literal(String),
    Group(usize),
}

fn parse_replacement(
    replacement: &str,
    regex: &Regex,
) -> Result<Vec<ReplacementToken>, RegexError> {
    let mut chars = replacement.char_indices().peekable();
    let mut literal = String::new();
    let mut tokens = Vec::new();
    while let Some((offset, character)) = chars.next() {
        let error = |reason| RegexError::InvalidReplacement { offset, reason };
        match character {
            '\\' => {
                let (_, escaped) = chars.next().ok_or_else(|| error("trailing escape"))?;
                literal.push(escaped);
            }
            '$' => {
                let (_, next) = chars
                    .next()
                    .ok_or_else(|| error("missing group reference"))?;
                let group = if next == '{' {
                    let mut name = String::new();
                    loop {
                        let (_, character) =
                            chars.next().ok_or_else(|| error("unclosed named group"))?;
                        if character == '}' {
                            break;
                        }
                        name.push(character);
                    }
                    let mut letters = name.chars();
                    if !letters
                        .next()
                        .is_some_and(|character| character.is_ascii_alphabetic())
                        || !letters.all(|character| character.is_ascii_alphanumeric())
                    {
                        return Err(error("invalid group name"));
                    }
                    *regex
                        .named_groups()
                        .get(&name)
                        .ok_or_else(|| error("unknown named group"))?
                } else if next.is_ascii_digit() {
                    let mut group = (next as u8 - b'0') as usize;
                    if group > regex.group_count() {
                        return Err(error("unknown numbered group"));
                    }
                    while let Some((_, digit)) = chars.peek().copied() {
                        if !digit.is_ascii_digit() {
                            break;
                        }
                        let Some(candidate) = group
                            .checked_mul(10)
                            .and_then(|group| group.checked_add((digit as u8 - b'0') as usize))
                            .filter(|candidate| *candidate <= regex.group_count())
                        else {
                            break;
                        };
                        group = candidate;
                        chars.next();
                    }
                    group
                } else {
                    return Err(error("invalid group reference"));
                };
                if !literal.is_empty() {
                    tokens.push(ReplacementToken::Literal(std::mem::take(&mut literal)));
                }
                tokens.push(ReplacementToken::Group(group));
            }
            character => literal.push(character),
        }
    }
    if !literal.is_empty() {
        tokens.push(ReplacementToken::Literal(literal));
    }
    Ok(tokens)
}

fn checked_replace(
    regex: &Regex,
    input: &str,
    replacement: &str,
    first: bool,
) -> Result<String, RegexError> {
    // Parse only after an actual match; discard all output on replacement or budget errors.
    let mut plan = None;
    let mut expand = |matched: &MatchInfo| {
        let plan = plan.get_or_insert_with(|| parse_replacement(replacement, regex));
        let Ok(tokens) = plan else {
            return matched.matched_text.clone();
        };
        let mut output = String::new();
        for token in tokens {
            match token {
                ReplacementToken::Literal(literal) => output.push_str(literal),
                ReplacementToken::Group(group) => {
                    output.push_str(matched.group(*group).unwrap_or(""))
                }
            }
        }
        output
    };
    let output = if first {
        regex.try_replace_first(input, &mut expand)
    } else {
        regex.try_replace_all(input, &mut expand)
    }
    .map_err(|_| RegexError::BudgetExceeded)?;
    match plan {
        Some(Err(error)) => Err(error),
        _ => Ok(output),
    }
}

pub(crate) fn replace_all(
    input: &str,
    pattern: &str,
    replacement: &str,
) -> Result<String, RegexError> {
    replace_all_with_flags(input, pattern, replacement, "uU")
}

pub(crate) fn replace_all_with_flags(
    input: &str,
    pattern: &str,
    replacement: &str,
    flags: &str,
) -> Result<String, RegexError> {
    let regex = get_cached_regex_with_flags(pattern, flags).ok_or(RegexError::InvalidPattern)?;
    checked_replace(&regex, input, replacement, false)
}

// Callback results are literal text, not Java replacement expressions.
pub(crate) fn replace_all_with(
    input: &str,
    pattern: &str,
    flags: &str,
    mut replace: impl FnMut(&str) -> anyhow::Result<String>,
) -> anyhow::Result<String> {
    let regex = get_cached_regex_with_flags(pattern, flags)
        .ok_or_else(|| anyhow::anyhow!(RegexError::InvalidPattern))?;
    let mut error = None;
    let output = regex
        .try_replace_all(input, |matched: &MatchInfo| {
            if error.is_none() {
                match replace(&matched.matched_text) {
                    Ok(value) => return value,
                    Err(err) => error = Some(err),
                }
            }
            matched.matched_text.clone()
        })
        .map_err(|_| anyhow::anyhow!(RegexError::BudgetExceeded))?;
    if let Some(error) = error {
        return Err(error);
    }
    Ok(output)
}

pub(crate) fn replace_first_match(
    input: &str,
    pattern: &str,
    replacement: &str,
) -> Result<Option<String>, RegexError> {
    let regex = get_cached_regex(pattern).ok_or(RegexError::InvalidPattern)?;
    let mut matches = regex.find_iter(input);
    let found = matches.next();
    if matches.budget_exhausted() {
        return Err(RegexError::BudgetExceeded);
    }
    let Some(found) = found else {
        return Ok(None);
    };

    // Preserve Legado's second matching pass on group(0), including context loss.
    checked_replace(&regex, &found.matched_text, replacement, true).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_separates_android_and_qread_flags() {
        assert_eq!(replace_all("a\nb", "^b", "x"), Ok("a\nb".into()));
        assert_eq!(
            replace_all_with_flags("a\nb", "^b", "x", "uUm"),
            Ok("a\nx".into())
        );
    }

    #[test]
    fn replacement_metadata_includes_nonparticipating_named_groups() {
        let regex = Regex::new("(?<left>a)?(?<right>b)").unwrap();
        assert_eq!(regex.group_count(), 2);
        assert_eq!(regex.named_groups().get("left"), Some(&1));
        assert_eq!(regex.named_groups().get("right"), Some(&2));
        assert_eq!(
            replace_all("b", "(?<left>a)?(?<right>b)", "${left}/${right}"),
            Ok("/b".into())
        );
    }

    #[test]
    fn replacement_numbered_groups_use_java_greedy_downgrade_without_overflow() {
        assert_eq!(replace_all("a", "(a)", "$0/$11"), Ok("a/a1".into()));
        assert_eq!(
            replace_all("abcdefghijk", "(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)(k)", "$11"),
            Ok("k".into())
        );
        let digits = "9".repeat(1000);
        assert_eq!(
            replace_all("a", "(a)", &format!("$1{digits}")),
            Ok(format!("a{digits}"))
        );
        assert_eq!(replace_all("b", "(a)?b", "<$1>"), Ok("<>".into()));
    }

    #[test]
    fn replacement_escape_tokens_preserve_java_literal_behavior() {
        assert_eq!(replace_all("a", "a", r"\$1\\\q"), Ok(r"$1\q".into()));
        assert_eq!(replace_all("a", "a", r"\中"), Ok("中".into()));
    }

    #[test]
    fn replacement_invalid_references_are_typed_errors_not_partial_output() {
        for replacement in [
            "$9",
            "$99",
            "${missing}",
            "${}",
            "${1x}",
            "${a_b}",
            "${name",
            "$",
            "$x",
            "$$",
            "\\",
        ] {
            assert!(
                matches!(
                    replace_all("prefix a suffix a", "(a)", replacement),
                    Err(RegexError::InvalidReplacement { .. })
                ),
                "{replacement:?}"
            );
        }
        assert!(matches!(
            replace_all("a", "(a)", "中$9"),
            Err(RegexError::InvalidReplacement { offset: 3, .. })
        ));
        assert_eq!(replace_all("a", "[", "$9"), Err(RegexError::InvalidPattern));
    }

    #[test]
    fn replacement_validation_only_runs_when_replacement_actually_matches() {
        for replacement in ["$9", "${missing}", "$", "\\"] {
            assert_eq!(replace_all("a", "b", replacement), Ok("a".into()));
            assert_eq!(replace_first_match("a", "b", replacement), Ok(None));
        }
        assert_eq!(
            replace_first_match("chapter-12", r"(?<=chapter-)\d+", "$99"),
            Ok(Some("12".into()))
        );
        assert!(matches!(
            replace_first_match("x12y34", r"(\d+)", "$99"),
            Err(RegexError::InvalidReplacement { .. })
        ));
    }

    #[test]
    fn budget_exhaustion_discards_partial_scans_and_replacements() {
        let input = format!("{}!", "a".repeat(16)).repeat(12);
        let pattern = "(a+)+b|.";
        let regex = get_cached_regex(pattern).unwrap();
        assert!(matches!(
            collect_matches(&regex, &input),
            Err(RegexError::BudgetExceeded)
        ));
        assert_eq!(find_all(pattern, &input), None);
        assert_eq!(captures_all(pattern, &input), None);
        assert_eq!(
            replace_all(&input, pattern, "X"),
            Err(RegexError::BudgetExceeded)
        );
        assert_eq!(
            replace_first_match(&"a".repeat(20), "(a+)+b|.", "X"),
            Err(RegexError::BudgetExceeded)
        );
        // Budgets belong to each scan, not the cached compiled pattern.
        assert_eq!(find_all(pattern, "ok"), Some(vec!["o".into(), "k".into()]));
    }

    #[test]
    fn source_regex_preserves_java_match_shapes() {
        assert!(is_valid(r"(?i)reader"));
        assert!(is_full_match(r"reader\d+", "reader42"));
        assert!(!is_full_match(r"reader\d+", "xreader42"));

        assert_eq!(
            captures_first(r"(a)?b", "b"),
            Some(vec![Some("b".into()), None])
        );
        assert_eq!(find_all(r"[ab]", "a b"), Some(vec!["a".into(), "b".into()]));
    }

    #[test]
    fn source_regex_supports_java_pattern_features() {
        assert_eq!(
            find_all(r"(?<=chapter-)\d+", "chapter-12 x chapter-34"),
            Some(vec!["12".into(), "34".into()])
        );
        assert_eq!(
            find_all(r"([ab])\1", "aa ab bb"),
            Some(vec!["aa".into(), "bb".into()])
        );
        assert!(is_full_match(r"(?>a|ab)c", "ac"));
        assert!(!is_full_match(r"(?>a|ab)c", "abc"));
        assert!(is_full_match(r"a++", "aaa"));
        assert!(!is_full_match(r"a++a", "aaa"));
        assert!(is_full_match(r"\Q[a-z]+\E", "[a-z]+"));
    }

    #[test]
    fn source_regex_uses_android_unicode_defaults() {
        assert!(is_full_match(r"\d+", "١٢٣"));
        assert!(is_full_match(r"\w+", "中文"));
        assert!(is_full_match(r"\s", "\u{3000}"));
        assert!(is_full_match(r"(?i)ä", "Ä"));
    }

    #[test]
    fn source_regex_uses_java_replacement_syntax() {
        assert_eq!(
            replace_all("a1 b22", r"(\d+)", "[$1]"),
            Ok("a[1] b[22]".into())
        );
        assert_eq!(replace_all("a1", r"(\d)", r"\$1"), Ok("a$1".into()));
        assert_eq!(
            replace_first_match("x12y34", r"(\d+)", "<$1>"),
            Ok(Some("<12>".into()))
        );
    }
}
