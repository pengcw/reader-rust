use java_regex::{MatchInfo, Regex};
use std::cell::RefCell;
use std::collections::HashMap;

const SOURCE_REGEX_CACHE_CAPACITY: usize = 128;

thread_local! {
    static SOURCE_REGEX_CACHE: RefCell<HashMap<String, Regex>> =
        RefCell::new(HashMap::with_capacity(SOURCE_REGEX_CACHE_CAPACITY));
}

fn compile_android_pattern(pattern: &str) -> Option<Regex> {
    // Android's java.util.regex.Pattern is ICU-backed and always uses Unicode
    // character classes/case handling. java_regex targets OpenJDK, so enable
    // the equivalent Java U/u flags by default at this compatibility boundary.
    Regex::with_flags(pattern, "uU").ok()
}

fn get_cached_regex(pattern: &str) -> Option<Regex> {
    SOURCE_REGEX_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(regex) = cache.get(pattern) {
            return Some(regex.clone());
        }

        let regex = compile_android_pattern(pattern)?;
        if cache.len() >= SOURCE_REGEX_CACHE_CAPACITY {
            cache.clear();
        }
        cache.insert(pattern.to_string(), regex.clone());
        Some(regex)
    })
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

pub(crate) fn find_all(pattern: &str, input: &str) -> Option<Vec<String>> {
    let regex = get_cached_regex(pattern)?;
    Some(
        regex
            .find_iter(input)
            .map(|found| found.matched_text)
            .collect(),
    )
}

pub(crate) fn captures_first(pattern: &str, input: &str) -> Option<Vec<Option<String>>> {
    let regex = get_cached_regex(pattern)?;
    regex.find_iter(input).next().map(match_captures)
}

pub(crate) fn captures_all(
    pattern: &str,
    input: &str,
) -> Option<Vec<Vec<Option<String>>>> {
    let regex = get_cached_regex(pattern)?;
    Some(regex.find_iter(input).map(match_captures).collect())
}

pub(crate) fn replace_all(
    input: &str,
    pattern: &str,
    replacement: &str,
) -> Result<String, ()> {
    let regex = get_cached_regex(pattern).ok_or(())?;
    Ok(regex.replace_all(input, replacement))
}

pub(crate) fn replace_first_match(
    input: &str,
    pattern: &str,
    replacement: &str,
) -> Result<Option<String>, ()> {
    let regex = get_cached_regex(pattern).ok_or(())?;
    let Some(found) = regex.find_iter(input).next() else {
        return Ok(None);
    };

    // Legado first finds the first match in the original input, then applies
    // replaceFirst to matcher.group(0) and returns only that transformed match.
    // Using matched_text also avoids depending on Java UTF-16 byte offsets.
    Ok(Some(regex.replace_first(&found.matched_text, replacement)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_regex_preserves_java_match_shapes() {
        assert!(is_valid(r"(?i)reader"));
        assert!(is_full_match(r"reader\d+", "reader42"));
        assert!(!is_full_match(r"reader\d+", "xreader42"));

        assert_eq!(
            captures_first(r"(a)?b", "b"),
            Some(vec![Some("b".into()), None])
        );
        assert_eq!(
            find_all(r"[ab]", "a b"),
            Some(vec!["a".into(), "b".into()])
        );
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
        assert_eq!(
            replace_all("a1", r"(\d)", r"\$1"),
            Ok("a$1".into())
        );
        assert_eq!(
            replace_first_match("x12y34", r"(\d+)", "<$1>"),
            Ok(Some("<12>".into()))
        );
    }
}
