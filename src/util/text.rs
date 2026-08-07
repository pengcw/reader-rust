use regex::Regex;

pub fn strip_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    static REGEX_CACHE: RefCell<HashMap<String, Regex>> = RefCell::new(HashMap::with_capacity(128));
}

pub fn get_cached_regex(pattern: &str) -> Option<Regex> {
    REGEX_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(re) = cache.get(pattern) {
            return Some(re.clone());
        }
        if let Ok(re) = Regex::new(pattern) {
            if cache.len() >= 128 {
                cache.clear();
            }
            cache.insert(pattern.to_string(), re.clone());
            Some(re)
        } else {
            None
        }
    })
}

pub fn apply_regex_replace(input: &str, pattern: &str, replace: &str) -> String {
    if let Some(re) = get_cached_regex(pattern) {
        re.replace_all(input, replace).to_string()
    } else {
        input.to_string()
    }
}

pub fn normalize_source_url(input: &str) -> String {
    input
        .chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t'))
        .collect::<String>()
        .trim()
        .to_string()
}

pub fn repair_encoded_url(input: &str) -> String {
    let normalized = normalize_source_url(input);
    if !(normalized.contains("%3F")
        || normalized.contains("%3f")
        || normalized.contains("%26")
        || normalized.contains("%26")
        || normalized.contains("%3D")
        || normalized.contains("%3d"))
    {
        return normalized;
    }

    normalized
        .replace("%3F", "?")
        .replace("%3f", "?")
        .replace("%26", "&")
        .replace("%3D", "=")
        .replace("%3d", "=")
        .replace("%23", "#")
        .replace("%23", "#")
}
