use once_cell::sync::Lazy;
use scraper::{ElementRef, Html, Selector};
use std::collections::HashSet;

use crate::parser::rule_analyzer::{self, split_top_level};

#[cfg(test)]
thread_local! {
    static SELECTOR_VISITS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[derive(Clone, Debug, PartialEq)]
enum SelectorBase {
    Css(String),
    Children,
    Text(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IndexMode {
    Select,
    Exclude,
}

#[derive(Clone, Debug, PartialEq)]
enum IndexItem {
    Single(i32),
    Range {
        start: Option<i32>,
        end: Option<i32>,
        step: i32,
    },
}

#[derive(Clone, Debug, PartialEq)]
struct ParsedSelector {
    base: SelectorBase,
    explicit_index: bool,
    index_mode: IndexMode,
    index_items: Vec<IndexItem>,
}

pub fn parse_document(html: &str) -> Html {
    Html::parse_document(html)
}

/// Convert Legado selector format to CSS selector
/// Legado formats:
/// - class.xxx yyy zzz → .xxx.yyy.zzz (multiple classes on one element)
/// - class.xxx or .xxx → .xxx
/// - tag.xxx → xxx (tag name)
/// - id.xxx or #xxx → #xxx
/// - tag.xxx@tag.yyy → nested selectors (split by @)
fn legado_to_css(selector: &str) -> String {
    let selector = selector.trim();

    // Handle special "class." prefix - multiple classes separated by space
    if let Some(rest) = selector.strip_prefix("class.") {
        let classes: Vec<&str> = rest.split_whitespace().collect();
        if classes.len() > 1 {
            return format!(".{}", classes.join("."));
        } else {
            return format!(".{}", rest.trim());
        }
    }

    // Handle id. prefix
    if selector.starts_with("id.") {
        return format!("#{}", &selector[3..]);
    }

    // Handle tag. prefix
    if selector.starts_with("tag.") {
        return selector[4..].to_string();
    }

    // Everything else is standard CSS. Do not guess that descendant
    // whitespace means multiple classes: "ul li" must stay a descendant selector.
    selector.to_string()
}

fn quote_unquoted_colon_attribute_value(attribute: &str) -> Option<String> {
    let mut quote = None;
    let mut escaped = false;
    let mut equals = None;
    for (index, ch) in attribute.char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active_quote {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '=' => {
                equals = Some(index);
                break;
            }
            _ => {}
        }
    }

    let value_start = equals? + 1;
    let leading_space =
        attribute[value_start..].len() - attribute[value_start..].trim_start().len();
    let value_start = value_start + leading_space;
    let value_end = attribute[value_start..]
        .char_indices()
        .find(|(_, ch)| ch.is_whitespace())
        .map_or(attribute.len(), |(index, _)| value_start + index);
    let value = &attribute[value_start..value_end];
    if value.is_empty()
        || !value.contains(':')
        || value.chars().any(|ch| matches!(ch, '\\' | '\'' | '"'))
    {
        return None;
    }

    let mut normalized = String::with_capacity(attribute.len() + 2);
    normalized.push_str(&attribute[..value_start]);
    normalized.push('"');
    normalized.push_str(value);
    normalized.push('"');
    normalized.push_str(&attribute[value_end..]);
    Some(normalized)
}

fn quote_unquoted_colon_attribute_values(selector: &str) -> Option<String> {
    let mut output = String::with_capacity(selector.len());
    let mut copied_until = 0;
    let mut bracket_start = None;
    let mut quote = None;
    let mut escaped = false;
    let mut changed = false;

    for (index, ch) in selector.char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active_quote {
                quote = None;
            }
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '\'' | '"' => quote = Some(ch),
            '[' if bracket_start.is_none() => bracket_start = Some(index),
            ']' => {
                if let Some(start) = bracket_start.take() {
                    if let Some(attribute) =
                        quote_unquoted_colon_attribute_value(&selector[start + 1..index])
                    {
                        output.push_str(&selector[copied_until..start + 1]);
                        output.push_str(&attribute);
                        output.push(']');
                        copied_until = index + 1;
                        changed = true;
                    }
                }
            }
            _ => {}
        }
    }

    if !changed {
        return None;
    }
    output.push_str(&selector[copied_until..]);
    Some(output)
}

// Jsoup's :eq/:lt/:gt test the zero-based *element sibling* index, not the
// position in the complete query result. CSS :nth-child is one-based.
fn normalize_jsoup_eq(selector: &str) -> Option<String> {
    let mut output = String::with_capacity(selector.len());
    let mut cursor = 0;
    let mut quote = None;
    let mut bracket_depth = 0usize;
    let mut escaped = false;
    for (index, ch) in selector.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ':' if bracket_depth == 0 => {
                let kind = ["eq", "lt", "gt"]
                    .into_iter()
                    .find(|kind| selector[index..].starts_with(&format!(":{kind}(")));
                if let Some(kind) = kind {
                    let start = index + kind.len() + 2;
                    let close = start + selector[start..].find(')')?;
                    let arg = selector[start..close].trim();
                    if !arg.is_empty() && arg.bytes().all(|b| b.is_ascii_digit()) {
                        let index_value = arg.parse::<usize>().ok()?;
                        let css = match kind {
                            "eq" => format!(":nth-child({})", index_value.checked_add(1)?),
                            "lt" => format!(":nth-child(-n+{index_value})"),
                            "gt" => format!(":nth-child(n+{})", index_value.checked_add(2)?),
                            _ => unreachable!(),
                        };
                        output.push_str(&selector[cursor..index]);
                        output.push_str(&css);
                        cursor = close + 1;
                    }
                }
            }
            _ => {}
        }
    }
    output.push_str(&selector[cursor..]);
    Some(output)
}

fn parse_css_selector(css_selector: &str) -> Option<Selector> {
    let normalized = normalize_jsoup_eq(css_selector)?;
    Selector::parse(&normalized).ok().or_else(|| {
        let quoted = quote_unquoted_colon_attribute_values(&normalized)?;
        Selector::parse(&quoted).ok()
    })
}

// Jsoup's regex pseudos inspect the matched element's text, before evaluating
// sibling/descendant combinators. Leave regex metacharacters untouched.
fn split_jsoup_matches(selector: &str) -> Option<(&str, &str, &str, bool)> {
    let mut quote = None;
    let mut bracket_depth = 0usize;
    let mut escaped = false;
    for (index, ch) in selector.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ':' if bracket_depth == 0 => {
                let (start, own) = if selector[index..].starts_with(":matchesOwn(") {
                    (index + ":matchesOwn(".len(), true)
                } else if selector[index..].starts_with(":matches(") {
                    (index + ":matches(".len(), false)
                } else {
                    continue;
                };
                let prefix = selector[..index].trim();
                let prefix = if prefix.is_empty() { "*" } else { prefix };
                let mut depth = 1usize;
                let mut in_class = false;
                let mut quoted_literal = false;
                let mut escaped = false;
                for (offset, ch) in selector[start..].char_indices() {
                    if escaped {
                        escaped = false;
                        continue;
                    }
                    if ch == '\\' {
                        let remaining = &selector[start + offset..];
                        if !in_class && remaining.starts_with("\\Q") {
                            quoted_literal = true;
                        } else if quoted_literal && remaining.starts_with("\\E") {
                            quoted_literal = false;
                        }
                        escaped = true;
                        continue;
                    }
                    if quoted_literal {
                        continue;
                    }
                    match ch {
                        '[' => in_class = true,
                        ']' => in_class = false,
                        '(' if !in_class => depth += 1,
                        ')' if !in_class => {
                            depth -= 1;
                            if depth == 0 {
                                let end = start + offset;
                                return Some((
                                    prefix,
                                    &selector[start..end],
                                    &selector[end + 1..],
                                    own,
                                ));
                            }
                        }
                        _ => {}
                    }
                }
                return None;
            }
            _ => {}
        }
    }
    None
}

fn matches_suffix_valid(suffix: &str) -> bool {
    if suffix.is_empty() {
        return true;
    }
    let trimmed = suffix.trim();
    if let Some(rest) = trimmed.strip_prefix(['+', '~']) {
        let (sibling, descendant) = split_contains_sibling(rest);
        return parse_css_selector(sibling).is_some()
            && (descendant.is_empty()
                || parse_css_selector(&scope_child_selector(descendant)).is_some());
    }
    suffix.chars().next().is_some_and(char::is_whitespace)
        && !trimmed.starts_with('>')
        && parse_css_selector(trimmed).is_some()
}

fn select_css_with_matches<'a>(
    selector: &str,
    select: impl Fn(&str) -> Vec<ElementRef<'a>>,
) -> Option<Vec<ElementRef<'a>>> {
    let (prefix, pattern, suffix, own) = split_jsoup_matches(selector)?;
    if !matches_suffix_valid(suffix) || !crate::parser::source_regex::is_valid(pattern) {
        return Some(Vec::new());
    }
    Some(
        select(prefix)
            .into_iter()
            .filter(|el| {
                let text = if own {
                    el.children()
                        .filter_map(|node| node.value().as_text())
                        .map(|node| node.text.as_ref())
                        .collect::<Vec<_>>()
                        .join(" ")
                } else {
                    el.text().collect::<Vec<_>>().join(" ")
                };
                let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
                crate::parser::source_regex::captures_first(pattern, &normalized).is_some()
            })
            .flat_map(|el| {
                let suffix = suffix.trim();
                if suffix.is_empty() {
                    return vec![el];
                }
                if let Some(rest) = suffix.strip_prefix(['+', '~']) {
                    let adjacent = suffix.starts_with('+');
                    let (sibling, descendant) = split_contains_sibling(rest);
                    let Some(sel) = parse_css_selector(sibling) else {
                        return Vec::new();
                    };
                    let matches: Vec<_> = if adjacent {
                        el.next_siblings()
                            .find_map(ElementRef::wrap)
                            .filter(|next| sel.matches(next))
                            .into_iter()
                            .collect()
                    } else {
                        el.next_siblings()
                            .filter_map(ElementRef::wrap)
                            .filter(|next| sel.matches(next))
                            .collect()
                    };
                    if descendant.is_empty() {
                        return matches;
                    }
                    return matches
                        .into_iter()
                        .flat_map(|next| select_css_from_element(next, descendant))
                        .collect();
                }
                select_css_from_element(el, suffix)
            })
            .collect(),
    )
}

// Keep the text predicate attached to the element before a descendant or +/~
// combinator. Filtering the final selector results would inspect the wrong node.
fn split_jsoup_contains(selector: &str) -> Option<(&str, &str, &str, bool)> {
    let mut quote = None;
    let mut bracket_depth = 0usize;
    let mut escaped = false;
    for (index, ch) in selector.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ':' if bracket_depth == 0 => {
                let (start, own) = if selector[index..].starts_with(":containsOwn(") {
                    (index + ":containsOwn(".len(), true)
                } else if selector[index..].starts_with(":contains(") {
                    (index + ":contains(".len(), false)
                } else {
                    continue;
                };
                let mut depth = 1usize;
                let mut escaped = false;
                let mut quote = None;
                let end = selector[start..].char_indices().find_map(|(offset, ch)| {
                    if escaped {
                        escaped = false;
                        return None;
                    }
                    if ch == '\\' {
                        escaped = true;
                        return None;
                    }
                    if let Some(active) = quote {
                        if ch == active {
                            quote = None;
                        }
                        return None;
                    }
                    match ch {
                        '\'' | '"' => quote = Some(ch),
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                return Some(start + offset);
                            }
                        }
                        _ => {}
                    }
                    None
                })?;
                let needle = selector[start..end].trim().trim_matches(['\'', '"']);
                if needle.is_empty() {
                    return None;
                }
                let prefix = selector[..index].trim();
                let prefix = if prefix.is_empty() { "*" } else { prefix };
                return Some((prefix, needle, &selector[end + 1..], own));
            }
            _ => {}
        }
    }
    None
}

fn contains_suffix_valid(suffix: &str) -> bool {
    if suffix.is_empty() {
        return true;
    }
    let trimmed = suffix.trim();
    if let Some(rest) = trimmed.strip_prefix(['+', '~']) {
        let (sibling, descendant) = split_contains_sibling(rest);
        return parse_css_selector(sibling).is_some()
            && (descendant.is_empty()
                || parse_css_selector(&scope_child_selector(descendant)).is_some());
    }
    suffix.chars().next().is_some_and(char::is_whitespace)
        && !trimmed.starts_with('>')
        && parse_css_selector(trimmed).is_some()
}

fn scope_child_selector(selector: &str) -> std::borrow::Cow<'_, str> {
    let selector = selector.trim();
    if selector.starts_with('>') {
        std::borrow::Cow::Owned(format!(":scope {selector}"))
    } else {
        std::borrow::Cow::Borrowed(selector)
    }
}

fn split_contains_sibling(suffix: &str) -> (&str, &str) {
    let suffix = suffix.trim();
    let split = split_top_level(suffix, &[" ", "\t", "\n", "\r", "\x0c", ">", "+", "~"]);
    let end = split.parts.first().map_or(0, String::len);
    (&suffix[..end], suffix[end..].trim())
}

fn css_contains_text(element: &ElementRef<'_>, needle: &str) -> bool {
    let text = element.text().collect::<Vec<_>>().join(" ");
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.to_lowercase().contains(
        &needle
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase(),
    )
}

fn select_css_with_contains<'a>(
    selector: &str,
    select: impl Fn(&str) -> Vec<ElementRef<'a>>,
) -> Vec<ElementRef<'a>> {
    let Some((prefix, needle, suffix, own)) = split_jsoup_contains(selector) else {
        return select(selector);
    };
    if !contains_suffix_valid(suffix) {
        return Vec::new();
    }
    // Jsoup TokenQueue.unescape removes escape markers, retaining doubled slashes.
    let mut chars = needle.chars();
    let mut unescaped = String::with_capacity(needle.len());
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next) = chars.next() {
                unescaped.push(next);
            }
        } else {
            unescaped.push(ch);
        }
    }
    let needle = unescaped.as_str();
    select(prefix)
        .into_iter()
        .filter(|el| {
            if own {
                let text = own_text(el);
                let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
                normalized.to_lowercase().contains(
                    &needle
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ")
                        .to_lowercase(),
                )
            } else {
                css_contains_text(el, needle)
            }
        })
        .flat_map(|el| {
            let suffix = suffix.trim();
            if suffix.is_empty() {
                return vec![el];
            }
            if let Some(rest) = suffix.strip_prefix(['+', '~']) {
                let adjacent = suffix.starts_with('+');
                let (sibling, descendant) = split_contains_sibling(rest);
                let Some(sel) = parse_css_selector(sibling) else {
                    return Vec::new();
                };
                let matches: Vec<_> = if adjacent {
                    el.next_siblings()
                        .find_map(ElementRef::wrap)
                        .filter(|next| sel.matches(next))
                        .into_iter()
                        .collect()
                } else {
                    el.next_siblings()
                        .filter_map(ElementRef::wrap)
                        .filter(|next| sel.matches(next))
                        .collect()
                };
                if descendant.is_empty() {
                    return matches;
                }
                return matches
                    .into_iter()
                    .flat_map(|next| select_css_from_element(next, descendant))
                    .collect();
            }
            select_css_from_element(el, suffix)
        })
        .collect()
}

fn parse_selector_with_index(selector: &str) -> ParsedSelector {
    let selector = selector.trim();

    if let Some((base, index_mode, index_items)) = parse_bracket_index_spec(selector) {
        return ParsedSelector {
            base: parse_selector_base(base),
            explicit_index: true,
            index_mode,
            index_items,
        };
    }

    if let Some((base, index_mode, index_items)) = parse_legacy_index_spec(selector) {
        return ParsedSelector {
            base: parse_selector_base(base),
            explicit_index: true,
            index_mode,
            index_items,
        };
    }

    ParsedSelector {
        base: parse_selector_base(selector),
        explicit_index: false,
        index_mode: IndexMode::Select,
        index_items: Vec::new(),
    }
}

pub(crate) fn css_rule_is_valid(rule: &str) -> bool {
    let combinations = split_top_level(rule, &["&&", "||", "%%"]);
    combinations.parts.iter().all(|part| {
        let chain = split_top_level(part, &["@@"]);
        chain.parts.iter().all(|step| {
            let selector = split_top_level(step, &["@"])
                .parts
                .into_iter()
                .next()
                .unwrap_or_default();
            match parse_selector_with_index(&selector).base {
                SelectorBase::Css(css) => css_fragment_is_valid(&css),
                SelectorBase::Children | SelectorBase::Text(_) => true,
            }
        })
    })
}

// Validate nested CSS fragments without interpreting Legado rule-level extractors.
fn css_fragment_is_valid(css: &str) -> bool {
    if parse_css_selector(css).is_some() {
        return true;
    }
    let groups = split_top_level(css, &[","]);
    if groups.parts.len() > 1 {
        return groups
            .parts
            .iter()
            .all(|group| !group.trim().is_empty() && css_fragment_is_valid(group));
    }
    if let Some((prefix, inner, suffix)) = split_jsoup_not(css) {
        let prefix = if prefix.trim().is_empty() {
            "*"
        } else {
            prefix
        };
        let suffix_valid = if suffix.starts_with([':', '.', '#', '[']) {
            let (condition, relation) = split_contains_sibling(suffix);
            css_fragment_is_valid(&format!("{prefix}{condition}"))
                && (relation.is_empty()
                    || if relation.starts_with(['+', '~']) {
                        contains_suffix_valid(relation)
                    } else {
                        css_fragment_is_valid(&scope_child_selector(relation))
                    })
        } else if suffix.trim_start().starts_with('>') {
            css_fragment_is_valid(&scope_child_selector(suffix))
        } else {
            contains_suffix_valid(suffix)
        };
        css_fragment_is_valid(prefix)
            && !inner.trim().is_empty()
            && css_fragment_is_valid(inner)
            && suffix_valid
    } else if let Some((prefix, inner, suffix)) = split_jsoup_has(css) {
        parse_css_selector(prefix).is_some()
            && (suffix.is_empty()
                || if suffix.trim_start().starts_with('>') {
                    css_fragment_is_valid(&scope_child_selector(suffix))
                } else {
                    contains_suffix_valid(suffix)
                })
            && split_top_level(inner, &[","]).parts.iter().all(|branch| {
                let branch = branch.trim();
                let scoped = if branch.starts_with('>') {
                    format!(":scope {branch}")
                } else {
                    branch.to_owned()
                };
                !branch.is_empty() && css_fragment_is_valid(&scoped)
            })
    } else if let Some((prefix, pattern, suffix, _)) = split_jsoup_matches(css) {
        parse_css_selector(prefix).is_some()
            && crate::parser::source_regex::is_valid(pattern)
            && matches_suffix_valid(suffix)
    } else {
        split_jsoup_contains(css).map_or_else(
            || parse_css_selector(css).is_some(),
            |(prefix, _, suffix, _)| {
                parse_css_selector(prefix).is_some() && contains_suffix_valid(suffix)
            },
        )
    }
}

fn parse_selector_base(selector: &str) -> SelectorBase {
    let selector = selector.trim();
    if selector.is_empty() || selector == "children" {
        return SelectorBase::Children;
    }
    if let Some(text) = selector.strip_prefix("text.") {
        return SelectorBase::Text(text.trim().to_string());
    }
    SelectorBase::Css(legado_to_css(selector))
}

fn parse_bracket_index_spec(selector: &str) -> Option<(&str, IndexMode, Vec<IndexItem>)> {
    let selector = selector.trim();
    if !selector.ends_with(']') {
        return None;
    }
    let start = selector.rfind('[')?;
    let base = selector[..start].trim();
    let mut inner = selector[start + 1..selector.len() - 1].trim();
    let index_mode = if let Some(rest) = inner.strip_prefix('!') {
        inner = rest.trim();
        IndexMode::Exclude
    } else {
        IndexMode::Select
    };

    let mut items = Vec::new();
    if !inner.is_empty() {
        for part in inner.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some(item) = parse_bracket_index_item(part) {
                items.push(item);
            } else {
                return None;
            }
        }
    }

    Some((base, index_mode, items))
}

fn parse_bracket_index_item(part: &str) -> Option<IndexItem> {
    if part.contains(':') {
        let segments: Vec<&str> = part.split(':').collect();
        if segments.len() < 2 || segments.len() > 3 {
            return None;
        }
        let start = parse_optional_i32(segments[0])?;
        let end = parse_optional_i32(segments[1])?;
        let step = match segments.get(2) {
            Some(value) => parse_optional_i32(value)?.unwrap_or(1),
            None => 1,
        };
        return Some(IndexItem::Range { start, end, step });
    }

    Some(IndexItem::Single(part.parse().ok()?))
}

fn parse_optional_i32(part: &str) -> Option<Option<i32>> {
    let part = part.trim();
    if part.is_empty() {
        return Some(None);
    }
    Some(Some(part.parse().ok()?))
}

fn parse_legacy_index_spec(selector: &str) -> Option<(&str, IndexMode, Vec<IndexItem>)> {
    for (delimiter, index_mode) in [('!', IndexMode::Exclude), ('.', IndexMode::Select)] {
        let Some(pos) = selector.rfind(delimiter) else {
            continue;
        };
        let base = selector[..pos].trim();
        let tail = selector[pos + 1..].trim();
        if tail.is_empty() {
            continue;
        }

        let mut items = Vec::new();
        for part in tail.split(':') {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            items.push(IndexItem::Single(part.parse().ok()?));
        }
        return Some((base, index_mode, items));
    }
    None
}

fn collect_matches<'a>(doc: &'a Html, selector: &ParsedSelector) -> Vec<ElementRef<'a>> {
    let matches = match &selector.base {
        SelectorBase::Css(css_selector) => select_css(doc, css_selector),
        SelectorBase::Children => Vec::new(),
        SelectorBase::Text(text) => select_by_text_doc(doc, text),
    };
    apply_indices(matches, selector)
}

fn collect_matches_from_element<'a>(
    el: ElementRef<'a>,
    selector: &ParsedSelector,
) -> Vec<ElementRef<'a>> {
    let matches = match &selector.base {
        SelectorBase::Css(css_selector) => select_css_from_element(el, css_selector),
        SelectorBase::Children => child_elements(el),
        SelectorBase::Text(text) => select_by_text_from_element(el, text),
    };
    apply_indices(matches, selector)
}

fn unique_in_document_order<'a>(
    matches: Vec<ElementRef<'a>>,
    document_elements: impl Iterator<Item = ElementRef<'a>>,
) -> Vec<ElementRef<'a>> {
    if matches.is_empty() {
        return matches;
    }
    let mut remaining: HashSet<_> = matches.into_iter().map(|el| el.id()).collect();
    document_elements
        .filter(|el| remaining.remove(&el.id()))
        .collect()
}

fn split_jsoup_has(selector: &str) -> Option<(&str, &str, &str)> {
    let mut quote = None;
    let mut bracket_depth = 0usize;
    let mut escaped = false;
    for (index, ch) in selector.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ':' if bracket_depth == 0 && selector[index..].starts_with(":has(") => {
                let start = index + ":has(".len();
                let mut depth = 1usize;
                let mut in_quote = None;
                let mut end = None;
                let mut escaped = false;
                for (offset, ch) in selector[start..].char_indices() {
                    if escaped {
                        escaped = false;
                        continue;
                    }
                    if ch == '\\' {
                        escaped = true;
                        continue;
                    }
                    if let Some(q) = in_quote {
                        if ch == q {
                            in_quote = None;
                        }
                        continue;
                    }
                    match ch {
                        '\'' | '"' => in_quote = Some(ch),
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                end = Some(start + offset);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let end = end?;
                let inner = selector[start..end].trim();
                if inner.is_empty() {
                    return None;
                }
                let prefix = selector[..index].trim();
                let prefix = if prefix.is_empty() { "*" } else { prefix };
                return Some((prefix, inner, &selector[end + 1..]));
            }
            _ => {}
        }
    }
    None
}

// Choose the last outer :not so chained predicates are evaluated left to right.
fn split_jsoup_not(selector: &str) -> Option<(&str, &str, &str)> {
    let mut depth = 0usize;
    let mut bracket = 0usize;
    let mut quote = None;
    let mut escaped = false;
    let mut start = None;
    let mut found = None;
    for (index, ch) in selector.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '[' => bracket += 1,
            ']' => bracket = bracket.saturating_sub(1),
            ':' if bracket == 0 && depth == 0 && selector[index..].starts_with(":not(") => {
                start = Some(index);
            }
            '(' if bracket == 0 => depth += 1,
            ')' if bracket == 0 => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    if let Some(begin) = start.take() {
                        found = Some((
                            &selector[..begin],
                            &selector[begin + 5..index],
                            &selector[index + 1..],
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    found
}

fn select_css_with_not<'a>(
    selector: &str,
    select: impl Fn(&str) -> Vec<ElementRef<'a>>,
) -> Option<Vec<ElementRef<'a>>> {
    let (prefix, inner, suffix) = split_jsoup_not(selector)?;
    if inner.trim().is_empty() {
        return Some(Vec::new());
    }
    let excluded: HashSet<_> = select(inner).into_iter().map(|el| el.id()).collect();
    let prefix = if prefix.trim().is_empty() {
        "*"
    } else {
        prefix
    };
    // Conditions immediately after :not still constrain the same subject.
    let (condition, relation) = if suffix.starts_with([':', '.', '#', '[']) {
        split_contains_sibling(suffix)
    } else {
        ("", suffix)
    };
    let candidate_rule = format!("{prefix}{condition}");
    Some(
        select(&candidate_rule)
            .into_iter()
            .filter(|el| !excluded.contains(&el.id()))
            .flat_map(|el| select_css_suffix(el, relation))
            .collect(),
    )
}

fn has_condition_matches(el: ElementRef<'_>, inner: &str) -> bool {
    let sub_selectors = split_top_level(inner, &[","]);
    for sub in sub_selectors.parts {
        let sub = sub.trim();
        if sub.is_empty() {
            continue;
        }
        if sub.starts_with('>') {
            if !select_css_from_element(el, &format!(":scope {sub}")).is_empty() {
                return true;
            }
        } else if !select_css_from_element(el, sub).is_empty() {
            return true;
        }
    }
    false
}

fn select_css_with_has<'a>(
    selector: &str,
    select: impl Fn(&str) -> Vec<ElementRef<'a>>,
) -> Option<Vec<ElementRef<'a>>> {
    if parse_css_selector(selector).is_some() {
        return None;
    }
    let (prefix, inner, suffix) = split_jsoup_has(selector)?;
    let candidates = select(prefix);
    let matched_candidates = candidates
        .into_iter()
        .filter(|el| has_condition_matches(*el, inner))
        .collect::<Vec<_>>();
    Some(
        matched_candidates
            .into_iter()
            .flat_map(|el| select_css_suffix(el, suffix))
            .collect(),
    )
}

fn select_css_suffix<'a>(el: ElementRef<'a>, suffix: &str) -> Vec<ElementRef<'a>> {
    let suffix = suffix.trim();
    if suffix.is_empty() {
        return vec![el];
    }
    let mut results = Vec::new();
    if let Some(rest) = suffix.strip_prefix(['+', '~']) {
        let adjacent = suffix.starts_with('+');
        let (sibling, descendant) = split_contains_sibling(rest);
        let Some(sel) = parse_css_selector(sibling) else {
            return Vec::new();
        };
        let matches: Vec<_> = if adjacent {
            el.next_siblings()
                .find_map(ElementRef::wrap)
                .filter(|next| sel.matches(next))
                .into_iter()
                .collect()
        } else {
            el.next_siblings()
                .filter_map(ElementRef::wrap)
                .filter(|next| sel.matches(next))
                .collect()
        };
        if descendant.is_empty() {
            results.extend(matches);
        } else {
            for next in matches {
                results.extend(select_css_from_element(next, descendant));
            }
        }
    } else {
        results.extend(select_css_from_element(el, suffix));
    }
    results
}

fn select_css<'a>(doc: &'a Html, css_selector: &str) -> Vec<ElementRef<'a>> {
    #[cfg(test)]
    SELECTOR_VISITS.with(|visits| visits.borrow_mut().push(css_selector.to_owned()));
    let groups = split_top_level(css_selector, &[","]);
    if groups.parts.len() > 1 {
        let matches = groups
            .parts
            .iter()
            .flat_map(|part| select_css(doc, part))
            .collect();
        let all = Selector::parse("*").expect("valid universal selector");
        return unique_in_document_order(matches, doc.select(&all));
    }
    if let Some(matches) = select_css_with_not(css_selector, |part| select_css(doc, part)) {
        let all = Selector::parse("*").expect("valid universal selector");
        return unique_in_document_order(matches, doc.select(&all));
    }
    if let Some(matches) = select_css_with_has(css_selector, |part| select_css(doc, part)) {
        let all = Selector::parse("*").expect("valid universal selector");
        return unique_in_document_order(matches, doc.select(&all));
    }
    if let Some(matches) = select_css_with_matches(css_selector, |part| {
        parse_css_selector(part)
            .map(|sel| doc.select(&sel).collect())
            .unwrap_or_default()
    }) {
        let all = Selector::parse("*").expect("valid universal selector");
        return unique_in_document_order(matches, doc.select(&all));
    }
    select_css_with_contains(css_selector, |part| {
        let Some(sel) = parse_css_selector(part) else {
            return Vec::new();
        };
        doc.select(&sel).collect()
    })
}

pub(crate) fn select_css_list<'a>(doc: &'a Html, css_selector: &str) -> Vec<ElementRef<'a>> {
    select_css(doc, css_selector)
}

pub(crate) fn select_css_from_element<'a>(
    el: ElementRef<'a>,
    css_selector: &str,
) -> Vec<ElementRef<'a>> {
    let scoped = scope_child_selector(css_selector);
    let css_selector = scoped.as_ref();
    let groups = split_top_level(css_selector, &[","]);
    if groups.parts.len() > 1 {
        let matches = groups
            .parts
            .iter()
            .flat_map(|part| select_css_from_element(el, part))
            .collect();
        let all = Selector::parse("*").expect("valid universal selector");
        return unique_in_document_order(matches, el.select(&all));
    }
    if let Some(matches) =
        select_css_with_not(css_selector, |part| select_css_from_element(el, part))
    {
        let all = Selector::parse("*").expect("valid universal selector");
        return unique_in_document_order(matches, el.select(&all));
    }
    if let Some(matches) =
        select_css_with_has(css_selector, |part| select_css_from_element(el, part))
    {
        let all = Selector::parse("*").expect("valid universal selector");
        return unique_in_document_order(matches, el.select(&all));
    }
    if let Some(matches) = select_css_with_matches(css_selector, |part| {
        parse_css_selector(part)
            .map(|sel| el.select(&sel).collect())
            .unwrap_or_default()
    }) {
        let all = Selector::parse("*").expect("valid universal selector");
        return unique_in_document_order(matches, el.select(&all));
    }
    select_css_with_contains(css_selector, |part| {
        let Some(sel) = parse_css_selector(part) else {
            return Vec::new();
        };
        el.select(&sel).collect()
    })
}

fn child_elements<'a>(el: ElementRef<'a>) -> Vec<ElementRef<'a>> {
    el.children().filter_map(ElementRef::wrap).collect()
}

fn select_by_text_doc<'a>(doc: &'a Html, needle: &str) -> Vec<ElementRef<'a>> {
    let sel = Selector::parse("*").unwrap();
    doc.select(&sel)
        .filter(|el| own_text(el).contains(needle))
        .collect()
}

fn select_by_text_from_element<'a>(el: ElementRef<'a>, needle: &str) -> Vec<ElementRef<'a>> {
    let mut matches = Vec::new();
    if own_text(&el).contains(needle) {
        matches.push(el);
    }
    if let Ok(sel) = Selector::parse("*") {
        matches.extend(
            el.select(&sel)
                .filter(|candidate| own_text(candidate).contains(needle)),
        );
    }
    matches
}

fn own_text(el: &ElementRef) -> String {
    let mut text = String::new();
    for node in el.children() {
        if let Some(text_node) = node.value().as_text() {
            text.push_str(text_node.text.trim());
        }
    }
    text
}

fn apply_indices<'a>(
    matches: Vec<ElementRef<'a>>,
    selector: &ParsedSelector,
) -> Vec<ElementRef<'a>> {
    if !selector.explicit_index {
        return matches;
    }

    let resolved = resolve_indices(matches.len(), &selector.index_items);
    if selector.index_mode == IndexMode::Exclude {
        let exclude_set: HashSet<usize> = resolved.into_iter().collect();
        return matches
            .into_iter()
            .enumerate()
            .filter(|(idx, _)| !exclude_set.contains(idx))
            .map(|(_, el)| el)
            .collect();
    }

    resolved
        .into_iter()
        .filter_map(|idx| matches.get(idx).copied())
        .collect()
}

fn resolve_indices(len: usize, items: &[IndexItem]) -> Vec<usize> {
    if len == 0 {
        return Vec::new();
    }

    let mut seen = HashSet::new();
    let mut resolved = Vec::new();
    for item in items {
        for idx in expand_index_item(len, item) {
            if seen.insert(idx) {
                resolved.push(idx);
            }
        }
    }
    resolved
}

fn expand_index_item(len: usize, item: &IndexItem) -> Vec<usize> {
    match item {
        IndexItem::Single(idx) => normalize_index(*idx, len).into_iter().collect(),
        IndexItem::Range { start, end, step } => expand_range(len, *start, *end, *step),
    }
}

fn normalize_index(index: i32, len: usize) -> Option<usize> {
    let len_i32 = len as i32;
    let resolved = if index < 0 { len_i32 + index } else { index };
    if resolved < 0 || resolved >= len_i32 {
        return None;
    }
    Some(resolved as usize)
}

fn expand_range(len: usize, start: Option<i32>, end: Option<i32>, step: i32) -> Vec<usize> {
    if len == 0 {
        return Vec::new();
    }

    let len_i32 = len as i32;
    let mut start = start.unwrap_or(0);
    let mut end = end.unwrap_or(len_i32 - 1);

    if start < 0 {
        start += len_i32;
    }
    if end < 0 {
        end += len_i32;
    }

    if (start < 0 && end < 0) || (start >= len_i32 && end >= len_i32) {
        return Vec::new();
    }

    start = start.clamp(0, len_i32 - 1);
    end = end.clamp(0, len_i32 - 1);

    let step = if step > 0 {
        step as usize
    } else if -step < len_i32 {
        (step + len_i32).max(1) as usize
    } else {
        1
    };

    let mut indices = Vec::new();
    if start <= end {
        let mut current = start as usize;
        let end = end as usize;
        while current <= end {
            indices.push(current);
            current = match current.checked_add(step) {
                Some(next) => next,
                None => break,
            };
        }
    } else {
        let mut current = start as usize;
        let end = end as usize;
        loop {
            indices.push(current);
            if current <= end || current < step {
                break;
            }
            current -= step;
        }
    }

    indices
}

fn is_value_extractor(part: &str) -> bool {
    let s = part.trim();
    let s = s.strip_prefix('@').unwrap_or(s);
    matches!(
        s,
        "text" | "textNodes" | "ownText" | "html" | "all" | "src" | "href"
    ) || s.starts_with("attr[")
}

fn select_chain<'a>(doc: &'a Html, rule: &str) -> Vec<ElementRef<'a>> {
    let rule = rule.trim();
    if rule.is_empty() {
        return Vec::new();
    }
    let rule = rule.strip_prefix("@@").unwrap_or(rule);
    let parts = split_top_level(rule, &["@", "@@"]).parts;
    let mut current_matches: Vec<ElementRef<'a>> = Vec::new();
    let mut is_first = true;

    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if is_value_extractor(part) {
            break;
        }
        let parsed = parse_selector_with_index(part);
        if is_first {
            current_matches = collect_matches(doc, &parsed);
            is_first = false;
        } else {
            let mut next = Vec::new();
            for parent in current_matches {
                next.extend(collect_matches_from_element(parent, &parsed));
            }
            current_matches = next;
        }
        if current_matches.is_empty() {
            break;
        }
    }
    current_matches
}

/// Select elements with Legado rule syntax
pub fn select_list<'a>(doc: &'a Html, selector: &str) -> Vec<ElementRef<'a>> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Vec::new();
    }

    // Handle list combination operators at the top level
    if selector.contains("&&") || selector.contains("||") || selector.contains("%%") {
        return select_with_combination(doc, selector);
    }

    select_chain(doc, selector)
}

/// Handle list combination operators
fn select_with_combination<'a>(doc: &'a Html, rule: &str) -> Vec<ElementRef<'a>> {
    let split = split_top_level(rule, &["&&", "||", "%%"]);
    let rules = split.parts;

    if rules.is_empty() {
        return vec![];
    }

    let operator = split.delimiter.as_deref().unwrap_or("");
    if operator == "%%" {
        return rule_analyzer::interleave_result_groups(
            rules.iter().map(|rule| select_chain(doc, rule)).collect(),
        );
    }

    let mut result = select_chain(doc, &rules[0]);
    for next_rule in rules.iter().skip(1) {
        if operator == "||" && !result.is_empty() {
            break;
        }
        let next_results = select_chain(doc, next_rule);
        match operator {
            "&&" => result.extend(next_results),
            "||" if result.is_empty() => result = next_results,
            _ => {}
        }
    }

    result
}

/// Extract text from element with various Legado extractors
pub fn extract_text(el: &ElementRef, extractor: &str) -> Option<String> {
    let extractor = extractor.trim();

    match extractor {
        "text" | "@text" => {
            let text = el.text().collect::<Vec<_>>().join(" ");
            let text = text.trim().to_string();
            if text.is_empty() {
                None
            } else {
                Some(text)
            }
        }
        "textNodes" | "@textNodes" => {
            let text = get_text_nodes(el);
            if text.is_empty() {
                None
            } else {
                Some(text)
            }
        }
        "ownText" | "@ownText" => {
            let mut own_text = String::new();
            for node in el.children() {
                if let Some(text_node) = node.value().as_text() {
                    own_text.push_str(text_node.text.trim());
                    own_text.push(' ');
                }
            }
            let text = own_text.trim().to_string();
            if text.is_empty() {
                None
            } else {
                Some(text)
            }
        }
        // @html 语义为 innerHTML（不含元素自身标签）；el.html() 是 outerHTML，
        // 会把容器开标签（如 <div id="clickeye_content">）带入正文导致"没清理干净"。
        "html" | "@html" => Some(el.inner_html()),
        "all" | "@all" => Some(el.html()),
        _ => {
            if let Some(attr_name) = parse_attr_extractor(extractor) {
                return el.value().attr(attr_name).map(|v| v.to_string());
            }

            if extractor.starts_with('@') {
                el.value().attr(&extractor[1..]).map(|v| v.to_string())
            } else {
                el.value().attr(extractor).map(|v| v.to_string())
            }
        }
    }
}

fn parse_attr_extractor(extractor: &str) -> Option<&str> {
    let extractor = extractor.trim();
    let extractor = extractor.strip_prefix('@').unwrap_or(extractor);
    extractor
        .strip_prefix("attr[")
        .and_then(|s| s.strip_suffix(']'))
        .filter(|s| !s.is_empty())
}

/// Match Jsoup `TextNode.text()` followed by Legado's `trim { it <= ' ' }`.
///
/// Jsoup collapses its "actual whitespace" set (ASCII whitespace plus NBSP) to
/// a single regular space and removes zero-width spaces / soft hyphens. Keep
/// other Unicode whitespace, such as U+3000 IDEOGRAPHIC SPACE, untouched.
pub(crate) fn normalize_jsoup_text_node(text: &str) -> String {
    let mut normalized = String::with_capacity(text.len());
    let mut last_was_whitespace = false;

    for ch in text.chars() {
        if matches!(ch, ' ' | '\t' | '\n' | '\r' | '\x0C' | '\u{00A0}') {
            if !last_was_whitespace {
                normalized.push(' ');
                last_was_whitespace = true;
            }
        } else if matches!(ch, '\u{200B}' | '\u{00AD}') {
            continue;
        } else {
            normalized.push(ch);
            last_was_whitespace = false;
        }
    }

    normalized.trim_matches(|ch| ch <= '\u{0020}').to_string()
}

/// Extract direct text nodes, matching Legado's Jsoup `Element.textNodes()` behavior.
fn get_text_nodes(el: &ElementRef) -> String {
    let tag = el.value().name();
    if tag.eq_ignore_ascii_case("script") || tag.eq_ignore_ascii_case("style") {
        return String::new();
    }

    el.children()
        .filter_map(|node| node.value().as_text())
        .map(|text_node| normalize_jsoup_text_node(&text_node.text))
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Preserve recursive text collection for internal rule input, which is not the `textNodes` extractor.
pub(crate) fn get_descendant_text_nodes(el: &ElementRef) -> String {
    let mut texts = Vec::new();
    collect_descendant_text_nodes(*el, &mut texts);
    texts.join("\n")
}

fn collect_descendant_text_nodes(el: ElementRef, texts: &mut Vec<String>) {
    for node in el.children() {
        if let Some(text_node) = node.value().as_text() {
            let text = text_node.text.trim().to_string();
            if !text.is_empty() {
                texts.push(text);
            }
        }
        if let Some(child_el) = ElementRef::wrap(node) {
            collect_descendant_text_nodes(child_el, texts);
        }
    }
}

pub fn select_text_from_element(el: &ElementRef, rule: &str) -> Option<String> {
    let parts = split_top_level(rule, &["@"]).parts;
    let mut current_matches = vec![*el];

    for i in 0..parts.len() {
        let part = parts[i].trim();
        if part.is_empty() {
            continue;
        }

        if i == parts.len() - 1 {
            return current_matches
                .into_iter()
                .find_map(|current| extract_text(&current, part));
        }

        let parsed = parse_selector_with_index(part);
        let current_level = current_matches;
        let mut next_matches = Vec::new();
        for current in current_level {
            next_matches.extend(collect_matches_from_element(current, &parsed));
        }
        if next_matches.is_empty() {
            return None;
        }
        current_matches = next_matches;
    }

    current_matches
        .into_iter()
        .find_map(|current| extract_text(&current, "text"))
}

/// Element-relative list extraction used by composite field rules. The scalar
/// entry point above retains its historical first-match behavior.
pub(crate) fn select_text_list_from_element(el: &ElementRef, rule: &str) -> Vec<String> {
    let parts = split_top_level(rule, &["@"]).parts;
    let mut matches = vec![*el];
    for (index, part) in parts.iter().enumerate() {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if index == parts.len() - 1 {
            return matches
                .into_iter()
                .filter_map(|el| extract_text(&el, part))
                .collect();
        }
        let selector = parse_selector_with_index(part);
        matches = matches
            .into_iter()
            .flat_map(|el| collect_matches_from_element(el, &selector))
            .collect();
        if matches.is_empty() {
            return Vec::new();
        }
    }
    matches
        .into_iter()
        .filter_map(|el| extract_text(&el, "text"))
        .collect()
}

/// Select all matching elements and collect their text, joined by newlines
pub fn select_all_text(doc: &Html, rule: &str) -> Option<String> {
    let parts = split_top_level(rule, &["@"]).parts;
    if parts.is_empty() {
        return None;
    }

    let first_part = parts[0].trim();
    let roots = collect_matches(doc, &parse_selector_with_index(first_part));
    if roots.is_empty() {
        return None;
    }

    if parts.len() > 1 {
        let mut all_texts = Vec::new();
        let sub_rule = parts[1..].join("@");

        for root in roots {
            let extracted = select_text_list_from_element(&root, &sub_rule);
            if !extracted.is_empty() {
                all_texts.extend(extracted);
                continue;
            }

            let last_part = sub_rule.trim();
            if let Some(text) = extract_text(&root, last_part) {
                if !text.is_empty() {
                    all_texts.push(text);
                }
                continue;
            }

            let parsed = parse_selector_with_index(sub_rule.trim());
            for el in collect_matches_from_element(root, &parsed) {
                if let Some(text) = extract_text(&el, "text") {
                    if !text.is_empty() {
                        all_texts.push(text);
                    }
                }
            }
        }

        if all_texts.is_empty() {
            return None;
        }
        return Some(all_texts.join("\n"));
    }

    let mut texts = Vec::new();
    for root in roots {
        if let Some(text) = extract_text(&root, "textNodes") {
            if !text.is_empty() {
                texts.push(text);
            }
        }
    }
    if texts.is_empty() {
        return None;
    }
    Some(texts.join("\n"))
}

pub fn select_text(doc: &Html, rule: &str) -> Option<String> {
    select_text_list(doc, rule).into_iter().next()
}

pub fn select_text_list(doc: &Html, rule: &str) -> Vec<String> {
    let combo = split_top_level(rule, &["&&", "||", "%%"]);
    if let Some(operator) = combo.delimiter.as_deref() {
        if operator == "%%" {
            return rule_analyzer::interleave_result_groups(
                combo
                    .parts
                    .iter()
                    .map(|part| select_text_list(doc, part))
                    .collect(),
            );
        }

        let mut result =
            select_text_list(doc, combo.parts.first().map(String::as_str).unwrap_or(""));
        for part in combo.parts.iter().skip(1) {
            if operator == "||" && !result.is_empty() {
                break;
            }
            let next = select_text_list(doc, part);
            match operator {
                "&&" => result.extend(next),
                "||" if result.is_empty() => result = next,
                _ => {}
            }
        }
        return result;
    }

    // Handle rule chaining with @@ only when it appears at the top level.
    let chain = split_top_level(rule, &["@@"]);
    if chain.delimiter.is_some() {
        let mut rules = chain.parts.into_iter();
        let Some(first_rule) = rules.next() else {
            return vec![];
        };
        let mut current_texts = select_text_list(doc, &first_rule);

        for rule in rules {
            if current_texts.is_empty() {
                break;
            }
            let mut new_texts = Vec::new();
            for text in &current_texts {
                let sub_doc = Html::parse_document(text);
                new_texts.extend(select_text_list(&sub_doc, &rule));
            }
            current_texts = new_texts;
        }

        return current_texts;
    }

    let parts = split_top_level(rule, &["@"]).parts;
    if parts.is_empty() {
        return vec![];
    }

    let first_part = parts[0].trim();

    let matches = collect_matches(doc, &parse_selector_with_index(first_part));
    if matches.is_empty() {
        return vec![];
    }

    let mut results = Vec::new();
    for el in matches {
        if parts.len() > 1 {
            let rest = parts[1..].join("@");
            if let Some(v) = select_text_from_element(&el, &rest) {
                results.push(v);
            }
        } else {
            results.push(extract_text(&el, "text").unwrap_or_default());
        }
    }
    results
}

/// Parse XML/XHTML or HTML-like input for XPath evaluation.
///
/// Match Legado's parser choice: only an explicit XML declaration selects XML
/// mode; all other strings are repaired through the HTML parser first.
pub(crate) fn parse_xpath_package(
    input: &str,
) -> Result<sxd_document::Package, sxd_document::parser::Error> {
    parse_xpath_package_with_mode(input).map(|(package, _)| package)
}

pub(crate) fn parse_xpath_package_with_mode(
    input: &str,
) -> Result<(sxd_document::Package, bool), sxd_document::parser::Error> {
    // Legado only chooses XML mode when the trimmed input starts with an XML
    // declaration. Everything else goes through the HTML parser, even if it is
    // otherwise well-formed XML.
    let mut prepared = input.to_string();
    if prepared.ends_with("</td>") {
        prepared = format!("<tr>{prepared}</tr>");
    }
    if prepared.ends_with("</tr>") || prepared.ends_with("</tbody>") {
        prepared = format!("<table>{prepared}</table>");
    }

    if prepared
        .trim_start()
        .get(.."<?xml".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("<?xml"))
    {
        let normalized = normalize_xpath_entities(prepared.trim_start());
        if let Ok(package) = sxd_document::parser::parse(normalized.as_ref()) {
            return Ok((package, false));
        }
    }

    // HTML mode mirrors JXDocument.create(String): repair malformed HTML first,
    // then bridge the resulting DOM into the XML-only XPath evaluator.
    let document = Html::parse_document(&prepared);
    let repaired = html_to_xpath_xml(&document.html());
    sxd_document::parser::parse(&repaired).map(|package| (package, true))
}

fn html_to_xpath_xml(html: &str) -> String {
    static DOCTYPE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"(?is)<!doctype[^>]*>").expect("valid doctype regex"));
    static VOID_ELEMENT: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r"(?is)<(area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)(\b[^>]*)>",
        )
        .expect("valid HTML void element regex")
    });

    let without_doctype = DOCTYPE.replace_all(html, "");
    let xml = VOID_ELEMENT.replace_all(&without_doctype, |captures: &regex::Captures| {
        let whole = captures
            .get(0)
            .map(|value| value.as_str())
            .unwrap_or_default();
        let attrs = captures
            .get(2)
            .map(|value| value.as_str())
            .unwrap_or_default();
        if attrs.trim_end().ends_with('/') {
            whole.to_string()
        } else {
            format!("<{}{} />", &captures[1], attrs)
        }
    });
    normalize_xpath_entities(xml.as_ref()).into_owned()
}

fn normalize_xpath_entities(input: &str) -> std::borrow::Cow<'_, str> {
    if !input.contains('&') {
        return std::borrow::Cow::Borrowed(input);
    }

    let mut normalized = String::with_capacity(input.len());
    let mut cursor = 0;
    let mut changed = false;

    while let Some(relative_ampersand) = input[cursor..].find('&') {
        let ampersand = cursor + relative_ampersand;
        normalized.push_str(&input[cursor..ampersand]);
        let Some(relative_semicolon) = input[ampersand..].find(';') else {
            normalized.push_str(&input[ampersand..]);
            cursor = input.len();
            break;
        };
        let semicolon = ampersand + relative_semicolon;
        let entity = &input[ampersand + 1..semicolon];

        if let Some(replacement) = xpath_html_entity(entity) {
            normalized.push_str(replacement);
            changed = true;
        } else {
            normalized.push_str(&input[ampersand..=semicolon]);
        }
        cursor = semicolon + 1;
    }

    normalized.push_str(&input[cursor..]);
    if changed {
        std::borrow::Cow::Owned(normalized)
    } else {
        std::borrow::Cow::Borrowed(input)
    }
}

fn xpath_html_entity(entity: &str) -> Option<&'static str> {
    match entity {
        "nbsp" => Some("\u{00A0}"),
        "copy" => Some("©"),
        "reg" => Some("®"),
        "trade" => Some("™"),
        "middot" => Some("·"),
        "mdash" => Some("—"),
        "ndash" => Some("–"),
        "hellip" => Some("…"),
        "emsp" => Some("\u{2003}"),
        "ensp" => Some("\u{2002}"),
        // XML's five predefined entities, numeric entities, and unknown names
        // stay untouched for the XML parser to interpret or reject.
        _ => None,
    }
}

/// XPath id() function implementation for HTML/XML documents
struct HtmlIdFunction;

impl sxd_xpath::function::Function for HtmlIdFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath::context::Evaluation<'c, 'd>,
        mut args: Vec<sxd_xpath::Value<'d>>,
    ) -> Result<sxd_xpath::Value<'d>, sxd_xpath::function::Error> {
        if args.is_empty() {
            return Err(sxd_xpath::function::Error::NotEnoughArguments {
                expected: 1,
                actual: 0,
            });
        }
        if args.len() > 1 {
            return Err(sxd_xpath::function::Error::TooManyArguments {
                expected: 1,
                actual: args.len(),
            });
        }
        let arg = args.pop().unwrap();
        let id_targets: Vec<String> = match arg {
            sxd_xpath::Value::Nodeset(ns) => ns
                .document_order()
                .into_iter()
                .flat_map(|n| {
                    n.string_value()
                        .split_whitespace()
                        .map(String::from)
                        .collect::<Vec<_>>()
                })
                .collect(),
            val => val.string().split_whitespace().map(String::from).collect(),
        };

        let mut matched = sxd_xpath::nodeset::Nodeset::new();
        if !id_targets.is_empty() {
            fn collect_element<'d>(
                elem: sxd_document::dom::Element<'d>,
                targets: &[String],
                matched: &mut sxd_xpath::nodeset::Nodeset<'d>,
            ) {
                if let Some(id_val) = elem.attribute("id").map(|a| a.value()) {
                    if targets.iter().any(|t| t == id_val) {
                        matched.add(elem);
                    }
                }
                for child in elem.children() {
                    if let sxd_document::dom::ChildOfElement::Element(e) = child {
                        collect_element(e, targets, matched);
                    }
                }
            }

            for child in context.node.document().root().children() {
                if let sxd_document::dom::ChildOfRoot::Element(e) = child {
                    collect_element(e, &id_targets, &mut matched);
                }
            }
        }

        Ok(sxd_xpath::Value::Nodeset(matched))
    }
}

fn xpath_name_start(character: char) -> bool {
    character == '_'
        || character.is_alphabetic()
        || (!character.is_ascii() && !character.is_whitespace())
}

fn xpath_name_char(character: char) -> bool {
    xpath_name_start(character) || character.is_ascii_digit() || matches!(character, '.' | '-')
}

fn xpath_prefixes(xpath: &str) -> HashSet<String> {
    let characters: Vec<_> = xpath.char_indices().collect();
    let mut prefixes = HashSet::new();
    let mut quote = None;

    for index in 0..characters.len() {
        let (_, character) = characters[index];
        if let Some(active_quote) = quote {
            if character == active_quote {
                quote = None;
            }
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
            continue;
        }
        if character != ':'
            || index == 0
            || index + 1 == characters.len()
            || characters[index - 1].1 == ':'
            || characters[index + 1].1 == ':'
        {
            continue;
        }

        let mut start = index;
        while start > 0 && xpath_name_char(characters[start - 1].1) {
            start -= 1;
        }
        if start == index || !xpath_name_start(characters[start].1) {
            continue;
        }
        let next = characters[index + 1].1;
        if next != '*' && !xpath_name_start(next) {
            continue;
        }

        let prefix_start = characters[start].0;
        let (last_offset, last_character) = characters[index - 1];
        let prefix_end = last_offset + last_character.len_utf8();
        prefixes.insert(xpath[prefix_start..prefix_end].to_string());
    }

    prefixes
}

fn register_xpath_element_namespaces<'d>(
    context: &mut sxd_xpath::Context<'d>,
    element: sxd_document::dom::Element<'d>,
    required: &HashSet<String>,
    registered: &mut HashSet<String>,
) -> bool {
    for namespace in element.namespaces_in_scope() {
        let prefix = namespace.prefix();
        if required.contains(prefix) && registered.insert(prefix.to_string()) {
            context.set_namespace(prefix, namespace.uri());
        }
    }
    if required.is_subset(registered) {
        return true;
    }
    for child in element.children() {
        if let sxd_document::dom::ChildOfElement::Element(child) = child {
            if register_xpath_element_namespaces(context, child, required, registered) {
                return true;
            }
        }
    }
    false
}

fn new_xpath_context<'d>(
    node: sxd_xpath::nodeset::Node<'d>,
    xpath: &str,
) -> Option<sxd_xpath::Context<'d>> {
    let mut context = sxd_xpath::Context::new();
    context.set_function("id", HtmlIdFunction);

    let required = xpath_prefixes(xpath);
    if required.is_empty() {
        return Some(context);
    }

    let mut registered = HashSet::new();
    let scope = match node {
        sxd_xpath::nodeset::Node::Element(element) => Some(element),
        _ => node.parent().and_then(|parent| match parent {
            sxd_xpath::nodeset::Node::Element(element) => Some(element),
            _ => None,
        }),
    };
    if let Some(element) = scope {
        for namespace in element.namespaces_in_scope() {
            if required.contains(namespace.prefix()) {
                context.set_namespace(namespace.prefix(), namespace.uri());
                registered.insert(namespace.prefix().to_string());
            }
        }
        return required.is_subset(&registered).then_some(context);
    }
    // Root queries retain the existing document-wide prefix discovery policy.
    for child in node.document().root().children() {
        if let sxd_document::dom::ChildOfRoot::Element(element) = child {
            if register_xpath_element_namespaces(&mut context, element, &required, &mut registered)
            {
                break;
            }
        }
    }

    // sxd-xpath 0.4.2 panics while evaluating an unbound prefix. Treat an
    // unresolved prefix as a non-match instead of allowing it to abort the FFI host.
    if !required.is_subset(&registered) {
        return None;
    }
    Some(context)
}

pub(crate) fn xpath_rule(rule: &str) -> Option<&str> {
    let rule = rule.trim();
    if rule
        .get(.."@xpath:".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("@xpath:"))
    {
        return Some(rule["@xpath:".len()..].trim());
    }
    (rule.starts_with('/') || rule.starts_with("./") || rule.starts_with("id(")).then_some(rule)
}

fn normalize_xpath_query(xpath: &str) -> std::borrow::Cow<'_, str> {
    let trimmed = xpath.trim();
    if matches!(trimmed, "allText()" | "html()") {
        return std::borrow::Cow::Borrowed(".");
    }
    if trimmed == "@text" {
        return std::borrow::Cow::Borrowed("text()");
    }

    let (base, suffix) = if let Some(value) = trimmed.strip_suffix("/allText()") {
        (value, "all_text")
    } else if let Some(value) = trimmed.strip_suffix("/@text") {
        (value, "text")
    } else if let Some(value) = trimmed.strip_suffix("/html()") {
        (value, "html")
    } else {
        return std::borrow::Cow::Borrowed(trimmed);
    };

    let normalized = match suffix {
        "text" => format!("{base}/text()"),
        "all_text" | "html" if base.is_empty() => ".".to_string(),
        _ => base.to_string(),
    };
    std::borrow::Cow::Owned(normalized)
}

fn xpath_candidates(xpath: &str, root: bool) -> Vec<String> {
    let mut candidates = vec![xpath.to_string()];
    if !root {
        return candidates;
    }

    if let Some(rest) = xpath.strip_prefix("/reader-root/") {
        candidates.push(format!("/html/body/{rest}"));
        return candidates;
    }

    if xpath.starts_with('/') && !xpath.starts_with("//") && !xpath.starts_with("/html") {
        candidates.push(if xpath.starts_with("/body") {
            format!("/html{xpath}")
        } else {
            format!("/html/body{xpath}")
        });
    }
    candidates
}

/// XPath support using sxd-xpath
pub fn select_xpath(html: &str, xpath: &str) -> Vec<String> {
    select_xpath_values(html, xpath, false)
}

pub(crate) fn select_xpath_content(html: &str, xpath: &str) -> Vec<String> {
    select_xpath_values(html, xpath, true)
}

fn evaluate_xpath_with_fallback<'d>(
    node: sxd_xpath::nodeset::Node<'d>,
    xpath: &str,
) -> Option<sxd_xpath::Value<'d>> {
    let norm = normalize_xpath_query(xpath);
    let context = new_xpath_context(node, norm.as_ref())?;
    for candidate in xpath_candidates(
        norm.as_ref(),
        matches!(node, sxd_xpath::nodeset::Node::Root(_)),
    ) {
        let Some(expression) = sxd_xpath::Factory::new().build(&candidate).ok().flatten() else {
            continue;
        };
        let Ok(value) = expression.evaluate(&context, node) else {
            continue;
        };
        if matches!(&value, sxd_xpath::Value::Nodeset(nodes) if nodes.size() == 0) {
            continue;
        }
        return Some(value);
    }
    None
}

pub(crate) fn xpath_select_nodes<'d>(
    node: sxd_xpath::nodeset::Node<'d>,
    xpath: &str,
) -> Vec<sxd_xpath::nodeset::Node<'d>> {
    let split = split_top_level(xpath, &["&&", "||", "%%"]);
    if let Some(operator) = split.delimiter.as_deref() {
        if operator == "||" {
            for part in split.parts {
                let result = xpath_select_nodes(node, &part);
                if !result.is_empty() {
                    return result;
                }
            }
            return Vec::new();
        }

        let groups = split
            .parts
            .iter()
            .map(|part| xpath_select_nodes(node, part))
            .collect::<Vec<_>>();
        if operator == "%%" {
            return rule_analyzer::interleave_result_groups(groups);
        }
        return groups.into_iter().flatten().collect();
    }

    match evaluate_xpath_with_fallback(node, xpath) {
        Some(sxd_xpath::Value::Nodeset(nodes)) => nodes.document_order(),
        _ => Vec::new(),
    }
}

pub(crate) fn xpath_select_nodes_in_mode<'d>(
    node: sxd_xpath::nodeset::Node<'d>,
    xpath: &str,
    html_mode: bool,
) -> Vec<sxd_xpath::nodeset::Node<'d>> {
    let xpath = normalize_html_xpath_attribute_names(xpath, html_mode);
    xpath_select_nodes(node, xpath.as_ref())
}

pub(crate) fn xpath_eval_strings(node: sxd_xpath::nodeset::Node<'_>, xpath: &str) -> Vec<String> {
    let wants_html = xpath.trim() == "html()" || xpath.trim().ends_with("/html()");
    match evaluate_xpath_with_fallback(node, xpath) {
        Some(sxd_xpath::Value::Nodeset(nodes)) => nodes
            .document_order()
            .into_iter()
            .map(|node| {
                if wants_html {
                    if let sxd_xpath::nodeset::Node::Element(element) = node {
                        return sxd_element_to_html(element, false);
                    }
                }
                node.string_value()
            })
            .collect(),
        Some(sxd_xpath::Value::String(value)) => vec![value],
        Some(sxd_xpath::Value::Number(value)) => vec![value.to_string()],
        Some(sxd_xpath::Value::Boolean(value)) => vec![value.to_string()],
        None => Vec::new(),
    }
}

pub(crate) fn xpath_eval_strings_in_mode(
    node: sxd_xpath::nodeset::Node<'_>,
    xpath: &str,
    html_mode: bool,
) -> Vec<String> {
    let xpath = normalize_html_xpath_attribute_names(xpath, html_mode);
    xpath_eval_strings(node, xpath.as_ref())
}

fn normalize_html_xpath_attribute_names(xpath: &str, html_mode: bool) -> std::borrow::Cow<'_, str> {
    if !html_mode {
        return std::borrow::Cow::Borrowed(xpath);
    }

    let mut normalized = String::with_capacity(xpath.len());
    let mut characters = xpath.char_indices().peekable();
    let mut quote = None;
    let mut changed = false;

    while let Some((_, character)) = characters.next() {
        if let Some(active_quote) = quote {
            normalized.push(character);
            if character == active_quote {
                quote = None;
            }
            continue;
        }

        if matches!(character, '\'' | '"') {
            quote = Some(character);
            normalized.push(character);
            continue;
        }

        normalized.push(character);
        if character == '@' {
            while let Some((_, next)) = characters.peek().copied() {
                if !(next.is_ascii_alphanumeric() || matches!(next, '_' | ':' | '-' | '.')) {
                    break;
                }
                characters.next();
                changed |= next.is_ascii_uppercase();
                normalized.push(next.to_ascii_lowercase());
            }
        }
    }

    if changed {
        std::borrow::Cow::Owned(normalized)
    } else {
        std::borrow::Cow::Borrowed(xpath)
    }
}

fn select_xpath_values(html: &str, xpath: &str, format_nodes: bool) -> Vec<String> {
    let (package, html_mode) = match parse_xpath_package_with_mode(html) {
        Ok(parsed) => parsed,
        Err(_) => return vec![],
    };
    let xpath = normalize_html_xpath_attribute_names(xpath, html_mode);
    let node = sxd_xpath::nodeset::Node::Root(package.as_document().root());
    if !format_nodes {
        return xpath_eval_strings(node, xpath.as_ref());
    }

    let wants_html = xpath.trim() == "html()" || xpath.trim().ends_with("/html()");
    match evaluate_xpath_with_fallback(node, xpath.as_ref()) {
        Some(sxd_xpath::Value::Nodeset(nodes)) => nodes
            .document_order()
            .into_iter()
            .map(|node| {
                if wants_html {
                    if let sxd_xpath::nodeset::Node::Element(element) = node {
                        return sxd_element_to_html(element, false);
                    }
                }
                xpath_formatted_text(node)
            })
            .collect(),
        Some(sxd_xpath::Value::String(value)) => vec![value],
        Some(sxd_xpath::Value::Number(value)) => vec![value.to_string()],
        Some(sxd_xpath::Value::Boolean(value)) => vec![value.to_string()],
        None => Vec::new(),
    }
}

pub(crate) fn select_xpath_elements_json(html: &str, xpath: &str) -> String {
    let (package, html_mode) = match parse_xpath_package_with_mode(html) {
        Ok(parsed) => parsed,
        Err(_) => return "[]".to_string(),
    };
    let xpath = normalize_html_xpath_attribute_names(xpath, html_mode);
    let nodes = xpath_select_nodes(
        sxd_xpath::nodeset::Node::Root(package.as_document().root()),
        xpath.as_ref(),
    );

    let Some(snapshot) =
        xpath_document_snapshot(sxd_xpath::nodeset::Node::Root(package.as_document().root()))
    else {
        return "[]".into();
    };
    let Some(items) = xpath_nodes_json(&nodes, html_mode, &snapshot) else {
        return "[]".into();
    };
    serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct XPathNodeContext {
    document: String,
    path: Vec<usize>,
    html_mode: bool,
}

const MAX_XPATH_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_XPATH_PATH_DEPTH: usize = 256;
const MAX_XPATH_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

fn with_xpath_node_context<T>(
    content: &str,
    invalid: T,
    query: impl FnOnce(sxd_xpath::nodeset::Node<'_>, bool, &str) -> T,
) -> Option<T> {
    if content.len() > MAX_XPATH_DOCUMENT_BYTES * 2 {
        return content.contains("\"__readerXPathNode\"").then_some(invalid);
    }
    let value: serde_json::Value = serde_json::from_str(content).ok()?;
    let marker = value.get("__readerXPathNode")?;
    let Ok(context) = serde_json::from_value::<XPathNodeContext>(marker.clone()) else {
        return Some(invalid);
    };
    if context.document.len() > MAX_XPATH_DOCUMENT_BYTES
        || context.path.is_empty()
        || context.path.len() > MAX_XPATH_PATH_DEPTH
    {
        return Some(invalid);
    }
    let Ok(package) = sxd_document::parser::parse(&context.document) else {
        return Some(invalid);
    };
    let mut node = sxd_xpath::nodeset::Node::Root(package.as_document().root());
    for index in &context.path {
        let Some(child) = node
            .children()
            .into_iter()
            .filter(|child| matches!(child, sxd_xpath::nodeset::Node::Element(_)))
            .nth(*index)
        else {
            return Some(invalid);
        };
        node = child;
    }
    Some(query(node, context.html_mode, &context.document))
}

pub(crate) fn select_xpath_from_context(content: &str, xpath: &str) -> Option<Vec<String>> {
    with_xpath_node_context(content, Vec::new(), |node, mode, _| {
        if !mode && (xpath.trim() == "html()" || xpath.trim().ends_with("/html()")) {
            return xpath_select_nodes(node, xpath)
                .into_iter()
                .map(|node| {
                    if let sxd_xpath::nodeset::Node::Element(element) = node {
                        let mut output = String::new();
                        append_sxd_xml_element(element, &mut output, false);
                        output
                    } else {
                        node.string_value()
                    }
                })
                .collect();
        }
        xpath_eval_strings_in_mode(node, xpath, mode)
    })
}

pub(crate) fn select_xpath_elements_from_context(content: &str, xpath: &str) -> Option<String> {
    with_xpath_node_context(content, "[]".to_string(), |node, mode, snapshot| {
        let nodes = xpath_select_nodes_in_mode(node, xpath, mode);
        let Some(items) = xpath_nodes_json(&nodes, mode, snapshot) else {
            return "[]".into();
        };
        serde_json::to_string(&items).unwrap_or_else(|_| "[]".into())
    })
}

fn xpath_element_path(mut element: sxd_document::dom::Element<'_>) -> Vec<usize> {
    use sxd_document::dom::{ChildOfElement, ChildOfRoot, ParentOfChild};
    let mut path = Vec::new();
    while let Some(parent) = element.parent() {
        match parent {
            ParentOfChild::Root(root) => {
                let index = root
                    .children()
                    .into_iter()
                    .filter_map(|child| match child {
                        ChildOfRoot::Element(child) => Some(child),
                        _ => None,
                    })
                    .position(|child| child == element)
                    .expect("attached element");
                path.push(index);
                break;
            }
            ParentOfChild::Element(parent) => {
                let index = parent
                    .children()
                    .into_iter()
                    .filter_map(|child| match child {
                        ChildOfElement::Element(child) => Some(child),
                        _ => None,
                    })
                    .position(|child| child == element)
                    .expect("attached element");
                path.push(index);
                element = parent;
            }
        }
    }
    path.reverse();
    path
}

fn xml_qname(
    element: sxd_document::dom::Element<'_>,
    name: sxd_document::QName<'_>,
    preferred: Option<&str>,
    attribute: bool,
) -> String {
    let Some(uri) = name.namespace_uri() else {
        return name.local_part().to_string();
    };
    if !attribute && preferred.is_none() {
        return name.local_part().to_string();
    }
    let namespaces = element.namespaces_in_scope();
    let preferred = preferred.filter(|prefix| {
        namespaces
            .iter()
            .any(|namespace| namespace.prefix() == *prefix && namespace.uri() == uri)
    });
    let prefix = preferred.or_else(|| {
        namespaces
            .iter()
            .find(|namespace| !namespace.prefix().is_empty() && namespace.uri() == uri)
            .map(|namespace| namespace.prefix())
    });
    match prefix {
        Some(prefix) => format!("{prefix}:{}", name.local_part()),
        None => name.local_part().to_string(),
    }
}

fn xpath_node_json(
    node: sxd_xpath::nodeset::Node<'_>,
    html_mode: bool,
    snapshot: Option<&str>,
) -> serde_json::Value {
    match node {
        sxd_xpath::nodeset::Node::Element(element) => {
            let attrs = element
                .attributes()
                .into_iter()
                .map(|attr| {
                    let name = if html_mode {
                        attr.name().local_part().to_string()
                    } else {
                        xml_qname(element, attr.name(), attr.preferred_prefix(), true)
                    };
                    (name, serde_json::Value::String(attr.value().to_string()))
                })
                .collect::<serde_json::Map<_, _>>();
            let serialize = |outer| {
                if html_mode {
                    sxd_element_to_html(element, outer)
                } else {
                    let mut output = String::new();
                    append_sxd_xml_element(element, &mut output, outer);
                    output
                }
            };
            let mut item = serde_json::json!({
                "__readerHtmlElement": true,
                "__readerXPathNode": {"path":xpath_element_path(element), "htmlMode":html_mode},
                "attrs":attrs, "html":serialize(false), "outerHtml":serialize(true), "text":node.string_value(),
            });
            if let Some(snapshot) = snapshot {
                item["__readerXPathNode"]["document"] =
                    serde_json::Value::String(snapshot.to_string());
            }
            item
        }
        _ => serde_json::Value::String(node.string_value()),
    }
}

/// One snapshot per result group, not per element. JS keeps it in a private
/// evaluation-local pool; serialized result elements contain only compact IDs.
pub(crate) fn xpath_nodes_json(
    nodes: &[sxd_xpath::nodeset::Node<'_>],
    mode: bool,
    snapshot: &str,
) -> Option<Vec<serde_json::Value>> {
    if snapshot.len() > MAX_XPATH_DOCUMENT_BYTES {
        return None;
    }
    let mut emitted = false;
    let mut bytes = 2usize;
    let mut items = Vec::new();
    for node in nodes {
        let element = matches!(node, sxd_xpath::nodeset::Node::Element(_));
        let item = xpath_node_json(*node, mode, (element && !emitted).then_some(snapshot));
        emitted |= element;
        if item
            .get("__readerXPathNode")
            .and_then(|context| context.get("path"))
            .and_then(serde_json::Value::as_array)
            .is_some_and(|path| path.len() > MAX_XPATH_PATH_DEPTH)
        {
            return None;
        }
        bytes = bytes.checked_add(serde_json::to_vec(&item).ok()?.len() + 1)?;
        if bytes > MAX_XPATH_OUTPUT_BYTES {
            return None;
        }
        items.push(item);
    }
    Some(items)
}

fn xml_escape_attribute(value: &str) -> String {
    html_escape_attribute(value)
        .replace('\t', "&#9;")
        .replace('\n', "&#10;")
        .replace('\r', "&#13;")
}

fn append_sxd_xml_element(
    element: sxd_document::dom::Element<'_>,
    output: &mut String,
    outer: bool,
) {
    if output.len() > MAX_XPATH_DOCUMENT_BYTES {
        return;
    }
    let name = xml_qname(element, element.name(), element.preferred_prefix(), false);
    if outer {
        output.push('<');
        output.push_str(&name);
        output.push_str(" xmlns=\"");
        output.push_str(&xml_escape_attribute(if name.contains(':') {
            element.recursive_default_namespace_uri().unwrap_or("")
        } else {
            element.name().namespace_uri().unwrap_or("")
        }));
        output.push('"');
        let mut namespaces = element.namespaces_in_scope();
        namespaces.sort_by(|a, b| a.prefix().cmp(b.prefix()));
        for namespace in namespaces {
            if namespace.prefix().is_empty() || namespace.prefix() == "xml" {
                continue;
            }
            output.push_str(" xmlns:");
            output.push_str(namespace.prefix());
            output.push_str("=\"");
            output.push_str(&xml_escape_attribute(namespace.uri()));
            output.push('"');
            if output.len() > MAX_XPATH_DOCUMENT_BYTES {
                return;
            }
        }
        for attr in element.attributes() {
            output.push(' ');
            output.push_str(&xml_qname(
                element,
                attr.name(),
                attr.preferred_prefix(),
                true,
            ));
            output.push_str("=\"");
            output.push_str(&xml_escape_attribute(attr.value()));
            output.push('"');
            if output.len() > MAX_XPATH_DOCUMENT_BYTES {
                return;
            }
        }
        output.push('>');
    }
    for child in element.children() {
        if output.len() > MAX_XPATH_DOCUMENT_BYTES {
            return;
        }
        match child {
            sxd_document::dom::ChildOfElement::Element(element) => {
                append_sxd_xml_element(element, output, true)
            }
            sxd_document::dom::ChildOfElement::Text(text) => {
                output.push_str(&html_escape_text(text.text()).replace('\r', "&#13;"))
            }
            sxd_document::dom::ChildOfElement::Comment(comment) => {
                output.push_str("<!--");
                output.push_str(comment.text());
                output.push_str("-->");
            }
            sxd_document::dom::ChildOfElement::ProcessingInstruction(pi) => {
                append_xml_pi(pi, output)
            }
        }
    }
    if outer {
        output.push_str("</");
        output.push_str(&name);
        output.push('>');
    }
}

fn append_xml_pi(pi: sxd_document::dom::ProcessingInstruction<'_>, output: &mut String) {
    output.push_str("<?");
    output.push_str(pi.target());
    if let Some(value) = pi.value() {
        output.push(' ');
        output.push_str(value);
    }
    output.push_str("?>");
}

pub(crate) fn xpath_document_snapshot(node: sxd_xpath::nodeset::Node<'_>) -> Option<String> {
    // Check depth before entering the recursive serializer.
    let mut pending = vec![(
        sxd_xpath::nodeset::Node::Root(node.document().root()),
        0usize,
    )];
    let mut input_bytes = 0usize;
    while let Some((node, depth)) = pending.pop() {
        if depth > MAX_XPATH_PATH_DEPTH {
            return None;
        }
        input_bytes = input_bytes.checked_add(match node {
            sxd_xpath::nodeset::Node::Element(element) => {
                element.name().local_part().len()
                    + element
                        .attributes()
                        .iter()
                        .map(|attr| attr.name().local_part().len() + attr.value().len())
                        .sum::<usize>()
            }
            sxd_xpath::nodeset::Node::Text(text) => text.text().len(),
            sxd_xpath::nodeset::Node::Comment(comment) => comment.text().len(),
            sxd_xpath::nodeset::Node::ProcessingInstruction(pi) => {
                pi.target().len() + pi.value().map(str::len).unwrap_or(0)
            }
            _ => 0,
        })?;
        if input_bytes > MAX_XPATH_DOCUMENT_BYTES {
            return None;
        }
        pending.extend(node.children().into_iter().map(|child| {
            let next_depth =
                depth + usize::from(matches!(child, sxd_xpath::nodeset::Node::Element(_)));
            (child, next_depth)
        }));
    }
    let mut output = String::from("<?xml version=\"1.0\"?>");
    for child in node.document().root().children() {
        match child {
            sxd_document::dom::ChildOfRoot::Element(element) => {
                append_sxd_xml_element(element, &mut output, true)
            }
            sxd_document::dom::ChildOfRoot::Comment(comment) => {
                output.push_str("<!--");
                output.push_str(comment.text());
                output.push_str("-->");
            }
            sxd_document::dom::ChildOfRoot::ProcessingInstruction(pi) => {
                append_xml_pi(pi, &mut output)
            }
        }
    }
    (output.len() <= MAX_XPATH_DOCUMENT_BYTES).then_some(output)
}

pub(crate) fn sxd_element_to_html(element: sxd_document::dom::Element<'_>, outer: bool) -> String {
    let mut out = String::new();
    append_sxd_element(element, &mut out, outer);
    out
}

fn append_sxd_element(element: sxd_document::dom::Element<'_>, out: &mut String, outer: bool) {
    let name = element.name().local_part();
    let is_void = matches!(
        name,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    );
    if outer {
        out.push('<');
        out.push_str(name);
        for attr in element.attributes() {
            out.push(' ');
            out.push_str(attr.name().local_part());
            out.push_str("=\"");
            out.push_str(&html_escape_attribute(attr.value()));
            out.push('"');
        }
        if is_void {
            out.push_str(" />");
            return;
        }
        out.push('>');
    }

    for child in element.children() {
        match child {
            sxd_document::dom::ChildOfElement::Element(e) => {
                append_sxd_element(e, out, true);
            }
            sxd_document::dom::ChildOfElement::Text(t) => {
                out.push_str(&html_escape_text(t.text()));
            }
            _ => {}
        }
    }

    if outer {
        out.push_str("</");
        out.push_str(name);
        out.push('>');
    }
}

fn html_escape_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn html_escape_attribute(s: &str) -> String {
    html_escape_text(s).replace('"', "&quot;")
}

fn xpath_formatted_text(node: sxd_xpath::nodeset::Node<'_>) -> String {
    let mut text = String::new();
    match node {
        sxd_xpath::nodeset::Node::Element(element) => append_xpath_element_text(element, &mut text),
        sxd_xpath::nodeset::Node::Root(root) => {
            for child in root.children() {
                if let sxd_document::dom::ChildOfRoot::Element(element) = child {
                    append_xpath_element_text(element, &mut text);
                }
            }
        }
        _ => return node.string_value(),
    }
    text
}

fn append_xpath_element_text(element: sxd_document::dom::Element<'_>, output: &mut String) {
    let name = element.name().local_part();
    let is_block = matches!(
        name,
        "p" | "div"
            | "br"
            | "li"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "blockquote"
            | "section"
    );
    if is_block {
        append_xpath_line_break(output);
    }

    for child in element.children() {
        match child {
            sxd_document::dom::ChildOfElement::Element(child) => {
                append_xpath_element_text(child, output)
            }
            sxd_document::dom::ChildOfElement::Text(child) => output.push_str(child.text()),
            _ => {}
        }
    }

    if is_block {
        append_xpath_line_break(output);
    }
}

fn append_xpath_line_break(output: &mut String) {
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
}

/// HTML 实体反转义
pub fn html_unescape(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    let mut result = input.to_string();
    result = result
        .replace("&nbsp;", " ")
        .replace("&emsp;", "　")
        .replace("&ensp;", " ")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&copy;", "©")
        .replace("&reg;", "®")
        .replace("&trade;", "™")
        .replace("&mdash;", "—")
        .replace("&ndash;", "–")
        .replace("&hellip;", "…")
        .replace("&amp;", "&");

    if result.contains("&#") {
        if let Ok(num_re) = regex::Regex::new(r"&#(?:x([0-9a-fA-F]+)|(\d+));") {
            result = num_re
                .replace_all(&result, |caps: &regex::Captures| {
                    if let Some(hex) = caps.get(1) {
                        if let Ok(code) = u32::from_str_radix(hex.as_str(), 16) {
                            if let Some(c) = char::from_u32(code) {
                                return c.to_string();
                            }
                        }
                    } else if let Some(dec) = caps.get(2) {
                        if let Ok(code) = dec.as_str().parse::<u32>() {
                            if let Some(c) = char::from_u32(code) {
                                return c.to_string();
                            }
                        }
                    }
                    caps.get(0).unwrap().as_str().to_string()
                })
                .into_owned();
        }
    }
    result
}

/// 按照阅读 3.0 规范第 16 节实现 HtmlFormatter.formatKeepImg：
/// 保留图片并补全 URL，将 <p>/<br> 等块级标签清洗为换行符，剔除其他无意义 HTML 标签。
pub fn format_keep_img(content: &str, redirect_url: &str) -> String {
    format_keep_img_with_script_text(content, redirect_url, false)
}

/// JS htmlFormat strips tags but retains their text, unlike reader content cleaning.
pub(crate) fn format_js_html(content: &str, redirect_url: &str) -> String {
    format_keep_img_with_script_text(content, redirect_url, true)
}

fn format_keep_img_with_script_text(
    content: &str,
    redirect_url: &str,
    keep_script_text: bool,
) -> String {
    if content.trim().is_empty() {
        return String::new();
    }

    // Reader cleaning drops script/style bodies; the JS facade only strips tags below.
    let mut text = content.to_string();
    let removed = if keep_script_text {
        r"(?s)<!--.*?-->"
    } else {
        r"(?is)<script[^>]*>.*?</script>|<style[^>]*>.*?</style>|<!--.*?-->"
    };
    if let Ok(re) = regex::Regex::new(removed) {
        text = re.replace_all(&text, "").into_owned();
    }

    // 2. 提取并保留 <img> 标签，补全相对 URL，使用占位符保护
    let mut img_placeholders: Vec<String> = Vec::new();
    if let Ok(img_re) = regex::Regex::new(r"(?i)<img\b[^>]*>") {
        if let Ok(src_re) =
            regex::Regex::new(r#"(?i)\b(?:src|data-src|data-original)\s*=\s*["']?([^"'\s>]+)["']?"#)
        {
            text = img_re
                .replace_all(&text, |caps: &regex::Captures| {
                    let img_tag = caps.get(0).unwrap().as_str();
                    let full_img = if let Some(src_caps) = src_re.captures(img_tag) {
                        let raw_src = src_caps.get(1).map(|m| m.as_str()).unwrap_or_default();
                        if !raw_src.is_empty() && !redirect_url.is_empty() {
                            let abs_src =
                                crate::parser::rule_engine::resolve_url(redirect_url, raw_src);
                            format!(r#"<img src="{}">"#, abs_src)
                        } else {
                            format!(r#"<img src="{}">"#, raw_src)
                        }
                    } else {
                        img_tag.to_string()
                    };
                    let placeholder =
                        format!("__READER_IMG_PLACEHOLDER_{}__", img_placeholders.len());
                    img_placeholders.push(full_img);
                    format!("\n{}\n", placeholder)
                })
                .into_owned();
        }
    }

    // 3. 将块级换行标签转换为换行符 \n
    if let Ok(block_re) =
        regex::Regex::new(r"(?i)<br\s*/?>|</?(?:p|div|h[1-6]|li|ul|ol|hr|article|dd|dl)\b[^>]*>")
    {
        text = block_re.replace_all(&text, "\n").into_owned();
    }

    // 4. 清理剩余所有 HTML 标签
    if let Ok(tag_re) = regex::Regex::new(r"<[^>]+>") {
        text = tag_re.replace_all(&text, "").into_owned();
    }

    // 5. 还原 <img> 占位符
    for (i, img_tag) in img_placeholders.into_iter().enumerate() {
        let placeholder = format!("__READER_IMG_PLACEHOLDER_{}__", i);
        text = text.replace(&placeholder, &img_tag);
    }

    // 6. 若含 &，进行 HTML-unescape
    if text.contains('&') {
        text = html_unescape(&text);
    }

    // 7. 规范化空白行与段落：按 \n 切分，每行 trim，去掉连续空行
    let mut lines = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if !line.is_empty() {
            lines.push(line.to_string());
        }
    }

    lines.join("\n")
}

/// 将 HTML 转换为换行与段落保留的纯文本。
/// 会移除 script、style 与注释，将所有块级换行标签（含 <p>, <br>, <li>, <div>, <h1-h6> 等）转换为 \n，
/// 剔除所有 HTML 标签并执行 HTML 实体反转义。
pub fn html_to_text(html: &str) -> String {
    if html.trim().is_empty() {
        return String::new();
    }

    // 1. 移除 script、style 与注释
    let mut text = html.to_string();
    if let Ok(re) =
        regex::Regex::new(r"(?is)<script[^>]*>.*?</script>|<style[^>]*>.*?</style>|<!--.*?-->")
    {
        text = re.replace_all(&text, "").into_owned();
    }

    // 2. 将块级换行标签转换为换行符 \n
    if let Ok(block_re) =
        regex::Regex::new(r"(?i)<br\s*/?>|</?(?:p|div|h[1-6]|li|ul|ol|hr|article|dd|dl)\b[^>]*>")
    {
        text = block_re.replace_all(&text, "\n").into_owned();
    }

    // 3. 清理剩余所有 HTML 标签
    if let Ok(tag_re) = regex::Regex::new(r"<[^>]+>") {
        text = tag_re.replace_all(&text, "").into_owned();
    }

    // 4. 若含 &，进行 HTML-unescape
    if text.contains('&') {
        text = html_unescape(&text);
    }

    // 5. 规范化空白行与段落：按 \n 切分，每行 trim，去掉连续空行
    let mut lines = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if !line.is_empty() {
            lines.push(line.to_string());
        }
    }

    lines.join("\n")
}

/// 净化 HTML（保留基础排版标签，剥离属性与 CSS/脚本）。
/// 常用于电子书阅读排版（保留 p, br, b, strong, i, em, u, h1-h6, li, ul, ol 等基础标签）。
pub fn clean_html(html: &str) -> String {
    use regex::Regex;
    let mut output = html.to_string();
    for pattern in [
        r"(?is)<script[^>]*>.*?</script>",
        r"(?is)<style[^>]*>.*?</style>",
        r"(?s)<!--.*?-->",
    ] {
        if let Ok(regex) = Regex::new(pattern) {
            output = regex.replace_all(&output, "").into_owned();
        }
    }
    if let Ok(regex) =
        Regex::new(r"(?i)<(/?)(p|br|b|strong|i|em|u|h[1-6]|li|ul|ol)(?:\s+[^>]*)?/?>")
    {
        output = regex.replace_all(&output, "<$1$2>").into_owned();
    }
    if let Ok(regex) = Regex::new(r"<[^>]+>") {
        let mut cleaned = String::new();
        let mut last_end = 0;
        for found in regex.find_iter(&output) {
            cleaned.push_str(&output[last_end..found.start()]);
            match found.as_str().to_ascii_lowercase().as_str() {
                "<p>" | "</p>" | "<br>" | "<b>" | "</b>" | "<strong>" | "</strong>" | "<i>"
                | "</i>" | "<em>" | "</em>" | "<u>" | "</u>" | "<h1>" | "</h1>" | "<h2>"
                | "</h2>" | "<h3>" | "</h3>" | "<h4>" | "</h4>" | "<h5>" | "</h5>" | "<h6>"
                | "</h6>" | "<li>" | "</li>" | "<ul>" | "</ul>" | "<ol>" | "</ol>" => {
                    cleaned.push_str(found.as_str());
                }
                _ => {}
            }
            last_end = found.end();
        }
        cleaned.push_str(&output[last_end..]);
        output = cleaned;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "manual XPath stage measurement; no timing assertions"]
    fn xpath_stage_cost_measurement() {
        use std::hint::black_box;
        use std::time::Instant;

        const SAMPLES: usize = 30;
        const ITERATIONS: usize = 100;
        const ROOT_QUERY: &str = "//div[@class='book']/h2/text()";
        const FIELD_QUERY: &str = "h2/text()";

        fn measure(label: &str, books: usize, mut work: impl FnMut()) {
            for _ in 0..10 {
                work();
            }
            let mut samples = Vec::with_capacity(SAMPLES);
            for _ in 0..SAMPLES {
                let started = Instant::now();
                for _ in 0..ITERATIONS {
                    work();
                }
                samples.push(started.elapsed().as_nanos() / ITERATIONS as u128);
            }
            samples.sort_unstable();
            eprintln!(
                "xpath-stage books={books} stage={label} samples={SAMPLES} iterations={ITERATIONS} ns_per_call median={} min={} max={}",
                samples[SAMPLES / 2], samples[0], samples[SAMPLES - 1]
            );
        }

        eprintln!("xpath-stage debug_assertions={} synthetic_only=true; stages overlap and must not be added", cfg!(debug_assertions));
        for books in [2, 32, 128] {
            let mut body = String::from("<html><body>");
            for index in 1..=books {
                body.push_str(&format!(
                    "<div class='book'><h2>Book {index}</h2><a href='/b{index}'>作者</a></div>"
                ));
            }
            body.push_str("</body></html>");
            let (package, html_mode) = parse_xpath_package_with_mode(&body).unwrap();
            assert!(html_mode);
            let root = package.as_document().root().into();
            let expected: Vec<String> = (1..=books).map(|index| format!("Book {index}")).collect();
            assert_eq!(
                xpath_eval_strings_in_mode(root, ROOT_QUERY, html_mode),
                expected
            );
            let nodes = xpath_select_nodes(root, "//div[@class='book']");
            assert_eq!(nodes.len(), books);
            let field_node = nodes[0];
            assert_eq!(
                xpath_eval_strings_in_mode(field_node, FIELD_QUERY, html_mode),
                vec!["Book 1"]
            );
            let context = new_xpath_context(field_node, FIELD_QUERY).unwrap();
            let expression = sxd_xpath::Factory::new()
                .build(FIELD_QUERY)
                .unwrap()
                .unwrap();
            assert_eq!(
                expression.evaluate(&context, field_node).unwrap().string(),
                "Book 1"
            );

            // Construction/compilation include destruction; setup is outside evaluate timing.
            measure("html_package", books, || {
                black_box(parse_xpath_package_with_mode(black_box(&body)).unwrap());
            });
            measure("factory_field", books, || {
                black_box(
                    sxd_xpath::Factory::new()
                        .build(black_box(FIELD_QUERY))
                        .unwrap()
                        .unwrap(),
                );
            });
            measure("evaluate_field", books, || {
                black_box(
                    expression
                        .evaluate(black_box(&context), black_box(field_node))
                        .unwrap(),
                );
            });
            measure("field_adapter", books, || {
                black_box(xpath_eval_strings_in_mode(
                    black_box(field_node),
                    black_box(FIELD_QUERY),
                    html_mode,
                ));
            });
            // Root query visits all books; it is not comparable to one relative field call.
            measure("root_adapter", books, || {
                black_box(xpath_eval_strings_in_mode(
                    black_box(root),
                    black_box(ROOT_QUERY),
                    html_mode,
                ));
            });
        }
    }

    #[test]
    fn css_fragment_validation_rejects_bad_tails_but_keeps_custom_tags() {
        for rule in [
            "li:not(.ad)[id] text.",
            "li:has(a)???",
            "li:not(.ad):has(a)???",
        ] {
            assert!(!css_rule_is_valid(rule), "{rule}");
        }
        for rule in [
            "li:not(.ad)[id] children",
            "li:not(.ad)[id] text.foo",
            "li:not(.ad) > a",
            "li:not(.ad):has(a) > a",
            "li:not(.ad):has(a) + li > a",
        ] {
            assert!(css_rule_is_valid(rule), "{rule}");
        }
    }

    #[test]
    fn html_fallback_skips_unneeded_selector_evaluation() {
        let doc = parse_document("<h1>first</h1><p>fallback</p>");
        SELECTOR_VISITS.with(|visits| visits.borrow_mut().clear());
        assert_eq!(select_list(&doc, "h1||p").len(), 1);
        assert_eq!(
            SELECTOR_VISITS.with(|visits| visits.borrow().clone()),
            vec!["h1"]
        );
        SELECTOR_VISITS.with(|visits| visits.borrow_mut().clear());
        assert_eq!(select_text_list(&doc, "h1@text||p@text"), vec!["first"]);
        assert_eq!(
            SELECTOR_VISITS.with(|visits| visits.borrow().clone()),
            vec!["h1"]
        );
        SELECTOR_VISITS.with(|visits| visits.borrow_mut().clear());
        assert_eq!(
            select_text_list(&doc, ".missing@text||p@text"),
            vec!["fallback"]
        );
        assert_eq!(
            SELECTOR_VISITS.with(|visits| visits.borrow().clone()),
            vec![".missing", "p"]
        );
        assert_eq!(
            select_text_list(&doc, "h1@text&&p@text"),
            vec!["first", "fallback"]
        );
    }

    #[test]
    fn xml_node_context_snapshot_preserves_namespace_resets_and_attribute_aliases() {
        let xml = r#"<?xml version="1.0"?><root xmlns="urn:a" xmlns:p="urn:a"><child xmlns:p="urn:b"/><plain xmlns=""/></root>"#;
        let (package, _) = parse_xpath_package_with_mode(xml).unwrap();
        let snapshot =
            xpath_document_snapshot(sxd_xpath::nodeset::Node::Root(package.as_document().root()))
                .unwrap();
        let restored = sxd_document::parser::parse(&snapshot).unwrap();
        let children = xpath_select_nodes(
            sxd_xpath::nodeset::Node::Root(restored.as_document().root()),
            "/*/*",
        );
        let namespaces: Vec<_> = children
            .iter()
            .map(|node| match node {
                sxd_xpath::nodeset::Node::Element(element) => element.name().namespace_uri(),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(namespaces, vec![Some("urn:a"), None]);
        let xml =
            r#"<?xml version="1.0"?><root xmlns:x="urn:a"><item xmlns:y="urn:a" x:id="X"/></root>"#;
        let wrapped: serde_json::Value =
            serde_json::from_str(&select_xpath_elements_json(xml, "//item")).unwrap();
        assert_eq!(wrapped[0]["attrs"]["x:id"], "X");
        assert!(wrapped[0]["attrs"].get("y:id").is_none());
    }

    #[test]
    fn xml_node_context_result_shares_snapshot_and_enforces_budgets() {
        let xml = format!(
            "<?xml version=\"1.0\"?><root><noise>{}</noise>{}</root>",
            "x".repeat(64 * 1024),
            "<Item><Child>V</Child></Item>".repeat(200)
        );
        let output = select_xpath_elements_json(&xml, "//Item");
        let items: serde_json::Value = serde_json::from_str(&output).unwrap();
        let items = items.as_array().unwrap();
        assert_eq!(items.len(), 200);
        assert_eq!(
            items
                .iter()
                .filter(|item| item["__readerXPathNode"].get("document").is_some())
                .count(),
            1
        );
        assert!(
            output.len() < xml.len() * 6,
            "output expanded to {} bytes",
            output.len()
        );
        let package = sxd_document::parser::parse("<root>value</root>").unwrap();
        let root = sxd_xpath::nodeset::Node::Root(package.as_document().root());
        assert!(xpath_nodes_json(&[], false, &"x".repeat(MAX_XPATH_DOCUMENT_BYTES + 1)).is_none());
        let huge = format!("<root>{}</root>", "x".repeat(128 * 1024));
        let package = sxd_document::parser::parse(&huge).unwrap();
        let node = xpath_select_nodes(
            sxd_xpath::nodeset::Node::Root(package.as_document().root()),
            "/root",
        )[0];
        assert!(xpath_nodes_json(&vec![node; 100], false, &huge).is_none());
        let deep = format!(
            "{}{}",
            "<a>".repeat(MAX_XPATH_PATH_DEPTH + 1),
            "</a>".repeat(MAX_XPATH_PATH_DEPTH + 1)
        );
        let package = sxd_document::parser::parse(&deep).unwrap();
        assert!(xpath_document_snapshot(sxd_xpath::nodeset::Node::Root(
            package.as_document().root()
        ))
        .is_none());
        assert!(xpath_document_snapshot(root).is_some());
    }

    #[test]
    fn xml_node_context_invalid_descriptors_never_fall_back_to_html() {
        for marker in [
            serde_json::json!({}),
            serde_json::json!({"document":"<root/>","htmlMode":false,"path":[]}),
            serde_json::json!({"document":"<root/>","htmlMode":false,"path":[99]}),
            serde_json::json!({"document":"broken","htmlMode":false,"path":[0]}),
            serde_json::json!({"document":"<root/>","htmlMode":false,"path":[0],"extra":true}),
            serde_json::json!({"document":"<root/>","htmlMode":false,"path":vec![0; MAX_XPATH_PATH_DEPTH + 1]}),
        ] {
            let content = serde_json::json!({"__readerXPathNode":marker}).to_string();
            assert_eq!(select_xpath_from_context(&content, "//*"), Some(Vec::new()));
            assert_eq!(
                select_xpath_elements_from_context(&content, "//*").as_deref(),
                Some("[]")
            );
        }
        assert!(select_xpath_from_context("<root/>", "//*").is_none());
    }

    #[test]
    fn xpath_parser_normalizes_common_html_entities() {
        let values = select_xpath(
            "<p>A&nbsp;&copy;&reg;&trade;&middot;&mdash;&ndash;&hellip;&emsp;&ensp;B</p>",
            "//p",
        );
        assert_eq!(values, vec!["A\u{00a0}©®™·—–…\u{2003}\u{2002}B"]);
    }

    #[test]
    fn xpath_parser_preserves_xml_and_numeric_entities() {
        let values = select_xpath(
            "<?xml version=\"1.0\"?><root>&amp;|&lt;|&gt;|&quot;|&apos;|&#65;|&#x42;</root>",
            "string(/root)",
        );
        assert_eq!(values, vec!["&|<|>|\"|'|A|B"]);
    }

    #[test]
    fn xpath_parser_uses_html_mode_without_xml_declaration() {
        let input = "<Root><Item>X</Item></Root>";
        assert_eq!(select_xpath(input, "//item"), vec!["X"]);
        assert!(select_xpath(input, "//Item").is_empty());
    }

    #[test]
    fn xpath_parser_wraps_multi_root_fragments_only_as_fallback() {
        let values = select_xpath("<p>A</p><p>B</p>", "/reader-root/p");
        assert_eq!(values.len(), 2);
        assert!(values.contains(&"A".to_string()));
        assert!(values.contains(&"B".to_string()));
    }

    #[test]
    fn xpath_parser_keeps_normal_xhtml_structure() {
        let values = select_xpath(
            "<?xml version=\"1.0\"?><html><body><p>Normal</p></body></html>",
            "/html/body/p",
        );
        assert_eq!(values, vec!["Normal"]);
    }

    #[test]
    fn xpath_parser_resolves_declared_prefixes_and_rejects_unknown_ones_safely() {
        let xml = r#"<?xml version="1.0"?><root note="urn:x:books"><branch xmlns:x="urn:books"><x:Item x:id="a">Book</x:Item></branch></root>"#;
        assert_eq!(select_xpath(xml, "//x:Item"), vec!["Book"]);
        assert_eq!(select_xpath(xml, "//x:Item[@x:id='a']"), vec!["Book"]);
        assert!(select_xpath(xml, "//unknown:Item").is_empty());
        assert_eq!(
            select_xpath(xml, "count(//root[@note='urn:x:books'])"),
            vec!["1"]
        );
    }

    #[test]
    fn xpath_parser_repairs_ordinary_html_before_xml_fallback() {
        let values = select_xpath(
            r#"<!doctype html><div class=test>Hello<br><img src=/cover.jpg><span>World</span></div>"#,
            "//div[@class='test']",
        );
        assert_eq!(values, vec!["HelloWorld"]);
        assert_eq!(
            select_xpath(
                r#"<div><img src=/cover.jpg><span>World</span></div>"#,
                "string(//img/@src)",
            ),
            vec!["/cover.jpg"]
        );
        assert_eq!(select_xpath("<td>Cell</td>", "//td"), vec!["Cell"]);
    }

    #[test]
    fn css_attribute_selector_accepts_unquoted_colon_values() {
        let doc =
            parse_document(r#"<meta property="og:novel:read_url" content="/novel/3805/catalog">"#);
        let rule = "meta[property=og:novel:read_url]@content";

        assert!(css_rule_is_valid(rule));
        assert_eq!(
            select_text(&doc, rule),
            Some("/novel/3805/catalog".to_string())
        );
    }

    #[test]
    fn standard_css_descendant_selectors_keep_tag_and_pseudo_syntax() {
        let doc = parse_document(
            r#"<div class="book-cell"><p>Other</p><p>169 万字</p></div>
<section id="bookSummary"><content>简介内容</content></section>"#,
        );

        assert_eq!(
            select_text(&doc, "div.book-cell p:nth-of-type(2)@text"),
            Some("169 万字".to_string())
        );
        assert_eq!(
            select_text(&doc, "section#bookSummary content@html"),
            Some("简介内容".to_string())
        );

        let list_doc = parse_document("<ul><li>one</li><li>two</li></ul>");
        assert_eq!(select_list(&list_doc, "ul li").len(), 2);
    }

    #[test]
    fn text_nodes_only_extract_direct_text_and_skip_script_style_data() {
        let doc = parse_document(
            r#"<div id="content"> first <span>nested</span><script>read2();</script><style>.x { color: red; }</style> second </div>"#,
        );
        let element = select_list(&doc, "#content").into_iter().next().unwrap();
        assert_eq!(
            extract_text(&element, "textNodes"),
            Some("first\nsecond".to_string())
        );

        let script = select_list(&doc, "#content script")
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(extract_text(&script, "textNodes"), None);
        let style = select_list(&doc, "#content style")
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(extract_text(&style, "textNodes"), None);

        let recursive_input = get_descendant_text_nodes(&element);
        assert!(recursive_input.contains("nested"));
        assert!(recursive_input.contains("read2();"));
    }

    #[test]
    fn text_nodes_match_jsoup_whitespace_normalization() {
        let doc = parse_document(
            "<div id=\"content\">  alpha   \t beta&nbsp;&nbsp;gamma  <span>nested</span>　　正文　 </div>",
        );
        let element = select_list(&doc, "#content").into_iter().next().unwrap();

        assert_eq!(
            extract_text(&element, "textNodes"),
            Some("alpha beta gamma\n　　正文　".to_string())
        );
        assert_eq!(
            normalize_jsoup_text_node(" a\u{200B}\u{00AD}b "),
            "ab".to_string()
        );
    }

    #[test]
    fn compat_default_css_rule_selects_first_item_and_fields() {
        let doc = parse_document(
            r#"<ul><li><a href="/b/1">书名</a><span>作者</span></li><li><a href="/b/2">其他</a></li></ul>"#,
        );
        let item = select_list(&doc, "tag.li.0").into_iter().next().unwrap();

        assert_eq!(
            select_text_from_element(&item, "tag.a.0@text"),
            Some("书名".into())
        );
        assert_eq!(
            select_text_from_element(&item, "tag.a.0@href"),
            Some("/b/1".into())
        );
        assert_eq!(
            select_text_from_element(&item, "tag.span.0@text"),
            Some("作者".into())
        );
    }

    #[test]
    fn compat_combination_falls_back_when_first_rule_is_empty() {
        let doc = parse_document("<h1></h1><div class=\"title\">标题</div>");
        assert_eq!(
            select_text(&doc, "h1@text||.title@text"),
            Some("标题".into())
        );
    }

    #[test]
    fn test_legado_to_css() {
        assert_eq!(legado_to_css("class.mod block"), ".mod.block");
        assert_eq!(legado_to_css("class.test"), ".test");
        assert_eq!(legado_to_css("id.main"), "#main");
        assert_eq!(legado_to_css("tag.div"), "div");
        assert_eq!(legado_to_css("ul li"), "ul li");
    }

    #[test]
    fn jsoup_eq_uses_element_sibling_index_not_result_index() {
        let doc = parse_document(
            r#"<div class="item"><a>first</a></div><div>other</div><div class="item"><a>third</a></div><section><div class="item"><a>nested first</a></div></section>"#,
        );
        let texts = select_css_list(&doc, ".item:eq(2) a")
            .iter()
            .map(|el| el.text().collect::<String>())
            .collect::<Vec<_>>();
        assert_eq!(texts, vec!["third"]);
        let first = select_css_list(&doc, ".item:eq(0) a")
            .iter()
            .map(|el| el.text().collect::<String>())
            .collect::<Vec<_>>();
        assert_eq!(first, vec!["first", "nested first"]);
        assert!(css_rule_is_valid(".item:eq(1) a@text"));
        assert_eq!(select_text_list(&doc, ".item:eq(2) a@text"), vec!["third"]);
        assert_eq!(select_css_list(&doc, ".item:eq(1) a").len(), 0);
        assert!(parse_css_selector(r#"[data-name=":eq(0)"]"#).is_some());
        assert_eq!(select_css_list(&doc, ".item:eq(-1)").len(), 0);
    }

    #[test]
    fn jsoup_lt_gt_use_element_sibling_indices_before_descendant_selection() {
        let doc = parse_document(
            r#"<ul><li class="item"><a>first</a></li><li>other</li><li class="item"><a>third</a></li><li class="item"><a>fourth</a></li></ul><ul><li class="item"><a>second list</a></li></ul>"#,
        );
        assert_eq!(
            select_text_list(&doc, "li.item:lt(2) a@text"),
            vec!["first", "second list"]
        );
        assert_eq!(
            select_text_list(&doc, "li.item:gt(1) a@text"),
            vec!["third", "fourth"]
        );
        assert_eq!(
            select_text_list(&doc, "li.item:lt(0) a@text"),
            Vec::<String>::new()
        );
        assert!(css_rule_is_valid("li.item:gt(1) a@text"));
        assert!(css_rule_is_valid("li.item:lt(2) a@text"));
        assert!(parse_css_selector(r#"[data-x=":lt(2)"]"#).is_some());
        assert!(parse_css_selector("li:gt(-1)").is_none());
    }

    #[test]
    fn jsoup_contains_filters_before_adjacent_sibling_and_descendants() {
        let doc = parse_document(
            r#"<div class="info"><dl><dt>状态</dt><dd><a>连载</a></dd><dt>图书 <span>分类</span></dt><dd><a>奇幻</a></dd><dt>简介</dt><dd>分类说明</dd></dl></div>"#,
        );
        assert!(css_rule_is_valid(".info dl dt:contains(分类) + dd a@text"));
        assert_eq!(
            select_text_list(&doc, ".info dl dt:contains(分类) + dd a@text"),
            vec!["奇幻"]
        );
        assert_eq!(
            select_text_list(&doc, ".info dl dt:contains(状态) + dd a@text"),
            vec!["连载"]
        );
        assert_eq!(
            select_text_list(&doc, "dt:contains(图书 分类)@text"),
            vec!["图书  分类"]
        );
        assert_eq!(select_css_list(&doc, "dt:contains(不存在) + dd").len(), 0);
        assert!(parse_css_selector(r#"[data-x=":contains(分类)"]"#).is_some());
        assert!(!css_rule_is_valid("dt:contains(分类).tag@text"));
    }

    #[test]
    fn jsoup_matches_filters_before_sibling_and_descendant_selection() {
        let doc = parse_document(
            "<dl><dt>简介</dt><a>ignore</a><dt>章节目录</dt><a href='1'>一</a><span>other</span><a href='2'>二</a><dt>其他</dt><a href='3'>三</a></dl>",
        );
        assert!(css_rule_is_valid("dl dt:matches(章节目录|目录章节)~a@href"));
        assert_eq!(
            select_text_list(&doc, "dl dt:matches(章节目录|目录章节)~a@href"),
            vec!["1", "2", "3"]
        );
        assert_eq!(
            select_text_list(&doc, "dl dt:matches(章节目录)+a@href"),
            vec!["1"]
        );
        assert_eq!(
            select_text_list(&doc, "dl dt:matches((章节|目录)+)~a@href"),
            vec!["1", "2", "3"]
        );
        assert!(!css_rule_is_valid("dl dt:matches(()~a@href"));
        assert!(parse_css_selector(r#"[data-x=":matches(目录)"]"#).is_some());
        let literal = parse_document("<p class='target'>右括号 )</p>");
        assert_eq!(
            select_css_list(&literal, r"p.target:matches(\Q)\E)").len(),
            1
        );
        assert_eq!(select_css_list(&literal, r"p.target:matches([)])").len(), 1);
    }

    #[test]
    fn jsoup_matches_multiple_headings_dedupes_in_document_order() {
        let doc = parse_document(
            "<dl><dt>目录一</dt><a href='1'>一</a><dt>目录二</dt><a href='2'>二</a><dt>其他</dt><a href='3'>三</a></dl>",
        );
        let rule = "dl dt:matches(目录)~a@href";
        assert_eq!(select_text_list(&doc, rule), vec!["1", "2", "3"]);
        assert_eq!(
            select_list(&doc, "dl dt:matches(目录)~a")
                .iter()
                .filter_map(|el| el.value().attr("href"))
                .collect::<Vec<_>>(),
            vec!["1", "2", "3"]
        );
        let root = select_css_list(&doc, "dl")[0];
        assert_eq!(
            select_css_from_element(root, "dt:matches(目录)~a")
                .iter()
                .filter_map(|el| el.value().attr("href"))
                .collect::<Vec<_>>(),
            vec!["1", "2", "3"]
        );
    }

    #[test]
    fn jsoup_matches_own_ignores_descendant_text() {
        let doc = parse_document(
            "<div class='item'>前缀<span>章节目录</span></div><div class='item'>目录<span>章节</span></div>",
        );
        assert_eq!(select_css_list(&doc, "div.item:matches(章节目录)").len(), 1);
        assert_eq!(
            select_css_list(&doc, "div.item:matchesOwn(章节目录)").len(),
            0
        );
        assert_eq!(select_css_list(&doc, "div.item:matchesOwn(目录)").len(), 1);
    }

    #[test]
    fn test_parse_selector_with_index() {
        let parsed = parse_selector_with_index(".test.0");
        assert_eq!(parsed.base, SelectorBase::Css(".test".to_string()));
        assert!(parsed.explicit_index);
        assert_eq!(parsed.index_mode, IndexMode::Select);
        assert_eq!(parsed.index_items, vec![IndexItem::Single(0)]);

        let parsed = parse_selector_with_index(".test.-1");
        assert_eq!(parsed.base, SelectorBase::Css(".test".to_string()));
        assert_eq!(parsed.index_items, vec![IndexItem::Single(-1)]);

        let parsed = parse_selector_with_index(".test!0");
        assert_eq!(parsed.base, SelectorBase::Css(".test".to_string()));
        assert_eq!(parsed.index_mode, IndexMode::Exclude);
        assert_eq!(parsed.index_items, vec![IndexItem::Single(0)]);

        let parsed = parse_selector_with_index("div[-1, 1:3]");
        assert_eq!(parsed.base, SelectorBase::Css("div".to_string()));
        assert_eq!(
            parsed.index_items,
            vec![
                IndexItem::Single(-1),
                IndexItem::Range {
                    start: Some(1),
                    end: Some(3),
                    step: 1,
                },
            ]
        );
    }

    #[test]
    fn compat_css_chain_split_ignores_embedded_at_signs() {
        let doc = parse_document(
            r#"<div data-value="left@@right">Literal</div><section><span>Nested</span></section>"#,
        );

        assert_eq!(
            select_text(&doc, r#"div[data-value="left@@right"]@text"#),
            Some("Literal".to_string())
        );
        assert_eq!(
            select_text_list(&doc, "section@html@@span@text"),
            vec!["Nested".to_string()]
        );

        let regex_chain = split_top_level(":regex((?:left@@right))@@span", &["@@"]);
        assert_eq!(
            regex_chain.parts,
            vec![":regex((?:left@@right))".to_string(), "span".to_string()]
        );
    }

    #[test]
    fn test_select_text_list_with_bracket_indices() {
        let doc = parse_document(
            r#"<div><a href="/1">A</a><a href="/2">B</a><a href="/3">C</a><a href="/4">D</a></div>"#,
        );

        assert_eq!(
            select_text_list(&doc, "a[1:2]@text"),
            vec!["B".to_string(), "C".to_string()]
        );
        assert_eq!(
            select_text_list(&doc, "a[!1,2]@text"),
            vec!["A".to_string(), "D".to_string()]
        );
        assert_eq!(
            select_text_list(&doc, "a[-1:0]@text"),
            vec![
                "D".to_string(),
                "C".to_string(),
                "B".to_string(),
                "A".to_string()
            ]
        );
    }

    #[test]
    fn test_extract_attr_bracket_syntax() {
        let doc = parse_document(r#"<div><a href="/book/1" data-id="abc">Book</a></div>"#);

        assert_eq!(
            select_text(&doc, "a@attr[href]"),
            Some("/book/1".to_string())
        );
        assert_eq!(
            select_text(&doc, "a@attr[data-id]"),
            Some("abc".to_string())
        );
        assert_eq!(select_text(&doc, "a@href"), Some("/book/1".to_string()));
    }

    #[test]
    fn test_format_keep_img() {
        // 清洗 <p> 标签并正确分段
        let html_content = "<p>“第一行文字”</p><p>“第二行文字”</p>";
        assert_eq!(
            format_keep_img(html_content, ""),
            "“第一行文字”\n“第二行文字”"
        );

        // 保留图片并补全相对 URL
        let img_html = "<p>前文</p><img src=\"/images/1.jpg\"><p>后文</p>";
        assert_eq!(
            format_keep_img(img_html, "https://example.com/chapter/1.html"),
            "前文\n<img src=\"https://example.com/images/1.jpg\">\n后文"
        );

        // 清洗无用标签与脚本样式
        let messy_html =
            "<div><script>alert(1);</script><p>正文内容<span>注释</span><br>第二行</p></div>";
        assert_eq!(format_keep_img(messy_html, ""), "正文内容注释\n第二行");

        // 清洗 <li> 标签并正确分段换行
        let list_html = "<ul><li>第一条列表项</li><li>第二条列表项</li></ul>";
        assert_eq!(format_keep_img(list_html, ""), "第一条列表项\n第二条列表项");
    }

    #[test]
    fn test_html_to_text() {
        let html =
            "<div><h1>标题</h1><p>第一段</p><ul><li>项目 1</li><li>项目 2</li></ul><br>尾注</div>";
        assert_eq!(html_to_text(html), "标题\n第一段\n项目 1\n项目 2\n尾注");
    }

    #[test]
    fn test_clean_html() {
        let html = r#"<div style="color:red"><script>var a=1;</script><p class="content">段落</p><ul><li class="item">列表项</li></ul></div>"#;
        assert_eq!(clean_html(html), "<p>段落</p><ul><li>列表项</li></ul>");
    }

    #[test]
    fn test_html_unescape() {
        assert_eq!(
            html_unescape(
                "&nbsp;文字&quot;双引号&quot;&apos;单引号&apos;&amp;和&lt;小于&gt;大于&#160;"
            ),
            " 文字\"双引号\"'单引号'&和<小于>大于\u{a0}"
        );
    }

    #[test]
    fn test_xpath_id_function_and_normalization() {
        let html = r#"<!DOCTYPE html>
<html>
    <body>
        <div id="intro"><p>Hello World</p></div>
        <div id="list">
            <dl id="target-dl">
                <dd><a href="/chapter1">Chapter 1</a></dd>
            </dl>
        </div>
    </body>
</html>"#;
        // Test id("list")
        let res = select_xpath(html, "id('list')//a/@href");
        assert_eq!(res, vec!["/chapter1"]);

        // Test id(//dl/@id)
        let res2 = select_xpath(html, "id(//dl/@id)//a/text()");
        assert_eq!(res2, vec!["Chapter 1"]);

        // Test normalize /allText() and /@text
        let res3 = select_xpath(html, "//div[@id='intro']/allText()");
        assert_eq!(res3, vec!["Hello World"]);

        // Test flat root query fallback /body/div[@id='intro']
        let res4 = select_xpath(html, "/body/div[@id='intro']/p");
        assert_eq!(res4, vec!["Hello World"]);
    }

    #[test]
    fn test_xpath_advanced_edge_cases() {
        let html = r#"<!DOCTYPE html>
<html>
    <body>
        <div id="c1" class="ch">Chapter 1</div>
        <div id="c2" class="ch">Chapter 2</div>
        <div id="intro"><p>Hello World</p><span>Extra Text</span></div>
    </body>
</html>"#;

        // 1. W3C multi-ID whitespace separation
        let multi = select_xpath(html, "id('c1 c2')/text()");
        assert_eq!(multi, vec!["Chapter 1", "Chapter 2"]);

        // 2. Non-existent ID returns empty cleanly
        let not_found = select_xpath(html, "id('non-existent')");
        assert!(not_found.is_empty());

        // 3. JsoupXpath /@text rewrite
        let text_attr = select_xpath(html, "//p/@text");
        assert_eq!(text_attr, vec!["Hello World"]);

        // 4. JsoupXpath /html() rewrite
        let html_fn = select_xpath(html, "//div[@id='c1']/html()");
        assert_eq!(html_fn, vec!["Chapter 1"]);

        // 5. Flat root without /body (direct /div)
        let direct_div = select_xpath(html, "/div[@id='intro']/p");
        assert_eq!(direct_div, vec!["Hello World"]);

        // 6. Pure multi-root HTML fragment
        let frag = "<p>Frag 1</p><p>Frag 2</p>";
        assert_eq!(select_xpath(frag, "/p"), vec!["Frag 1", "Frag 2"]);

        // 7. Non-existent path returns empty without panic
        assert_eq!(
            select_xpath(html, "/unknown/nonexistent/path"),
            Vec::<String>::new()
        );

        // 8. A real attribute whose name starts with "text" must not be rewritten.
        let attr_html = r#"<div textContent="raw-value">body</div>"#;
        assert_eq!(
            select_xpath(attr_html, "//div/@textContent"),
            vec!["raw-value"]
        );

        let xml = r#"<?xml version="1.0"?><root textContent="raw-value"/>"#;
        assert_eq!(select_xpath(xml, "//root/@textContent"), vec!["raw-value"]);
        assert!(select_xpath(xml, "//root/@textcontent").is_empty());

        let (html_package, html_mode) = parse_xpath_package_with_mode(attr_html).unwrap();
        assert!(html_mode);
        let html_root = sxd_xpath::nodeset::Node::Root(html_package.as_document().root());
        assert_eq!(
            xpath_eval_strings_in_mode(html_root, "//div/@textContent", html_mode),
            vec!["raw-value"]
        );

        let (xml_package, xml_mode) = parse_xpath_package_with_mode(xml).unwrap();
        assert!(!xml_mode);
        let xml_root = sxd_xpath::nodeset::Node::Root(xml_package.as_document().root());
        assert_eq!(
            xpath_eval_strings_in_mode(xml_root, "//root/@textContent", xml_mode),
            vec!["raw-value"]
        );
        assert!(xpath_eval_strings_in_mode(xml_root, "//root/@textcontent", xml_mode).is_empty());

        // 9. XPath html() must re-escape text when serializing inner HTML.
        let entity_html = r#"<div id="entity">1 &lt; 2 &amp; 3</div>"#;
        assert_eq!(
            select_xpath(entity_html, "id('entity')/html()"),
            vec!["1 &lt; 2 &amp; 3"]
        );

        // 10. JS element queries share the same multi-root fallback.
        let fragment_elements: serde_json::Value =
            serde_json::from_str(&select_xpath_elements_json(frag, "/p")).unwrap();
        assert_eq!(fragment_elements.as_array().unwrap().len(), 2);

        // 11. XPath element combinations use Legado's one-pass %% interleave.
        let combined_html = "<root><a>A1</a><a>A2</a><b>B1</b><b>B2</b><b>B3</b><c>C1</c></root>";
        let combined: serde_json::Value =
            serde_json::from_str(&select_xpath_elements_json(combined_html, "//a%%//b%%//c"))
                .unwrap();
        let texts = combined
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item.get("text").and_then(serde_json::Value::as_str))
            .collect::<Vec<_>>();
        assert_eq!(texts, vec!["A1", "B1", "C1", "A2", "B2"]);
    }
}
