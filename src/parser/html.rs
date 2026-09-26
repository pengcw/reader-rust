use once_cell::sync::Lazy;
use scraper::{ElementRef, Html, Selector};
use std::collections::HashSet;

use crate::parser::rule_analyzer::{self, split_top_level};

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
    let leading_space = attribute[value_start..].len() - attribute[value_start..].trim_start().len();
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

fn parse_css_selector(css_selector: &str) -> Option<Selector> {
    Selector::parse(css_selector).ok().or_else(|| {
        let normalized = quote_unquoted_colon_attribute_values(css_selector)?;
        Selector::parse(&normalized).ok()
    })
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
                SelectorBase::Css(css) => parse_css_selector(&css).is_some(),
                SelectorBase::Children | SelectorBase::Text(_) => true,
            }
        })
    })
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

fn select_css<'a>(doc: &'a Html, css_selector: &str) -> Vec<ElementRef<'a>> {
    let Some(sel) = parse_css_selector(css_selector) else {
        return vec![];
    };
    doc.select(&sel).collect()
}

pub(crate) fn select_css_list<'a>(doc: &'a Html, css_selector: &str) -> Vec<ElementRef<'a>> {
    select_css(doc, css_selector)
}

fn select_css_from_element<'a>(el: ElementRef<'a>, css_selector: &str) -> Vec<ElementRef<'a>> {
    let Some(sel) = parse_css_selector(css_selector) else {
        return vec![];
    };
    el.select(&sel).collect()
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

/// Get all text nodes from an element, preserving structure
fn get_text_nodes(el: &ElementRef) -> String {
    let mut texts = Vec::new();
    collect_text_nodes(*el, &mut texts);
    texts.join("\n")
}

fn collect_text_nodes(el: ElementRef, texts: &mut Vec<String>) {
    for node in el.children() {
        if let Some(text_node) = node.value().as_text() {
            let text = text_node.text.trim().to_string();
            if !text.is_empty() {
                texts.push(text);
            }
        }
        if let Some(child_el) = ElementRef::wrap(node) {
            collect_text_nodes(child_el, texts);
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
                combo.parts
                    .iter()
                    .map(|part| select_text_list(doc, part))
                    .collect(),
            );
        }

        let mut result =
            select_text_list(doc, combo.parts.first().map(String::as_str).unwrap_or(""));
        for part in combo.parts.iter().skip(1) {
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
            return Ok(package);
        }
    }

    // HTML mode mirrors JXDocument.create(String): repair malformed HTML first,
    // then bridge the resulting DOM into the XML-only XPath evaluator.
    let document = Html::parse_document(&prepared);
    let repaired = html_to_xpath_xml(&document.html());
    sxd_document::parser::parse(&repaired)
}

fn html_to_xpath_xml(html: &str) -> String {
    static DOCTYPE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r"(?is)<!doctype[^>]*>").expect("valid doctype regex")
    });
    static VOID_ELEMENT: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r"(?is)<(area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)(\b[^>]*)>",
        )
        .expect("valid HTML void element regex")
    });

    let without_doctype = DOCTYPE.replace_all(html, "");
    let xml = VOID_ELEMENT.replace_all(&without_doctype, |captures: &regex::Captures| {
        let whole = captures.get(0).map(|value| value.as_str()).unwrap_or_default();
        let attrs = captures.get(2).map(|value| value.as_str()).unwrap_or_default();
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

fn new_xpath_context<'d>() -> sxd_xpath::Context<'d> {
    let mut context = sxd_xpath::Context::new();
    context.set_function("id", HtmlIdFunction);
    context
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
    let context = new_xpath_context();
    for candidate in xpath_candidates(norm.as_ref(), matches!(node, sxd_xpath::nodeset::Node::Root(_))) {
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

pub(crate) fn xpath_eval_strings(
    node: sxd_xpath::nodeset::Node<'_>,
    xpath: &str,
) -> Vec<String> {
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

fn normalize_html_xpath_attribute_names<'a>(
    html: &str,
    xpath: &'a str,
) -> std::borrow::Cow<'a, str> {
    if html
        .trim_start()
        .get(.."<?xml".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("<?xml"))
    {
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
    let package = match parse_xpath_package(html) {
        Ok(package) => package,
        Err(_) => return vec![],
    };
    let xpath = normalize_html_xpath_attribute_names(html, xpath);
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
    let package = match parse_xpath_package(html) {
        Ok(package) => package,
        Err(_) => return "[]".to_string(),
    };
    let xpath = normalize_html_xpath_attribute_names(html, xpath);
    let nodes = xpath_select_nodes(
        sxd_xpath::nodeset::Node::Root(package.as_document().root()),
        xpath.as_ref(),
    );

    let items: Vec<serde_json::Value> = nodes
        .into_iter()
        .map(|node| {
            let text = node.string_value();
            match node {
                sxd_xpath::nodeset::Node::Element(el) => {
                    let attrs = el
                        .attributes()
                        .iter()
                        .map(|a| {
                            (
                                a.name().local_part().to_string(),
                                serde_json::Value::String(a.value().to_string()),
                            )
                        })
                        .collect::<serde_json::Map<_, _>>();
                    serde_json::json!({
                        "__readerHtmlElement": true,
                        "attrs": attrs,
                        "html": sxd_element_to_html(el, false),
                        "outerHtml": sxd_element_to_html(el, true),
                        "text": text,
                    })
                }
                sxd_xpath::nodeset::Node::Attribute(attr) => {
                    serde_json::Value::String(attr.value().to_string())
                }
                _ => serde_json::Value::String(text),
            }
        })
        .collect();

    serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string())
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
        "area" | "base" | "br" | "col" | "embed" | "hr" | "img" | "input" | "link" | "meta" | "param" | "source" | "track" | "wbr"
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
    if content.trim().is_empty() {
        return String::new();
    }

    // 1. 移除 script、style 与注释
    let mut text = content.to_string();
    if let Ok(re) =
        regex::Regex::new(r"(?is)<script[^>]*>.*?</script>|<style[^>]*>.*?</style>|<!--.*?-->")
    {
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
        assert_eq!(select_xpath(html, "/unknown/nonexistent/path"), Vec::<String>::new());

        // 8. A real attribute whose name starts with "text" must not be rewritten.
        let attr_html = r#"<div textContent="raw-value">body</div>"#;
        assert_eq!(
            select_xpath(attr_html, "//div/@textContent"),
            vec!["raw-value"]
        );

        let xml = r#"<?xml version="1.0"?><root textContent="raw-value"/>"#;
        assert_eq!(select_xpath(xml, "//root/@textContent"), vec!["raw-value"]);
        assert!(select_xpath(xml, "//root/@textcontent").is_empty());

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
        let combined_html =
            "<root><a>A1</a><a>A2</a><b>B1</b><b>B2</b><b>B3</b><c>C1</c></root>";
        let combined: serde_json::Value = serde_json::from_str(
            &select_xpath_elements_json(combined_html, "//a%%//b%%//c"),
        )
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
