use scraper::{ElementRef, Html, Selector};
use std::collections::HashSet;

use crate::parser::rule_analyzer::split_top_level;

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

    // Already CSS selector format (index will be stripped in parse_selector_with_index)
    if selector.starts_with('.') {
        return selector.to_string();
    }

    if selector.starts_with('#') || selector.starts_with('[') {
        return selector.to_string();
    }

    // Default: treat as class if it doesn't look like a tag
    if selector
        .chars()
        .next()
        .map(|c| c.is_alphabetic())
        .unwrap_or(false)
    {
        let parts: Vec<&str> = selector.split_whitespace().collect();
        if parts.len() > 1 {
            return format!(".{}", parts.join("."));
        }
        return selector.to_string();
    }

    selector.to_string()
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
    let sel = match Selector::parse(css_selector) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    doc.select(&sel).collect()
}

fn select_css_from_element<'a>(el: ElementRef<'a>, css_selector: &str) -> Vec<ElementRef<'a>> {
    let sel = match Selector::parse(css_selector) {
        Ok(s) => s,
        Err(_) => return vec![],
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

/// Select elements with Legado rule syntax
pub fn select_list<'a>(doc: &'a Html, selector: &str) -> Vec<ElementRef<'a>> {
    let selector = selector.trim();

    // Split by @ first to get the base selector (handle @@ separately in text extraction)
    let sel_text = selector.split("@@").next().unwrap_or(selector).trim();
    let split = split_top_level(sel_text, &["@"]);
    let sel_text = split
        .parts
        .first()
        .map(String::as_str)
        .unwrap_or(sel_text)
        .trim();

    // Handle list combination operators at the top level
    if sel_text.contains("&&") || sel_text.contains("||") || sel_text.contains("%%") {
        return select_with_combination(doc, sel_text);
    }

    collect_matches(doc, &parse_selector_with_index(sel_text))
}

/// Handle list combination operators
fn select_with_combination<'a>(doc: &'a Html, rule: &str) -> Vec<ElementRef<'a>> {
    let split = split_top_level(rule, &["&&", "||", "%%"]);
    let rules = split.parts;

    if rules.is_empty() {
        return vec![];
    }

    let mut result = select_list_simple(doc, &rules[0]);
    let operator = split.delimiter.as_deref().unwrap_or("");

    for next_rule in rules.iter().skip(1) {
        let next_results = select_list_simple(doc, next_rule);

        match operator {
            "&&" => {
                result.extend(next_results);
            }
            "||" => {
                if result.is_empty() {
                    result = next_results;
                }
            }
            "%%" => {
                let mut zipped = Vec::new();
                let max_len = result.len().max(next_results.len());
                for j in 0..max_len {
                    if j < result.len() {
                        zipped.push(result[j]);
                    }
                    if j < next_results.len() {
                        zipped.push(next_results[j]);
                    }
                }
                result = zipped;
            }
            _ => {}
        }
    }

    result
}

/// Simple select without combination operators
fn select_list_simple<'a>(doc: &'a Html, selector: &str) -> Vec<ElementRef<'a>> {
    collect_matches(doc, &parse_selector_with_index(selector))
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
        let mut result =
            select_text_list(doc, combo.parts.first().map(String::as_str).unwrap_or(""));
        for part in combo.parts.iter().skip(1) {
            let next = select_text_list(doc, part);
            match operator {
                "&&" => result.extend(next),
                "||" => {
                    if result.is_empty() {
                        result = next;
                    }
                }
                "%%" => {
                    let mut zipped = Vec::new();
                    let max_len = result.len().max(next.len());
                    for idx in 0..max_len {
                        if idx < result.len() {
                            zipped.push(result[idx].clone());
                        }
                        if idx < next.len() {
                            zipped.push(next[idx].clone());
                        }
                    }
                    result = zipped;
                }
                _ => {}
            }
        }
        return result;
    }

    // Handle rule chaining with @@
    if rule.contains("@@") {
        let rules: Vec<&str> = rule.split("@@").collect();
        if rules.is_empty() {
            return vec![];
        }

        // Start with first rule - get all matching texts
        let mut current_texts = select_text_list(doc, rules[0]);

        // Apply subsequent rules
        for r in rules.iter().skip(1) {
            if current_texts.is_empty() {
                break;
            }
            let mut new_texts = Vec::new();
            for text in &current_texts {
                let sub_doc = Html::parse_document(text);
                new_texts.extend(select_text_list(&sub_doc, r));
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
/// HTML-only named entities are normalized without touching XML entities, and
/// multiple-root fragments are wrapped only when parsing the original input fails.
pub(crate) fn parse_xpath_package(
    input: &str,
) -> Result<sxd_document::Package, sxd_document::parser::Error> {
    let normalized = normalize_xpath_entities(input);
    match sxd_document::parser::parse(normalized.as_ref()) {
        Ok(package) => Ok(package),
        Err(_) => {
            let fragment = format!("<reader-root>{normalized}</reader-root>");
            sxd_document::parser::parse(&fragment)
        }
    }
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

/// XPath support using sxd-xpath
pub fn select_xpath(html: &str, xpath: &str) -> Vec<String> {
    let package = match parse_xpath_package(html) {
        Ok(p) => p,
        Err(_) => return vec![],
    };

    let document = package.as_document();
    let context = sxd_xpath::Context::new();

    match sxd_xpath::Factory::new().build(xpath) {
        Ok(Some(xpath_expr)) => match xpath_expr.evaluate(&context, document.root()) {
            Ok(value) => match value {
                sxd_xpath::Value::Nodeset(ns) => ns.into_iter().map(|n| n.string_value()).collect(),
                sxd_xpath::Value::String(s) => vec![s],
                sxd_xpath::Value::Number(n) => vec![n.to_string()],
                sxd_xpath::Value::Boolean(b) => vec![b.to_string()],
            },
            Err(_) => vec![],
        },
        _ => vec![],
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
    if let Ok(re) = regex::Regex::new(r"(?is)<script[^>]*>.*?</script>|<style[^>]*>.*?</style>|<!--.*?-->") {
        text = re.replace_all(&text, "").into_owned();
    }

    // 2. 提取并保留 <img> 标签，补全相对 URL，使用占位符保护
    let mut img_placeholders: Vec<String> = Vec::new();
    if let Ok(img_re) = regex::Regex::new(r"(?i)<img\b[^>]*>") {
        if let Ok(src_re) = regex::Regex::new(r#"(?i)\b(?:src|data-src|data-original)\s*=\s*["']?([^"'\s>]+)["']?"#) {
            text = img_re.replace_all(&text, |caps: &regex::Captures| {
                let img_tag = caps.get(0).unwrap().as_str();
                let full_img = if let Some(src_caps) = src_re.captures(img_tag) {
                    let raw_src = src_caps.get(1).map(|m| m.as_str()).unwrap_or_default();
                    if !raw_src.is_empty() && !redirect_url.is_empty() {
                        let abs_src = crate::parser::rule_engine::resolve_url(redirect_url, raw_src);
                        format!(r#"<img src="{}">"#, abs_src)
                    } else {
                        format!(r#"<img src="{}">"#, raw_src)
                    }
                } else {
                    img_tag.to_string()
                };
                let placeholder = format!("__READER_IMG_PLACEHOLDER_{}__", img_placeholders.len());
                img_placeholders.push(full_img);
                format!("\n{}\n", placeholder)
            }).into_owned();
        }
    }

    // 3. 将块级换行标签转换为换行符 \n
    if let Ok(block_re) = regex::Regex::new(r"(?i)<br\s*/?>|</?p\b[^>]*>|</?div\b[^>]*>|</?h[1-6]\b[^>]*>") {
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
            "<root>&amp;|&lt;|&gt;|&quot;|&apos;|&#65;|&#x42;</root>",
            "string(/root)",
        );
        assert_eq!(values, vec!["&|<|>|\"|'|A|B"]);
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
        let messy_html = "<div><script>alert(1);</script><p>正文内容<span>注释</span><br>第二行</p></div>";
        assert_eq!(
            format_keep_img(messy_html, ""),
            "正文内容注释\n第二行"
        );
    }

    #[test]
    fn test_html_unescape() {
        assert_eq!(
            html_unescape("&nbsp;文字&quot;双引号&quot;&apos;单引号&apos;&amp;和&lt;小于&gt;大于&#160;"),
            " 文字\"双引号\"'单引号'&和<小于>大于\u{a0}"
        );
    }
}

