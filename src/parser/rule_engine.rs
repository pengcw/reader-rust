use crate::crawler::current_active_session;
use crate::model::rule::{BookInfoRule, SearchRule, TocRule};
use crate::model::{
    book::Book, book_chapter::BookChapter, book_source::BookSource, search::SearchBook,
};
use crate::parser::{
    html,
    js::{eval_js_template_with_bindings, eval_js_with_bindings, with_js_lib},
    jsonpath, rule_analyzer,
};
use crate::util::text::normalize_source_url;
use serde_json::{json, Value};
use std::collections::HashMap;
use sxd_xpath::{Context as XPathContext, Factory as XPathFactory, Value as XPathValue};

#[derive(Clone, Default)]
pub struct RuleEngine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseMode {
    Css,
    XPath,
    JsonPath,
    Regex,
    Js,
}

#[derive(Debug, Clone, Default)]
struct RuleVariableContext {
    rule_data: Option<HashMap<String, String>>,
    book: Option<HashMap<String, String>>,
    chapter: Option<HashMap<String, String>>,
    book_name: Option<String>,
    chapter_title: Option<String>,
}

impl RuleVariableContext {
    fn for_book(variable: Option<&str>, book_name: Option<&str>) -> Self {
        Self {
            book: Some(parse_variable_map(variable)),
            book_name: book_name.map(str::to_string),
            ..Default::default()
        }
    }

    fn for_search_item() -> Self {
        Self {
            rule_data: Some(HashMap::new()),
            book: Some(HashMap::new()),
            ..Default::default()
        }
    }

    fn for_chapter(&self, variable: Option<&str>, title: &str) -> Self {
        Self {
            rule_data: self.rule_data.clone(),
            book: self.book.clone(),
            chapter: Some(parse_variable_map(variable)),
            book_name: self.book_name.clone(),
            chapter_title: Some(title.to_string()),
        }
    }

    fn get(&self, key: &str) -> Option<String> {
        match key {
            "bookName" => self.book_name.clone(),
            "title" => self.chapter_title.clone(),
            _ => self
                .chapter
                .as_ref()
                .and_then(|values| values.get(key))
                .or_else(|| self.book.as_ref().and_then(|values| values.get(key)))
                .or_else(|| self.rule_data.as_ref().and_then(|values| values.get(key)))
                .cloned()
                .or_else(|| {
                    current_active_session()
                        .and_then(|session| session.get_variable(key))
                        .map(value_to_rule_string)
                }),
        }
    }

    fn insert(&mut self, key: String, value: String) {
        if let Some(chapter) = self.chapter.as_mut() {
            chapter.insert(key, value);
        } else if let Some(book) = self.book.as_mut() {
            book.insert(key, value);
        } else if let Some(rule_data) = self.rule_data.as_mut() {
            rule_data.insert(key, value);
        } else if let Some(session) = current_active_session() {
            session.set_variable(key.as_str(), Value::String(value));
        }
    }

    fn book_variable(&self) -> Option<String> {
        serialize_variable_map(self.book.as_ref())
    }

    fn chapter_variable(&self) -> Option<String> {
        serialize_variable_map(self.chapter.as_ref())
    }

    fn js_bindings(&self) -> HashMap<String, Value> {
        let mut book = serde_json::Map::new();
        let mut book_variables = serde_json::Map::new();
        if let Some(values) = &self.book {
            for (key, value) in values {
                let value = Value::String(value.clone());
                book.insert(key.clone(), value.clone());
                book_variables.insert(key.clone(), value);
            }
        }
        book.insert("variableMap".to_string(), Value::Object(book_variables));
        if let Some(name) = &self.book_name {
            book.insert("name".to_string(), Value::String(name.clone()));
            book.insert("bookName".to_string(), Value::String(name.clone()));
        }

        let mut chapter = serde_json::Map::new();
        let mut chapter_variables = serde_json::Map::new();
        if let Some(values) = &self.chapter {
            for (key, value) in values {
                let value = Value::String(value.clone());
                chapter.insert(key.clone(), value.clone());
                chapter_variables.insert(key.clone(), value);
            }
        }
        chapter.insert("variableMap".to_string(), Value::Object(chapter_variables));
        if let Some(title) = &self.chapter_title {
            chapter.insert("title".to_string(), Value::String(title.clone()));
        }

        HashMap::from([
            ("book".to_string(), Value::Object(book)),
            ("chapter".to_string(), Value::Object(chapter)),
            (
                "title".to_string(),
                Value::String(self.chapter_title.clone().unwrap_or_default()),
            ),
        ])
    }
}

fn parse_variable_map(variable: Option<&str>) -> HashMap<String, String> {
    variable
        .and_then(|value| serde_json::from_str::<HashMap<String, Value>>(value).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| (key, value_to_rule_string(value)))
        .collect()
}

fn serialize_variable_map(map: Option<&HashMap<String, String>>) -> Option<String> {
    map.filter(|values| !values.is_empty())
        .and_then(|values| serde_json::to_string(values).ok())
}

fn value_to_rule_string(value: Value) -> String {
    match value {
        Value::String(value) => value,
        Value::Null => String::new(),
        value => value.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PutEntry {
    key: String,
    value_rule: String,
}

#[derive(Debug, Clone)]
struct SourceRule {
    mode: ParseMode,
    rule: String,
    replace_regex: Option<String>,
    replacement: Option<String>,
    replace_first: bool,
    replacement_rule: Option<String>,
    put_entries: Vec<PutEntry>,
}

impl SourceRule {
    fn compile(rule: &str, fallback: ParseMode, content_is_json: bool) -> Self {
        let (without_put, put_entries) = extract_put_entries(rule);
        let (mode, rule) = classify_rule_mode(&without_put, fallback, content_is_json);
        Self {
            mode,
            rule,
            replace_regex: None,
            replacement: None,
            replace_first: false,
            replacement_rule: None,
            put_entries,
        }
    }

    fn make_up_rule(&mut self, expanded_rule: &str) {
        let Some(index) = expanded_rule.find("##") else {
            self.rule = expanded_rule.trim().to_string();
            return;
        };
        let replacement_rule = &expanded_rule[index..];
        let fields = replacement_rule
            .trim_end_matches("###")
            .trim_start_matches("##")
            .split("##")
            .collect::<Vec<_>>();
        self.rule = expanded_rule[..index].trim().to_string();
        self.replace_regex = fields.first().map(|value| (*value).to_string());
        self.replacement = fields.get(1).map(|value| (*value).to_string());
        self.replace_first = replacement_rule.ends_with("###");
        self.replacement_rule = Some(replacement_rule.to_string());
    }

    fn apply_replacement(&self, value: &str) -> String {
        let Some(rule) = self.replacement_rule.as_deref() else {
            return value.to_string();
        };
        let steps = rule
            .strip_prefix("##")
            .unwrap_or(rule)
            .strip_suffix("###")
            .unwrap_or_else(|| rule.strip_prefix("##").unwrap_or(rule));
        if steps.split("##").count() <= 2 {
            let pattern = self.replace_regex.as_deref().unwrap_or_default();
            let replacement = self.replacement.as_deref().unwrap_or_default();
            return if self.replace_first {
                apply_regex_replace_first(value, pattern, replacement)
            } else {
                apply_regex_replace_all(value, pattern, replacement)
            };
        }
        apply_legado_regex(value, rule)
    }
}

fn classify_rule_mode(
    raw_rule: &str,
    fallback: ParseMode,
    content_is_json: bool,
) -> (ParseMode, String) {
    let rule = raw_rule.trim();
    if matches!(fallback, ParseMode::Js | ParseMode::Regex) {
        return (fallback, rule.to_string());
    }
    if let Some(rest) = strip_prefix_ascii_case(rule, "@css:") {
        return (ParseMode::Css, rest.trim().to_string());
    }
    if let Some(rest) = rule.strip_prefix("@@") {
        return (ParseMode::Css, rest.to_string());
    }
    if let Some(rest) = strip_prefix_ascii_case(rule, "@xpath:") {
        return (ParseMode::XPath, rest.to_string());
    }
    if let Some(rest) = strip_prefix_ascii_case(rule, "@json:") {
        return (ParseMode::JsonPath, rest.to_string());
    }
    if let Some(rest) = strip_prefix_ascii_case(rule, "@regex:") {
        return (ParseMode::Regex, rest.trim().to_string());
    }
    if let Some(rest) =
        strip_prefix_ascii_case(rule, "js:").or_else(|| strip_prefix_ascii_case(rule, "@js:"))
    {
        return (ParseMode::Js, rest.trim().to_string());
    }
    if rule.starts_with("<js>") {
        return (ParseMode::Js, rule.to_string());
    }
    if content_is_json || rule.starts_with("$.") || rule.starts_with("$[") {
        return (ParseMode::JsonPath, rule.to_string());
    }
    if rule.starts_with('/') || rule.starts_with("./") {
        return (ParseMode::XPath, rule.to_string());
    }
    if rule.starts_with(':') {
        return (ParseMode::Regex, rule.to_string());
    }
    (fallback, rule.to_string())
}

fn starts_with_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn find_ascii_case(value: &str, needle: &str) -> Option<usize> {
    value
        .char_indices()
        .find_map(|(index, _)| starts_with_ascii_case(&value[index..], needle).then_some(index))
}

fn strip_prefix_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    starts_with_ascii_case(value, prefix).then(|| &value[prefix.len()..])
}

impl RuleEngine {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self)
    }

    /// Detect the parsing mode from the rule and its current content.
    fn detect_mode(&self, rule: &str, content: &str) -> ParseMode {
        let content = content.trim();
        let content_is_json = (content.starts_with('{') || content.starts_with('['))
            && serde_json::from_str::<Value>(content).is_ok();
        classify_rule_mode(rule, ParseMode::Css, content_is_json).0
    }

    /// Strip mode prefix from rule
    fn strip_mode_prefix<'a>(&self, rule: &'a str) -> &'a str {
        strip_mode_prefix(rule)
    }

    pub fn search_books(&self, source: &BookSource, body: &str, base_url: &str) -> Vec<SearchBook> {
        with_js_lib(source.js_lib.as_deref(), || {
            if book_url_pattern_matches(source.book_url_pattern.as_deref(), base_url) {
                return self
                    .search_detail_fallback(source, body, base_url)
                    .into_iter()
                    .collect();
            }
            let rule = source.rule_search.clone().unwrap_or_default();
            let (list_rule, reverse) = normalize_list_rule(rule.book_list.as_deref().unwrap_or(""));
            let mode = self.detect_mode(list_rule, body);
            let mut results = match mode {
                ParseMode::JsonPath => {
                    self.search_books_json(source, body, base_url, &rule, list_rule)
                }
                ParseMode::XPath => {
                    self.search_books_xpath(source, body, base_url, &rule, list_rule)
                }
                ParseMode::Js => self.search_books_js(source, body, base_url, &rule, list_rule),
                ParseMode::Regex => {
                    self.search_books_regex(source, body, base_url, &rule, list_rule)
                }
                ParseMode::Css => self.search_books_html(source, body, base_url, &rule, list_rule),
            };

            if results.is_empty() && !has_book_url_pattern(source.book_url_pattern.as_deref()) {
                if let Some(detail_book) = self.search_detail_fallback(source, body, base_url) {
                    results.push(detail_book);
                }
            }
            dedupe_search_books(&mut results);
            if reverse {
                results.reverse();
            }
            results
        })
    }

    pub fn explore_books(
        &self,
        source: &BookSource,
        body: &str,
        base_url: &str,
    ) -> Vec<SearchBook> {
        with_js_lib(source.js_lib.as_deref(), || {
            let rule = source
                .rule_explore
                .clone()
                .filter(|rule| {
                    rule.book_list
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty())
                })
                .unwrap_or_else(|| source.rule_search.clone().unwrap_or_default());
            let (list_rule, reverse) = normalize_list_rule(rule.book_list.as_deref().unwrap_or(""));
            let mode = self.detect_mode(list_rule, body);
            let mut results = match mode {
                ParseMode::JsonPath => {
                    self.search_books_json(source, body, base_url, &rule, list_rule)
                }
                ParseMode::XPath => {
                    self.search_books_xpath(source, body, base_url, &rule, list_rule)
                }
                ParseMode::Js => self.search_books_js(source, body, base_url, &rule, list_rule),
                ParseMode::Regex => {
                    self.search_books_regex(source, body, base_url, &rule, list_rule)
                }
                ParseMode::Css => self.search_books_html(source, body, base_url, &rule, list_rule),
            };
            if results.is_empty() && !has_book_url_pattern(source.book_url_pattern.as_deref()) {
                if let Some(detail_book) = self.search_detail_fallback(source, body, base_url) {
                    results.push(detail_book);
                }
            }
            dedupe_search_books(&mut results);
            if reverse {
                results.reverse();
            }
            results
        })
    }

    pub fn book_info(
        &self,
        source: &BookSource,
        body: &str,
        base_url: &str,
        book_url: &str,
    ) -> Book {
        self.book_info_with_variable(source, body, base_url, book_url, None, None)
    }

    pub fn book_info_with_variable(
        &self,
        source: &BookSource,
        body: &str,
        base_url: &str,
        book_url: &str,
        variable: Option<&str>,
        book_name: Option<&str>,
    ) -> Book {
        with_js_lib(source.js_lib.as_deref(), || {
            let rule = source.rule_book_info.clone().unwrap_or_default();
            let mut context = RuleVariableContext::for_book(variable, book_name);

            let mode = self.detect_mode(rule.name.as_deref().unwrap_or(""), body);
            match mode {
                ParseMode::JsonPath => {
                    if let Ok(v) = serde_json::from_str::<Value>(body) {
                        return parse_book_info_json(
                            source,
                            &v,
                            base_url,
                            &rule,
                            book_url,
                            &mut context,
                        );
                    }
                }
                ParseMode::XPath => {
                    return parse_book_info_xpath(
                        source,
                        body,
                        base_url,
                        &rule,
                        book_url,
                        &mut context,
                    );
                }
                _ => {}
            }
            parse_book_info_html(source, body, base_url, &rule, book_url, &mut context)
        })
    }

    pub fn chapter_list(
        &self,
        source: &BookSource,
        body: &str,
        base_url: &str,
    ) -> (Vec<BookChapter>, Vec<String>) {
        self.chapter_list_with_variable(source, body, base_url, None, None)
    }

    pub fn chapter_list_with_variable(
        &self,
        source: &BookSource,
        body: &str,
        base_url: &str,
        variable: Option<&str>,
        book_name: Option<&str>,
    ) -> (Vec<BookChapter>, Vec<String>) {
        with_js_lib(source.js_lib.as_deref(), || {
            let rule = source.rule_toc.clone().unwrap_or_default();
            let mut context = RuleVariableContext::for_book(variable, book_name);
            let (list_rule, reverse) =
                normalize_list_rule(rule.chapter_list.as_deref().unwrap_or(""));
            let prepared_body = prepare_toc_body(body, base_url, &rule, &context);
            let mode = self.detect_mode(list_rule, &prepared_body);
            let (mut chapters, next_urls) = match mode {
                ParseMode::JsonPath => parse_chapter_list_json(
                    &prepared_body,
                    base_url,
                    &rule,
                    list_rule,
                    &mut context,
                ),
                ParseMode::XPath => parse_chapter_list_xpath(
                    &prepared_body,
                    base_url,
                    &rule,
                    list_rule,
                    &mut context,
                ),
                ParseMode::Js => self.parse_chapter_list_js(
                    &prepared_body,
                    base_url,
                    &rule,
                    list_rule,
                    &mut context,
                ),
                ParseMode::Regex => self.parse_chapter_list_regex(
                    &prepared_body,
                    base_url,
                    &rule,
                    list_rule,
                    &mut context,
                ),
                ParseMode::Css => parse_chapter_list_html(
                    &prepared_body,
                    base_url,
                    &rule,
                    list_rule,
                    &mut context,
                ),
            };
            apply_toc_format_js(&mut chapters, rule.format_js.as_deref(), base_url, &context);
            if reverse {
                chapters.reverse();
            }
            for (index, chapter) in chapters.iter_mut().enumerate() {
                chapter.index = index as i32;
            }
            (chapters, next_urls)
        })
    }

    pub fn content(&self, source: &BookSource, body: &str, base_url: &str) -> String {
        self.content_with_variables(source, body, base_url, None, None, None, None)
    }

    pub fn content_with_variables(
        &self,
        source: &BookSource,
        body: &str,
        base_url: &str,
        book_variable: Option<&str>,
        chapter_variable: Option<&str>,
        book_name: Option<&str>,
        chapter_title: Option<&str>,
    ) -> String {
        with_js_lib(source.js_lib.as_deref(), || {
            let mut context = RuleVariableContext::for_book(book_variable, book_name);
            if chapter_variable.is_some() {
                context.chapter = Some(parse_variable_map(chapter_variable));
            }
            context.chapter_title = chapter_title.map(str::to_string);
            let rule = source.rule_content.clone().unwrap_or_default();
            let mut content_body = body.to_string();

            if let Some(source_regex) = rule
                .source_regex
                .as_deref()
                .filter(|s| !s.trim().is_empty())
            {
                content_body = apply_legado_regex(&content_body, source_regex);
            }
            if let Some(web_js) = rule.web_js.as_deref().filter(|s| !s.trim().is_empty()) {
                if let Ok(processed) = eval_js_with_bindings(
                    self.strip_mode_prefix(web_js),
                    &content_body,
                    base_url,
                    &context.js_bindings(),
                ) {
                    if !processed.trim().is_empty() {
                        content_body = processed;
                    }
                }
            }

            if let Some(content_rule) = rule.content.clone() {
                let has_templates = content_rule.contains("{{");
                let content_rule =
                    interpolate_common_templates(&content_rule, &content_body, base_url, &context);
                if has_templates && content_rule.trim_start().starts_with('<') {
                    let content = html::format_keep_img(&content_rule, base_url);
                    return apply_content_replacement(
                        content,
                        rule.replace_regex.as_deref(),
                        &content_body,
                        base_url,
                        &context,
                    );
                }
                if matches!(
                    self.detect_mode(&content_rule, &content_body),
                    ParseMode::Js
                ) {
                    let script = self.strip_mode_prefix(&content_rule);
                    if let Ok(res) = eval_js_with_bindings(
                        script,
                        &content_body,
                        base_url,
                        &context.js_bindings(),
                    ) {
                        let content = html::format_keep_img(&res, base_url);
                        return apply_content_replacement(
                            content,
                            rule.replace_regex.as_deref(),
                            &content_body,
                            base_url,
                            &context,
                        );
                    }
                }

                let mode = self.detect_mode(&content_rule, &content_body);
                let mut content = match mode {
                    ParseMode::JsonPath => {
                        if let Ok(v) = serde_json::from_str::<Value>(&content_body) {
                            jsonpath::jsonpath_first_string(
                                &v,
                                self.strip_mode_prefix(&content_rule),
                            )
                            .unwrap_or_default()
                        } else {
                            String::new()
                        }
                    }
                    ParseMode::XPath => {
                        html::select_xpath(&content_body, self.strip_mode_prefix(&content_rule))
                            .first()
                            .cloned()
                            .unwrap_or_default()
                    }
                    _ => {
                        let doc = html::parse_document(&content_body);
                        let result =
                            html::select_all_text(&doc, self.strip_mode_prefix(&content_rule));
                        result.unwrap_or_default()
                    }
                };

                content = html::format_keep_img(&content, base_url);
                return apply_content_replacement(
                    content,
                    rule.replace_regex.as_deref(),
                    &content_body,
                    base_url,
                    &context,
                );
            }

            String::new()
        })
    }

    /// Get the next content page URL if pagination exists.
    pub fn next_content_url(
        &self,
        source: &BookSource,
        body: &str,
        base_url: &str,
    ) -> Option<String> {
        self.next_content_url_with_variables(source, body, base_url, None, None, None, None)
    }

    pub fn next_content_url_with_variables(
        &self,
        source: &BookSource,
        body: &str,
        base_url: &str,
        book_variable: Option<&str>,
        chapter_variable: Option<&str>,
        book_name: Option<&str>,
        chapter_title: Option<&str>,
    ) -> Option<String> {
        with_js_lib(source.js_lib.as_deref(), || {
            let rule = source.rule_content.clone().unwrap_or_default();
            let next_rule = rule.next_content_url.as_deref()?.trim();
            if next_rule.is_empty() {
                return None;
            }

            let mut context = RuleVariableContext::for_book(book_variable, book_name);
            if chapter_variable.is_some() {
                context.chapter = Some(parse_variable_map(chapter_variable));
            }
            context.chapter_title = chapter_title.map(str::to_string);

            let next_url = if self.detect_mode(next_rule, body) == ParseMode::JsonPath {
                let value = serde_json::from_str::<Value>(body).ok()?;
                eval_field_json_with_ctx(next_rule, &value, base_url, &mut context)
            } else {
                let doc = html::parse_document(body);
                eval_field_html_doc_with_ctx(next_rule, &doc, base_url, &mut context)
            }?;
            (!next_url.is_empty()).then(|| resolve_url(base_url, &next_url))
        })
    }

    fn search_detail_fallback(
        &self,
        source: &BookSource,
        body: &str,
        base_url: &str,
    ) -> Option<SearchBook> {
        let book = self.book_info(source, body, base_url, base_url);
        search_book_from_book(book)
    }

    fn search_books_js(
        &self,
        source: &BookSource,
        body: &str,
        base_url: &str,
        rule: &SearchRule,
        list_rule: &str,
    ) -> Vec<SearchBook> {
        let context = RuleVariableContext::default();
        let output = match eval_js_with_bindings(
            self.strip_mode_prefix(list_rule),
            body,
            base_url,
            &context.js_bindings(),
        ) {
            Ok(result) => result,
            Err(_) => return vec![],
        };

        if let Some(items) = parse_js_output_items(&output) {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let mut context = RuleVariableContext::for_search_item();
                if let Some(book) =
                    build_search_book_from_json(source, &item, base_url, rule, &mut context)
                {
                    out.push(book);
                }
            }
            return out;
        }

        let doc = html::parse_document(&output);
        let sel = match scraper::Selector::parse("body > *") {
            Ok(sel) => sel,
            Err(_) => return vec![],
        };
        let mut out = Vec::new();
        for el in doc.select(&sel) {
            let mut context = RuleVariableContext::for_search_item();
            let name = rule
                .name
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context))
                .unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let author = rule
                .author
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context))
                .unwrap_or_default();
            let book_url = rule
                .book_url
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context))
                .unwrap_or_default();
            let cover_url = rule
                .cover_url
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context))
                .map(|u| resolve_url(base_url, &u));
            let intro = rule
                .intro
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context));
            let kind = rule
                .kind
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context));
            let last_chapter = rule
                .last_chapter
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context));
            let update_time = rule
                .update_time
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context));
            let word_count = rule
                .word_count
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context));
            out.push(SearchBook {
                name,
                author,
                book_url: resolve_url(base_url, &book_url),
                origin: source.book_source_url.clone(),
                cover_url,
                intro,
                kind,
                last_chapter,
                update_time,
                word_count,
                variable: context.book_variable(),
                book_source_urls: None,
            });
        }
        out
    }

    fn search_books_regex(
        &self,
        source: &BookSource,
        body: &str,
        base_url: &str,
        rule: &SearchRule,
        list_rule: &str,
    ) -> Vec<SearchBook> {
        let rows = regex_capture_rows(self.strip_mode_prefix(list_rule), body);
        let mut out = Vec::new();
        for captures in rows {
            let mut context = RuleVariableContext::for_search_item();
            let name = capture_rule_values_with_ctx(rule.name.as_deref(), &captures, &mut context)
                .unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let author =
                capture_rule_values_with_ctx(rule.author.as_deref(), &captures, &mut context)
                    .unwrap_or_default();
            let book_url =
                capture_rule_values_with_ctx(rule.book_url.as_deref(), &captures, &mut context)
                    .unwrap_or_default();
            let cover_url =
                capture_rule_values_with_ctx(rule.cover_url.as_deref(), &captures, &mut context)
                    .map(|u| resolve_url(base_url, &u));
            let intro =
                capture_rule_values_with_ctx(rule.intro.as_deref(), &captures, &mut context);
            let kind = capture_rule_values_with_ctx(rule.kind.as_deref(), &captures, &mut context);
            let last_chapter =
                capture_rule_values_with_ctx(rule.last_chapter.as_deref(), &captures, &mut context);
            let update_time =
                capture_rule_values_with_ctx(rule.update_time.as_deref(), &captures, &mut context);
            let word_count =
                capture_rule_values_with_ctx(rule.word_count.as_deref(), &captures, &mut context);
            out.push(SearchBook {
                name,
                author,
                book_url: resolve_url(base_url, &book_url),
                origin: source.book_source_url.clone(),
                cover_url,
                intro,
                kind,
                last_chapter,
                update_time,
                word_count,
                variable: context.book_variable(),
                book_source_urls: None,
            });
        }
        out
    }

    fn parse_next_toc_urls(
        &self,
        body: &str,
        base_url: &str,
        rule: &TocRule,
        ctx: &RuleVariableContext,
    ) -> Vec<String> {
        let Some(next_rule) = rule.next_toc_url.as_deref().map(str::trim) else {
            return vec![];
        };
        if next_rule.is_empty() {
            return vec![];
        }
        if let Some(key) = direct_get_key(next_rule) {
            return normalize_toc_next_urls(base_url, ctx.get(key).into_iter().collect());
        }

        let expanded = interpolate_common_templates(next_rule, body, base_url, ctx);
        let mode = self.detect_mode(&expanded, body);
        let raw_urls = match mode {
            ParseMode::JsonPath => serde_json::from_str::<Value>(body)
                .ok()
                .map(|value| {
                    jsonpath::jsonpath_query(&value, self.strip_mode_prefix(&expanded))
                        .iter()
                        .filter_map(jsonpath::value_to_string)
                        .collect()
                })
                .unwrap_or_default(),
            ParseMode::XPath => html::select_xpath(body, self.strip_mode_prefix(&expanded)),
            ParseMode::Js => eval_js_with_bindings(
                self.strip_mode_prefix(&expanded),
                body,
                base_url,
                &ctx.js_bindings(),
            )
            .map(|output| {
                parse_js_output_items(&output)
                    .map(|items| items.iter().filter_map(jsonpath::value_to_string).collect())
                    .unwrap_or_else(|| vec![output])
            })
            .unwrap_or_default(),
            ParseMode::Regex => regex_capture_rows(
                self.strip_mode_prefix(&expanded)
                    .trim_start_matches(':')
                    .trim(),
                body,
            )
            .into_iter()
            .filter_map(|row| row.get(1).or_else(|| row.first()).and_then(Clone::clone))
            .collect(),
            ParseMode::Css => {
                let doc = html::parse_document(body);
                html::select_text_list(&doc, self.strip_mode_prefix(&expanded))
            }
        };
        normalize_toc_next_urls(base_url, raw_urls)
    }

    fn parse_chapter_list_js(
        &self,
        body: &str,
        base_url: &str,
        rule: &TocRule,
        list_rule: &str,
        ctx: &mut RuleVariableContext,
    ) -> (Vec<BookChapter>, Vec<String>) {
        let next_urls = self.parse_next_toc_urls(body, base_url, rule, ctx);
        let output = match eval_js_with_bindings(
            self.strip_mode_prefix(list_rule),
            body,
            base_url,
            &ctx.js_bindings(),
        ) {
            Ok(result) => result,
            Err(_) => return (vec![], vec![]),
        };

        if let Some(items) = parse_js_output_items(&output) {
            let mut out = Vec::with_capacity(items.len());
            let mut seen_urls = std::collections::HashSet::new();
            for item in items {
                let mut chapter_ctx =
                    ctx.for_chapter(item.get("variable").and_then(Value::as_str), "");
                if let Some(chapter) =
                    build_chapter_from_json(&item, base_url, rule, &mut chapter_ctx, out.len())
                {
                    if seen_urls.insert(chapter.url.clone()) {
                        out.push(chapter);
                    }
                }
            }
            return (out, next_urls);
        }

        let doc = html::parse_document(&output);
        let sel = match scraper::Selector::parse("body > *") {
            Ok(sel) => sel,
            Err(_) => return (vec![], vec![]),
        };
        let mut out = Vec::new();
        let mut seen_urls = std::collections::HashSet::new();
        for el in doc.select(&sel) {
            let mut chapter_ctx = ctx.for_chapter(None, "");
            let title = rule
                .chapter_name
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut chapter_ctx))
                .unwrap_or_default();
            chapter_ctx.chapter_title = Some(title.clone());
            if title.is_empty() {
                continue;
            }
            let raw_url = rule
                .chapter_url
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut chapter_ctx))
                .unwrap_or_default();
            let tag = rule
                .update_time
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut chapter_ctx));
            let is_volume = rule
                .is_volume
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut chapter_ctx))
                .map(is_truthy)
                .unwrap_or(false);
            let is_vip = rule
                .is_vip
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut chapter_ctx))
                .map(is_truthy)
                .unwrap_or(false);
            let is_pay = rule
                .is_pay
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut chapter_ctx))
                .map(is_truthy)
                .unwrap_or(false);
            let url = finalize_chapter_url(base_url, &raw_url, &title, is_volume, out.len());
            if !seen_urls.insert(url.clone()) {
                continue;
            }
            out.push(BookChapter {
                title,
                url,
                index: out.len() as i32,
                tag,
                is_vip,
                is_pay,
                is_volume,
                variable: chapter_ctx.chapter_variable(),
            });
        }
        (out, next_urls)
    }

    fn parse_chapter_list_regex(
        &self,
        body: &str,
        base_url: &str,
        rule: &TocRule,
        list_rule: &str,
        ctx: &mut RuleVariableContext,
    ) -> (Vec<BookChapter>, Vec<String>) {
        let rows = regex_capture_rows(self.strip_mode_prefix(list_rule), body);
        let mut out = Vec::new();
        let mut seen_urls = std::collections::HashSet::new();
        for captures in rows {
            let mut chapter_ctx = ctx.for_chapter(None, "");
            let title = capture_rule_values_with_ctx(
                rule.chapter_name.as_deref(),
                &captures,
                &mut chapter_ctx,
            )
            .unwrap_or_default();
            chapter_ctx.chapter_title = Some(title.clone());
            if title.is_empty() {
                continue;
            }
            let raw_url = capture_rule_values_with_ctx(
                rule.chapter_url.as_deref(),
                &captures,
                &mut chapter_ctx,
            )
            .unwrap_or_default();
            let tag = capture_rule_values_with_ctx(
                rule.update_time.as_deref(),
                &captures,
                &mut chapter_ctx,
            );
            let is_volume = capture_rule_values_with_ctx(
                rule.is_volume.as_deref(),
                &captures,
                &mut chapter_ctx,
            )
            .map(is_truthy)
            .unwrap_or(false);
            let is_vip =
                capture_rule_values_with_ctx(rule.is_vip.as_deref(), &captures, &mut chapter_ctx)
                    .map(is_truthy)
                    .unwrap_or(false);
            let is_pay =
                capture_rule_values_with_ctx(rule.is_pay.as_deref(), &captures, &mut chapter_ctx)
                    .map(is_truthy)
                    .unwrap_or(false);
            let url = finalize_chapter_url(base_url, &raw_url, &title, is_volume, out.len());
            if !seen_urls.insert(url.clone()) {
                continue;
            }
            out.push(BookChapter {
                title,
                url,
                index: out.len() as i32,
                tag,
                is_vip,
                is_pay,
                is_volume,
                variable: chapter_ctx.chapter_variable(),
            });
        }
        (out, vec![])
    }

    fn search_books_html(
        &self,
        source: &BookSource,
        body: &str,
        base_url: &str,
        rule: &SearchRule,
        list_sel: &str,
    ) -> Vec<SearchBook> {
        if list_sel.trim().is_empty() {
            return vec![];
        }
        let doc = html::parse_document(body);
        let items = html::select_list(&doc, self.strip_mode_prefix(list_sel));
        let mut out = Vec::with_capacity(items.len());

        for el in items {
            let mut context = RuleVariableContext::for_search_item();
            let name = rule
                .name
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context))
                .unwrap_or_default();
            let author = rule
                .author
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context))
                .unwrap_or_default();
            let book_url = rule
                .book_url
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context))
                .unwrap_or_default();
            let cover_url = rule
                .cover_url
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context));
            let intro = rule
                .intro
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context));
            let kind = rule
                .kind
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context));
            let last_chapter = rule
                .last_chapter
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context));
            let update_time = rule
                .update_time
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context));
            let word_count = rule
                .word_count
                .as_ref()
                .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut context));
            let book_url_abs = resolve_url(base_url, &book_url);
            let cover_url_abs = cover_url.map(|u| resolve_url(base_url, &u));
            out.push(SearchBook {
                name,
                author,
                book_url: book_url_abs,
                origin: source.book_source_url.clone(),
                cover_url: cover_url_abs,
                intro,
                kind,
                last_chapter,
                update_time,
                word_count,
                variable: context.book_variable(),
                book_source_urls: None,
            });
        }
        out
    }

    fn search_books_xpath(
        &self,
        source: &BookSource,
        body: &str,
        base_url: &str,
        rule: &SearchRule,
        list_rule: &str,
    ) -> Vec<SearchBook> {
        let package = match html::parse_xpath_package(body) {
            Ok(p) => p,
            Err(_) => return vec![],
        };
        let document = package.as_document();
        let items = xpath_select_nodes(
            sxd_xpath::nodeset::Node::Root(document.root()),
            self.strip_mode_prefix(list_rule),
        );
        let mut out = Vec::with_capacity(items.len());

        for item in items {
            let mut context = RuleVariableContext::for_search_item();
            let name = eval_field_xpath_with_ctx(
                rule.name.as_deref().unwrap_or(""),
                item,
                base_url,
                &mut context,
            );
            let author = eval_field_xpath_with_ctx(
                rule.author.as_deref().unwrap_or(""),
                item,
                base_url,
                &mut context,
            );
            let book_url = eval_field_xpath_with_ctx(
                rule.book_url.as_deref().unwrap_or(""),
                item,
                base_url,
                &mut context,
            );
            let cover_url = eval_field_xpath_with_ctx(
                rule.cover_url.as_deref().unwrap_or(""),
                item,
                base_url,
                &mut context,
            );
            let intro = eval_field_xpath_with_ctx(
                rule.intro.as_deref().unwrap_or(""),
                item,
                base_url,
                &mut context,
            );
            let kind = eval_field_xpath_with_ctx(
                rule.kind.as_deref().unwrap_or(""),
                item,
                base_url,
                &mut context,
            );
            let last_chapter = eval_field_xpath_with_ctx(
                rule.last_chapter.as_deref().unwrap_or(""),
                item,
                base_url,
                &mut context,
            );
            let update_time = eval_field_xpath_with_ctx(
                rule.update_time.as_deref().unwrap_or(""),
                item,
                base_url,
                &mut context,
            );
            let word_count = eval_field_xpath_with_ctx(
                rule.word_count.as_deref().unwrap_or(""),
                item,
                base_url,
                &mut context,
            );
            out.push(SearchBook {
                name: name.unwrap_or_default(),
                author: author.unwrap_or_default(),
                book_url: resolve_url(base_url, &book_url.unwrap_or_default()),
                origin: source.book_source_url.clone(),
                cover_url: cover_url.map(|u| resolve_url(base_url, &u)),
                intro,
                kind,
                last_chapter,
                update_time,
                word_count,
                variable: context.book_variable(),
                book_source_urls: None,
            });
        }

        out
    }

    fn search_books_json(
        &self,
        source: &BookSource,
        body: &str,
        base_url: &str,
        rule: &SearchRule,
        list_rule: &str,
    ) -> Vec<SearchBook> {
        let v: Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => return vec![],
        };
        let items = jsonpath::jsonpath_query(&v, self.strip_mode_prefix(list_rule));
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let mut context = RuleVariableContext::for_search_item();
            let name = eval_field_json_with_ctx(
                rule.name.as_deref().unwrap_or(""),
                &item,
                base_url,
                &mut context,
            );
            let author = eval_field_json_with_ctx(
                rule.author.as_deref().unwrap_or(""),
                &item,
                base_url,
                &mut context,
            );
            let book_url = eval_field_json_with_ctx(
                rule.book_url.as_deref().unwrap_or(""),
                &item,
                base_url,
                &mut context,
            );
            let cover_url = eval_field_json_with_ctx(
                rule.cover_url.as_deref().unwrap_or(""),
                &item,
                base_url,
                &mut context,
            );
            let intro = eval_field_json_with_ctx(
                rule.intro.as_deref().unwrap_or(""),
                &item,
                base_url,
                &mut context,
            );
            let kind = eval_field_json_with_ctx(
                rule.kind.as_deref().unwrap_or(""),
                &item,
                base_url,
                &mut context,
            );
            let last_chapter = eval_field_json_with_ctx(
                rule.last_chapter.as_deref().unwrap_or(""),
                &item,
                base_url,
                &mut context,
            );
            let update_time = eval_field_json_with_ctx(
                rule.update_time.as_deref().unwrap_or(""),
                &item,
                base_url,
                &mut context,
            );
            let word_count = eval_field_json_with_ctx(
                rule.word_count.as_deref().unwrap_or(""),
                &item,
                base_url,
                &mut context,
            );
            let book_url = book_url.map(|u| resolve_url(base_url, &u));
            let cover_url = cover_url.map(|u| resolve_url(base_url, &u));
            out.push(SearchBook {
                name: name.unwrap_or_default(),
                author: author.unwrap_or_default(),
                book_url: book_url.unwrap_or_default(),
                origin: source.book_source_url.clone(),
                cover_url,
                intro,
                kind,
                last_chapter,
                update_time,
                word_count,
                variable: context.book_variable(),
                book_source_urls: None,
            });
        }
        out
    }
}

fn prepare_html_init_scope(
    init: &str,
    doc: &scraper::Html,
    base_url: &str,
    ctx: &mut RuleVariableContext,
) -> Option<scraper::Html> {
    let init = init.trim();
    if init.is_empty() {
        return None;
    }

    if init.starts_with("@put:") || init.starts_with("@get:") {
        let _ = eval_field_html_doc_with_ctx(init, doc, base_url, ctx);
        return None;
    }

    let is_js_rule = init.starts_with("js:") || extract_js(init).1.is_some();
    if is_js_rule {
        let result = if init.starts_with("js:") {
            eval_js_with_bindings(
                strip_js_rule(init),
                &doc.html(),
                base_url,
                &ctx.js_bindings(),
            )
            .ok()
        } else {
            eval_field_html_doc_with_ctx(init, doc, base_url, ctx)
        }?;
        return looks_like_html_fragment(&result).then(|| html::parse_document(&result));
    }

    let selector = if let Some(selector) = init
        .strip_prefix("@css:")
        .or_else(|| init.strip_prefix("@CSS:"))
    {
        selector
    } else if init.starts_with('@') {
        // Preserve existing behavior for non-CSS rules without treating their
        // scalar result as a new document scope.
        let _ = eval_field_html_doc_with_ctx(init, doc, base_url, ctx);
        return None;
    } else {
        init
    };

    let selected = html::select_list(doc, selector).into_iter().next()?;
    Some(html::parse_document(&selected.html()))
}

fn looks_like_html_fragment(value: &str) -> bool {
    let value = value.trim();
    value.starts_with('<')
        && value
            .find('>')
            .is_some_and(|end| end > 1 && value[1..end].chars().any(char::is_alphabetic))
}

fn parse_book_info_html(
    source: &BookSource,
    body: &str,
    base_url: &str,
    rule: &BookInfoRule,
    book_url: &str,
    ctx: &mut RuleVariableContext,
) -> Book {
    let original_doc = html::parse_document(body);
    let scoped_doc = rule
        .init
        .as_deref()
        .and_then(|init| prepare_html_init_scope(init, &original_doc, base_url, ctx));
    let doc = scoped_doc.unwrap_or(original_doc);

    let name = rule
        .name
        .as_ref()
        .and_then(|r| eval_field_html_doc_with_ctx(r, &doc, base_url, ctx))
        .unwrap_or_default();
    let author = rule
        .author
        .as_ref()
        .and_then(|r| eval_field_html_doc_with_ctx(r, &doc, base_url, ctx))
        .unwrap_or_default();
    let intro = rule
        .intro
        .as_ref()
        .and_then(|r| eval_field_html_doc_with_ctx(r, &doc, base_url, ctx));
    let kind = rule
        .kind
        .as_ref()
        .and_then(|r| eval_field_html_doc_with_ctx(r, &doc, base_url, ctx));
    let last_chapter = rule
        .last_chapter
        .as_ref()
        .and_then(|r| eval_field_html_doc_with_ctx(r, &doc, base_url, ctx));
    let update_time = rule
        .update_time
        .as_ref()
        .and_then(|r| eval_field_html_doc_with_ctx(r, &doc, base_url, ctx));
    let cover_url = rule
        .cover_url
        .as_ref()
        .and_then(|r| eval_field_html_doc_with_ctx(r, &doc, base_url, ctx))
        .map(|u| resolve_url(base_url, &u));
    let word_count = rule
        .word_count
        .as_ref()
        .and_then(|r| eval_field_html_doc_with_ctx(r, &doc, base_url, ctx));
    let toc_url = rule
        .toc_url
        .as_ref()
        .and_then(|r| eval_field_html_doc_with_ctx(r, &doc, base_url, ctx))
        .map(|u| resolve_url(base_url, &u));
    let can_re_name = rule
        .can_re_name
        .as_ref()
        .and_then(|r| eval_field_html_doc_with_ctx(r, &doc, base_url, ctx));
    let download_urls = rule
        .download_urls
        .as_ref()
        .and_then(|r| eval_field_html_doc_with_ctx(r, &doc, base_url, ctx));

    let final_toc_url = toc_url.or_else(|| Some(book_url.to_string()));

    Book {
        name,
        author,
        book_url: book_url.to_string(),
        origin: source.book_source_url.clone(),
        origin_name: Some(source.book_source_name.clone()),
        cover_url,
        toc_url: final_toc_url,
        intro,
        latest_chapter_title: last_chapter,
        word_count,
        info_html: None,
        toc_html: None,
        kind,
        update_time,
        can_re_name,
        download_urls,
        variable: ctx.book_variable(),
        ..Default::default()
    }
}

fn parse_book_info_xpath(
    source: &BookSource,
    body: &str,
    base_url: &str,
    rule: &BookInfoRule,
    book_url: &str,
    ctx: &mut RuleVariableContext,
) -> Book {
    let package = match html::parse_xpath_package(body) {
        Ok(p) => p,
        Err(_) => return parse_book_info_html(source, body, base_url, rule, book_url, ctx),
    };
    let document = package.as_document();
    let scope = select_xpath_scope(
        sxd_xpath::nodeset::Node::Root(document.root()),
        rule.init.as_deref(),
    );

    let name = eval_field_xpath_with_ctx(rule.name.as_deref().unwrap_or(""), scope, base_url, ctx)
        .unwrap_or_default();
    let author =
        eval_field_xpath_with_ctx(rule.author.as_deref().unwrap_or(""), scope, base_url, ctx)
            .unwrap_or_default();
    let intro =
        eval_field_xpath_with_ctx(rule.intro.as_deref().unwrap_or(""), scope, base_url, ctx);
    let kind = eval_field_xpath_with_ctx(rule.kind.as_deref().unwrap_or(""), scope, base_url, ctx);
    let last_chapter = eval_field_xpath_with_ctx(
        rule.last_chapter.as_deref().unwrap_or(""),
        scope,
        base_url,
        ctx,
    );
    let update_time = eval_field_xpath_with_ctx(
        rule.update_time.as_deref().unwrap_or(""),
        scope,
        base_url,
        ctx,
    );
    let cover_url = eval_field_xpath_with_ctx(
        rule.cover_url.as_deref().unwrap_or(""),
        scope,
        base_url,
        ctx,
    )
    .map(|u| resolve_url(base_url, &u));
    let word_count = eval_field_xpath_with_ctx(
        rule.word_count.as_deref().unwrap_or(""),
        scope,
        base_url,
        ctx,
    );
    let toc_url =
        eval_field_xpath_with_ctx(rule.toc_url.as_deref().unwrap_or(""), scope, base_url, ctx)
            .map(|u| resolve_url(base_url, &u));
    let can_re_name = eval_field_xpath_with_ctx(
        rule.can_re_name.as_deref().unwrap_or(""),
        scope,
        base_url,
        ctx,
    );
    let download_urls = eval_field_xpath_with_ctx(
        rule.download_urls.as_deref().unwrap_or(""),
        scope,
        base_url,
        ctx,
    );

    Book {
        name,
        author,
        book_url: book_url.to_string(),
        origin: source.book_source_url.clone(),
        origin_name: Some(source.book_source_name.clone()),
        cover_url,
        toc_url: toc_url.or_else(|| Some(book_url.to_string())),
        intro,
        latest_chapter_title: last_chapter,
        word_count,
        info_html: None,
        toc_html: None,
        kind,
        update_time,
        can_re_name,
        download_urls,
        variable: ctx.book_variable(),
        ..Default::default()
    }
}

fn parse_book_info_json(
    source: &BookSource,
    v: &Value,
    base_url: &str,
    rule: &BookInfoRule,
    book_url: &str,
    ctx: &mut RuleVariableContext,
) -> Book {
    let scope = select_json_scope(v, rule.init.as_deref(), base_url, ctx);
    let name = eval_field_json_with_ctx(rule.name.as_deref().unwrap_or(""), &scope, base_url, ctx)
        .unwrap_or_default();
    let author =
        eval_field_json_with_ctx(rule.author.as_deref().unwrap_or(""), &scope, base_url, ctx)
            .unwrap_or_default();
    let intro =
        eval_field_json_with_ctx(rule.intro.as_deref().unwrap_or(""), &scope, base_url, ctx);
    let kind = eval_field_json_with_ctx(rule.kind.as_deref().unwrap_or(""), &scope, base_url, ctx);
    let last_chapter = eval_field_json_with_ctx(
        rule.last_chapter.as_deref().unwrap_or(""),
        &scope,
        base_url,
        ctx,
    );
    let update_time = eval_field_json_with_ctx(
        rule.update_time.as_deref().unwrap_or(""),
        &scope,
        base_url,
        ctx,
    );
    let cover_url = eval_field_json_with_ctx(
        rule.cover_url.as_deref().unwrap_or(""),
        &scope,
        base_url,
        ctx,
    )
    .map(|u| resolve_url(base_url, &u));
    let word_count = eval_field_json_with_ctx(
        rule.word_count.as_deref().unwrap_or(""),
        &scope,
        base_url,
        ctx,
    );
    let toc_url =
        eval_field_json_with_ctx(rule.toc_url.as_deref().unwrap_or(""), &scope, base_url, ctx)
            .map(|u| resolve_url(base_url, &u));
    let can_re_name = eval_field_json_with_ctx(
        rule.can_re_name.as_deref().unwrap_or(""),
        &scope,
        base_url,
        ctx,
    );
    let download_urls = eval_field_json_with_ctx(
        rule.download_urls.as_deref().unwrap_or(""),
        &scope,
        base_url,
        ctx,
    );
    Book {
        name,
        author,
        book_url: book_url.to_string(),
        origin: source.book_source_url.clone(),
        origin_name: Some(source.book_source_name.clone()),
        cover_url,
        toc_url: toc_url.or_else(|| Some(book_url.to_string())),
        intro,
        latest_chapter_title: last_chapter,
        word_count,
        info_html: None,
        toc_html: None,
        kind,
        update_time,
        can_re_name,
        download_urls,
        variable: ctx.book_variable(),
        ..Default::default()
    }
}

fn parse_chapter_list_html(
    body: &str,
    base_url: &str,
    rule: &TocRule,
    list_sel: &str,
    ctx: &mut RuleVariableContext,
) -> (Vec<BookChapter>, Vec<String>) {
    if list_sel.trim().is_empty() {
        return (vec![], vec![]);
    }
    let doc = html::parse_document(body);

    // Execute init rule if present
    if let Some(init) = &rule.init {
        let _ = eval_field_html_doc_with_ctx(init, &doc, base_url, ctx);
    }

    let items = html::select_list(&doc, strip_mode_prefix(list_sel));

    // Use a set to deduplicate chapters by URL
    let mut seen_urls = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(items.len());

    for el in items {
        let mut chapter_ctx = ctx.for_chapter(None, "");
        let title = rule
            .chapter_name
            .as_ref()
            .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut chapter_ctx))
            .unwrap_or_default();
        chapter_ctx.chapter_title = Some(title.clone());
        let url = rule
            .chapter_url
            .as_ref()
            .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut chapter_ctx))
            .unwrap_or_default();
        let tag = rule
            .update_time
            .as_ref()
            .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut chapter_ctx));
        let is_volume = rule
            .is_volume
            .as_ref()
            .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut chapter_ctx))
            .map(is_truthy)
            .unwrap_or(false);
        let is_vip = rule
            .is_vip
            .as_ref()
            .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut chapter_ctx))
            .map(is_truthy)
            .unwrap_or(false);
        let is_pay = rule
            .is_pay
            .as_ref()
            .and_then(|r| eval_field_html_with_ctx(r, &el, base_url, &mut chapter_ctx))
            .map(is_truthy)
            .unwrap_or(false);
        let url_abs = finalize_chapter_url(base_url, &url, &title, is_volume, out.len());

        if seen_urls.contains(&url_abs) {
            continue;
        }
        seen_urls.insert(url_abs.clone());
        out.push(BookChapter {
            title,
            url: url_abs,
            index: out.len() as i32,
            tag,
            is_vip,
            is_pay,
            is_volume,
            variable: chapter_ctx.chapter_variable(),
        });
    }

    // Extract next_toc_url(s)
    let rule_str = rule.next_toc_url.as_deref().unwrap_or("");
    let raw_urls: Vec<String> = html::select_text_list(&doc, rule_str);
    let next_urls = normalize_toc_next_urls(base_url, raw_urls);

    (out, next_urls)
}

fn parse_chapter_list_xpath(
    body: &str,
    base_url: &str,
    rule: &TocRule,
    list_rule: &str,
    ctx: &mut RuleVariableContext,
) -> (Vec<BookChapter>, Vec<String>) {
    let package = match html::parse_xpath_package(body) {
        Ok(p) => p,
        Err(_) => return parse_chapter_list_html(body, base_url, rule, list_rule, ctx),
    };
    let document = package.as_document();
    let scope = select_xpath_scope(
        sxd_xpath::nodeset::Node::Root(document.root()),
        rule.init.as_deref(),
    );
    let items = xpath_select_nodes(scope, list_rule);

    let mut seen_urls = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let mut chapter_ctx = ctx.for_chapter(None, "");
        let title = eval_field_xpath_with_ctx(
            rule.chapter_name.as_deref().unwrap_or(""),
            item,
            base_url,
            &mut chapter_ctx,
        )
        .unwrap_or_default();
        chapter_ctx.chapter_title = Some(title.clone());
        let url = eval_field_xpath_with_ctx(
            rule.chapter_url.as_deref().unwrap_or(""),
            item,
            base_url,
            &mut chapter_ctx,
        )
        .unwrap_or_default();
        let tag = eval_field_xpath_with_ctx(
            rule.update_time.as_deref().unwrap_or(""),
            item,
            base_url,
            &mut chapter_ctx,
        );
        let is_volume = eval_field_xpath_with_ctx(
            rule.is_volume.as_deref().unwrap_or(""),
            item,
            base_url,
            &mut chapter_ctx,
        )
        .map(is_truthy)
        .unwrap_or(false);
        let is_vip = eval_field_xpath_with_ctx(
            rule.is_vip.as_deref().unwrap_or(""),
            item,
            base_url,
            &mut chapter_ctx,
        )
        .map(is_truthy)
        .unwrap_or(false);
        let is_pay = eval_field_xpath_with_ctx(
            rule.is_pay.as_deref().unwrap_or(""),
            item,
            base_url,
            &mut chapter_ctx,
        )
        .map(is_truthy)
        .unwrap_or(false);
        let url_abs = finalize_chapter_url(base_url, &url, &title, is_volume, out.len());
        if seen_urls.contains(&url_abs) {
            continue;
        }
        seen_urls.insert(url_abs.clone());
        out.push(BookChapter {
            title,
            url: url_abs,
            index: out.len() as i32,
            tag,
            is_vip,
            is_pay,
            is_volume,
            variable: chapter_ctx.chapter_variable(),
        });
    }

    let next_urls = rule
        .next_toc_url
        .as_deref()
        .map(|xpath| xpath_eval_strings(scope, xpath))
        .unwrap_or_default();
    let next_urls = normalize_toc_next_urls(base_url, next_urls);

    (out, next_urls)
}

fn parse_chapter_list_json(
    body: &str,
    base_url: &str,
    rule: &TocRule,
    list_rule: &str,
    ctx: &mut RuleVariableContext,
) -> (Vec<BookChapter>, Vec<String>) {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return (vec![], vec![]),
    };
    let scope = select_json_scope(&v, rule.init.as_deref(), base_url, ctx);
    let items = jsonpath::jsonpath_query(&scope, list_rule);

    let mut seen_urls = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let mut chapter_ctx = ctx.for_chapter(item.get("variable").and_then(Value::as_str), "");
        let title = eval_field_json_with_ctx(
            rule.chapter_name.as_deref().unwrap_or(""),
            &item,
            base_url,
            &mut chapter_ctx,
        )
        .unwrap_or_default();
        chapter_ctx.chapter_title = Some(title.clone());
        let url = eval_field_json_with_ctx(
            rule.chapter_url.as_deref().unwrap_or(""),
            &item,
            base_url,
            &mut chapter_ctx,
        )
        .unwrap_or_default();
        let tag = eval_field_json_with_ctx(
            rule.update_time.as_deref().unwrap_or(""),
            &item,
            base_url,
            &mut chapter_ctx,
        );
        let is_volume = eval_field_json_with_ctx(
            rule.is_volume.as_deref().unwrap_or(""),
            &item,
            base_url,
            &mut chapter_ctx,
        )
        .map(is_truthy)
        .unwrap_or(false);
        let is_vip = eval_field_json_with_ctx(
            rule.is_vip.as_deref().unwrap_or(""),
            &item,
            base_url,
            &mut chapter_ctx,
        )
        .map(is_truthy)
        .unwrap_or(false);
        let is_pay = eval_field_json_with_ctx(
            rule.is_pay.as_deref().unwrap_or(""),
            &item,
            base_url,
            &mut chapter_ctx,
        )
        .map(is_truthy)
        .unwrap_or(false);
        let url_abs = finalize_chapter_url(base_url, &url, &title, is_volume, out.len());

        if seen_urls.contains(&url_abs) {
            continue;
        }
        seen_urls.insert(url_abs.clone());

        out.push(BookChapter {
            title,
            url: url_abs,
            index: out.len() as i32,
            tag,
            is_vip,
            is_pay,
            is_volume,
            variable: chapter_ctx.chapter_variable(),
        });
    }

    let next_urls = rule
        .next_toc_url
        .as_ref()
        .map(|r| {
            jsonpath::jsonpath_query(&scope, r)
                .into_iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let next_urls = normalize_toc_next_urls(base_url, next_urls);

    (out, next_urls)
}

fn normalize_toc_next_urls(base_url: &str, urls: Vec<String>) -> Vec<String> {
    let current = normalized_url_identity(base_url);
    let mut seen = std::collections::HashSet::new();
    urls.into_iter()
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty())
        .map(|url| resolve_url(base_url, &url))
        .filter(|url| {
            let identity = normalized_url_identity(url);
            identity != current && seen.insert(identity)
        })
        .collect()
}

fn normalized_url_identity(url: &str) -> String {
    let normalized = normalize_source_url(url);
    match url::Url::parse(&normalized) {
        Ok(mut url) => {
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => normalized,
    }
}

fn select_json_scope(
    v: &Value,
    init_rule: Option<&str>,
    base_url: &str,
    ctx: &mut RuleVariableContext,
) -> Value {
    let Some(init_rule) = init_rule.map(str::trim).filter(|s| !s.is_empty()) else {
        return v.clone();
    };

    if direct_get_key(init_rule).is_some() {
        return v.clone();
    }
    let mut source_rule = SourceRule::compile(init_rule, ParseMode::JsonPath, true);
    evaluate_put_entries(&source_rule.put_entries, ctx, |put_rule, ctx| {
        eval_field_json_with_ctx(put_rule, v, base_url, ctx)
    });
    let interpolated = interpolate_json_templates(&source_rule.rule, v, base_url, ctx);
    source_rule.make_up_rule(&interpolated);
    let (pure, _) = extract_js(&source_rule.rule);
    if pure.is_empty() || source_rule.mode != ParseMode::JsonPath {
        return v.clone();
    }

    jsonpath::jsonpath_query(v, pure)
        .into_iter()
        .next()
        .unwrap_or_else(|| v.clone())
}

fn pick_json_field(v: &Value, rule: Option<&str>) -> Option<String> {
    let rule = rule?;
    if rule.trim_start().starts_with('$') {
        return jsonpath::jsonpath_first_string(v, rule);
    }
    if let Some(obj) = v.as_object() {
        if let Some(val) = obj.get(rule) {
            return jsonpath::value_to_string(val);
        }
    }
    None
}

pub(crate) fn resolve_url(base: &str, url: &str) -> String {
    let base = normalize_source_url(base);
    let url = normalize_source_url(strip_url_config(url));

    if url.is_empty() {
        return base.to_string();
    }
    if url.starts_with("http://") || url.starts_with("https://") {
        return url.to_string();
    }
    if url.starts_with("//") {
        return format!("https:{}", url);
    }

    let mut base_url = match url::Url::parse(&base) {
        Ok(u) => u,
        Err(_) => return url.to_string(),
    };
    base_url.set_fragment(None);

    match base_url.join(&url) {
        Ok(u) => u.to_string(),
        Err(_) => {
            let base = base.trim_end_matches('/');
            format!("{}/{}", base, url.trim_start_matches('/'))
        }
    }
}

fn extract_put_entries(rule: &str) -> (String, Vec<PutEntry>) {
    let lower = rule.to_ascii_lowercase();
    let mut output = String::with_capacity(rule.len());
    let mut entries = Vec::new();
    let mut cursor = 0;

    while let Some(relative) = lower[cursor..].find("@put:") {
        let marker = cursor + relative;
        let object_start = marker + "@put:".len();
        if !rule[object_start..].starts_with('{') {
            output.push_str(&rule[cursor..object_start]);
            cursor = object_start;
            continue;
        }
        let Some(object_end) = find_put_object_end(rule, object_start) else {
            output.push_str(&rule[cursor..]);
            return (output, entries);
        };

        output.push_str(&rule[cursor..marker]);
        entries.extend(parse_put_entries(&rule[object_start..=object_end]));
        cursor = object_end + 1;
    }

    output.push_str(&rule[cursor..]);
    (output, entries)
}

fn find_put_object_end(rule: &str, open: usize) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in rule[open + 1..].char_indices() {
        let index = open + 1 + index;
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
            '}' => return Some(index),
            _ => {}
        }
    }
    None
}

fn parse_put_entries(object: &str) -> Vec<PutEntry> {
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(object) {
        return map
            .into_iter()
            .filter_map(|(key, value)| {
                let value_rule = match value {
                    Value::String(value) => value,
                    Value::Object(_) | Value::Array(_) | Value::Null => return None,
                    value => value.to_string(),
                };
                Some(PutEntry { key, value_rule })
            })
            .collect();
    }

    let Some(inner) = object.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
        return Vec::new();
    };
    rule_analyzer::split_top_level(inner, &[","])
        .parts
        .into_iter()
        .filter_map(|part| {
            let pair = rule_analyzer::split_top_level(&part, &[":"]);
            if pair.parts.len() < 2 {
                return None;
            }
            let key = pair.parts[0].trim().trim_matches(['\'', '"']).to_string();
            let value_rule = pair.parts[1..].join(":");
            (!key.is_empty()).then_some(PutEntry {
                key,
                value_rule: unquote_put_value(&value_rule),
            })
        })
        .collect()
}

fn unquote_put_value(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let quote = value.as_bytes()[0] as char;
        if matches!(quote, '\'' | '"') && value.ends_with(quote) {
            let inner = &value[1..value.len() - 1];
            if quote == '"' {
                return serde_json::from_str::<String>(value).unwrap_or_else(|_| inner.to_string());
            }
            return inner.replace("\\'", "'").replace("\\\\", "\\");
        }
    }
    value.to_string()
}

fn interpolate_json_templates(
    rule: &str,
    v: &Value,
    base_url: &str,
    ctx: &RuleVariableContext,
) -> String {
    let input = serde_json::to_string(v).unwrap_or_default();
    interpolate_templates(rule, &input, base_url, ctx, Some(v))
}

fn interpolate_common_templates(
    rule: &str,
    input: &str,
    base_url: &str,
    ctx: &RuleVariableContext,
) -> String {
    interpolate_templates(rule, input, base_url, ctx, None)
}

fn interpolate_templates(
    rule: &str,
    input: &str,
    base_url: &str,
    ctx: &RuleVariableContext,
    json_value: Option<&Value>,
) -> String {
    let mut output = String::with_capacity(rule.len());
    let mut cursor = 0;
    while cursor < rule.len() {
        let remaining = &rule[cursor..];
        if let Some(expression) = remaining.strip_prefix("{{") {
            if let Some(end) = find_template_close(expression) {
                output.push_str(&evaluate_template_expression(
                    expression[..end].trim(),
                    input,
                    base_url,
                    ctx,
                    json_value,
                ));
                cursor += 2 + end + 2;
                continue;
            }
        }
        if let Some(key_and_rest) = remaining.strip_prefix("@get:{") {
            if let Some(end) = key_and_rest.find('}') {
                let key = key_and_rest[..end].trim();
                output.push_str(&ctx.get(key).unwrap_or_default());
                cursor += "@get:{".len() + end + 1;
                continue;
            }
        }
        let ch = remaining.chars().next().expect("cursor remains in string");
        output.push(ch);
        cursor += ch.len_utf8();
    }
    output
}

fn find_template_close(expression: &str) -> Option<usize> {
    let mut brace_depth = 0;
    for (index, ch) in expression.char_indices() {
        match ch {
            '{' => brace_depth += 1,
            '}' if brace_depth > 0 => brace_depth -= 1,
            '}' if expression[index..].starts_with("}}") => return Some(index),
            _ => {}
        }
    }
    None
}

fn evaluate_template_expression(
    expression: &str,
    input: &str,
    base_url: &str,
    ctx: &RuleVariableContext,
    json_value: Option<&Value>,
) -> String {
    if expression.is_empty() {
        return String::new();
    }
    if let Some(key) = expression
        .strip_prefix("@get:{")
        .and_then(|value| value.strip_suffix('}'))
    {
        return ctx.get(key.trim()).unwrap_or_default();
    }
    if let Some(value) = ctx.get(expression) {
        return value;
    }
    if expression.starts_with("$.") || expression.starts_with("$[") {
        let parsed;
        let value = if let Some(value) = json_value {
            value
        } else {
            parsed = serde_json::from_str::<Value>(input).ok();
            let Some(value) = parsed.as_ref() else {
                return String::new();
            };
            value
        };
        return pick_json_field(value, Some(expression)).unwrap_or_default();
    }
    if expression.starts_with("//") || starts_with_ascii_case(expression, "@xpath:") {
        let xpath = strip_prefix_ascii_case(expression, "@xpath:").unwrap_or(expression);
        return html::select_xpath(input, xpath)
            .into_iter()
            .next()
            .unwrap_or_default();
    }
    if starts_with_ascii_case(expression, "@css:") {
        let selector = strip_prefix_ascii_case(expression, "@css:").unwrap_or(expression);
        return html::select_text(&html::parse_document(input), selector).unwrap_or_default();
    }
    if starts_with_ascii_case(expression, "@json:") {
        let path = strip_prefix_ascii_case(expression, "@json:").unwrap_or(expression);
        let parsed;
        let value = if let Some(value) = json_value {
            value
        } else {
            parsed = serde_json::from_str::<Value>(input).ok();
            let Some(value) = parsed.as_ref() else {
                return String::new();
            };
            value
        };
        return pick_json_field(value, Some(path)).unwrap_or_default();
    }
    if let Some(script) = strip_prefix_ascii_case(expression, "@js:") {
        return eval_js_template_with_bindings(script, input, base_url, &ctx.js_bindings())
            .unwrap_or_default();
    }
    if let Some(pattern) = strip_prefix_ascii_case(expression, "@regex:") {
        let rows = regex_capture_rows(pattern, input);
        return rows
            .first()
            .and_then(|row| row.get(1).or_else(|| row.first()))
            .and_then(Clone::clone)
            .unwrap_or_default();
    }
    if expression.starts_with('@') {
        return ctx
            .get(expression.trim_start_matches('@'))
            .unwrap_or_default();
    }
    eval_js_template_with_bindings(expression, input, base_url, &ctx.js_bindings())
        .unwrap_or_default()
}

fn strip_url_config(url: &str) -> &str {
    if let Some(idx) = url.find("##$##") {
        &url[..idx]
    } else if let Some(idx) = url.find(",{'webView'") {
        &url[..idx]
    } else if let Some(idx) = url.find(",{\"webView\"") {
        &url[..idx]
    } else {
        url
    }
}

fn extract_js(rule: &str) -> (&str, Option<&str>) {
    if let Some(idx) = rule.find("<js>") {
        if let Some(end_idx) = rule.rfind("</js>") {
            if end_idx > idx {
                let pure = rule[..idx].trim();
                let js = &rule[idx + 4..end_idx];
                return (pure, Some(js));
            }
        }
    }
    if let Some(idx) = find_ascii_case(rule, "@js:") {
        let pure = rule[..idx].trim();
        let js = &rule[idx + 4..];
        return (pure, Some(js));
    }
    (rule, None)
}

fn direct_get_key(rule: &str) -> Option<&str> {
    rule.trim()
        .strip_prefix("@get:{")
        .and_then(|value| value.strip_suffix('}'))
        .map(str::trim)
}

fn evaluate_put_entries(
    entries: &[PutEntry],
    ctx: &mut RuleVariableContext,
    mut evaluate: impl FnMut(&str, &mut RuleVariableContext) -> Option<String>,
) {
    for entry in entries {
        let value = evaluate(&entry.value_rule, ctx).unwrap_or_default();
        ctx.insert(entry.key.clone(), value);
    }
}

fn eval_field_html_with_ctx(
    rule: &str,
    el: &scraper::ElementRef,
    base_url: &str,
    ctx: &mut RuleVariableContext,
) -> Option<String> {
    if let Some(key) = direct_get_key(rule) {
        return ctx.get(key);
    }
    let input = html::extract_text(el, "textNodes").unwrap_or_default();
    let mut source_rule = SourceRule::compile(rule, ParseMode::Css, false);
    evaluate_put_entries(&source_rule.put_entries, ctx, |put_rule, ctx| {
        eval_field_html_with_ctx(put_rule, el, base_url, ctx)
    });
    let expanded = interpolate_common_templates(&source_rule.rule, &input, base_url, ctx);
    let had_templates = expanded != source_rule.rule;
    source_rule.make_up_rule(&expanded);
    let (pure, js) = extract_js(&source_rule.rule);

    let mut text = match source_rule.mode {
        ParseMode::Css => {
            if pure.is_empty() {
                String::new()
            } else {
                html::select_text_from_element(el, pure).unwrap_or_default()
            }
        }
        ParseMode::XPath => html::select_xpath(&el.html(), pure)
            .into_iter()
            .next()
            .unwrap_or_default(),
        ParseMode::Regex => {
            let rows = regex_capture_rows(pure.trim_start_matches(':').trim(), &input);
            rows.first()
                .and_then(|row| row.get(1).or_else(|| row.first()))
                .and_then(Clone::clone)
                .unwrap_or_default()
        }
        ParseMode::Js => {
            eval_js_with_bindings(strip_js_rule(pure), &input, base_url, &ctx.js_bindings())
                .unwrap_or_default()
        }
        ParseMode::JsonPath => String::new(),
    };
    if text.is_empty() && had_templates && source_rule.mode == ParseMode::Css && !pure.is_empty() {
        text = pure.to_string();
    }
    if let Some(script) = js {
        if let Ok(result) = eval_js_with_bindings(script, &text, base_url, &ctx.js_bindings()) {
            text = result;
        }
    }
    text = source_rule.apply_replacement(&text);
    (!text.is_empty()).then_some(text)
}

fn eval_field_html_doc_with_ctx(
    rule: &str,
    doc: &scraper::Html,
    base_url: &str,
    ctx: &mut RuleVariableContext,
) -> Option<String> {
    if let Some(key) = direct_get_key(rule) {
        return ctx.get(key);
    }
    let input = doc.html();
    let mut source_rule = SourceRule::compile(rule, ParseMode::Css, false);
    evaluate_put_entries(&source_rule.put_entries, ctx, |put_rule, ctx| {
        eval_field_html_doc_with_ctx(put_rule, doc, base_url, ctx)
    });
    let expanded = interpolate_common_templates(&source_rule.rule, &input, base_url, ctx);
    let had_templates = expanded != source_rule.rule;
    source_rule.make_up_rule(&expanded);
    let (pure, js) = extract_js(&source_rule.rule);

    let mut text = match source_rule.mode {
        ParseMode::Css => html::select_text(doc, pure).unwrap_or_default(),
        ParseMode::XPath => html::select_xpath(&input, pure)
            .first()
            .cloned()
            .unwrap_or_default(),
        ParseMode::Regex => {
            let rows = regex_capture_rows(pure.trim_start_matches(':').trim(), &input);
            rows.first()
                .and_then(|row| row.get(1).or_else(|| row.first()))
                .and_then(Clone::clone)
                .unwrap_or_default()
        }
        ParseMode::Js => {
            eval_js_with_bindings(strip_js_rule(pure), &input, base_url, &ctx.js_bindings())
                .unwrap_or_default()
        }
        ParseMode::JsonPath => String::new(),
    };
    if text.is_empty() && had_templates && source_rule.mode == ParseMode::Css && !pure.is_empty() {
        text = pure.to_string();
    }
    if let Some(script) = js {
        if let Ok(result) = eval_js_with_bindings(script, &text, base_url, &ctx.js_bindings()) {
            text = result;
        }
    }
    text = source_rule.apply_replacement(&text);
    (!text.is_empty()).then_some(text)
}

fn eval_field_xpath_with_ctx(
    rule: &str,
    node: sxd_xpath::nodeset::Node<'_>,
    base_url: &str,
    ctx: &mut RuleVariableContext,
) -> Option<String> {
    if let Some(key) = direct_get_key(rule) {
        return ctx.get(key);
    }
    let input = node.string_value();
    let mut source_rule = SourceRule::compile(rule, ParseMode::XPath, false);
    evaluate_put_entries(&source_rule.put_entries, ctx, |put_rule, ctx| {
        eval_field_xpath_with_ctx(put_rule, node, base_url, ctx)
    });
    let expanded = interpolate_common_templates(&source_rule.rule, &input, base_url, ctx);
    let had_templates = expanded != source_rule.rule;
    source_rule.make_up_rule(&expanded);
    let (pure, js) = extract_js(&source_rule.rule);

    let mut text = match source_rule.mode {
        ParseMode::XPath if pure.trim().is_empty() => input.clone(),
        ParseMode::XPath => xpath_eval_strings(node, pure)
            .into_iter()
            .next()
            .unwrap_or_default(),
        ParseMode::Regex => {
            let rows = regex_capture_rows(pure.trim_start_matches(':').trim(), &input);
            rows.first()
                .and_then(|row| row.get(1).or_else(|| row.first()))
                .and_then(Clone::clone)
                .unwrap_or_default()
        }
        ParseMode::Js => {
            eval_js_with_bindings(strip_js_rule(pure), &input, base_url, &ctx.js_bindings())
                .unwrap_or_default()
        }
        ParseMode::Css => {
            let doc = html::parse_document(&input);
            html::select_text(&doc, pure).unwrap_or_default()
        }
        ParseMode::JsonPath => String::new(),
    };
    if text.is_empty() && had_templates && !pure.is_empty() {
        text = pure.to_string();
    }
    if let Some(script) = js {
        if let Ok(result) = eval_js_with_bindings(script, &text, base_url, &ctx.js_bindings()) {
            text = result;
        }
    }
    text = source_rule.apply_replacement(&text);
    (!text.is_empty()).then_some(text)
}

fn select_xpath_scope<'a>(
    node: sxd_xpath::nodeset::Node<'a>,
    init_rule: Option<&str>,
) -> sxd_xpath::nodeset::Node<'a> {
    let Some(init_rule) = init_rule.map(str::trim).filter(|s| !s.is_empty()) else {
        return node;
    };
    xpath_select_nodes(node, init_rule)
        .into_iter()
        .next()
        .unwrap_or(node)
}

fn xpath_select_nodes<'a>(
    node: sxd_xpath::nodeset::Node<'a>,
    xpath: &str,
) -> Vec<sxd_xpath::nodeset::Node<'a>> {
    let xpath = xpath.trim();
    if xpath.is_empty() {
        return vec![];
    }
    let context = XPathContext::new();
    match XPathFactory::new().build(xpath) {
        Ok(Some(expr)) => match expr.evaluate(&context, node) {
            Ok(XPathValue::Nodeset(ns)) => ns.document_order(),
            _ => vec![],
        },
        _ => vec![],
    }
}

fn xpath_eval_strings(node: sxd_xpath::nodeset::Node<'_>, xpath: &str) -> Vec<String> {
    let xpath = xpath.trim();
    if xpath.is_empty() {
        return vec![];
    }
    let context = XPathContext::new();
    match XPathFactory::new().build(xpath) {
        Ok(Some(expr)) => match expr.evaluate(&context, node) {
            Ok(XPathValue::Nodeset(ns)) => ns
                .document_order()
                .into_iter()
                .map(|n| n.string_value())
                .collect(),
            Ok(XPathValue::String(s)) => vec![s],
            Ok(XPathValue::Number(n)) => vec![n.to_string()],
            Ok(XPathValue::Boolean(b)) => vec![b.to_string()],
            Err(_) => vec![],
        },
        _ => vec![],
    }
}

fn eval_field_json_with_ctx(
    rule: &str,
    v: &Value,
    base_url: &str,
    ctx: &mut RuleVariableContext,
) -> Option<String> {
    if let Some(key) = direct_get_key(rule) {
        return ctx.get(key);
    }
    let input = serde_json::to_string(v).unwrap_or_default();
    let mut source_rule = SourceRule::compile(rule, ParseMode::JsonPath, true);
    evaluate_put_entries(&source_rule.put_entries, ctx, |put_rule, ctx| {
        eval_field_json_with_ctx(put_rule, v, base_url, ctx)
    });
    let expanded = interpolate_json_templates(&source_rule.rule, v, base_url, ctx);
    source_rule.make_up_rule(&expanded);
    let (pure, js) = extract_js(&source_rule.rule);

    let mut text = match source_rule.mode {
        ParseMode::JsonPath => {
            if pure.is_empty() {
                String::new()
            } else if pure.contains('/')
                || pure.contains('?')
                || pure.contains('&')
                || pure.contains('=')
                || pure.contains(',')
            {
                pure.to_string()
            } else {
                pick_json_field(v, Some(pure)).unwrap_or_default()
            }
        }
        ParseMode::Regex => {
            let rows = regex_capture_rows(pure.trim_start_matches(':').trim(), &input);
            rows.first()
                .and_then(|row| row.get(1).or_else(|| row.first()))
                .and_then(Clone::clone)
                .unwrap_or_default()
        }
        ParseMode::Js => {
            eval_js_with_bindings(strip_js_rule(pure), &input, base_url, &ctx.js_bindings())
                .unwrap_or_default()
        }
        ParseMode::XPath => html::select_xpath(&input, pure)
            .first()
            .cloned()
            .unwrap_or_default(),
        ParseMode::Css => {
            let doc = html::parse_document(&input);
            html::select_text(&doc, pure).unwrap_or_default()
        }
    };
    if let Some(script) = js {
        if let Ok(result) = eval_js_with_bindings(script, &text, base_url, &ctx.js_bindings()) {
            text = result;
        }
    }
    text = source_rule.apply_replacement(&text);
    (!text.is_empty()).then_some(text)
}

pub(crate) fn split_legado_regex(rule: &str) -> (String, Option<&str>) {
    if let Some(idx) = rule.find("##") {
        let (pure, reg) = rule.split_at(idx);
        return (pure.trim().to_string(), Some(reg));
    }
    (rule.to_string(), None)
}

pub fn apply_legado_regex(text: &str, regex_part: &str) -> String {
    let regex_part = regex_part.trim();
    let Some(steps) = regex_part.strip_prefix("##") else {
        return text.to_string();
    };
    let first_only = steps.ends_with("###");
    let steps = steps.strip_suffix("###").unwrap_or(steps);
    let parts = steps.split("##").collect::<Vec<_>>();
    if parts.first().is_some_and(|pattern| pattern.is_empty()) {
        return text.to_string();
    }

    let mut output = text.to_string();
    let mut index = 0;
    while index < parts.len() {
        let pattern = parts[index];
        if pattern.is_empty() {
            index += 1;
            continue;
        }
        let replacement = parts.get(index + 1).copied().unwrap_or_default();
        let is_last = index + 2 >= parts.len();
        output = if first_only && is_last {
            apply_regex_replace_first(&output, pattern, replacement)
        } else {
            apply_regex_replace_all(&output, pattern, replacement)
        };
        index += 2;
    }
    output
}

fn apply_content_replacement(
    content: String,
    rule: Option<&str>,
    input: &str,
    base_url: &str,
    context: &RuleVariableContext,
) -> String {
    let Some(rule) = rule else {
        return content;
    };
    let rule = interpolate_common_templates(rule, input, base_url, context);
    apply_legado_regex(&content, &rule)
}

fn apply_regex_replace_all(text: &str, pattern: &str, replacement: &str) -> String {
    crate::util::text::get_cached_regex(pattern)
        .map(|regex| regex.replace_all(text, replacement).into_owned())
        .unwrap_or_else(|| text.replace(pattern, replacement))
}

fn apply_regex_replace_first(text: &str, pattern: &str, replacement: &str) -> String {
    let Some(regex) = crate::util::text::get_cached_regex(pattern) else {
        return replacement.to_string();
    };
    let Some(found) = regex.find(text) else {
        return String::new();
    };
    regex
        .replace(&text[found.start()..found.end()], replacement)
        .into_owned()
}

fn normalize_list_rule(rule: &str) -> (&str, bool) {
    let rule = rule.trim();
    if let Some(rest) = rule.strip_prefix('-') {
        return (rest.trim(), true);
    }
    if let Some(rest) = rule.strip_prefix('+') {
        return (rest.trim(), false);
    }
    (rule, false)
}

fn strip_mode_prefix(rule: &str) -> &str {
    let rule = rule.trim();
    if let Some(rest) = rule
        .strip_prefix("<js>")
        .and_then(|value| value.strip_suffix("</js>"))
    {
        return rest;
    }
    if let Some(rest) = rule.strip_prefix("@@") {
        return rest;
    }
    for prefix in ["@css:", "@xpath:", "@json:", "@regex:", "@js:", "js:"] {
        if let Some(rest) = strip_prefix_ascii_case(rule, prefix) {
            return rest;
        }
    }
    rule
}

pub(crate) fn strip_js_rule(rule: &str) -> &str {
    let rule = rule.trim();
    if let Some(rest) = rule
        .strip_prefix("<js>")
        .and_then(|value| value.strip_suffix("</js>"))
    {
        return rest;
    }
    strip_prefix_ascii_case(rule, "@js:")
        .or_else(|| strip_prefix_ascii_case(rule, "js:"))
        .unwrap_or(rule)
}

fn prepare_toc_body(
    body: &str,
    base_url: &str,
    rule: &TocRule,
    ctx: &RuleVariableContext,
) -> String {
    let Some(script) = rule
        .pre_update_js
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    else {
        return body.to_string();
    };
    match eval_js_with_bindings(strip_js_rule(script), body, base_url, &ctx.js_bindings()) {
        Ok(result) if !result.trim().is_empty() => result,
        _ => body.to_string(),
    }
}

fn apply_toc_format_js(
    chapters: &mut [BookChapter],
    format_js: Option<&str>,
    base_url: &str,
    ctx: &RuleVariableContext,
) {
    let Some(script) = format_js.filter(|s| !s.trim().is_empty()) else {
        return;
    };
    let script = strip_js_rule(script);
    for (index, chapter) in chapters.iter_mut().enumerate() {
        let chapter_ctx = ctx.for_chapter(chapter.variable.as_deref(), &chapter.title);
        let mut bindings = chapter_ctx.js_bindings();
        bindings.insert("index".to_string(), json!(index + 1));
        let mut chapter_value = serde_json::to_value(&*chapter).unwrap_or_else(|_| json!({}));
        if let Value::Object(fields) = &mut chapter_value {
            fields.insert(
                "variableMap".to_string(),
                json!(parse_variable_map(chapter.variable.as_deref())),
            );
        }
        bindings.insert("chapter".to_string(), chapter_value);
        if let Ok(result) = eval_js_with_bindings(script, &chapter.title, base_url, &bindings) {
            if !result.trim().is_empty() {
                chapter.title = result;
            }
        }
    }
}

fn parse_js_output_items(output: &str) -> Option<Vec<Value>> {
    let value = serde_json::from_str::<Value>(output.trim()).ok()?;
    match value {
        Value::Array(items) => Some(items),
        Value::Object(_) => Some(vec![value]),
        _ => None,
    }
}

fn has_book_url_pattern(pattern: Option<&str>) -> bool {
    pattern
        .map(str::trim)
        .is_some_and(|pattern| !pattern.is_empty() && !pattern.eq_ignore_ascii_case("NONE"))
}

fn book_url_pattern_matches(pattern: Option<&str>, url: &str) -> bool {
    let Some(pattern) = pattern
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty() && !pattern.eq_ignore_ascii_case("NONE"))
    else {
        return false;
    };
    let anchored = format!(r"\A(?:{pattern})\z");
    crate::util::text::get_cached_regex(&anchored).is_some_and(|regex| regex.is_match(url))
}

fn dedupe_search_books(books: &mut Vec<SearchBook>) {
    let mut seen = std::collections::HashSet::new();
    books.retain(|book| seen.insert((book.origin.clone(), book.book_url.clone())));
}

fn search_book_from_book(book: Book) -> Option<SearchBook> {
    if book.name.trim().is_empty() {
        return None;
    }
    Some(SearchBook {
        name: book.name,
        author: book.author,
        book_url: book.book_url,
        origin: book.origin,
        cover_url: book.cover_url,
        intro: book.intro,
        kind: book.kind,
        last_chapter: book.latest_chapter_title,
        update_time: book.update_time,
        word_count: book.word_count,
        variable: book.variable,
        book_source_urls: None,
    })
}

fn build_search_book_from_json(
    source: &BookSource,
    item: &Value,
    base_url: &str,
    rule: &SearchRule,
    ctx: &mut RuleVariableContext,
) -> Option<SearchBook> {
    let name = eval_field_json_with_ctx(rule.name.as_deref().unwrap_or(""), item, base_url, ctx)
        .unwrap_or_default();
    if name.is_empty() {
        return None;
    }
    let author =
        eval_field_json_with_ctx(rule.author.as_deref().unwrap_or(""), item, base_url, ctx)
            .unwrap_or_default();
    let book_url =
        eval_field_json_with_ctx(rule.book_url.as_deref().unwrap_or(""), item, base_url, ctx)
            .unwrap_or_default();
    let cover_url =
        eval_field_json_with_ctx(rule.cover_url.as_deref().unwrap_or(""), item, base_url, ctx)
            .map(|u| resolve_url(base_url, &u));
    let intro = eval_field_json_with_ctx(rule.intro.as_deref().unwrap_or(""), item, base_url, ctx);
    let kind = eval_field_json_with_ctx(rule.kind.as_deref().unwrap_or(""), item, base_url, ctx);
    let last_chapter = eval_field_json_with_ctx(
        rule.last_chapter.as_deref().unwrap_or(""),
        item,
        base_url,
        ctx,
    );
    let update_time = eval_field_json_with_ctx(
        rule.update_time.as_deref().unwrap_or(""),
        item,
        base_url,
        ctx,
    );
    let word_count = eval_field_json_with_ctx(
        rule.word_count.as_deref().unwrap_or(""),
        item,
        base_url,
        ctx,
    );
    Some(SearchBook {
        name,
        author,
        book_url: resolve_url(base_url, &book_url),
        origin: source.book_source_url.clone(),
        cover_url,
        intro,
        kind,
        last_chapter,
        update_time,
        word_count,
        variable: ctx.book_variable(),
        book_source_urls: None,
    })
}

fn build_chapter_from_json(
    item: &Value,
    base_url: &str,
    rule: &TocRule,
    ctx: &mut RuleVariableContext,
    index: usize,
) -> Option<BookChapter> {
    let title = eval_field_json_with_ctx(
        rule.chapter_name.as_deref().unwrap_or(""),
        item,
        base_url,
        ctx,
    )
    .unwrap_or_default();
    if title.is_empty() {
        return None;
    }
    ctx.chapter_title = Some(title.clone());
    let raw_url = eval_field_json_with_ctx(
        rule.chapter_url.as_deref().unwrap_or(""),
        item,
        base_url,
        ctx,
    )
    .unwrap_or_default();
    let tag = eval_field_json_with_ctx(
        rule.update_time.as_deref().unwrap_or(""),
        item,
        base_url,
        ctx,
    );
    let is_volume =
        eval_field_json_with_ctx(rule.is_volume.as_deref().unwrap_or(""), item, base_url, ctx)
            .map(is_truthy)
            .unwrap_or(false);
    let is_vip =
        eval_field_json_with_ctx(rule.is_vip.as_deref().unwrap_or(""), item, base_url, ctx)
            .map(is_truthy)
            .unwrap_or(false);
    let is_pay =
        eval_field_json_with_ctx(rule.is_pay.as_deref().unwrap_or(""), item, base_url, ctx)
            .map(is_truthy)
            .unwrap_or(false);
    Some(BookChapter {
        title: title.clone(),
        url: finalize_chapter_url(base_url, &raw_url, &title, is_volume, index),
        index: index as i32,
        tag,
        is_vip,
        is_pay,
        is_volume,
        variable: ctx.chapter_variable(),
    })
}

fn regex_capture_rows(rule: &str, input: &str) -> Vec<Vec<Option<String>>> {
    let patterns = rule_analyzer::split_top_level(rule, &["&&"]).parts;
    let mut inputs = vec![input.to_string()];

    for (stage, pattern) in patterns.iter().enumerate() {
        let pattern = pattern.trim().trim_start_matches(':').trim();
        let pattern = strip_prefix_ascii_case(pattern, "@regex:").unwrap_or(pattern);
        let Some(regex) = crate::util::text::get_cached_regex(pattern.trim()) else {
            return Vec::new();
        };

        if stage + 1 == patterns.len() {
            return inputs
                .iter()
                .flat_map(|input| {
                    regex.captures_iter(input).map(|captures| {
                        (0..captures.len())
                            .map(|index| {
                                captures.get(index).map(|value| value.as_str().to_string())
                            })
                            .collect()
                    })
                })
                .collect();
        }

        inputs = inputs
            .iter()
            .flat_map(|input| {
                regex
                    .captures_iter(input)
                    .filter_map(|captures| captures.get(0).map(|value| value.as_str().to_string()))
                    .collect::<Vec<_>>()
            })
            .collect();
        if inputs.is_empty() {
            return Vec::new();
        }
    }
    Vec::new()
}

fn capture_rule_values_with_ctx(
    rule: Option<&str>,
    captures: &[Option<String>],
    context: &mut RuleVariableContext,
) -> Option<String> {
    let rule = rule?;
    let (rule, entries) = extract_put_entries(rule);
    evaluate_put_entries(&entries, context, |value_rule, _| {
        capture_rule_values(Some(value_rule), captures)
    });
    capture_rule_values(Some(&rule), captures)
}

fn capture_rule_values(rule: Option<&str>, captures: &[Option<String>]) -> Option<String> {
    let rule = rule?.trim();
    if rule.is_empty() {
        return None;
    }
    let placeholder = regex::Regex::new(r"\$(\d{1,2})").expect("valid capture placeholder");
    let replaced = placeholder.replace_all(rule, |cap: &regex::Captures| {
        let index = cap
            .get(1)
            .and_then(|value| value.as_str().parse::<usize>().ok())
            .unwrap_or(0);
        if index == 0 {
            return cap[0].to_string();
        }
        captures
            .get(index)
            .and_then(Option::as_deref)
            .map(str::to_string)
            .unwrap_or_else(|| cap[0].to_string())
    });
    let (pure, regex_part) = split_legado_regex(&replaced);
    let output = regex_part
        .map(|replacement| apply_legado_regex(&pure, replacement))
        .unwrap_or(pure);
    (!output.is_empty()).then_some(output)
}

fn finalize_chapter_url(
    base_url: &str,
    raw_url: &str,
    title: &str,
    is_volume: bool,
    index: usize,
) -> String {
    if !raw_url.trim().is_empty() {
        return resolve_url(base_url, raw_url);
    }
    if is_volume {
        return format!("{}{}", title, index);
    }
    base_url.to_string()
}

fn is_truthy(value: String) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    !matches!(
        value.to_ascii_lowercase().as_str(),
        "0" | "false" | "null" | "none" | "no" | "not" | "off"
    )
}

/// Extract chapter number from title
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::book_source::BookSource;
    use crate::model::rule::{BookInfoRule, ContentRule, SearchRule, TocRule};
    use crate::parser::js::eval_js;

    #[test]
    fn test_detect_mode() {
        let engine = RuleEngine::new().unwrap();

        assert_eq!(engine.detect_mode("@css:.test", ""), ParseMode::Css);
        assert_eq!(engine.detect_mode("@xpath://div", ""), ParseMode::XPath);
        assert_eq!(engine.detect_mode("$.data.list", ""), ParseMode::JsonPath);
        assert_eq!(engine.detect_mode("/html/body/div", ""), ParseMode::XPath);
        assert_eq!(engine.detect_mode(".class", ""), ParseMode::Css);
        assert_eq!(engine.detect_mode("js:return 1", ""), ParseMode::Js);
        assert_eq!(engine.detect_mode("<js>return 1</js>", ""), ParseMode::Js);
    }

    #[test]
    fn xpath_book_info_uses_tolerant_fragment_parser() {
        let source = BookSource {
            book_source_name: "XPath".to_string(),
            book_source_url: "https://source.example".to_string(),
            ..Default::default()
        };
        let rule = BookInfoRule {
            name: Some("//name/text()".to_string()),
            author: Some("//author/text()".to_string()),
            ..Default::default()
        };
        let mut ctx = RuleVariableContext::for_book(None, None);
        let book = parse_book_info_xpath(
            &source,
            "<name>Book&nbsp;Title</name><author>Writer</author>",
            "https://books.example/detail/1",
            &rule,
            "https://books.example/detail/1",
            &mut ctx,
        );

        assert_eq!(book.name, "Book\u{00a0}Title");
        assert_eq!(book.author, "Writer");
    }

    #[test]
    fn xpath_toc_uses_tolerant_fragment_parser() {
        let rule = TocRule {
            chapter_list: Some("//chapter".to_string()),
            chapter_name: Some("./name/text()".to_string()),
            chapter_url: Some("./url/text()".to_string()),
            ..Default::default()
        };
        let body = "<chapter><name>One&nbsp;Chapter</name><url>/1</url></chapter><chapter><name>Two</name><url>/2</url></chapter>";
        let (chapters, next_urls) = parse_chapter_list_xpath(
            body,
            "https://books.example/toc",
            &rule,
            "//chapter",
            &mut RuleVariableContext::default(),
        );

        assert!(next_urls.is_empty());
        assert_eq!(chapters.len(), 2);
        assert_eq!(chapters[0].title, "One\u{00a0}Chapter");
        assert_eq!(chapters[0].url, "https://books.example/1");
        assert_eq!(chapters[1].title, "Two");
    }

    #[test]
    fn compat_all_in_one_regex_exposes_groups_and_keeps_group_zero_literal() {
        let source = BookSource {
            book_source_name: "Regex compatibility".to_string(),
            book_source_url: "https://regex.example".to_string(),
            rule_search: Some(SearchRule {
                book_list: Some(r#":<a href="([^"]+)">([^<]+)</a>"#.to_string()),
                name: Some("$2".to_string()),
                book_url: Some("$1".to_string()),
                author: Some("$0".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let results = RuleEngine::new().unwrap().search_books(
            &source,
            r#"<li><a href="/1">第一章</a></li><li><a href="/2">第二章</a></li>"#,
            "https://regex.example",
        );

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "第一章");
        assert_eq!(results[0].book_url, "https://regex.example/1");
        assert_eq!(results[0].author, "$0");
        assert_eq!(results[1].name, "第二章");
    }

    #[test]
    fn compat_all_in_one_regex_chains_stages_and_preserves_literal_groups() {
        let rows = regex_capture_rows(r":([a-z]\d)&&([a-z])(\d)", "a1 b2");
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            vec![Some("a1".into()), Some("a".into()), Some("1".into())]
        );
        assert_eq!(
            capture_rule_values(Some("$1/$2/$0/$99"), &rows[0]).as_deref(),
            Some("a/1/$0/$99")
        );
    }

    #[test]
    fn compat_mode_detection_strips_css_override_and_double_at() {
        assert_eq!(
            classify_rule_mode("@@.title", ParseMode::Css, false),
            (ParseMode::Css, ".title".to_string())
        );
        assert_eq!(
            classify_rule_mode("@CSS:.title", ParseMode::Css, false),
            (ParseMode::Css, ".title".to_string())
        );
    }

    #[test]
    fn compat_put_parser_keeps_quoted_commas_inside_values() {
        let (rule, entries) = extract_put_entries(r#"@put:{alias: ".name, .author"}"#);
        assert!(rule.is_empty());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "alias");
        assert_eq!(entries[0].value_rule, ".name, .author");
    }

    #[test]
    fn compat_search_item_variables_survive_into_book_info_independently() {
        let source = BookSource {
            book_source_name: "Variable scope".to_string(),
            book_source_url: "https://source.example".to_string(),
            rule_search: Some(SearchRule {
                book_list: Some(".item".to_string()),
                name: Some(".name@text@put:{bid:.id@text}".to_string()),
                book_url: Some(".url@href".to_string()),
                ..Default::default()
            }),
            rule_book_info: Some(BookInfoRule {
                name: Some("@get:{bid}".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let books = RuleEngine::new().unwrap().search_books(
            &source,
            r#"<div class="item"><span class="name">Alpha</span><i class="id">A</i><a class="url" href="/A"></a></div><div class="item"><span class="name">Beta</span><i class="id">B</i><a class="url" href="/B"></a></div>"#,
            "https://source.example/search",
        );
        assert_eq!(books.len(), 2);
        assert_eq!(
            serde_json::from_str::<HashMap<String, String>>(books[0].variable.as_deref().unwrap())
                .unwrap()["bid"],
            "A"
        );
        assert_eq!(
            serde_json::from_str::<HashMap<String, String>>(books[1].variable.as_deref().unwrap())
                .unwrap()["bid"],
            "B"
        );

        let detail = RuleEngine::new().unwrap().book_info_with_variable(
            &source,
            "<html></html>",
            "https://source.example/B",
            "https://source.example/B",
            books[1].variable.as_deref(),
            Some(&books[1].name),
        );
        assert_eq!(detail.name, "B");
        assert_eq!(detail.variable, books[1].variable);
    }

    #[test]
    fn compat_chapter_variables_are_isolated_and_reach_content_rules() {
        let source = BookSource {
            rule_toc: Some(TocRule {
                chapter_list: Some(".chapter".to_string()),
                chapter_name: Some(".name@text@put:{cid:.id@text}".to_string()),
                chapter_url: Some(".url@href".to_string()),
                ..Default::default()
            }),
            rule_content: Some(ContentRule {
                content: Some("js:'{{@get:{bid}}}/{{@get:{cid}}}/{{title}}'".to_string()),
                next_content_url: Some("js:'next/{{@get:{cid}}}-{{title}}'".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let book_variable = r#"{"bid":"book"}"#;
        let body = r#"
            <div class="chapter"><span class="id">A</span><span class="name">Alpha</span><a class="url" href="/a"></a></div>
            <div class="chapter"><span class="id">B</span><span class="name">Beta</span><a class="url" href="/b"></a></div>
        "#;
        let (chapters, _) = RuleEngine::new().unwrap().chapter_list_with_variable(
            &source,
            body,
            "https://source.example/toc",
            Some(book_variable),
            Some("Book"),
        );

        assert_eq!(chapters.len(), 2);
        assert_eq!(
            serde_json::from_str::<HashMap<String, String>>(
                chapters[0].variable.as_deref().unwrap()
            )
            .unwrap()["cid"],
            "A"
        );
        assert_eq!(
            serde_json::from_str::<HashMap<String, String>>(
                chapters[1].variable.as_deref().unwrap()
            )
            .unwrap()["cid"],
            "B"
        );
        let engine = RuleEngine::new().unwrap();
        assert_eq!(
            engine.content_with_variables(
                &source,
                "<div>ignored</div>",
                "https://source.example/chapter/b",
                Some(book_variable),
                chapters[1].variable.as_deref(),
                Some("Book"),
                Some(&chapters[1].title),
            ),
            "book/B/Beta"
        );
        assert_eq!(
            engine.next_content_url_with_variables(
                &source,
                "<div>ignored</div>",
                "https://source.example/chapter/b",
                Some(book_variable),
                chapters[1].variable.as_deref(),
                Some("Book"),
                Some(&chapters[1].title),
            ),
            Some("https://source.example/chapter/next/B-Beta".to_string())
        );
    }

    #[test]
    fn compat_variable_context_obeys_scope_priority_and_persists_source_fallback() {
        let mut context = RuleVariableContext::for_book(
            Some(r#"{"key":"book","bookOnly":"book"}"#),
            Some("Current Book"),
        );
        context.rule_data = Some(HashMap::from([("key".to_string(), "ruleData".to_string())]));
        context.chapter = Some(HashMap::from([("key".to_string(), "chapter".to_string())]));
        context.chapter_title = Some("Current Chapter".to_string());
        assert_eq!(context.get("key").as_deref(), Some("chapter"));
        assert_eq!(context.get("bookOnly").as_deref(), Some("book"));
        assert_eq!(context.get("bookName").as_deref(), Some("Current Book"));
        assert_eq!(context.get("title").as_deref(), Some("Current Chapter"));
        context.insert("written".to_string(), "chapter-value".to_string());
        assert_eq!(
            context.chapter.as_ref().unwrap()["written"],
            "chapter-value"
        );

        let initial = crate::crawler::ExecuteSession {
            variables: Some(HashMap::from([(
                "sourceKey".to_string(),
                json!("source-value"),
            )])),
            ..Default::default()
        };
        let (_, delta) =
            crate::crawler::with_active_session(Some(&initial), "https://source.example", |_| {
                let mut context = RuleVariableContext::default();
                assert_eq!(context.get("sourceKey").as_deref(), Some("source-value"));
                context.insert("sourceKey".to_string(), "updated".to_string());
            });
        assert_eq!(
            delta.unwrap().variables.unwrap()["sourceKey"],
            json!("updated")
        );
    }

    #[test]
    fn compat_templates_coerce_values_and_expand_only_once() {
        let value = json!({"name": "Book"});
        let mut ctx = RuleVariableContext::for_book(None, None);
        ctx.insert("alias".to_string(), "Alias".to_string());
        let expanded = interpolate_templates(
            "{{$.name}}|{{1 + 2}}|{{null}}|{{String.fromCharCode(123,123) + 'x' + String.fromCharCode(125,125)}}|{{@get:{alias}}}",
            r#"{"name":"Book"}"#,
            "https://example.test",
            &ctx,
            Some(&value),
        );
        assert_eq!(expanded, "Book|3||{{x}}|Alias");
    }

    #[test]
    fn compat_css_rule_can_chain_javascript_transform() {
        let doc = html::parse_document(r#"<div class="name">Book</div>"#);
        let value = eval_field_html_doc_with_ctx(
            ".name@js:result.toUpperCase()",
            &doc,
            "https://example.test",
            &mut RuleVariableContext::default(),
        );
        assert_eq!(value.as_deref(), Some("BOOK"));
    }

    #[test]
    fn compat_regex_search_put_values_are_scoped_per_item() {
        let source = BookSource {
            rule_search: Some(SearchRule {
                book_list: Some(r#":<a href="([^"]+)">([^<]+)</a>"#.to_string()),
                name: Some("$2@put:{bid:$1}".to_string()),
                book_url: Some("$1".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let books = RuleEngine::new().unwrap().search_books(
            &source,
            r#"<a href="/a">Alpha</a><a href="/b">Beta</a>"#,
            "https://source.example",
        );
        assert_eq!(books.len(), 2);
        assert_eq!(
            serde_json::from_str::<HashMap<String, String>>(books[0].variable.as_deref().unwrap())
                .unwrap()["bid"],
            "/a"
        );
        assert_eq!(
            serde_json::from_str::<HashMap<String, String>>(books[1].variable.as_deref().unwrap())
                .unwrap()["bid"],
            "/b"
        );
    }

    #[test]
    fn compat_toc_truthiness_matches_standard_values() {
        for value in ["", "null", "false", "no", "0"] {
            assert!(!is_truthy(value.to_string()), "{value:?} must be false");
        }
        for value in ["true", "1", "VIP"] {
            assert!(is_truthy(value.to_string()), "{value:?} must be true");
        }
    }

    #[test]
    fn compat_toc_truthiness_treats_not_as_false() {
        assert!(!is_truthy("not".to_string()));
        assert!(!is_truthy("NOT".to_string()));
    }

    #[test]
    fn test_apply_legado_regex() {
        let text = "Hello World 123 456";

        assert_eq!(
            apply_legado_regex(text, "##\\d+##NUM"),
            "Hello World NUM NUM"
        );
        assert_eq!(apply_legado_regex(text, "##\\d+##NUM###"), "NUM");
        assert_eq!(apply_legado_regex(text, "##[##X"), "Hello World 123 456");
        assert_eq!(apply_legado_regex("a[b", "##[##X"), "aXb");
        assert_eq!(apply_legado_regex("nothing", "##\\d+##N###"), "");
        assert_eq!(apply_legado_regex("a[b", "##[##X###"), "X");
        assert_eq!(apply_legado_regex("no match", "##[##X###"), "X");
    }

    #[test]
    fn test_search_detail_fallback_uses_book_info_rules() {
        let engine = RuleEngine::new().unwrap();
        let source = BookSource {
            book_source_name: "Test".to_string(),
            book_source_url: "https://source.example".to_string(),
            rule_search: Some(SearchRule {
                book_list: Some(String::new()),
                ..Default::default()
            }),
            rule_book_info: Some(BookInfoRule {
                name: Some(".name@text".to_string()),
                author: Some(".author@text".to_string()),
                intro: Some(".intro@text".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let body = r#"
            <div class="name">Fallback Book</div>
            <div class="author">Fallback Author</div>
            <div class="intro">Fallback Intro</div>
        "#;

        let results = engine.search_books(&source, body, "https://books.example/detail/1");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Fallback Book");
        assert_eq!(results[0].author, "Fallback Author");
        assert_eq!(results[0].intro.as_deref(), Some("Fallback Intro"));
    }

    #[test]
    fn compat_book_url_pattern_prefers_detail_parse_and_matches_whole_url() {
        let source = BookSource {
            book_url_pattern: Some(r"https://books\.example/detail/\d+".to_string()),
            rule_search: Some(SearchRule {
                book_list: Some(".result".to_string()),
                name: Some(".list-name@text".to_string()),
                ..Default::default()
            }),
            rule_book_info: Some(BookInfoRule {
                name: Some(".detail-name@text".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let body = r#"<div class="result"><span class="list-name">List result</span></div><h1 class="detail-name">Detail page</h1>"#;
        let results = RuleEngine::new().unwrap().search_books(
            &source,
            body,
            "https://books.example/detail/12",
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Detail page");
        assert!(!book_url_pattern_matches(
            source.book_url_pattern.as_deref(),
            "https://books.example/detail/12?query=1"
        ));
        assert!(!book_url_pattern_matches(
            Some("NONE"),
            "https://books.example/detail/12"
        ));
    }

    #[test]
    fn compat_empty_explore_falls_back_to_detail_and_search_dedupes_in_order() {
        let source = BookSource {
            rule_explore: Some(SearchRule {
                book_list: Some(".missing".to_string()),
                ..Default::default()
            }),
            rule_search: Some(SearchRule {
                book_list: Some("-.item".to_string()),
                name: Some(".name@text".to_string()),
                book_url: Some("@href".to_string()),
                ..Default::default()
            }),
            rule_book_info: Some(BookInfoRule {
                name: Some(".detail-name@text".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let engine = RuleEngine::new().unwrap();
        let detail = engine.explore_books(
            &source,
            r#"<h1 class="detail-name">Fallback detail</h1>"#,
            "https://books.example/detail/1",
        );
        assert_eq!(detail.len(), 1);
        assert_eq!(detail[0].name, "Fallback detail");

        let results = engine.search_books(
            &source,
            r#"<a class="item" href="/a"><span class="name">First</span></a><a class="item" href="/b"><span class="name">Middle</span></a><a class="item" href="/a"><span class="name">Duplicate</span></a>"#,
            "https://books.example/search",
        );
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "Middle");
        assert_eq!(results[1].name, "First");
    }

    #[test]
    fn test_search_books_regex_list() {
        let engine = RuleEngine::new().unwrap();
        let source = BookSource {
            book_source_name: "Regex".to_string(),
            book_source_url: "https://source.example".to_string(),
            rule_search: Some(SearchRule {
                book_list: Some(r#":<a href="([^"]+)">([^<]+)</a>"#.to_string()),
                name: Some("$2".to_string()),
                book_url: Some("$1".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let body = r#"<a href="/book/1">One</a><a href="/book/2">Two</a>"#;

        let results = engine.search_books(&source, body, "https://books.example");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "One");
        assert_eq!(results[0].book_url, "https://books.example/book/1");
        assert_eq!(results[1].name, "Two");
    }

    #[test]
    fn test_search_books_js_json_list() {
        let engine = RuleEngine::new().unwrap();
        let source = BookSource {
            book_source_name: "JS".to_string(),
            book_source_url: "https://source.example".to_string(),
            rule_search: Some(SearchRule {
                book_list: Some(
                    "js:JSON.stringify([{name:'Alpha',author:'Tester',bookUrl:'/alpha'}])"
                        .to_string(),
                ),
                name: Some("name".to_string()),
                author: Some("author".to_string()),
                book_url: Some("bookUrl".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let results = engine.search_books(&source, "<html></html>", "https://books.example");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Alpha");
        assert_eq!(results[0].author, "Tester");
        assert_eq!(results[0].book_url, "https://books.example/alpha");
    }

    #[test]
    fn test_chapter_list_js_and_format_js() {
        let engine = RuleEngine::new().unwrap();
        let source = BookSource {
            book_source_name: "JS TOC".to_string(),
            book_source_url: "https://source.example".to_string(),
            rule_toc: Some(TocRule {
                chapter_list: Some("js:JSON.stringify([{chapterName:'One',chapterUrl:'/1',isVip:'1'},{chapterName:'Two',chapterUrl:'/2',isPay:'true'}])".to_string()),
                chapter_name: Some("chapterName".to_string()),
                chapter_url: Some("chapterUrl".to_string()),
                is_vip: Some("isVip".to_string()),
                is_pay: Some("isPay".to_string()),
                format_js: Some("`${index}.${title}`".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let (chapters, next_urls) =
            engine.chapter_list(&source, "<html></html>", "https://books.example");
        assert!(next_urls.is_empty());
        assert_eq!(chapters.len(), 2);
        assert_eq!(chapters[0].title, "1.One");
        assert_eq!(chapters[0].url, "https://books.example/1");
        assert!(chapters[0].is_vip);
        assert_eq!(chapters[1].title, "2.Two");
        assert!(chapters[1].is_pay);
    }

    #[test]
    fn compat_toc_next_urls_drop_current_page_and_dedupe() {
        let source = BookSource {
            rule_toc: Some(TocRule {
                chapter_list: Some(".chapter".to_string()),
                chapter_name: Some(".name@text".to_string()),
                chapter_url: Some(".url@href".to_string()),
                next_toc_url: Some(".next@href".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let body = r#"
            <div class="chapter"><span class="name">One</span><a class="url" href="/one"></a></div>
            <a class="next" href="/toc/1#page"></a>
            <a class="next" href="/toc/2"></a>
            <a class="next" href="/toc/2"></a>
        "#;
        let (chapters, next_urls) =
            RuleEngine::new()
                .unwrap()
                .chapter_list(&source, body, "https://books.example/toc/1");
        assert_eq!(chapters.len(), 1);
        assert_eq!(next_urls, vec!["https://books.example/toc/2"]);
    }

    #[test]
    fn compat_js_toc_rule_keeps_next_page_urls() {
        let source = BookSource {
            rule_toc: Some(TocRule {
                chapter_list: Some(
                    "js:JSON.stringify([{chapterName:'One',chapterUrl:'/one'}])".to_string(),
                ),
                chapter_name: Some("chapterName".to_string()),
                chapter_url: Some("chapterUrl".to_string()),
                next_toc_url: Some("$.next".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let (chapters, next_urls) = RuleEngine::new().unwrap().chapter_list(
            &source,
            r#"{"next":"/toc/2"}"#,
            "https://books.example/toc/1",
        );
        assert_eq!(chapters.len(), 1);
        assert_eq!(next_urls, vec!["https://books.example/toc/2"]);
    }

    #[test]
    fn test_chapter_list_keeps_real_chapterlist_container() {
        let engine = RuleEngine::new().unwrap();
        let source = BookSource {
            book_source_name: "HTML TOC".to_string(),
            book_source_url: "https://source.example".to_string(),
            rule_toc: Some(TocRule {
                chapter_list: Some("#chapterlist a".to_string()),
                chapter_name: Some("@text".to_string()),
                chapter_url: Some("@href".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let body = r#"
            <div id="chapterlist">
                <a href="/1">第一章</a>
                <a href="/2">第二章</a>
            </div>
        "#;

        let (chapters, next_urls) = engine.chapter_list(&source, body, "https://books.example");
        assert!(next_urls.is_empty());
        assert_eq!(chapters.len(), 2);
        assert_eq!(chapters[0].url, "https://books.example/1");
        assert_eq!(chapters[1].url, "https://books.example/2");
    }

    #[test]
    fn test_search_books_js_uses_js_lib() {
        let engine = RuleEngine::new().unwrap();
        let source = BookSource {
            book_source_name: "JS Lib".to_string(),
            book_source_url: "https://source.example".to_string(),
            js_lib: Some("function buildName(v){ return v + '-lib'; }".to_string()),
            rule_search: Some(SearchRule {
                book_list: Some("js:JSON.stringify([{name:buildName('Alpha'),author:'Tester',bookUrl:'/alpha'}])".to_string()),
                name: Some("name".to_string()),
                author: Some("author".to_string()),
                book_url: Some("bookUrl".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let results = engine.search_books(&source, "<html></html>", "https://books.example");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Alpha-lib");
    }

    #[test]
    fn html_book_info_init_selector_limits_field_scope() {
        let source = BookSource {
            book_source_name: "Scoped Info".to_string(),
            book_source_url: "https://source.example".to_string(),
            ..Default::default()
        };
        let rule = BookInfoRule {
            init: Some(".book-detail".to_string()),
            name: Some(".name@text".to_string()),
            author: Some(".author@text".to_string()),
            ..Default::default()
        };
        let body = r#"<section class="book-detail"><h1 class="name">Scoped</h1><span class="author">Alice</span></section><h1 class="name">Outside</h1>"#;
        let book = parse_book_info_html(
            &source,
            body,
            "https://books.example/detail/1",
            &rule,
            "https://books.example/detail/1",
            &mut RuleVariableContext::for_book(None, None),
        );

        assert_eq!(book.name, "Scoped");
        assert_eq!(book.author, "Alice");
    }

    #[test]
    fn html_book_info_init_selector_miss_falls_back_to_document() {
        let source = BookSource::default();
        let rule = BookInfoRule {
            init: Some(".missing".to_string()),
            name: Some(".name@text".to_string()),
            ..Default::default()
        };
        let book = parse_book_info_html(
            &source,
            r#"<div class="name">Original scope</div>"#,
            "https://books.example/detail/1",
            &rule,
            "https://books.example/detail/1",
            &mut RuleVariableContext::for_book(None, None),
        );

        assert_eq!(book.name, "Original scope");
    }

    #[test]
    fn html_book_info_js_init_uses_returned_html_as_scope() {
        let source = BookSource::default();
        let js_init = r#"@js:'<section><h1 class="name">From JS</h1></section>'"#;
        let rule = BookInfoRule {
            init: Some(js_init.to_string()),
            name: Some(".name@text".to_string()),
            ..Default::default()
        };
        let book = parse_book_info_html(
            &source,
            r#"<div class="name">Original</div>"#,
            "https://books.example/detail/1",
            &rule,
            "https://books.example/detail/1",
            &mut RuleVariableContext::for_book(None, None),
        );

        assert_eq!(book.name, "From JS");
    }

    #[test]
    fn html_book_info_js_init_plain_text_keeps_original_scope() {
        let source = BookSource::default();
        let rule = BookInfoRule {
            init: Some("@js:'not HTML'".to_string()),
            name: Some(".name@text".to_string()),
            ..Default::default()
        };
        let book = parse_book_info_html(
            &source,
            r#"<div class="name">Original</div>"#,
            "https://books.example/detail/1",
            &rule,
            "https://books.example/detail/1",
            &mut RuleVariableContext::for_book(None, None),
        );

        assert_eq!(book.name, "Original");
    }

    #[test]
    fn html_book_info_keeps_json_and_xpath_init_scopes() {
        let source = BookSource::default();
        let json_rule = BookInfoRule {
            init: Some("$.data.book".to_string()),
            name: Some("$.name".to_string()),
            ..Default::default()
        };
        let json_value = json!({
            "data": {"book": {"name": "JSON scoped"}},
            "name": "JSON outer"
        });
        let json_book = parse_book_info_json(
            &source,
            &json_value,
            "https://books.example/detail/1",
            &json_rule,
            "https://books.example/detail/1",
            &mut RuleVariableContext::for_book(None, None),
        );

        let xpath_rule = BookInfoRule {
            init: Some("//book".to_string()),
            name: Some("name/text()".to_string()),
            ..Default::default()
        };
        let xpath_book = parse_book_info_xpath(
            &source,
            "<root><book><name>XPath scoped</name></book></root>",
            "https://books.example/detail/1",
            &xpath_rule,
            "https://books.example/detail/1",
            &mut RuleVariableContext::for_book(None, None),
        );

        assert_eq!(json_book.name, "JSON scoped");
        assert_eq!(xpath_book.name, "XPath scoped");
    }

    #[test]
    fn test_book_info_html_interpolates_get_template() {
        let source = BookSource {
            book_source_name: "Info".to_string(),
            book_source_url: "https://source.example".to_string(),
            rule_book_info: Some(BookInfoRule {
                init: Some("@put:{alias:.name@text}".to_string()),
                name: Some("Book-@get:{alias}".to_string()),
                author: Some(".author@text".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let body = r#"<div class="name">Alias</div><div class="author">Tester</div>"#;
        let mut ctx = RuleVariableContext::for_book(None, None);
        let book = parse_book_info_html(
            &source,
            body,
            "https://books.example/detail/1",
            &source.rule_book_info.clone().unwrap(),
            "https://books.example/detail/1",
            &mut ctx,
        );
        assert_eq!(book.name, "Book-Alias");
        assert_eq!(book.author, "Tester");
    }

    #[test]
    fn test_content_format_keep_img_and_double_braces() {
        let engine = RuleEngine::new().unwrap();
        let source = BookSource {
            book_source_name: "起步新榜（优）".to_string(),
            book_source_url: "DragonQuestQBqqnb".to_string(),
            rule_content: Some(ContentRule {
                content: Some("<p>{{$.data.Content[0].Content}}</p>".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let body = r#"{
            "ret": 0,
            "data": {
                "Content": [{
                    "Content": [
                        "“李珞！你这也太过分了！赶紧给班长道歉！”\r\n  “就是啊，溪溪好心想要给你最后冲刺一下，你不领情也就算了，推人干嘛？”\r\n  “当然！”"
                    ]
                }]
            }
        }"#;

        let content = engine.content(&source, body, "https://novel.html5.qq.com");
        assert_eq!(
            content,
            "“李珞！你这也太过分了！赶紧给班长道歉！”\n“就是啊，溪溪好心想要给你最后冲刺一下，你不领情也就算了，推人干嘛？”\n“当然！”"
        );
    }

    #[test]
    fn compat_javascript_receives_book_chapter_and_title_bindings() {
        let source = BookSource {
            rule_toc: Some(TocRule {
                chapter_list: Some(
                    r#"js:JSON.stringify([{chapterName:'Original',chapterUrl:'/one',variable:'{"cid":"C"}'}])"#
                        .to_string(),
                ),
                chapter_name: Some("chapterName".to_string()),
                chapter_url: Some("chapterUrl".to_string()),
                format_js: Some("book.variableMap.bid + '/' + chapter.variableMap.cid + '/' + title".to_string()),
                ..Default::default()
            }),
            rule_content: Some(ContentRule {
                content: Some("js:book.variableMap.bid + '/' + chapter.variableMap.cid + '/' + title".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let engine = RuleEngine::new().unwrap();
        let book_variable = r#"{"bid":"B"}"#;
        let (chapters, _) = engine.chapter_list_with_variable(
            &source,
            "<html></html>",
            "https://books.example/toc",
            Some(book_variable),
            Some("Book"),
        );
        assert_eq!(chapters.len(), 1);
        assert_eq!(chapters[0].title, "B/C/Original");
        assert_eq!(
            engine.content_with_variables(
                &source,
                "<html></html>",
                "https://books.example/chapter/1",
                Some(book_variable),
                chapters[0].variable.as_deref(),
                Some("Book"),
                Some(&chapters[0].title),
            ),
            "B/C/B/C/Original"
        );
    }

    #[test]
    fn compat_content_replacement_reads_scoped_variables() {
        let source = BookSource {
            rule_content: Some(ContentRule {
                content: Some(".text@text".to_string()),
                replace_regex: Some("##{{@get:{pattern}}}##X".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let output = RuleEngine::new().unwrap().content_with_variables(
            &source,
            r#"<div class="text">ABAC</div>"#,
            "https://books.example/chapter/1",
            Some(r#"{"pattern":"A"}"#),
            None,
            Some("Book"),
            Some("Chapter"),
        );
        assert_eq!(output, "XBXC");
    }

    #[test]
    fn test_content_comic_js_get_string_and_aes_decode() {
        let engine = RuleEngine::new().unwrap();
        let source = BookSource {
            book_source_name: "全免漫画（优）".to_string(),
            book_source_url: "https://api-cdn.kaimanhua.com/".to_string(),
            rule_content: Some(ContentRule {
                content: Some(
                    r#"<js>
result=String(java.getString("$.data")).replace(/arsadata/,"");
u=java.aesBase64DecodeToString(result,"4548ded8c9e02690","AES/CBC/PKCS5Padding","1992360ee9bc4f8f");
img=u.match(/\[(.*)\]/)[1].split(",").map(x=>'\n<img src='+x+'>').join("\n")
</js>"#
                        .to_string(),
                ),
                ..Default::default()
            }),
            ..Default::default()
        };
        let body = r#"{"data":"arsadataI3j2wv8QgjqgVWTZ7b+iuTNgOpkoIWewfuKkbsdwz1TfkSIzFHBDmZs+KQVExU+qxB7UfJf/z38gew7KMuqrwA==","status":0,"message":"ok"}"#;

        let script = r#"
result=String(java.getString("$.data")).replace(/arsadata/,"");
u=java.aesBase64DecodeToString(result,"4548ded8c9e02690","AES/CBC/PKCS5Padding","1992360ee9bc4f8f");
img=u.match(/\[(.*)\]/)[1].split(",").map(x=>'\n<img src='+x+'>').join("\n")
"#;
        let js_res = eval_js(script, body, "https://api-cdn.kaimanhua.com");
        assert!(js_res.is_ok());

        let content = engine.content(&source, body, "https://api-cdn.kaimanhua.com");
        assert!(content.contains(r#"<img src="https://example.com/1.jpg">"#));
        assert!(content.contains(r#"<img src="https://example.com/2.jpg">"#));
    }
}
