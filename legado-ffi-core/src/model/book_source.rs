use crate::util::text::find_template_close;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Map, Value};

use crate::model::rule::{BookInfoRule, ContentRule, ExploreRule, ReviewRule, SearchRule, TocRule};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct BookSource {
    pub book_source_name: String,
    pub book_source_group: Option<String>,
    pub book_source_url: String,
    pub book_source_type: Option<i32>,
    pub book_url_pattern: Option<String>,
    pub custom_order: Option<i32>,
    pub enabled: Option<bool>,
    pub enabled_explore: Option<bool>,
    pub enabled_cookie_jar: Option<bool>,
    pub js_lib: Option<String>,
    pub concurrent_rate: Option<String>,
    pub header: Option<String>,
    pub login_url: Option<String>,
    pub login_ui: Option<String>,
    pub login_check_js: Option<String>,
    pub cover_decode_js: Option<String>,
    #[serde(deserialize_with = "deserialize_i64_option")]
    pub last_update_time: Option<i64>,
    pub weight: Option<i32>,
    pub explore_url: Option<String>,
    pub explore_screen: Option<String>,
    #[serde(deserialize_with = "deserialize_rule_option")]
    pub rule_explore: Option<ExploreRule>,
    pub search_url: Option<String>,
    #[serde(deserialize_with = "deserialize_rule_option")]
    pub rule_search: Option<SearchRule>,
    #[serde(deserialize_with = "deserialize_rule_option")]
    pub rule_book_info: Option<BookInfoRule>,
    #[serde(deserialize_with = "deserialize_rule_option")]
    pub rule_toc: Option<TocRule>,
    #[serde(deserialize_with = "deserialize_rule_option")]
    pub rule_content: Option<ContentRule>,
    #[serde(deserialize_with = "deserialize_rule_option")]
    pub rule_review: Option<ReviewRule>,
    pub book_source_comment: Option<String>,
    pub variable_comment: Option<String>,
    #[serde(deserialize_with = "deserialize_i64_option")]
    pub respond_time: Option<i64>,
    pub load_with_base_url: Option<bool>,
    pub single_url: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct ExploreKind {
    pub title: String,
    pub url: Option<String>,
    pub style: Option<Value>,
}

fn deserialize_rule_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        Value::Null => Ok(None),
        Value::String(raw) => {
            let raw = raw.trim();
            if raw.is_empty() || raw.eq_ignore_ascii_case("null") {
                Ok(None)
            } else {
                serde_json::from_str(raw)
                    .map(Some)
                    .map_err(serde::de::Error::custom)
            }
        }
        other => serde_json::from_value(other)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

fn deserialize_i64_option<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        Value::Null => Ok(None),
        Value::Number(num) => num
            .as_i64()
            .or_else(|| num.as_u64().map(|u| u as i64))
            .or_else(|| num.as_f64().map(|f| f as i64))
            .map(Some)
            .ok_or_else(|| serde::de::Error::custom("expected i64-compatible number")),
        Value::String(raw) => {
            let raw = raw.trim();
            if raw.is_empty() || raw.eq_ignore_ascii_case("null") {
                Ok(None)
            } else {
                raw.parse::<i64>()
                    .map(Some)
                    .map_err(serde::de::Error::custom)
            }
        }
        other => Err(serde::de::Error::custom(format!(
            "expected i64-compatible value, got {other}"
        ))),
    }
}

pub fn book_source_from_value(value: Value) -> serde_json::Result<BookSource> {
    serde_json::from_value(migrate_legacy_book_source_value(value))
}

pub fn migrate_legacy_book_source_value(mut value: Value) -> Value {
    let Some(obj) = value.as_object_mut() else {
        return value;
    };

    move_if_absent(obj, "ruleBookUrlPattern", "bookUrlPattern");
    move_if_absent(obj, "serialNumber", "customOrder");
    // Only URLs moved from legacy fields need conversion. Current fields may
    // contain JavaScript or JSON options that must remain byte-for-byte intact.
    for (old, new) in [
        ("ruleFindUrl", "exploreUrl"),
        ("ruleSearchUrl", "searchUrl"),
    ] {
        if !obj.contains_key(new) {
            move_if_absent(obj, old, new);
            if let Some(Value::String(raw)) = obj.get(new).cloned() {
                let converted = if new == "exploreUrl" {
                    convert_legacy_explore_urls(&raw)
                } else {
                    convert_legacy_url_rule(&raw)
                };
                obj.insert(new.to_string(), Value::String(converted));
            }
        }
    }
    move_if_absent(obj, "enable", "enabled");

    if let Some(Value::String(kind)) = obj.get("bookSourceType").cloned() {
        let mapped = if kind.eq_ignore_ascii_case("AUDIO") {
            1
        } else {
            0
        };
        obj.insert("bookSourceType".to_string(), json!(mapped));
    }

    if !obj.contains_key("header") {
        if let Some(ua) = obj.get("httpUserAgent").and_then(Value::as_str) {
            if !ua.trim().is_empty() {
                obj.insert(
                    "header".to_string(),
                    Value::String(json!({ "User-Agent": ua }).to_string()),
                );
            }
        }
    }

    migrate_rule_object(
        obj,
        "ruleSearch",
        &[
            ("ruleSearchList", "bookList"),
            ("ruleSearchName", "name"),
            ("ruleSearchAuthor", "author"),
            ("ruleSearchIntro", "intro"),
            ("ruleSearchKind", "kind"),
            ("ruleSearchLastChapter", "lastChapter"),
            ("ruleSearchUpdateTime", "updateTime"),
            ("ruleSearchNoteUrl", "bookUrl"),
            ("ruleSearchBookUrl", "bookUrl"),
            ("ruleSearchCoverUrl", "coverUrl"),
            ("ruleSearchWordCount", "wordCount"),
        ],
    );
    migrate_rule_object(
        obj,
        "ruleExplore",
        &[
            ("ruleFindList", "bookList"),
            ("ruleFindName", "name"),
            ("ruleFindAuthor", "author"),
            ("ruleFindIntro", "intro"),
            ("ruleFindKind", "kind"),
            ("ruleFindLastChapter", "lastChapter"),
            ("ruleFindUpdateTime", "updateTime"),
            ("ruleFindNoteUrl", "bookUrl"),
            ("ruleFindBookUrl", "bookUrl"),
            ("ruleFindCoverUrl", "coverUrl"),
            ("ruleFindWordCount", "wordCount"),
        ],
    );
    migrate_rule_object(
        obj,
        "ruleBookInfo",
        &[
            ("ruleBookInfoInit", "init"),
            ("ruleBookName", "name"),
            ("ruleBookAuthor", "author"),
            ("ruleIntroduce", "intro"),
            ("ruleBookIntro", "intro"),
            ("ruleBookKind", "kind"),
            ("ruleBookLastChapter", "lastChapter"),
            ("ruleBookUpdateTime", "updateTime"),
            ("ruleCoverUrl", "coverUrl"),
            ("ruleBookCoverUrl", "coverUrl"),
            ("ruleBookWordCount", "wordCount"),
            ("ruleChapterUrl", "tocUrl"),
            ("ruleBookTocUrl", "tocUrl"),
        ],
    );
    migrate_rule_object(
        obj,
        "ruleToc",
        &[
            ("ruleChapterList", "chapterList"),
            ("ruleChapterName", "chapterName"),
            ("ruleContentUrl", "chapterUrl"),
            ("ruleChapterUrl", "chapterUrl"),
            ("ruleChapterUpdateTime", "updateTime"),
            ("ruleChapterUrlNext", "nextTocUrl"),
            ("ruleTocUrlNext", "nextTocUrl"),
        ],
    );
    migrate_rule_object(
        obj,
        "ruleContent",
        &[
            ("ruleBookContent", "content"),
            ("ruleBookContentReplace", "replaceRegex"),
            ("ruleContentUrlNext", "nextContentUrl"),
            ("ruleContentTitle", "title"),
        ],
    );

    value
}

fn move_if_absent(obj: &mut Map<String, Value>, old: &str, new: &str) {
    if obj.contains_key(new) {
        return;
    }
    if let Some(value) = obj.remove(old) {
        obj.insert(new.to_string(), value);
    }
}

fn migrate_rule_object(obj: &mut Map<String, Value>, target: &str, fields: &[(&str, &str)]) {
    let mut target_obj = obj
        .get(target)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (old, new) in fields {
        if target_obj.contains_key(*new) {
            continue;
        }
        if let Some(value) = obj.remove(*old) {
            if !value.as_str().map(str::trim).unwrap_or("x").is_empty() {
                target_obj.insert((*new).to_string(), value);
            }
        }
    }
    if !target_obj.is_empty() {
        obj.insert(target.to_string(), Value::Object(target_obj));
    }
}

fn convert_legacy_explore_urls(raw: &str) -> String {
    if raw.starts_with("@js:") || raw.starts_with("<js>") {
        return raw.to_string();
    }
    // Reuse syntax-aware splitting so delimiters inside templates and JSON
    // strings cannot leak options into another category.
    let mut items = vec![raw.to_string()];
    for delimiter in ["&&", "\r\n", "\n"] {
        items = items
            .into_iter()
            .flat_map(|item| {
                crate::parser::rule_analyzer::split_top_level(&item, &[delimiter]).parts
            })
            .collect();
    }
    items
        .into_iter()
        .filter(|item| !item.is_empty())
        .map(|item| {
            if let Some((title, url)) = item.split_once("::") {
                // An IPv6 literal in a bare URL is not a category separator.
                if !title.contains("://") {
                    return format!("{title}::{}", convert_legacy_url_rule(url.trim()));
                }
            }
            convert_legacy_url_rule(&item)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn convert_legacy_url_rule(raw: &str) -> String {
    if raw
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("<js>"))
    {
        return raw
            .replace("=searchKey", "={{key}}")
            .replace("=searchPage", "={{page}}");
    }
    let mut url = raw.to_string();
    let mut option = Map::new();

    if let Some((start, end, header)) = extract_legacy_header(&url) {
        url.replace_range(start..end, "");
        if let Ok(value) = serde_json::from_str::<Value>(&header) {
            option.insert("headers".to_string(), value);
        } else {
            option.insert("headers".to_string(), Value::String(header));
        }
    }

    if let Some(idx) = find_legacy_url_marker(&url, "|charset=") {
        let charset = url[idx + "|charset=".len()..].trim().to_string();
        url.truncate(idx);
        if !charset.is_empty() {
            option.insert("charset".to_string(), Value::String(charset));
        }
    }

    if let Some(idx) = find_legacy_url_marker(&url, "@body") {
        let body = url[idx + "@body".len()..]
            .trim_start_matches([':', '='])
            .trim()
            .to_string();
        url.truncate(idx);
        option.insert("method".to_string(), Value::String("POST".to_string()));
        option.insert("body".to_string(), Value::String(body));
    }

    url = legacy_url_segments(&url)
        .map(|(_, part, template)| {
            if template {
                if find_template_close(&part[2..]).is_some() {
                    part.replace("searchKey", "key")
                        .replace("searchPage", "page")
                } else {
                    part.to_string()
                }
            } else {
                convert_legacy_url_literal(part)
            }
        })
        .collect();

    if option.is_empty() {
        url
    } else {
        format!("{},{}", url, Value::Object(option))
    }
}

fn extract_legacy_header(input: &str) -> Option<(usize, usize, String)> {
    let start = find_legacy_url_marker(input, "@Header:")?;
    let object_start = start + "@Header:".len();
    let rest = input.get(object_start..)?.trim_start();
    let skipped = input.get(object_start..)?.len() - rest.len();
    let open = object_start + skipped;
    if !input.get(open..)?.starts_with('{') {
        return None;
    }
    let mut depth = 0i32;
    for (offset, ch) in input[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    let end = open + offset + ch.len_utf8();
                    return Some((start, end, input[open..end].to_string()));
                }
            }
            _ => {}
        }
    }
    None
}

// Borrow segments rather than masking templates with collision-prone placeholders.
fn legacy_url_segments(input: &str) -> impl Iterator<Item = (usize, &str, bool)> {
    let mut cursor = 0;
    std::iter::from_fn(move || {
        if cursor == input.len() {
            return None;
        }
        let start = cursor;
        let remaining = &input[start..];
        let template = remaining.starts_with("{{");
        cursor = if template {
            find_template_close(&remaining[2..])
                .map(|end| start + 2 + end + 2)
                .unwrap_or(input.len())
        } else {
            remaining
                .find("{{")
                .map(|end| start + end)
                .unwrap_or(input.len())
        };
        Some((start, &input[start..cursor], template))
    })
}

fn find_legacy_url_marker(input: &str, marker: &str) -> Option<usize> {
    legacy_url_segments(input).find_map(|(offset, part, template)| {
        if template {
            None
        } else {
            part.find(marker).map(|index| offset + index)
        }
    })
}

fn convert_legacy_url_literal(input: &str) -> String {
    static OFFSETS: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"<searchPage([-+]1)>|\{searchPage([-+]1)\}|searchPage([-+]1)").unwrap()
    });
    static CHOICES: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"\{([^{}]*,[^{}]*)\}").unwrap());
    let url = OFFSETS.replace_all(input, |captures: &regex::Captures<'_>| {
        let offset = captures.iter().skip(1).flatten().next().unwrap().as_str();
        format!("{{{{page{offset}}}}}")
    });
    let url = url
        .replace("searchKey", "{{key}}")
        .replace("searchPage", "{{page}}");
    CHOICES.replace_all(&url, "<$1>").into_owned()
}
