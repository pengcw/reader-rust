use safer_ffi::prelude::*;
use crate::model::book_source::BookSource;
use crate::parser::rule_engine::RuleEngine;
use crate::parser::js::{eval_js, eval_js_search_with_source};

/// 释放 Rust 返回给 C 的字符串内存
#[ffi_export]
pub fn reader_free_string(s: Option<char_p::Box>) {
    drop(s);
}

/// 执行通用解析逻辑的内部助手
fn execute_parse<F, T>(
    source_json: char_p::Ref<'_>,
    html_body: char_p::Ref<'_>,
    base_url: char_p::Ref<'_>,
    parse_fn: F,
) -> char_p::Box
where
    F: FnOnce(&BookSource, &RuleEngine, &str, &str) -> T,
    T: serde::Serialize,
{
    let source_str = source_json.to_str();
    let body_str = html_body.to_str();
    let url_str = base_url.to_str();

    let source: BookSource = match serde_json::from_str(source_str) {
        Ok(s) => s,
        Err(e) => return char_p::Box::try_from(format!("{{\"error\":\"Invalid Source: {}\"}}", e)).unwrap(),
    };

    let engine = match RuleEngine::new() {
        Ok(e) => e,
        Err(e) => return char_p::Box::try_from(format!("{{\"error\":\"Engine Init: {}\"}}", e)).unwrap(),
    };

    let result = parse_fn(&source, &engine, body_str, url_str);
    let result_json = serde_json::to_string(&result)
        .unwrap_or_else(|e| format!("{{\"error\":\"Serialize Failed: {}\"}}", e));
    
    char_p::Box::try_from(result_json).unwrap()
}

/// 暴露给 Lua/C: 搜索解析
#[ffi_export]
pub fn parse_search_books(
    source_json: char_p::Ref<'_>,
    html_body: char_p::Ref<'_>,
    base_url: char_p::Ref<'_>,
) -> char_p::Box {
    execute_parse(source_json, html_body, base_url, |src, engine, body, url| {
        engine.search_books(src, body, url)
    })
}

/// 暴露给 Lua/C: 发现书籍解析
#[ffi_export]
pub fn parse_explore_books(
    source_json: char_p::Ref<'_>,
    html_body: char_p::Ref<'_>,
    base_url: char_p::Ref<'_>,
) -> char_p::Box {
    execute_parse(source_json, html_body, base_url, |src, engine, body, url| {
        engine.explore_books(src, body, url)
    })
}

/// 暴露给 Lua/C: 书籍详情解析
#[ffi_export]
pub fn parse_book_info(
    source_json: char_p::Ref<'_>,
    html_body: char_p::Ref<'_>,
    base_url: char_p::Ref<'_>,
    book_url: char_p::Ref<'_>,
) -> char_p::Box {
    let book_url_str = book_url.to_str();
    execute_parse(source_json, html_body, base_url, |src, engine, body, url| {
        engine.book_info(src, body, url, book_url_str)
    })
}

/// 暴露给 Lua/C: 目录解析
#[ffi_export]
pub fn parse_chapter_list(
    source_json: char_p::Ref<'_>,
    html_body: char_p::Ref<'_>,
    base_url: char_p::Ref<'_>,
) -> char_p::Box {
    execute_parse(source_json, html_body, base_url, |src, engine, body, url| {
        let (chapters, next_urls) = engine.chapter_list(src, body, url);
        serde_json::json!({
            "chapters": chapters,
            "next_urls": next_urls
        })
    })
}

/// 暴露给 Lua/C: 正文解析
#[ffi_export]
pub fn parse_content(
    source_json: char_p::Ref<'_>,
    html_body: char_p::Ref<'_>,
    base_url: char_p::Ref<'_>,
) -> char_p::Box {
    execute_parse(source_json, html_body, base_url, |src, engine, body, url| {
        let content = engine.content(src, body, url);
        let next_url = engine.next_content_url(src, body, url);
        serde_json::json!({
            "content": content,
            "next_url": next_url
        })
    })
}

/// 暴露给 Lua/C: 编译搜索 URL
#[ffi_export]
pub fn build_search_url(
    source_json: char_p::Ref<'_>,
    keyword: char_p::Ref<'_>,
    page: i32,
) -> char_p::Box {
    let source_str = source_json.to_str();
    let key_str = keyword.to_str();

    let source: BookSource = match serde_json::from_str(source_str) {
        Ok(s) => s,
        Err(e) => return char_p::Box::try_from(format!("{{\"error\":\"Invalid Source: {}\"}}", e)).unwrap(),
    };

    let search_url_template = source.search_url.unwrap_or_default();
    
    let url = if search_url_template.starts_with("<js>") || search_url_template.starts_with("@js:") || search_url_template.starts_with("js:") {
        let script = search_url_template.replace("<js>", "").replace("@js:", "").replace("js:", "");
        eval_js_search_with_source(&script, key_str, page, &source.book_source_url)
            .unwrap_or_else(|_| search_url_template.clone())
    } else {
        search_url_template
            .replace("{{key}}", &urlencoding::encode(key_str))
            .replace("{{page}}", &page.to_string())
    };

    let result_json = serde_json::json!({
        "url": url,
    }).to_string();

    char_p::Box::try_from(result_json).unwrap()
}

/// 暴露给 Lua/C: 编译发现 URL
#[ffi_export]
pub fn build_explore_url(
    source_json: char_p::Ref<'_>,
    explore_url: char_p::Ref<'_>,
    page: i32,
) -> char_p::Box {
    let source_str = source_json.to_str();
    let explore_str = explore_url.to_str();

    let source: BookSource = match serde_json::from_str(source_str) {
        Ok(s) => s,
        Err(e) => return char_p::Box::try_from(format!("{{\"error\":\"Invalid Source: {}\"}}", e)).unwrap(),
    };

    let url = if explore_str.starts_with("<js>") || explore_str.starts_with("@js:") || explore_str.starts_with("js:") {
        let script = explore_str.replace("<js>", "").replace("@js:", "").replace("js:", "");
        eval_js(&script, "", &source.book_source_url).unwrap_or_else(|_| explore_str.to_string())
    } else {
        explore_str.replace("{{page}}", &page.to_string())
    };

    let result_json = serde_json::json!({
        "url": url,
    }).to_string();

    char_p::Box::try_from(result_json).unwrap()
}

/// 暴露给 Lua/C: 独立的 JS 规则求值 (例如 loginCheckJs, coverDecodeJs)
#[ffi_export]
pub fn parse_rule_eval(
    rule: char_p::Ref<'_>,
    content: char_p::Ref<'_>,
    base_url: char_p::Ref<'_>,
) -> char_p::Box {
    let rule_str = rule.to_str();
    let content_str = content.to_str();
    let url_str = base_url.to_str();

    if rule_str.starts_with("@js:") || rule_str.starts_with("<js>") || rule_str.starts_with("js:") {
        let script = rule_str.replace("<js>", "").replace("@js:", "").replace("js:", "");
        let res = eval_js(&script, content_str, url_str).unwrap_or_else(|e| format!("{{\"error\":\"JS Eval Failed: {}\"}}", e));
        return char_p::Box::try_from(res).unwrap();
    }
    
    let res = format!("{{\"error\":\"Only JS is currently supported via standalone FFI eval\"}}");
    char_p::Box::try_from(res).unwrap()
}

/// 暴露给 Lua/C: URL 编码
#[ffi_export]
pub fn url_encode(input: char_p::Ref<'_>) -> char_p::Box {
    let encoded = urlencoding::encode(input.to_str()).into_owned();
    char_p::Box::try_from(encoded).unwrap()
}

/// 暴露给 Lua/C: URL 解码
#[ffi_export]
pub fn url_decode(input: char_p::Ref<'_>) -> char_p::Box {
    let decoded = urlencoding::decode(input.to_str()).map(|s| s.into_owned()).unwrap_or_default();
    char_p::Box::try_from(decoded).unwrap()
}

/// 暴露给 Lua/C: 内容替换 (应用 Legado Replace Rules)
#[ffi_export]
pub fn apply_replace_rules(
    content: char_p::Ref<'_>,
    rules_json: char_p::Ref<'_>,
) -> char_p::Box {
    let mut text = content.to_str().to_string();
    let rules_str = rules_json.to_str();
    if let Ok(rules) = serde_json::from_str::<Vec<crate::model::replace_rule::ReplaceRule>>(rules_str) {
        for rule in rules {
            if !rule.is_enabled {
                continue;
            }
            if rule.is_regex {
                let full_rule = if rule.pattern.starts_with("##") {
                    if !rule.replacement.is_empty() && !rule.pattern.contains(&format!("##{}", rule.replacement)) {
                        format!("{}##{}", rule.pattern, rule.replacement)
                    } else {
                        rule.pattern.clone()
                    }
                } else {
                    format!("##{}##{}", rule.pattern, rule.replacement)
                };
                text = crate::parser::rule_engine::apply_legado_regex(&text, &full_rule);
            } else {
                text = text.replace(&rule.pattern, &rule.replacement);
            }
        }
    }
    char_p::Box::try_from(text).unwrap()
}

/// 暴露给 Lua/C: 合并搜索结果
#[ffi_export]
pub fn merge_search_results(books_json: char_p::Ref<'_>) -> char_p::Box {
    let books_str = books_json.to_str();
    if let Ok(books) = serde_json::from_str::<Vec<crate::model::search::SearchBook>>(books_str) {
        let mut map: std::collections::HashMap<String, crate::model::search::SearchBook> = std::collections::HashMap::new();
        for mut book in books {
            let key = book.merge_key();
            if let Some(existing) = map.get_mut(&key) {
                let mut urls = existing.book_source_urls.clone().unwrap_or_else(|| vec![existing.origin.clone()]);
                if !urls.contains(&book.origin) {
                    urls.push(book.origin.clone());
                }
                existing.book_source_urls = Some(urls);
            } else {
                book.book_source_urls = Some(vec![book.origin.clone()]);
                map.insert(key, book);
            }
        }
        let merged: Vec<_> = map.into_values().collect();
        let res = serde_json::to_string(&merged).unwrap_or_else(|_| "[]".to_string());
        char_p::Box::try_from(res).unwrap()
    } else {
        char_p::Box::try_from("[]".to_string()).unwrap()
    }
}

/// 暴露给 Lua/C: 验证书源
#[ffi_export]
pub fn validate_source(source_json: char_p::Ref<'_>) -> char_p::Box {
    let source_str = source_json.to_str();
    let mut errors = Vec::new();
    let valid = match serde_json::from_str::<BookSource>(source_str) {
        Ok(source) => {
            if source.book_source_url.trim().is_empty() {
                errors.push("bookSourceUrl is empty");
            }
            if source.book_source_name.trim().is_empty() {
                errors.push("bookSourceName is empty");
            }
            errors.is_empty()
        },
        Err(e) => {
            errors.push(Box::leak(format!("JSON Parse Error: {}", e).into_boxed_str()));
            false
        }
    };
    let res = serde_json::json!({
        "valid": valid,
        "errors": errors
    }).to_string();
    char_p::Box::try_from(res).unwrap()
}

/// 暴露给 Lua/C: HTML 转纯文本
#[ffi_export]
pub fn html_to_text(html: char_p::Ref<'_>) -> char_p::Box {
    let text = html.to_str();
    let replaced = text.replace("<br/>", "\n")
        .replace("<br>", "\n")
        .replace("</p>", "\n")
        .replace("<p>", "");
    let doc = scraper::Html::parse_fragment(&replaced);
    let res = doc.root_element().text().collect::<Vec<_>>().join("");
    char_p::Box::try_from(res.trim().to_string()).unwrap()
}

/// 暴露给 Lua/C: 调试解析模式
#[ffi_export]
pub fn debug_parse(
    source_json: char_p::Ref<'_>,
    html_body: char_p::Ref<'_>,
    base_url: char_p::Ref<'_>,
    mode: char_p::Ref<'_>,
) -> char_p::Box {
    let mode_str = mode.to_str();
    let source_str = source_json.to_str();
    let body_str = html_body.to_str();
    let url_str = base_url.to_str();

    let source: BookSource = match serde_json::from_str(source_str) {
        Ok(s) => s,
        Err(e) => return char_p::Box::try_from(format!("{{\"error\":\"Invalid Source: {}\"}}", e)).unwrap(),
    };

    let engine = match RuleEngine::new() {
        Ok(e) => e,
        Err(e) => return char_p::Box::try_from(format!("{{\"error\":\"Engine Init: {}\"}}", e)).unwrap(),
    };

    let result = match mode_str {
        "search" => serde_json::to_value(engine.search_books(&source, body_str, url_str)),
        "explore" => serde_json::to_value(engine.explore_books(&source, body_str, url_str)),
        "info" => serde_json::to_value(engine.book_info(&source, body_str, url_str, url_str)),
        "chapter" => {
            let (chapters, next_urls) = engine.chapter_list(&source, body_str, url_str);
            serde_json::to_value(serde_json::json!({"chapters": chapters, "next_urls": next_urls}))
        }
        "content" => {
            let content = engine.content(&source, body_str, url_str);
            let next_url = engine.next_content_url(&source, body_str, url_str);
            serde_json::to_value(serde_json::json!({"content": content, "next_url": next_url}))
        }
        _ => Err(serde::ser::Error::custom("Unknown mode")),
    };

    let result_val = result.unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}));
    
    let res = serde_json::json!({
        "result": result_val,
        "logs": ["Debug mode is active. (Detailed rule traces not fully implemented in RuleEngine yet)"]
    }).to_string();
    
    char_p::Box::try_from(res).unwrap()
}

/// 暴露给 Lua/C: 净化 HTML（提取出适合 E-ink 阅读的纯净 HTML，剥离所有属性与 CSS，保留基础排版）
#[ffi_export]
pub fn format_html(html: char_p::Ref<'_>) -> char_p::Box {
    use regex::Regex;
    let mut text = html.to_str().to_string();
    
    // 1. Remove script and style tags with content
    if let Ok(re) = Regex::new(r"(?is)<script[^>]*>.*?</script>") {
        text = re.replace_all(&text, "").to_string();
    }
    if let Ok(re) = Regex::new(r"(?is)<style[^>]*>.*?</style>") {
        text = re.replace_all(&text, "").to_string();
    }
    
    // 2. Remove comments
    if let Ok(re) = Regex::new(r"(?s)<!--.*?-->") {
        text = re.replace_all(&text, "").to_string();
    }
    
    // 3. Normalize kept tags (strip attributes)
    if let Ok(re) = Regex::new(r"(?i)<(/?)(p|br|b|strong|i|em|u|h[1-6])(?:\s+[^>]*)?/?>") {
        text = re.replace_all(&text, "<$1$2>").to_string();
    }
    
    // 4. Remove all remaining tags except our normalized ones
    if let Ok(re) = Regex::new(r"<[^>]+>") {
        let mut final_text = String::new();
        let mut last_end = 0;
        for m in re.find_iter(&text) {
            final_text.push_str(&text[last_end..m.start()]);
            let tag = m.as_str();
            match tag {
                "<p>" | "</p>" | "<br>" | "<b>" | "</b>" |
                "<strong>" | "</strong>" | "<i>" | "</i>" |
                "<em>" | "</em>" | "<u>" | "</u>" |
                "<h1>" | "</h1>" | "<h2>" | "</h2>" |
                "<h3>" | "</h3>" | "<h4>" | "</h4>" |
                "<h5>" | "</h5>" | "<h6>" | "</h6>" => {
                    final_text.push_str(tag);
                }
                _ => {} // remove
            }
            last_end = m.end();
        }
        final_text.push_str(&text[last_end..]);
        text = final_text;
    }
    
    char_p::Box::try_from(text).unwrap()
}

/// 暴露给 Lua/C: 生成 UUID
#[ffi_export]
pub fn generate_uuid() -> char_p::Box {
    let uuid = uuid::Uuid::new_v4().to_string();
    char_p::Box::try_from(uuid).unwrap()
}

/// 暴露给 Lua/C: 获取随机 Android ID (16 字符 HEX)
#[ffi_export]
pub fn get_android_id() -> char_p::Box {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let android_id: String = (0..16).map(|_| {
        let idx = rng.gen_range(0..16);
        format!("{:x}", idx)
    }).collect();
    char_p::Box::try_from(android_id).unwrap()
}
