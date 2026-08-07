use safer_ffi::prelude::*;
use crate::model::book_source::BookSource;
use crate::parser::rule_engine::RuleEngine;
use crate::parser::js::{eval_js, eval_js_search_with_source};

/// 释放 Rust 返回给 C 的字符串内存
#[ffi_export]
pub fn reader_free_string(s: Option<char_p::Box>) {
    drop(s);
}

/// 终极双核 API 入口一：reader_eval (统一规则/求值/清洗/微指令)
#[ffi_export]
pub fn reader_eval(
    input: char_p::Ref<'_>,
    rule: char_p::Ref<'_>,
) -> char_p::Box {
    let input_str = input.to_str();
    let rule_str = rule.to_str().trim();

    // 1. 微指令：@uuid
    if rule_str == "@uuid" {
        let uuid = uuid::Uuid::new_v4().to_string();
        return char_p::Box::try_from(uuid).unwrap();
    }

    // 2. 微指令：@android_id
    if rule_str == "@android_id" {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let android_id: String = (0..16).map(|_| {
            let idx = rng.gen_range(0..16);
            format!("{:x}", idx)
        }).collect();
        return char_p::Box::try_from(android_id).unwrap();
    }

    // 3. 微指令：URL 编解码 (@encode, @decode)
    if rule_str == "@encode" {
        let encoded = urlencoding::encode(input_str).into_owned();
        return char_p::Box::try_from(encoded).unwrap();
    }
    if rule_str == "@decode" {
        let decoded = urlencoding::decode(input_str).map(|s| s.into_owned()).unwrap_or_default();
        return char_p::Box::try_from(decoded).unwrap();
    }

    // 4. 微指令：@clean (E-ink 样式与脱壳极速净化)
    if rule_str == "@clean" {
        return format_html(input);
    }

    // 5. 微指令：@text (HTML 剥离标签转纯文本)
    if rule_str == "@text" {
        return html_to_text(input);
    }

    // 6. 微指令：@merge (合并多源搜索结果)
    if rule_str == "@merge" {
        return merge_search_results(input);
    }

    // 7. 微指令：@validate (校验书源 JSON)
    if rule_str == "@validate" {
        return validate_source(input);
    }

    // 8. 减法过滤 (包含 " -" 说明是 Legado 减法过滤规则: "容器规则 - 剔除规则1 - 剔除规则2")
    if rule_str.contains(" -") || rule_str.starts_with('-') {
        let parts: Vec<&str> = rule_str.split(" -").collect();
        let target_rule = parts[0].trim();

        let mut doc_html = if !target_rule.is_empty() && !target_rule.starts_with('-') {
            let doc = crate::parser::html::parse_document(input_str);
            crate::parser::html::select_text(&doc, &format!("{}@outerHtml", target_rule))
                .unwrap_or_else(|| input_str.to_string())
        } else {
            input_str.to_string()
        };

        for &exclude in parts.iter().skip(if target_rule.starts_with('-') { 0 } else { 1 }) {
            let clean_ex = exclude.trim().trim_start_matches('-').trim();
            if !clean_ex.is_empty() {
                // TODO: 完整的 DOM 节点剔除逻辑
                doc_html = crate::parser::rule_engine::apply_legado_regex(&doc_html, clean_ex);
            }
        }
        return char_p::Box::try_from(doc_html).unwrap();
    }

    // 9. 正则替换：以 "##" 开头 (Legado 原生正则语法 ##pattern##replacement)
    if rule_str.starts_with("##") {
        let text = crate::parser::rule_engine::apply_legado_regex(input_str, rule_str);
        return char_p::Box::try_from(text).unwrap();
    }

    // 10. 批量规则替换：如果 rule_str 是 JSON 数组字符串
    if rule_str.starts_with('[') {
        return apply_replace_rules(input, rule);
    }

    // 11. JS 脚本评估：如果以 @js: 或 <js> 开头
    if rule_str.starts_with("@js:") || rule_str.starts_with("<js>") || rule_str.starts_with("js:") {
        let script = rule_str.replace("<js>", "").replace("@js:", "").replace("js:", "");
        let res = eval_js(&script, input_str, "").unwrap_or_else(|e| format!("{{\"error\":\"JS Eval Failed: {}\"}}", e));
        return char_p::Box::try_from(res).unwrap();
    }

    // 12. XPath 提取：如果以 // 开头
    if rule_str.starts_with("//") {
        let results = crate::parser::html::select_xpath(input_str, rule_str);
        let res = serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string());
        return char_p::Box::try_from(res).unwrap();
    }

    // 13. 标准 Legado CSS/链式/JSONPath 语法解析提取
    let doc = crate::parser::html::parse_document(input_str);
    let results = crate::parser::html::select_text_list(&doc, rule_str);
    let res_json = serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string());
    char_p::Box::try_from(res_json).unwrap()
}

/// 终极双核 API 入口二：reader_source (极简书源业务处理分发)
#[ffi_export]
pub fn reader_source(
    source_json: char_p::Ref<'_>,
    action: char_p::Ref<'_>,
    payload: char_p::Ref<'_>,
) -> char_p::Box {
    let action_str = action.to_str();
    let source_str = source_json.to_str();
    let payload_str = payload.to_str();

    match action_str {
        "search" => {
            let empty = char_p::Box::try_from("".to_string()).unwrap();
            parse_search_books(source_json, payload, empty.as_ref())
        },
        "explore" => {
            let empty = char_p::Box::try_from("".to_string()).unwrap();
            parse_explore_books(source_json, payload, empty.as_ref())
        },
        "toc" | "chapter" => {
            let empty = char_p::Box::try_from("".to_string()).unwrap();
            parse_chapter_list(source_json, payload, empty.as_ref())
        },
        "content" => {
            let empty = char_p::Box::try_from("".to_string()).unwrap();
            parse_content(source_json, payload, empty.as_ref())
        },
        "validate" => validate_source(source_json),
        "build_search_url" => {
            // payload 预计包含关键词与页码的 JSON {"key":"...", "page":1}
            let (key, page) = if let Ok(json) = serde_json::from_str::<serde_json::Value>(payload_str) {
                let k = json.get("key").and_then(|v| v.as_str()).unwrap_or(payload_str).to_string();
                let p = json.get("page").and_then(|v| v.as_i64()).unwrap_or(1) as i32;
                (k, p)
            } else {
                (payload_str.to_string(), 1)
            };
            let key_c = char_p::Box::try_from(key).unwrap();
            build_search_url(source_json, key_c.as_ref(), page)
        },
        "info" => {
            let (body, url) = if let Ok(json) = serde_json::from_str::<serde_json::Value>(payload_str) {
                let h = json.get("html").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let u = json.get("bookUrl").and_then(|v| v.as_str()).unwrap_or("").to_string();
                (h, u)
            } else {
                (payload_str.to_string(), "".to_string())
            };
            let body_c = char_p::Box::try_from(body).unwrap();
            let url_c = char_p::Box::try_from(url).unwrap();
            let empty = char_p::Box::try_from("".to_string()).unwrap();
            parse_book_info(source_json, body_c.as_ref(), empty.as_ref(), url_c.as_ref())
        },
        "build_explore_url" => {
            let (url, page) = if let Ok(json) = serde_json::from_str::<serde_json::Value>(payload_str) {
                let u = json.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let p = json.get("page").and_then(|v| v.as_i64()).unwrap_or(1) as i32;
                (u, p)
            } else {
                (payload_str.to_string(), 1)
            };
            let url_c = char_p::Box::try_from(url).unwrap();
            build_explore_url(source_json, url_c.as_ref(), page)
        },
        _ => char_p::Box::try_from(format!("{{\"error\":\"Unknown action: {}\"}}", action_str)).unwrap(),
    }
}


// 保留向下兼容的离散 FFI 导出来适配现有测试和旧模块

pub fn parse_search_books(
    source_json: char_p::Ref<'_>,
    html_body: char_p::Ref<'_>,
    base_url: char_p::Ref<'_>,
) -> char_p::Box {
    execute_parse(source_json, html_body, base_url, |src, engine, body, url| {
        engine.search_books(src, body, url)
    })
}

pub fn parse_explore_books(
    source_json: char_p::Ref<'_>,
    html_body: char_p::Ref<'_>,
    base_url: char_p::Ref<'_>,
) -> char_p::Box {
    execute_parse(source_json, html_body, base_url, |src, engine, body, url| {
        engine.explore_books(src, body, url)
    })
}

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

pub fn url_encode(input: char_p::Ref<'_>) -> char_p::Box {
    let encoded = urlencoding::encode(input.to_str()).into_owned();
    char_p::Box::try_from(encoded).unwrap()
}

pub fn url_decode(input: char_p::Ref<'_>) -> char_p::Box {
    let decoded = urlencoding::decode(input.to_str()).map(|s| s.into_owned()).unwrap_or_default();
    char_p::Box::try_from(decoded).unwrap()
}

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

pub fn format_html(html: char_p::Ref<'_>) -> char_p::Box {
    use regex::Regex;
    let mut text = html.to_str().to_string();
    
    if let Ok(re) = Regex::new(r"(?is)<script[^>]*>.*?</script>") {
        text = re.replace_all(&text, "").to_string();
    }
    if let Ok(re) = Regex::new(r"(?is)<style[^>]*>.*?</style>") {
        text = re.replace_all(&text, "").to_string();
    }
    if let Ok(re) = Regex::new(r"(?s)<!--.*?-->") {
        text = re.replace_all(&text, "").to_string();
    }
    if let Ok(re) = Regex::new(r"(?i)<(/?)(p|br|b|strong|i|em|u|h[1-6])(?:\s+[^>]*)?/?>") {
        text = re.replace_all(&text, "<$1$2>").to_string();
    }
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
                _ => {}
            }
            last_end = m.end();
        }
        final_text.push_str(&text[last_end..]);
        text = final_text;
    }
    
    char_p::Box::try_from(text).unwrap()
}

pub fn generate_uuid() -> char_p::Box {
    let uuid = uuid::Uuid::new_v4().to_string();
    char_p::Box::try_from(uuid).unwrap()
}

pub fn get_android_id() -> char_p::Box {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let android_id: String = (0..16).map(|_| {
        let idx = rng.gen_range(0..16);
        format!("{:x}", idx)
    }).collect();
    char_p::Box::try_from(android_id).unwrap()
}

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
