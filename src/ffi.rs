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
            .replace("{{key}}", key_str)
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
