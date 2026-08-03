use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use crate::model::book_source::BookSource;
use crate::parser::rule_engine::RuleEngine;

/// 释放 Rust 返回给 C 的字符串内存
#[no_mangle]
pub extern "C" fn reader_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s);
    }
}

/// 执行通用解析逻辑的内部助手
fn execute_parse<F, T>(
    source_json: *const c_char,
    html_body: *const c_char,
    base_url: *const c_char,
    parse_fn: F,
) -> *mut c_char
where
    F: FnOnce(&BookSource, &RuleEngine, &str, &str) -> T,
    T: serde::Serialize,
{
    let source_str = unsafe { CStr::from_ptr(source_json).to_string_lossy() };
    let body_str = unsafe { CStr::from_ptr(html_body).to_string_lossy() };
    let url_str = unsafe { CStr::from_ptr(base_url).to_string_lossy() };

    let source: BookSource = match serde_json::from_str(&source_str) {
        Ok(s) => s,
        Err(e) => return CString::new(format!("{{\"error\":\"Invalid Source: {}\"}}", e))
            .unwrap()
            .into_raw(),
    };

    let engine = match RuleEngine::new() {
        Ok(e) => e,
        Err(e) => return CString::new(format!("{{\"error\":\"Engine Init: {}\"}}", e))
            .unwrap()
            .into_raw(),
    };

    let result = parse_fn(&source, &engine, &body_str, &url_str);
    let result_json = serde_json::to_string(&result)
        .unwrap_or_else(|e| format!("{{\"error\":\"Serialize Failed: {}\"}}", e));
    
    CString::new(result_json).unwrap().into_raw()
}

/// 暴露给 Lua: 搜索解析
#[no_mangle]
pub extern "C" fn parse_search_books(
    source_json: *const c_char,
    html_body: *const c_char,
    base_url: *const c_char,
) -> *mut c_char {
    execute_parse(source_json, html_body, base_url, |src, engine, body, url| {
        engine.search_books(src, body, url)
    })
}

/// 暴露给 Lua: 发现书籍解析
#[no_mangle]
pub extern "C" fn parse_explore_books(
    source_json: *const c_char,
    html_body: *const c_char,
    base_url: *const c_char,
) -> *mut c_char {
    execute_parse(source_json, html_body, base_url, |src, engine, body, url| {
        engine.explore_books(src, body, url)
    })
}

/// 暴露给 Lua: 书籍详情解析
#[no_mangle]
pub extern "C" fn parse_book_info(
    source_json: *const c_char,
    html_body: *const c_char,
    base_url: *const c_char,
    book_url: *const c_char,
) -> *mut c_char {
    // book_url 需要单独拿出来
    let book_url_str = unsafe { CStr::from_ptr(book_url).to_string_lossy() };
    execute_parse(source_json, html_body, base_url, |src, engine, body, url| {
        engine.book_info(src, body, url, &book_url_str)
    })
}

/// 暴露给 Lua: 目录解析
#[no_mangle]
pub extern "C" fn parse_chapter_list(
    source_json: *const c_char,
    html_body: *const c_char,
    base_url: *const c_char,
) -> *mut c_char {
    execute_parse(source_json, html_body, base_url, |src, engine, body, url| {
        let (chapters, next_urls) = engine.chapter_list(src, body, url);
        serde_json::json!({
            "chapters": chapters,
            "next_urls": next_urls
        })
    })
}

/// 暴露给 Lua: 正文解析
#[no_mangle]
pub extern "C" fn parse_content(
    source_json: *const c_char,
    html_body: *const c_char,
    base_url: *const c_char,
) -> *mut c_char {
    execute_parse(source_json, html_body, base_url, |src, engine, body, url| {
        let content = engine.content(src, body, url);
        let next_url = engine.next_content_url(src, body, url);
        serde_json::json!({
            "content": content,
            "next_url": next_url
        })
    })
}
