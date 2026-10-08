//! URL-rule JavaScript bridge.
//!
//! This module owns the AnalyzeUrl-specific wrappers around the shared QuickJS
//! executor. Keep crawler URL compilation dependent on this narrow surface
//! instead of the full `parser::js` facade.

use crate::parser::js::eval_js_inner_with_source;
pub(crate) use crate::parser::js_state::with_js_lib;
use serde_json::Value as JsonValue;
use std::collections::HashMap;

pub fn eval_js_url(
    script: &str,
    result: &str,
    key: &str,
    page: i32,
    source_key: &str,
    base_url: &str,
) -> anyhow::Result<String> {
    eval_js_url_with_bindings(script, result, key, page, source_key, base_url, None)
}

pub fn eval_js_url_with_bindings(
    script: &str,
    result: &str,
    key: &str,
    page: i32,
    source_key: &str,
    base_url: &str,
    bindings: Option<&HashMap<String, JsonValue>>,
) -> anyhow::Result<String> {
    eval_js_inner_with_source(
        script,
        Some(result),
        Some(base_url),
        Some(key),
        Some(page),
        Some(source_key),
        bindings,
        false,
        None,
    )
}

/// Evaluate an AnalyzeUrl option script with its mutable, request-local headerMap.
pub fn eval_js_url_with_headers(
    script: &str,
    result: &str,
    key: &str,
    page: i32,
    source_key: &str,
    base_url: &str,
    bindings: Option<&HashMap<String, JsonValue>>,
    headers: &mut Vec<(String, String)>,
) -> anyhow::Result<String> {
    eval_js_url_with_headers_inner(
        script, result, key, page, source_key, base_url, bindings, headers, false,
    )
}

/// Option JS keeps its completion value; java.url writes are a compatibility fallback.
pub(crate) fn eval_js_url_option_with_headers(
    script: &str,
    result: &str,
    key: &str,
    page: i32,
    source_key: &str,
    base_url: &str,
    bindings: Option<&HashMap<String, JsonValue>>,
    headers: &mut Vec<(String, String)>,
) -> anyhow::Result<String> {
    let url = serde_json::to_string(result)?;
    let script = serde_json::to_string(script)?;
    // Run source eval in a function with no local bindings that could collide
    // with the source's var declarations. Shared execution restores nested java state.
    let wrapped = format!(
        "(function(values) {{ return values[0] !== undefined ? values[0] : values[1] !== {url} ? values[1] : globalThis.result; }})((function() {{ java.url = {url}; return [eval({script}), java.url]; }})())"
    );
    eval_js_url_with_headers_inner(
        &wrapped, result, key, page, source_key, base_url, bindings, headers, false,
    )
}

pub fn eval_js_url_template_with_headers(
    script: &str,
    result: &str,
    key: &str,
    page: i32,
    source_key: &str,
    base_url: &str,
    bindings: Option<&HashMap<String, JsonValue>>,
    headers: &mut Vec<(String, String)>,
) -> anyhow::Result<String> {
    eval_js_url_with_headers_inner(
        script, result, key, page, source_key, base_url, bindings, headers, true,
    )
}

fn eval_js_url_with_headers_inner(
    script: &str,
    result: &str,
    key: &str,
    page: i32,
    source_key: &str,
    base_url: &str,
    bindings: Option<&HashMap<String, JsonValue>>,
    headers: &mut Vec<(String, String)>,
    template_result: bool,
) -> anyhow::Result<String> {
    let initial: serde_json::Map<String, JsonValue> = headers
        .iter()
        .map(|(name, value)| (name.clone(), JsonValue::String(value.clone())))
        .collect();
    let updated = std::cell::RefCell::new(None);
    let result = eval_js_inner_with_source(
        script,
        Some(result),
        Some(base_url),
        Some(key),
        Some(page),
        Some(source_key),
        bindings,
        template_result,
        Some((&initial, &updated)),
    )?;
    if let Some(values) = updated.into_inner() {
        *headers = values;
    }
    Ok(result)
}

pub fn eval_js_url_template(
    script: &str,
    result: &str,
    key: &str,
    page: i32,
    source_key: &str,
    base_url: &str,
) -> anyhow::Result<String> {
    eval_js_url_template_with_bindings(script, result, key, page, source_key, base_url, None)
}

pub fn eval_js_url_template_with_bindings(
    script: &str,
    result: &str,
    key: &str,
    page: i32,
    source_key: &str,
    base_url: &str,
    bindings: Option<&HashMap<String, JsonValue>>,
) -> anyhow::Result<String> {
    eval_js_inner_with_source(
        script,
        Some(result),
        Some(base_url),
        Some(key),
        Some(page),
        Some(source_key),
        bindings,
        true,
        None,
    )
}
