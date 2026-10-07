//! Response body decoding and AnalyzeUrl response transforms.

use super::RequestSpec;
use crate::parser::js_url::{eval_js_url_with_bindings, with_js_lib};
use chardetng::EncodingDetector;
use encoding_rs::{Encoding, UTF_16BE, UTF_16LE, UTF_8};
use once_cell::sync::Lazy;

pub(crate) fn format_analyzed_body(
    spec: &RequestSpec,
    raw_body: &[u8],
    decoded_body: String,
    content_type: Option<&str>,
    response_url: &str,
) -> Result<String, String> {
    if spec.response_type.is_some() {
        return Ok(raw_body.iter().map(|byte| format!("{byte:02x}")).collect());
    }
    // Android AnalyzeUrl's XML declaration branch precedes bodyJs.
    if content_type.is_some_and(is_xml_content_type)
        && !decoded_body.trim_start().starts_with("<?xml")
    {
        return Ok(format!("<?xml version=\"1.0\"?>{decoded_body}"));
    }
    let Some(body_js) = &spec.body_js else {
        return Ok(decoded_body);
    };
    with_js_lib(body_js.js_lib.as_deref(), || {
        eval_js_url_with_bindings(
            &body_js.script,
            &decoded_body,
            &body_js.key,
            body_js.page,
            &body_js.source_key,
            response_url,
            body_js.bindings.as_ref(),
        )
    })
    .map_err(|error| format!("URL option bodyJs failed: {error}"))
}

fn is_xml_content_type(content_type: &str) -> bool {
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    mime == "text/xml" || mime == "application/xml" || mime.ends_with("+xml")
}

pub(crate) fn decode_body(
    bytes: &[u8],
    charset: Option<&str>,
    content_type: Option<&str>,
) -> String {
    // An explicitly supplied URL charset is authoritative when it is known.
    if let Some(encoding) = charset.and_then(|label| Encoding::for_label(label.as_bytes())) {
        return decode_with_encoding(bytes, encoding).0;
    }

    // A BOM is stronger evidence than response headers and must not leak into
    // the resulting text as a leading U+FEFF.
    if let Some((encoding, body)) = charset_from_bom(bytes) {
        return decode_with_encoding(body, encoding).0;
    }

    // Honor valid HTTP declarations. A broken UTF-8 declaration is common for
    // legacy pages, so allow meta declarations and statistical detection to
    // recover instead of immediately returning replacement characters.
    if let Some(encoding) = charset_from_content_type(content_type)
        .and_then(|label| Encoding::for_label(label.as_bytes()))
    {
        let (text, had_errors) = decode_with_encoding(bytes, encoding);
        if !had_errors {
            return text;
        }
    }

    if let Some(encoding) =
        charset_from_html_meta(bytes).and_then(|label| Encoding::for_label(label.as_bytes()))
    {
        let (text, had_errors) = decode_with_encoding(bytes, encoding);
        if !had_errors {
            return text;
        }
    }

    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_owned();
    }

    let mut detector = EncodingDetector::new();
    detector.feed(bytes, true);
    let encoding = detector.guess(None, true);
    let (text, had_errors) = decode_with_encoding(bytes, encoding);
    if !had_errors {
        return text;
    }

    String::from_utf8_lossy(bytes).into_owned()
}

fn charset_from_content_type(content_type: Option<&str>) -> Option<String> {
    content_type?.split(';').find_map(|part| {
        let (name, value) = part.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| value.trim().trim_matches(['\'', '"']).to_string())
    })
}

fn charset_from_bom(bytes: &[u8]) -> Option<(&'static Encoding, &[u8])> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        Some((UTF_8, &bytes[3..]))
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        Some((UTF_16LE, &bytes[2..]))
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        Some((UTF_16BE, &bytes[2..]))
    } else {
        None
    }
}

fn charset_from_html_meta(bytes: &[u8]) -> Option<String> {
    static META_TAG: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"(?is)<meta\b[^>]*>").expect("valid meta tag regex"));
    static META_ATTRIBUTE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r#"(?is)([a-z_:][a-z0-9_:.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#)
            .expect("valid meta attribute regex")
    });
    static CONTENT_CHARSET: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r#"(?i)charset\s*=\s*["']?([a-z0-9._:-]+)"#)
            .expect("valid content charset regex")
    });

    let prefix = &bytes[..bytes.len().min(4096)];
    let html = String::from_utf8_lossy(prefix);
    for tag in META_TAG.find_iter(&html) {
        let mut charset = None;
        let mut http_equiv = None;
        let mut content = None;
        for attribute in META_ATTRIBUTE.captures_iter(tag.as_str()) {
            let name = attribute.get(1)?.as_str();
            let value = (2..=4)
                .find_map(|index| attribute.get(index))
                .map(|value| value.as_str())
                .unwrap_or_default();
            if name.eq_ignore_ascii_case("charset") {
                charset = Some(value.to_string());
            } else if name.eq_ignore_ascii_case("http-equiv") {
                http_equiv = Some(value);
            } else if name.eq_ignore_ascii_case("content") {
                content = Some(value);
            }
        }
        if let Some(charset) = charset.filter(|value| !value.trim().is_empty()) {
            return Some(charset.trim().to_string());
        }
        if http_equiv.is_some_and(|value| value.eq_ignore_ascii_case("content-type")) {
            if let Some(capture) = content.and_then(|value| CONTENT_CHARSET.captures(value)) {
                return capture.get(1).map(|value| value.as_str().to_string());
            }
        }
    }
    None
}

fn decode_with_encoding(bytes: &[u8], encoding: &'static Encoding) -> (String, bool) {
    let (text, _, had_errors) = encoding.decode(bytes);
    (text.into_owned(), had_errors)
}
