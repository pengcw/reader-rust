//! Pure Legado/Java compatibility helpers used by the QuickJS facade.
//!
//! Keep runtime state, HTTP, DOM, and QuickJS context handling out of this module.

use base64::Engine;
use chrono::{FixedOffset, Local, TimeZone};
use ring::{digest, hmac};
use serde_json::Value as JsonValue;

pub(super) fn java_to_num_chapter(input: &str) -> String {
    static TITLE_NUM_RE: once_cell::sync::Lazy<regex::Regex> =
        once_cell::sync::Lazy::new(|| {
            regex::Regex::new(r"(第)(.+?)(章)").expect("valid title number regex")
        });

    let Some(captures) = TITLE_NUM_RE.captures(input) else {
        return input.to_string();
    };
    let Some(number) = captures.get(2) else {
        return input.to_string();
    };

    let value = legado_string_to_int(number.as_str());
    let whole = captures.get(0).expect("full regex match");
    let mut output = String::with_capacity(input.len());
    output.push_str(&input[..whole.start()]);
    output.push('第');
    output.push_str(&value.to_string());
    output.push('章');
    output.push_str(&input[whole.end()..]);
    output
}

fn legado_string_to_int(input: &str) -> i32 {
    let normalized = input
        .chars()
        .map(fullwidth_to_halfwidth)
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    normalized
        .parse::<i32>()
        .unwrap_or_else(|_| legado_chinese_num_to_int(&normalized))
}

fn fullwidth_to_halfwidth(ch: char) -> char {
    match ch {
        '　' => ' ',
        '！'..='～' => char::from_u32(ch as u32 - 0xFEE0).unwrap_or(ch),
        _ => ch,
    }
}

fn chinese_digit_value(ch: char) -> Option<i32> {
    match ch {
        '零' | '〇' => Some(0),
        '一' | '壹' => Some(1),
        '二' | '贰' | '两' => Some(2),
        '三' | '叁' => Some(3),
        '四' | '肆' => Some(4),
        '五' | '伍' => Some(5),
        '六' | '陆' => Some(6),
        '七' | '柒' => Some(7),
        '八' | '捌' => Some(8),
        '九' | '玖' => Some(9),
        '十' | '拾' => Some(10),
        '百' | '佰' => Some(100),
        '千' | '仟' => Some(1000),
        '万' => Some(10_000),
        '亿' => Some(100_000_000),
        _ => None,
    }
}

fn is_plain_chinese_digits(input: &str) -> bool {
    !input.is_empty()
        && input.chars().all(|ch| {
            matches!(
                ch,
                '〇' | '零'
                    | '一'
                    | '二'
                    | '三'
                    | '四'
                    | '五'
                    | '六'
                    | '七'
                    | '八'
                    | '九'
                    | '壹'
                    | '贰'
                    | '叁'
                    | '肆'
                    | '伍'
                    | '陆'
                    | '柒'
                    | '捌'
                    | '玖'
            )
        })
}

fn legado_chinese_num_to_int(input: &str) -> i32 {
    if input.is_empty() {
        return -1;
    }

    if is_plain_chinese_digits(input) {
        let mut value: i64 = 0;
        for ch in input.chars() {
            let Some(digit) = chinese_digit_value(ch) else {
                return -1;
            };
            value = value.saturating_mul(10).saturating_add(digit as i64);
            if value > i32::MAX as i64 {
                return -1;
            }
        }
        return value as i32;
    }

    let chars = input.chars().collect::<Vec<_>>();
    let mut result: i64 = 0;
    let mut tmp: i64 = 0;
    let mut billion: i64 = 0;

    for (index, ch) in chars.iter().copied().enumerate() {
        let Some(value) = chinese_digit_value(ch).map(i64::from) else {
            return -1;
        };

        match value {
            100_000_000 => {
                result = result.saturating_add(tmp);
                result = result.saturating_mul(value);
                billion = billion.saturating_add(result);
                result = 0;
                tmp = 0;
            }
            10_000 => {
                result = result.saturating_add(tmp);
                result = result.saturating_mul(value);
                tmp = 0;
            }
            10.. => {
                if tmp == 0 {
                    tmp = 1;
                }
                result = result.saturating_add(value.saturating_mul(tmp));
                tmp = 0;
            }
            digit => {
                if index + 1 == chars.len() && index > 0 {
                    if let Some(previous) = chinese_digit_value(chars[index - 1]).map(i64::from) {
                        if previous >= 10 {
                            tmp = digit.saturating_mul(previous / 10);
                            continue;
                        }
                    }
                }
                tmp = tmp.saturating_mul(10).saturating_add(digit);
            }
        }

        if result > i32::MAX as i64 || tmp > i32::MAX as i64 || billion > i32::MAX as i64 {
            return -1;
        }
    }

    let total = result.saturating_add(tmp).saturating_add(billion);
    if total > i32::MAX as i64 {
        -1
    } else {
        total as i32
    }
}

pub(super) fn java_time_format(timestamp_ms: i64) -> String {
    match Local.timestamp_millis_opt(timestamp_ms).single() {
        Some(dt) => dt.format("%Y/%m/%d %H:%M").to_string(),
        None => String::new(),
    }
}

pub(super) fn java_time_format_utc(timestamp_ms: i64, format: &str, offset_ms: i64) -> String {
    let Ok(offset_seconds) = i32::try_from(offset_ms / 1000) else {
        return String::new();
    };
    let Some(offset) = FixedOffset::east_opt(offset_seconds) else {
        return String::new();
    };
    let Some(utc) = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(timestamp_ms) else {
        return String::new();
    };
    let datetime = utc.with_timezone(&offset);
    datetime
        .format(&java_date_pattern_to_chrono(format))
        .to_string()
}

fn java_date_pattern_to_chrono(pattern: &str) -> String {
    let chars = pattern.chars().collect::<Vec<_>>();
    let mut output = String::new();
    let mut index = 0;
    let mut quoted = false;

    while index < chars.len() {
        let ch = chars[index];
        if ch == '\'' {
            if chars.get(index + 1) == Some(&'\'') {
                output.push('\'');
                index += 2;
                continue;
            }
            quoted = !quoted;
            index += 1;
            continue;
        }
        if quoted || !ch.is_ascii_alphabetic() {
            if ch == '%' {
                output.push_str("%%");
            } else {
                output.push(ch);
            }
            index += 1;
            continue;
        }

        let mut end = index + 1;
        while end < chars.len() && chars[end] == ch {
            end += 1;
        }
        let width = end - index;
        let directive = match ch {
            'y' => Some(if width == 2 { "%y" } else { "%Y" }),
            'M' => Some(match width {
                1 => "%-m",
                2 => "%m",
                3 => "%b",
                _ => "%B",
            }),
            'd' => Some(if width == 1 { "%-d" } else { "%d" }),
            'H' => Some(if width == 1 { "%-H" } else { "%H" }),
            'h' => Some(if width == 1 { "%-I" } else { "%I" }),
            'm' => Some(if width == 1 { "%-M" } else { "%M" }),
            's' => Some(if width == 1 { "%-S" } else { "%S" }),
            'S' => Some(match width {
                1 => "%1f",
                2 => "%2f",
                _ => "%3f",
            }),
            'a' => Some("%p"),
            'E' => Some(if width <= 3 { "%a" } else { "%A" }),
            'u' => Some("%u"),
            'Z' => Some("%z"),
            'X' => Some(if width >= 3 { "%:z" } else { "%z" }),
            _ => None,
        };
        if let Some(directive) = directive {
            output.push_str(directive);
        } else {
            for _ in 0..width {
                output.push(ch);
            }
        }
        index = end;
    }

    output
}

fn charset_encoding(charset: Option<&str>) -> &'static encoding_rs::Encoding {
    charset
        .and_then(|label| encoding_rs::Encoding::for_label(label.trim().as_bytes()))
        .unwrap_or(encoding_rs::UTF_8)
}

pub(super) fn java_str_to_bytes(input: &str, charset: Option<&str>) -> Vec<u8> {
    charset_encoding(charset).encode(input).0.into_owned()
}

pub(super) fn java_bytes_to_str(bytes: &[u8], charset: Option<&str>) -> String {
    charset_encoding(charset).decode(bytes).0.into_owned()
}

pub(super) fn java_base64_decode(input: &str, charset: Option<&str>) -> String {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(input.trim()));
    bytes
        .map(|bytes| java_bytes_to_str(&bytes, charset))
        .unwrap_or_default()
}

fn json_byte_array(input: &str) -> Vec<u8> {
    serde_json::from_str::<Vec<i64>>(input)
        .unwrap_or_default()
        .into_iter()
        .map(|byte| byte.rem_euclid(256) as u8)
        .collect()
}

pub(super) fn java_base64_encode_bytes(input_json: &str, flags: i32) -> String {
    let bytes = json_byte_array(input_json);
    let url_safe = flags & 8 != 0;
    let no_padding = flags & 1 != 0;
    let no_wrap = flags & 2 != 0;
    let crlf = flags & 4 != 0;
    let encoded = match (url_safe, no_padding) {
        (true, true) => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
        (true, false) => base64::engine::general_purpose::URL_SAFE.encode(bytes),
        (false, true) => base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes),
        (false, false) => base64::engine::general_purpose::STANDARD.encode(bytes),
    };
    if no_wrap || encoded.is_empty() {
        return encoded;
    }

    let separator = if crlf { "\r\n" } else { "\n" };
    let mut wrapped = String::with_capacity(encoded.len() + encoded.len() / 76 + 2);
    for (index, chunk) in encoded.as_bytes().chunks(76).enumerate() {
        if index > 0 {
            wrapped.push_str(separator);
        }
        wrapped.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    wrapped.push_str(separator);
    wrapped
}

pub(super) fn java_base64_decode_bytes(input: &str, flags: i32) -> String {
    let input = input
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    let url_safe = flags & 8 != 0;
    let decoded = if url_safe {
        base64::engine::general_purpose::URL_SAFE
            .decode(&input)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&input))
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(&input)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&input))
    }
    .unwrap_or_default();
    serde_json::to_string(&decoded).unwrap_or_else(|_| "[]".to_string())
}

fn normalize_crypto_algorithm(algorithm: &str) -> String {
    algorithm
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_uppercase())
        .collect()
}

pub(super) fn java_digest_bytes(data: &[u8], algorithm: &str) -> Option<Vec<u8>> {
    use md5::{Digest, Md5};

    let normalized = normalize_crypto_algorithm(algorithm);
    match normalized.as_str() {
        "MD5" => Some(Md5::digest(data).to_vec()),
        "SHA1" => Some(
            digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data)
                .as_ref()
                .to_vec(),
        ),
        "SHA256" => Some(digest::digest(&digest::SHA256, data).as_ref().to_vec()),
        "SHA384" => Some(digest::digest(&digest::SHA384, data).as_ref().to_vec()),
        "SHA512" => Some(digest::digest(&digest::SHA512, data).as_ref().to_vec()),
        _ => None,
    }
}

fn java_hmac_algorithm(algorithm: &str) -> Option<hmac::Algorithm> {
    match normalize_crypto_algorithm(algorithm).as_str() {
        "HMACSHA1" => Some(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY),
        "HMACSHA256" => Some(hmac::HMAC_SHA256),
        "HMACSHA384" => Some(hmac::HMAC_SHA384),
        "HMACSHA512" => Some(hmac::HMAC_SHA512),
        _ => None,
    }
}

pub(super) fn java_hmac_string_bytes(
    data: &str,
    algorithm: &str,
    key: &str,
) -> Option<Vec<u8>> {
    let algorithm = java_hmac_algorithm(algorithm)?;
    let key = hmac::Key::new(algorithm, key.as_bytes());
    Some(hmac::sign(&key, data.as_bytes()).as_ref().to_vec())
}

pub(super) fn java_hmac_bytes(algorithm: &str, key_json: &str, data_json: &str) -> String {
    let Some(algorithm) = java_hmac_algorithm(algorithm) else {
        return "[]".to_string();
    };
    let key = hmac::Key::new(algorithm, &json_byte_array(key_json));
    let tag = hmac::sign(&key, &json_byte_array(data_json));
    serde_json::to_string(tag.as_ref()).unwrap_or_else(|_| "[]".to_string())
}

pub(super) fn java_to_url_json(raw_url: &str, base_url: Option<&str>) -> String {
    let parsed = match base_url.filter(|base| !base.trim().is_empty()) {
        Some(base_url) => url::Url::parse(base_url).and_then(|base| base.join(raw_url)),
        None => url::Url::parse(raw_url),
    };
    let url = match parsed {
        Ok(url) => url,
        Err(error) => {
            return serde_json::json!({
                "error": error.to_string(),
            })
            .to_string();
        }
    };

    let search_params = if let Some(query) = url.query() {
        let mut values = serde_json::Map::new();
        for item in query.split('&') {
            let (key, value) = item.split_once('=').unwrap_or((item, ""));
            let decoded = urlencoding::decode(&value.replace('+', " "))
                .map(|value| value.into_owned())
                .unwrap_or_else(|_| value.to_string());
            values.insert(key.to_string(), JsonValue::String(decoded));
        }
        JsonValue::Object(values)
    } else {
        JsonValue::Null
    };

    serde_json::json!({
        "searchParams": search_params,
        "host": url.host_str().unwrap_or_default(),
        "origin": url.origin().ascii_serialization(),
        "pathname": url.path(),
    })
    .to_string()
}

pub(super) fn java_encode_uri(input: &str, charset: Option<&str>) -> String {
    let bytes = java_str_to_bytes(input, charset);
    let mut encoded = String::with_capacity(bytes.len());
    for byte in bytes {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => {
                encoded.push(byte as char)
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}
