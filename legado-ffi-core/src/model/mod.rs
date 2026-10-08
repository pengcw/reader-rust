pub mod book;
pub mod book_chapter;
pub mod book_source;
pub mod rule;
pub mod search;

use serde::{Deserialize, Deserializer};
use serde_json::Value;

pub fn deserialize_i64_option<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        Value::Null => Ok(None),
        Value::Number(num) => {
            // Optional metadata must not make a source unusable on 32-bit devices.
            // Never wrap u64 or saturate an out-of-range f64 into a bogus timestamp.
            let value = if let Some(n) = num.as_i64() {
                Some(n)
            } else if let Some(n) = num.as_u64() {
                i64::try_from(n).ok()
            } else {
                num.as_f64().and_then(|n| {
                    if n.is_finite()
                        && n.fract() == 0.0
                        && n >= i64::MIN as f64
                        && n < -(i64::MIN as f64)
                    {
                        Some(n as i64)
                    } else {
                        None
                    }
                })
            };
            Ok(value)
        },
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
