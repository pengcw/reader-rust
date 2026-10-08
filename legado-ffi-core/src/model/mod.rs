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
