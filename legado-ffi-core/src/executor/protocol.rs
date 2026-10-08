use super::{validate_options, ExecuteError, ExecuteOptions, ExecuteResult, ValidatedOptions};
use crate::runtime::session::ExecuteSession;
use crate::parser::js::InfoMapState;
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Operation {
    Search,
    Explore,
    ExploreKinds,
    Info,
    Toc,
    Content,
    LoginUi,
    Login,
    Click,
}

impl Operation {
    fn parse(value: &str) -> ExecuteResult<Self> {
        match value {
            "search" => Ok(Self::Search),
            "explore" => Ok(Self::Explore),
            "explore_kinds" => Ok(Self::ExploreKinds),
            "info" => Ok(Self::Info),
            "toc" => Ok(Self::Toc),
            "content" => Ok(Self::Content),
            "login_ui" => Ok(Self::LoginUi),
            "login" => Ok(Self::Login),
            "click" => Ok(Self::Click),
            _ => Err(ExecuteError::invalid_request(format!(
                "unsupported op: {value}"
            ))),
        }
    }
}

pub(super) struct ExecuteRequest {
    pub(super) operation: Operation,
    pub(super) params: Value,
    pub(super) options: ValidatedOptions,
    pub(super) session: Option<ExecuteSession>,
    pub(super) info_map: Option<InfoMapState>,
}

pub(super) fn parse_request(raw: &str) -> ExecuteResult<ExecuteRequest> {
    let value = serde_json::from_str::<Value>(raw)
        .map_err(|error| ExecuteError::invalid_request(format!("invalid request JSON: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| ExecuteError::invalid_request("request must be a JSON object"))?;

    if object.get("api").and_then(Value::as_u64) != Some(2) {
        return Err(ExecuteError::invalid_request("api must be 2"));
    }
    let operation = object
        .get("op")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ExecuteError::invalid_request("op is required"))?;
    let operation = Operation::parse(operation)?;

    let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
    if !params.is_object() {
        return Err(ExecuteError::invalid_request(
            "params must be a JSON object",
        ));
    }

    let raw_options = object.get("options").cloned().unwrap_or_else(|| json!({}));
    let raw_options = serde_json::from_value::<ExecuteOptions>(raw_options)
        .map_err(|error| ExecuteError::invalid_request(format!("invalid options: {error}")))?;
    let options = validate_options(raw_options)?;

    let session = match object.get("session") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            serde_json::from_value::<ExecuteSession>(value.clone()).map_err(|error| {
                ExecuteError::invalid_request(format!("invalid session: {error}"))
            })?,
        ),
    };

    let info_map = object
        .get("infoMap")
        .cloned()
        .map(InfoMapState::from_value)
        .transpose()
        .map_err(|error| ExecuteError::invalid_request(format!("invalid infoMap: {error}")))?;

    Ok(ExecuteRequest {
        operation,
        params,
        options,
        session,
        info_map,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{DEFAULT_MAX_PAGES, DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_TIMEOUT_MS};

    #[test]
    fn operation_names_match_v2_protocol() {
        let cases = [
            ("search", Operation::Search),
            ("explore", Operation::Explore),
            ("explore_kinds", Operation::ExploreKinds),
            ("info", Operation::Info),
            ("toc", Operation::Toc),
            ("content", Operation::Content),
            ("login_ui", Operation::LoginUi),
            ("login", Operation::Login),
            ("click", Operation::Click),
        ];

        for (raw, expected) in cases {
            assert_eq!(Operation::parse(raw).unwrap(), expected);
        }
    }

    #[test]
    fn request_keeps_trimmed_operation_and_default_options_contract() {
        let request = parse_request(r#"{"api":2,"op":" search ","params":{}}"#).unwrap();

        assert_eq!(request.operation, Operation::Search);
        assert_eq!(request.options.timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(request.options.max_pages, DEFAULT_MAX_PAGES);
        assert_eq!(request.options.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
        assert!(!request.options.debug);
    }

    #[test]
    fn lua_small_integer_wire_fields_keep_the_v2_contract() {
        let request = parse_request(
            r#"{"api":2,"op":"search","params":{"key":"book","page":2},"options":{"maxPages":100}}"#,
        ).unwrap();
        assert_eq!(request.operation, Operation::Search);
        assert_eq!(request.params["page"], 2);
        assert_eq!(request.options.max_pages, 100);
    }

    #[test]
    fn unknown_operation_keeps_existing_error_contract() {
        let error = match parse_request(r#"{"api":2,"op":"future_op","params":{}}"#) {
            Ok(_) => panic!("future_op must stay unsupported"),
            Err(error) => error,
        };

        assert_eq!(error.kind, "invalid_request");
        assert_eq!(error.message, "unsupported op: future_op");
    }
}
