//! Offline authentication contracts through public executor and session APIs.
use reader_parser::crawler::analyze_url;
use reader_parser::crawler::session::{with_active_session, ExecuteSession};
use reader_parser::executor::execute;
use reader_parser::ffi::{reader_execute, reader_free_string};
use reader_parser::model::book_source::BookSource;
use safer_ffi::prelude::*;
use serde_json::{json, Value};
use std::ffi::CString;

const BASE: &str = "https://login-session.test/";

fn source(base: &str) -> Value {
    json!({"bookSourceUrl": base, "bookSourceName": "synthetic login fixture"})
}

fn login(source: &Value, values: Value, action: &str, session: Value) -> Value {
    serde_json::from_str(&execute(
        &source.to_string(),
        &json!({"api": 2, "op": "login", "params": {"values": values, "action": action},
            "session": session})
        .to_string(),
    ))
    .unwrap()
}

fn ffi_login(source: &Value, values: Value, action: &str, session: Value) -> Value {
    let source = CString::new(source.to_string()).unwrap();
    let request = CString::new(
        json!({"api": 2, "op": "login",
        "params": {"values": values, "action": action}, "session": session})
        .to_string(),
    )
    .unwrap();
    let output = reader_execute(
        char_p::Ref::try_from(source.as_c_str()).unwrap(),
        char_p::Ref::try_from(request.as_c_str()).unwrap(),
    );
    let owned = output.to_str().to_owned();
    reader_free_string(Some(output));
    serde_json::from_str(&owned).unwrap()
}

#[test]
fn ffi_login_matches_rust_for_unicode_nul_and_reserved_map_keys() {
    let source = source(BASE);
    let values = json!({"token": "中文\0尾", "get": "reserved-value"});
    let action = "const map = source.getLoginInfoMap(); JSON.stringify([map.token, map.get('token'), typeof map.get, map.get('get')])";
    let rust = login(&source, values.clone(), action, Value::Null);
    let ffi = ffi_login(&source, values, action, Value::Null);
    assert_eq!(ffi, rust);
    assert_eq!(ffi["ok"], true, "{ffi}");
    let result: Value = serde_json::from_str(ffi["data"]["result"].as_str().unwrap()).unwrap();
    assert_eq!(
        result,
        json!(["中文\0尾", "中文\0尾", "function", "reserved-value"])
    );
}

#[test]
fn ffi_session_roundtrip_preserves_headers_when_update_is_rejected() {
    let source = source(BASE);
    let saved = ffi_login(&source, json!({"token": "saved"}),
        "source.putLoginHeader(JSON.stringify({Authorization: source.getLoginInfoMap().token, Cookie: 'sid=saved'})); 'ok'", Value::Null);
    assert_eq!(saved["ok"], true, "{saved}");
    let action = r#"
        let errorName = '';
        try { source.putLoginHeader('{"Authorization":"new","Cookie":"sid=new; broken"}'); }
        catch (error) { errorName = error.name; }
        JSON.stringify([errorName, source.getLoginHeaderMap().get('Authorization'), source.getLoginHeaderMap().get('Cookie')])
    "#;
    let restored = ffi_login(&source, json!({}), action, saved["session"].clone());
    assert_eq!(
        restored,
        login(&source, json!({}), action, saved["session"].clone())
    );
    assert_eq!(restored["ok"], true, "{restored}");
    let result: Value = serde_json::from_str(restored["data"]["result"].as_str().unwrap()).unwrap();
    assert_eq!(result, json!(["TypeError", "saved", "sid=saved"]));
    assert!(restored["session"].is_null());
}

#[test]
fn ffi_failed_login_does_not_publish_state_or_leak_to_next_call() {
    let source = source(BASE);
    for ending in ["false", "throw new Error('synthetic failure')"] {
        let failed = ffi_login(&source, json!({"token": "private"}), &format!(
            "source.put('saved-token', source.getLoginInfoMap().token); source.putLoginHeader('{{\"Authorization\":\"private\"}}'); {ending}"
        ), Value::Null);
        assert_eq!(failed["ok"], false, "{failed}");
        assert_eq!(failed["error"]["kind"], "auth_required");
        assert!(failed.get("session").is_none());
        let next = ffi_login(&source, json!({}),
            "JSON.stringify([source.get('saved-token'), source.getLoginHeaderMap() === null, typeof source.getLoginInfoMap().token])", Value::Null);
        assert_eq!(next["ok"], true, "{next}");
        let result: Value = serde_json::from_str(next["data"]["result"].as_str().unwrap()).unwrap();
        assert_eq!(result, json!(["", true, "undefined"]));
        assert!(next["session"].is_null());
    }
}

#[test]
fn login_map_credentials_become_headers_and_survive_session_roundtrip() {
    let source = source(BASE);
    let response = login(
        &source,
        json!({"token": "synthetic-token"}),
        r#"
        const map = source.getLoginInfoMap();
        if (map.token !== map.get('token')) throw new Error('inconsistent token');
        source.putLoginHeader(JSON.stringify({Authorization: 'Bearer ' + map.token, Cookie: 'sid=synthetic'}));
        'ok'
    "#,
        Value::Null,
    );
    assert_eq!(response["ok"], true, "{response}");
    assert_eq!(response["data"]["result"], "ok");
    let session: ExecuteSession = serde_json::from_value(response["session"].clone()).unwrap();
    let source: BookSource = serde_json::from_value(source).unwrap();
    let (spec, delta) = with_active_session(Some(&session), BASE, |_| {
        analyze_url("/protected", "", 1, BASE, &source).unwrap()
    });
    for (name, expected) in [
        ("authorization", "Bearer synthetic-token"),
        ("cookie", "sid=synthetic"),
    ] {
        assert!(
            spec.headers
                .iter()
                .any(|(key, value)| key.eq_ignore_ascii_case(name) && value == expected),
            "missing {name}"
        );
    }
    assert!(
        delta.is_none(),
        "reading authentication must not mutate session"
    );
}

#[test]
fn independent_logins_and_source_storage_do_not_leak_credentials() {
    let first = login(
        &source(BASE),
        json!({"token": "alice"}),
        "source.put('saved-token', source.getLoginInfoMap().token); 'ok'",
        Value::Null,
    );
    assert_eq!(first["ok"], true, "{first}");
    let other = login(
        &source(BASE),
        json!({"token": "bob"}),
        "JSON.stringify([source.getLoginInfoMap().token, source.get('saved-token')])",
        Value::Null,
    );
    assert_eq!(other["ok"], true, "{other}");
    let values: Value = serde_json::from_str(other["data"]["result"].as_str().unwrap()).unwrap();
    assert_eq!(values, json!(["bob", ""]));
    let restored = login(
        &source(BASE),
        json!({}),
        "source.get('saved-token')",
        first["session"].clone(),
    );
    assert_eq!(restored["data"]["result"], "alice");
    let different_source = login(
        &source("https://other-login.test/"),
        json!({}),
        "source.get('saved-token')",
        first["session"].clone(),
    );
    assert_eq!(different_source["ok"], true, "{different_source}");
    assert_eq!(different_source["data"]["result"], "");
}

#[test]
fn failed_login_does_not_publish_partial_authentication_state() {
    let source = source(BASE);
    let original = login(&source, json!({"token": "old"}),
        "source.putLoginHeader(JSON.stringify({Authorization: source.getLoginInfoMap().token})); 'ok'", Value::Null);
    assert_eq!(original["ok"], true, "{original}");
    for ending in ["throw new Error('synthetic failure')", "false"] {
        let failed = login(&source, json!({"token": "new"}), &format!(
            "source.putLoginHeader(JSON.stringify({{Authorization: source.getLoginInfoMap().token}})); {ending}"
        ), original["session"].clone());
        assert_eq!(failed["ok"], false, "{failed}");
        assert_eq!(failed["error"]["kind"], "auth_required");
        assert!(
            failed.get("session").is_none(),
            "failed operation must not publish a session delta"
        );
        let restored = login(
            &source,
            json!({}),
            "source.getLoginHeaderMap().get('Authorization')",
            original["session"].clone(),
        );
        assert_eq!(restored["ok"], true, "{restored}");
        assert_eq!(restored["data"]["result"], "old");
        assert!(restored["session"].is_null());
    }
}

#[test]
fn rejected_header_update_preserves_saved_authentication_in_login_action() {
    let source = source(BASE);
    let original = login(
        &source,
        json!({}),
        "source.putLoginHeader('{\"Authorization\":\"old\",\"Cookie\":\"sid=old\"}'); 'ok'",
        Value::Null,
    );
    assert_eq!(original["ok"], true, "{original}");
    let response = login(
        &source,
        json!({"token": "new"}),
        r#"
        let errorName = '';
        try { source.putLoginHeader(JSON.stringify({Authorization: source.getLoginInfoMap().token, Cookie: 'sid=new; broken'})); }
        catch (error) { errorName = error.name; }
        JSON.stringify([errorName, source.getLoginHeaderMap().get('Authorization'), source.getLoginHeaderMap().get('Cookie')])
    "#,
        original["session"].clone(),
    );
    assert_eq!(response["ok"], true, "{response}");
    let values: Value = serde_json::from_str(response["data"]["result"].as_str().unwrap()).unwrap();
    assert_eq!(values, json!(["TypeError", "old", "sid=old"]));
    assert!(
        response["session"].is_null(),
        "rejected mutation must leave state unchanged"
    );
}
