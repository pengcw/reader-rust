//! Login property reads supplement, rather than replace, the native Map API.
use reader_parser::parser::js::eval_js_with_bindings;
use serde_json::{json, Value};
use std::collections::HashMap;

fn evaluate(login: Option<Value>, script: &str) -> Value {
    let mut bindings = HashMap::new();
    if let Some(login) = login {
        bindings.insert("loginInfo".to_string(), login);
    }
    let output = eval_js_with_bindings(script, "", "https://login-map.test/", &bindings).unwrap();
    serde_json::from_str(&output).unwrap()
}

#[test]
fn ordinary_login_keys_support_method_and_property_reads() {
    let value = evaluate(
        Some(json!(
            r#"{"token":"synthetic-token","手动填写番茄token(可不填)":"synthetic-fq","a.b":"dot-value","":"empty-key"}"#
        )),
        r#"
        const map = source.getLoginInfoMap();
        [map.get('token'), map.token,
         map.get('手动填写番茄token(可不填)'), map['手动填写番茄token(可不填)'],
         map['a.b'], map['']];
    "#,
    );
    assert_eq!(
        value,
        json!([
            "synthetic-token",
            "synthetic-token",
            "synthetic-fq",
            "synthetic-fq",
            "dot-value",
            "empty-key"
        ])
    );
}

#[test]
fn native_map_identity_methods_iteration_and_mutation_are_preserved() {
    let value = evaluate(
        Some(json!({"token": "initial"})),
        r#"
        const map = source.getLoginInfoMap();
        const same = map.set('token', 'updated') === map;
        let callbackMapIsOriginal = false;
        map.forEach((value, key, owner) => {callbackMapIsOriginal = owner === map;});
        const before = [map instanceof Map, map.get === Map.prototype.get,
            map.set === Map.prototype.set, same, callbackMapIsOriginal,
            Map.prototype.get.call(map, 'token'), map.token, [...map]];
        map.delete('token');
        before.push(map.size, typeof map.token, typeof map.get('token'));
        before;
    "#,
    );
    assert_eq!(
        value,
        json!([
            true,
            true,
            true,
            true,
            true,
            "updated",
            "updated",
            [["token", "updated"]],
            0,
            "undefined",
            "undefined"
        ])
    );
}

#[test]
fn reserved_names_cannot_hide_methods_or_pollute_prototypes() {
    let value = evaluate(
        Some(json!(
            r#"{"get":"get-value","size":"size-value","constructor":"constructor-value","__proto__":"proto-value","token":"token-value"}"#
        )),
        r#"
        const map = source.getLoginInfoMap();
        [map.get === Map.prototype.get, map.size, map.constructor === Map,
         Object.getPrototypeOf(map) === Map.prototype, map.__proto__ === Map.prototype,
         map.get('get'), map.get('size'), map.get('constructor'), map.get('__proto__'),
         map.token, Object.prototype.hasOwnProperty.call(Map.prototype, 'token')];
    "#,
    );
    assert_eq!(
        value,
        json!([
            true,
            5,
            true,
            true,
            true,
            "get-value",
            "size-value",
            "constructor-value",
            "proto-value",
            "token-value",
            false
        ])
    );
}

#[test]
fn property_accessors_do_not_change_global_map_or_serialization() {
    let value = evaluate(
        Some(json!({"token": "test"})),
        r#"
        const map = source.getLoginInfoMap();
        const descriptor = Object.getOwnPropertyDescriptor(map, 'token');
        [typeof new Map([['token', 'other']]).token, Object.keys(map), JSON.stringify(map),
         !!descriptor && typeof descriptor.get === 'function',
         !!descriptor && descriptor.enumerable === false,
         typeof map.missing, typeof map.get('missing')];
    "#,
    );
    assert_eq!(
        value,
        json!(["undefined", [], "{}", true, true, "undefined", "undefined"])
    );
}

#[test]
fn local_mutation_does_not_write_back_login_info_or_adapt_new_keys() {
    let value = evaluate(
        Some(json!({"token": "saved"})),
        r#"
        const map = source.getLoginInfoMap();
        map.set('token', 'local'); map.set('newKey', 'new-value');
        [map.token, map.get('newKey'), typeof map.newKey,
         source.getLoginInfoMap().token, JSON.parse(source.getLoginInfo()).token];
    "#,
    );
    assert_eq!(
        value,
        json!(["local", "new-value", "undefined", "saved", "saved"])
    );
}

#[test]
fn absent_and_invalid_login_info_keep_existing_null_behavior() {
    for login in [
        None,
        Some(Value::Null),
        Some(json!("not JSON")),
        Some(json!(42)),
        Some(json!(true)),
        Some(json!("null")),
    ] {
        assert_eq!(
            evaluate(login, "source.getLoginInfoMap() === null"),
            json!(true)
        );
    }
    assert_eq!(
        evaluate(
            Some(json!({})),
            "const map = source.getLoginInfoMap(); [map instanceof Map, map.size]"
        ),
        json!([true, 0])
    );
}

#[test]
fn existing_value_coercion_and_array_input_are_not_tightened() {
    let value = evaluate(
        Some(json!({"number": 42, "boolean": true, "nil": null})),
        r#"
        const map = source.getLoginInfoMap();
        [map.get('number'), map.number, map.get('boolean'), map.boolean, map.get('nil'), map.nil];
    "#,
    );
    assert_eq!(value, json!(["42", "42", "true", "true", "null", "null"]));
    // This is the host's existing array treatment, not a claim of Gson parity.
    assert_eq!(
        evaluate(
            Some(json!(["array-value"])),
            "JSON.stringify(source.getLoginInfoMap().get('0'))"
        ),
        json!("array-value")
    );
}
