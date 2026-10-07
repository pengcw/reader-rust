//! Legado native login forms accept unprefixed login scripts.
use reader_parser::executor::execute;
use serde_json::{json, Value};

#[test]
fn login_form_accepts_plain_script_and_custom_action() {
    for prefix in ["", "@js:", "js:"] {
        let source = json!({
            "bookSourceUrl": "https://fixture.invalid",
            "bookSourceName": "plain login fixture",
            "loginUi": "[{\"name\":\"user\",\"type\":\"text\"}]",
            "loginUrl": format!("{prefix}function login() {{ return result.user; }} function choose() {{ return 'chosen'; }}")
        });
        for (action, expected) in [(None, "fixture"), (Some("choose()"), "chosen")] {
            let mut request = json!({"api":2,"op":"login","params":{"values":{"user":"fixture"}}});
            if let Some(action) = action {
                request["params"]["action"] = json!(action);
            }
            let result: Value =
                serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap();
            assert_eq!(result["ok"], true, "{result}");
            assert_eq!(result["data"]["result"], expected, "{result}");
        }
    }
}

#[test]
fn login_aes_shorthand_matches_ecb_reference_vector() {
    // openssl enc -aes-128-ecb，key 的 UTF-8 字节，PKCS#7（AES 下对应 PKCS5Padding）。
    for algorithm in ["AES", "aes", "AES/ECB/PKCS5Padding"] {
        let source = json!({
            "bookSourceUrl": "https://fixture.invalid", "bookSourceName": "AES fixture",
            "loginUi": "[{\"name\":\"user\"}]",
            "loginUrl": format!("function login() {{ const c=java.createSymmetricCrypto('{algorithm}', '1234567890abcdef'); return c.encryptBase64('reader') + '|' + c.decryptStr('c18aQE3ri8nAg4QUUjAyDw=='); }}")
        });
        let result: Value = serde_json::from_str(&execute(
            &source.to_string(),
            r#"{"api":2,"op":"login","params":{"values":{}}}"#,
        ))
        .unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(
            result["data"]["result"], "c18aQE3ri8nAg4QUUjAyDw==|reader",
            "{result}"
        );
    }
}

#[test]
fn android_id_has_aes_key_shape_without_changing_device_id() {
    let source = json!({
        "bookSourceUrl": "https://fixture.invalid", "bookSourceName": "Android ID fixture",
        "loginUi": "[{\"name\":\"user\"}]",
        "loginUrl": "function login(){const id=java.androidId(); const c=java.createSymmetricCrypto('AES',id); return [id, java.androidId()===id, java.deviceID().length, c.decryptStr(c.encrypt('fixture'))].join('|');}"
    });
    let mut previous = None;
    for _ in 0..2 {
        let result: Value = serde_json::from_str(&execute(
            &source.to_string(),
            r#"{"api":2,"op":"login","params":{"values":{}}}"#,
        ))
        .unwrap();
        assert_eq!(result["ok"], true, "{result}");
        let output = result["data"]["result"].as_str().unwrap();
        let parts: Vec<_> = output.split('|').collect();
        assert_eq!(parts[0].len(), 16);
        assert!(parts[0].bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(&parts[1..], &["true", "36", "fixture"]);
        if let Some(previous) = &previous {
            assert_eq!(previous, output);
        }
        previous = Some(output.to_string());
    }
}

#[test]
fn login_toasts_are_displayed_without_leaking_to_next_call() {
    let source = json!({
        "bookSourceUrl": "https://fixture.invalid", "bookSourceName": "toast fixture",
        "loginUi": "[{\"name\":\"user\"}]",
        "loginUrl": "function login(){java.toast('尚未登录');java.longToast('请检查账号');return 'checked';}"
    });
    let first: Value = serde_json::from_str(&execute(
        &source.to_string(),
        r#"{"api":2,"op":"login","params":{"values":{}}}"#,
    ))
    .unwrap();
    assert_eq!(first["ok"], true, "{first}");
    assert_eq!(first["data"]["result"], "checked");
    assert_eq!(first["data"]["message"], "尚未登录\n请检查账号");
    let second: Value = serde_json::from_str(&execute(
        &source.to_string(),
        r#"{"api":2,"op":"login","params":{"values":{},"action":"'quiet'"}}"#,
    ))
    .unwrap();
    assert_eq!(second["data"]["message"], "登录脚本执行成功");
}

#[test]
fn browser_preview_returns_html_but_never_claims_interactive_verification() {
    use base64::Engine;
    let source =
        json!({"bookSourceUrl":"https://fixture.invalid", "bookSourceName":"preview fixture"});
    let html = "<html><body><h1>preview fixture</h1><script>document.body.innerHTML='<p>rendered fixture</p>';</script></body></html>";
    let data_url = format!(
        "data:text/html;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(html)
    );
    for (url, supplied) in [("https://fixture.invalid", html), (data_url.as_str(), "")] {
        let action = format!(
            "java.startBrowser({}, 'fixture', {})",
            json!(url),
            json!(supplied)
        );
        let response: Value = serde_json::from_str(&execute(
            &source.to_string(),
            &json!({"api":2,"op":"login","params":{"values":{},"action":action}}).to_string(),
        ))
        .unwrap();
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(response["data"]["preview"]["title"], "fixture");
        assert!(response["data"]["preview"]["html"]
            .as_str()
            .unwrap()
            .contains("rendered fixture"));
    }
    let quiet: Value = serde_json::from_str(&execute(
        &source.to_string(),
        r#"{"api":2,"op":"login","params":{"values":{},"action":"'quiet'"}}"#,
    ))
    .unwrap();
    assert!(quiet["data"]["preview"].is_null());
    let await_result: Value = serde_json::from_str(&execute(&source.to_string(), r#"{"api":2,"op":"login","params":{"values":{},"action":"java.startBrowserAwait('https://fixture.invalid','verification')"}}"#)).unwrap();
    assert_eq!(await_result["ok"], false);
    assert!(await_result["error"]["message"]
        .as_str()
        .unwrap()
        .contains("不支持等待网页交互验证"));
}

#[test]
fn login_web_urls_are_not_executed_as_scripts() {
    for (ui, url) in [
        ("[]", "/login"),
        ("[{\"name\":\"user\"}]", "https://fixture.invalid/login"),
    ] {
        let source = json!({"bookSourceUrl":"https://fixture.invalid", "bookSourceName":"web fixture", "loginUi":ui, "loginUrl":url});
        let result: Value = serde_json::from_str(&execute(
            &source.to_string(),
            r#"{"api":2,"op":"login","params":{"values":{}}}"#,
        ))
        .unwrap();
        assert_eq!(result["ok"], false, "{result}");
        assert_eq!(result["error"]["auth"]["mode"], "web", "{result}");
    }
}
