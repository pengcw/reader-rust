//! Experimental offline HTML input interaction, not a browser/login implementation.
use serde_json::{json, Value};
use std::time::Duration;

fn exchange(request: String) -> String {
    match serde_json::from_str::<Value>(&request) {
        Ok(arguments) => match crate::parser::js::with_browser_host_wait(|| {
            crate::host_services::call(
                "browser",
                &json!({
                    "action":"exchange", "snapshot":arguments
                }),
            )
        }) {
            Ok(response) => response.to_string(),
            Err(_) => {
                json!({"ok":false,"error":{"message":"interaction wait expired"}}).to_string()
            }
        },
        Err(_) => json!({"ok":false,"error":{"message":"invalid interaction message"}}).to_string(),
    }
}

/// Native Await entry: opt-in host and local typed HTML only.
pub(crate) fn await_uri(url: &str, title: &str) -> Value {
    let unavailable = || {
        json!({"ok":false,"error":{
            "kind":"unsupported","message":"当前仅支持网页只读预览，不支持等待网页交互验证"
        }})
    };
    if !url.starts_with("data:text/html;") || url.len() > 2 * 1024 * 1024 {
        return unavailable();
    }
    // Probe is immediate and deliberately outside the trusted wait scope.
    let capabilities = crate::host_services::call("browser", &json!({"action":"probe"}));
    if capabilities["ok"] != true || capabilities["data"]["offlineHtml"] != true {
        return unavailable();
    }
    let result = (|| -> anyhow::Result<Value> {
        // Reuse the crawler's typed Base64 decoder and allocation limit, no fetch.
        let spec = crate::crawler::RequestSpec {
            url: url.to_string(),
            method: ureq::http::Method::GET,
            headers: Vec::new(),
            body: None,
            charset: None,
            retry: 0,
            proxy: None,
            response_type: Some("base64".to_string()),
            render_with_rakers: false,
            render_timeout_ms: None,
            blocked_scripts: Vec::new(),
            body_js: None,
        };
        let response = crate::crawler::execute_request_spec_limited(
            &crate::crawler::HttpClient::standalone(),
            &spec,
            Some(1024 * 1024),
        )
        .map_err(|_| anyhow::anyhow!("invalid offline HTML"))?;
        let html = String::from_utf8(response.body)?;
        run_titled(&html, title)
    })();
    match result {
        Ok(value) if value["cancelled"] == true => json!({"ok":false,"error":{
            "kind":"cancelled","message":"网页交互已取消"
        }}),
        Ok(value) => json!({"ok":true,"data":value}),
        Err(_) => json!({"ok":false,"error":{
            "kind":"interaction_failed","message":"离线网页交互失败"
        }}),
    }
}

pub(crate) fn run(html: &str) -> anyhow::Result<Value> {
    run_titled(html, "网页交互")
}

fn run_titled(html: &str, title: &str) -> anyhow::Result<Value> {
    anyhow::ensure!(html.len() <= 1024 * 1024, "interaction HTML exceeds 1 MiB");
    let page_id = format!("page{:016x}", rand::random::<u64>());
    let projection = include_str!("js_browser_projection.js");
    let title = serde_json::to_string(title)?;
    let script = format!(
        r#"
(async function(host) {{
    const page = ({projection})('{page_id}');
    // Permit short nested Promise chains to settle before the next snapshot.
    async function flushMicrotasks() {{
        for (let i = 0; i < 8; i++) await Promise.resolve();
    }}
    for (let step = 0; step < 32; step++) {{
        const snapshot = page.snapshot();
        snapshot.title = {title};
        const response = JSON.parse(host(JSON.stringify(snapshot)));
        if (!response.ok) throw new Error('interaction host failed');
        const event = response.data;
        if (!event || event.revision !== snapshot.revision) continue;
        if (event.kind === 'cancel') return JSON.stringify({{cancelled: true}});
        if (event.kind === 'finish') return JSON.stringify({{cancelled: false, html: page.body()}});
        if (event.kind === 'input') page.apply(event.uri, event.value, 'input');
        if (event.kind === 'click') page.apply(event.uri, undefined, 'click');
        await flushMicrotasks();
    }}
    throw new Error('interaction step limit exceeded');
}})
"#
    );
    struct Offline;
    impl rakers::HttpTransport for Offline {
        fn execute(&self, _: rakers::HttpRequest) -> Result<rakers::HttpResponse, String> {
            Err("network is disabled for offline interaction".to_string())
        }
    }
    // Each script keeps its compute deadline. Only the opt-in final-script host
    // bridge excludes UI waiting; worker timeout remains the hard-stop fallback.
    let config = rakers::HttpConfig {
        max_requests: Some(0),
        transport: Some(std::sync::Arc::new(Offline)),
        render_timeout: None,
        ..Default::default()
    };
    let rendered = rakers::with_final_script_host(exchange, || {
        rakers::render_detailed(
            html,
            false,
            None,
            &config,
            false,
            None,
            Some(Duration::from_secs(3)),
            Some(&script),
        )
    })?;
    let result = rendered
        .script_result
        .ok_or_else(|| anyhow::anyhow!("interaction script failed"))?;
    Ok(serde_json::from_str(&result)?)
}
