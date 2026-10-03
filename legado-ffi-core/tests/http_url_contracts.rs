use reader_parser::crawler::session::with_active_session;
use reader_parser::ffi::reader_set_host_services;
use reader_parser::host_services::ReaderHostServices;
use reader_parser::parser::js::eval_js;
use serde_json::json;
use std::cell::RefCell;
use std::ffi::{c_void, CStr};

const PSL: &str = "// ===BEGIN ICANN DOMAINS===\ncom\nuk\nco.uk\nck\n*.ck\n!www.ck\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n";
thread_local! {
    static PROVIDER: RefCell<(usize, serde_json::Value)> = RefCell::new((0, json!(null)));
}

unsafe extern "C" fn provide(
    _: *mut c_void,
    operation: *const safer_ffi::c_char,
    _: *const safer_ffi::c_char,
    output: *mut u8,
    capacity: usize,
) -> i32 {
    let operation = unsafe { CStr::from_ptr(operation.cast()) }.to_bytes();
    let response = PROVIDER.with(|cell| {
        let mut state = cell.borrow_mut();
        state.0 += 1;
        if operation == b"url.public_suffix.load" {
            state.1.to_string()
        } else {
            json!({"ok":false,"error":{"kind":"unsupported","message":"unknown operation"}})
                .to_string()
        }
    });
    if response.len() > capacity {
        return -2;
    }
    unsafe { std::ptr::copy_nonoverlapping(response.as_ptr(), output, response.len()) };
    response.len() as i32
}

struct Binding;
impl Drop for Binding {
    fn drop(&mut self) {
        unsafe { reader_set_host_services(None) };
    }
}
fn bind(response: serde_json::Value, capacity: usize) -> Binding {
    PROVIDER.with(|cell| *cell.borrow_mut() = (0, response));
    let services = ReaderHostServices {
        abi_version: 1,
        call: Some(provide),
        user_data: std::ptr::null_mut(),
        max_response_bytes: capacity,
    };
    assert_eq!(unsafe { reader_set_host_services(Some(&services)) }, 0);
    Binding
}
fn good_response(text: &str) -> serde_json::Value {
    json!({"ok":true,"data":{"revision":"test-v1","text":text}})
}
fn calls() -> usize {
    PROVIDER.with(|cell| cell.borrow().0)
}
fn evaluate(script: &str) -> String {
    eval_js(script, "", "https://example.com/").unwrap()
}

#[test]
fn basic_parsing_is_canonical_http_only_and_does_not_load_psl() {
    let _binding = bind(good_response(PSL), 2 * 1024 * 1024);
    assert_eq!(
        evaluate(
            r#"
        const nativeURL = globalThis.URL;
        const ji = new JavaImporter();
        ji.importClass(Packages.okhttp3.HttpUrl);
        JSON.stringify([
            ji.HttpUrl.parse('HTTPS://Example.COM:443/a/../b').toString(),
            ji.HttpUrl.parse('https://example.com:8443/').host,
            ji.HttpUrl.parse('ftp://example.com'),
            ji.HttpUrl.parse('file:///tmp/a'),
            ji.HttpUrl.parse('/relative'),
            globalThis.URL === nativeURL, typeof globalThis.HttpUrl
        ]);
    "#
        ),
        r#"["https://example.com/b","example.com",null,null,null,true,"undefined"]"#
    );
    assert_eq!(calls(), 0);
}

#[test]
fn ip_and_single_label_hosts_need_no_psl() {
    let _binding = bind(good_response(PSL), 2 * 1024 * 1024);
    assert_eq!(
        evaluate(
            r#"
        JSON.stringify(['http://127.0.0.1', 'http://[::1]', 'http://localhost']
            .map(url => Packages.okhttp3.HttpUrl.parse(url).topPrivateDomain()));
    "#
        ),
        "[null,null,null]"
    );
    assert_eq!(calls(), 0);
}

#[test]
fn suffix_rules_include_private_wildcard_and_exception_rules_and_load_once() {
    let _binding = bind(good_response(PSL), 2 * 1024 * 1024);
    assert_eq!(
        evaluate(
            r#"
        JSON.stringify(['a.example.co.uk','a.user.github.io','co.uk','github.io',
            'a.b.ck','b.ck','a.www.ck'].map(host =>
                Packages.okhttp3.HttpUrl.parse('https://' + host).topPrivateDomain()));
    "#
        ),
        r#"["example.co.uk","user.github.io",null,null,"a.b.ck",null,"www.ck"]"#
    );
    assert_eq!(calls(), 1);
}

#[test]
fn cache_is_shared_across_evaluations_in_a_session_but_not_between_sessions() {
    let _binding = bind(good_response(PSL), 2 * 1024 * 1024);
    let script = "Packages.okhttp3.HttpUrl.parse('https://a.user.github.io').topPrivateDomain()";
    with_active_session(None, "https://example.com", |_| {
        assert_eq!(evaluate(script), "user.github.io");
        assert_eq!(evaluate(script), "user.github.io");
        assert_eq!(calls(), 1);
    });
    PROVIDER.with(|cell| {
        cell.borrow_mut().1 =
            good_response("// ===BEGIN ICANN DOMAINS===\nio\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\n// ===END PRIVATE DOMAINS===\n")
    });
    with_active_session(None, "https://example.com", |_| {
        assert_eq!(evaluate(script), "github.io");
    });
    assert_eq!(calls(), 2);
}

#[test]
fn provider_errors_invalid_data_and_overflow_are_not_domain_null() {
    let script = r#"
        try { Packages.okhttp3.HttpUrl.parse('https://example.com').topPrivateDomain(); }
        catch (error) { error.kind; }
    "#;
    for (response, limit, expected) in [
        (
            json!({"ok":false,"error":{"kind":"unavailable","message":"missing PSL"}}),
            4096,
            "unavailable",
        ),
        (good_response("invalid"), 4096, "invalid_response"),
        (
            good_response("// ===BEGIN ICANN DOMAINS===\ncom\n"),
            4096,
            "invalid_response",
        ),
        (
            json!({"ok":true,"data":{"text":PSL}}),
            4096,
            "invalid_response",
        ),
        (good_response(PSL), 32, "response_too_large"),
        (
            good_response(&"x".repeat(512 * 1024 + 1)),
            2 * 1024 * 1024,
            "limit_exceeded",
        ),
    ] {
        let _binding = bind(response, limit);
        assert_eq!(evaluate(script), expected);
        assert_eq!(calls(), 1);
    }
}

#[test]
fn missing_host_registration_is_an_explicit_error() {
    unsafe { reader_set_host_services(None) };
    assert_eq!(
        evaluate(
            r#"
        try { Packages.okhttp3.HttpUrl.parse('https://example.com').topPrivateDomain(); }
        catch (error) { error.kind; }
    "#
        ),
        "unavailable"
    );
}

#[test]
fn ipv6_host_is_unbracketed_and_domain_results_drop_dns_trailing_dot() {
    let _binding = bind(good_response(PSL), 2 * 1024 * 1024);
    assert_eq!(
        evaluate(
            r#"
        const HttpUrl = Packages.okhttp3.HttpUrl;
        JSON.stringify([
            HttpUrl.parse('http://[::1]:8080/').host,
            HttpUrl.parse('http://[::1]:8080/').toString(),
            HttpUrl.parse('https://a.example.com.').topPrivateDomain(),
            HttpUrl.parse('https://co.uk.').topPrivateDomain()
        ]);
    "#
        ),
        r#"["::1","http://[::1]:8080/","example.com",null]"#
    );
    assert_eq!(calls(), 1);
}
