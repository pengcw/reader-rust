use reader_parser::ffi::reader_set_host_services;
use reader_parser::host_services::ReaderHostServices;
use reader_parser::parser::js::eval_js;
use std::cell::Cell;
use std::ffi::c_void;

thread_local! {
    static HOST_CALLS: Cell<usize> = const { Cell::new(0) };
}

unsafe extern "C" fn unexpected_host_call(
    _: *mut c_void,
    _: *const safer_ffi::c_char,
    _: *const safer_ffi::c_char,
    _: *mut u8,
    _: usize,
) -> i32 {
    HOST_CALLS.with(|count| count.set(count.get() + 1));
    -1
}

struct Binding;
impl Drop for Binding {
    fn drop(&mut self) {
        unsafe { reader_set_host_services(None) };
    }
}
fn bind() -> Binding {
    HOST_CALLS.with(|count| count.set(0));
    let services = ReaderHostServices {
        abi_version: 1,
        call: Some(unexpected_host_call),
        user_data: std::ptr::null_mut(),
        max_response_bytes: 0,
    };
    assert_eq!(unsafe { reader_set_host_services(Some(&services)) }, 0);
    Binding
}
fn evaluate(script: &str) -> String {
    eval_js(script, "", "https://example.com/").unwrap()
}

#[test]
fn basic_parsing_is_canonical_http_only_and_needs_no_host_data() {
    let _binding = bind();
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
    assert_eq!(HOST_CALLS.with(Cell::get), 0);
}

#[test]
fn ipv6_host_is_unbracketed_while_url_preserves_brackets() {
    assert_eq!(
        evaluate(
            r#"
            const value = Packages.okhttp3.HttpUrl.parse('http://[::1]:8080/');
            JSON.stringify([value.host, value.toString()]);
        "#
        ),
        r#"["::1","http://[::1]:8080/"]"#
    );
}

#[test]
fn private_domain_is_explicitly_unsupported_without_initialization_or_callback() {
    let _binding = bind();
    assert_eq!(
        evaluate(
            r#"
            JSON.stringify(['https://a.example.co.uk','https://a.user.github.io',
                'http://127.0.0.1'].map(url => {
                try { return Packages.okhttp3.HttpUrl.parse(url).topPrivateDomain(); }
                catch (error) { return error.kind; }
            }));
        "#
        ),
        r#"["unsupported","unsupported","unsupported"]"#
    );
    assert_eq!(HOST_CALLS.with(Cell::get), 0);
}

#[test]
fn existing_source_can_catch_unsupported_domain_lookup_and_fall_back() {
    assert_eq!(
        evaluate(
            r#"
            const ji = new JavaImporter(Packages.okhttp3.HttpUrl);
            function getSubDomain(url) {
                try { return ji.HttpUrl.parse(url).topPrivateDomain(); }
                catch (_) { return url; }
            }
            getSubDomain('https://sub.example.com');
        "#
        ),
        "https://sub.example.com"
    );
}
