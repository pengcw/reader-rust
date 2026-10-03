use reader_parser::parser::js::eval_js;

fn evaluate(script: &str) -> String {
    eval_js(script, "", "https://base.example/books/").unwrap()
}

#[test]
fn local_url_import_supports_function_and_constructor_calls() {
    let result = evaluate(
        r#"
        const ji = new JavaImporter();
        ji.importClass(Packages.java.net.URL);
        let result;
        with (ji) {
            const spec = 'https://sub.example.com:8443/a%20b?q=1#part';
            const first = URL(spec);
            const second = new URL(spec);
            result = JSON.stringify([
                first.host, first.path, first.pathname,
                first.getHost(), first.getPath(), first.toString(),
                second instanceof URL, second.getHost(), second.getPath()
            ]);
        }
        result;
        "#,
    );
    assert_eq!(
        result,
        r#"["sub.example.com","/a%20b","/a%20b","sub.example.com","/a%20b","https://sub.example.com:8443/a%20b?q=1#part",true,"sub.example.com","/a%20b"]"#
    );
}

#[test]
fn url_parsing_reuses_existing_helper_for_ftp_file_and_ipv6() {
    let result = evaluate(
        r#"
        const ji = new JavaImporter(Packages.java.net);
        JSON.stringify([
            'ftp://example.com/archive',
            'file:///tmp/book.txt',
            'https://[::1]:8443/chapter'
        ].map(spec => {
            const parsed = java.toURL(spec);
            const value = ji.URL(spec);
            return [value.getHost() === parsed.host,
                value.getPath() === parsed.pathname, value.path];
        }));
        "#,
    );
    assert_eq!(
        result,
        r#"[[true,true,"/archive"],[true,true,"/tmp/book.txt"],[true,true,"/chapter"]]"#
    );
}

#[test]
fn url_constructor_does_not_silently_resolve_relative_or_invalid_inputs() {
    let result = evaluate(
        r#"
        const URL = Packages.java.net.URL;
        JSON.stringify(['chapter/1', '//example.com/path', '', 'https://[invalid]']
            .map(spec => {
                try { new URL(spec); return false; }
                catch (_) { return true; }
            }));
        "#,
    );
    assert_eq!(result, "[true,true,true,true]");
}

#[test]
fn url_import_keeps_globals_and_other_importers_unchanged() {
    let result = evaluate(
        r#"
        const nativeURL = globalThis.URL;
        const nativeString = String;
        const first = new JavaImporter();
        const second = new JavaImporter();
        first.importClass(Packages.java.net.URL);
        const value = first.URL('https://example.com/chapter');
        value.host = 'changed.example';
        value.path = '/changed';
        JSON.stringify([
            globalThis.URL === nativeURL, String === nativeString,
            String.fromCharCode(65), Object.hasOwn(second, 'URL'),
            value.getHost(), value.getPath(),
            Object.hasOwn(globalThis, 'HttpUrl')
        ]);
        "#,
    );
    assert_eq!(
        result,
        r#"[true,true,"A",false,"example.com","/chapter",false]"#
    );
}
