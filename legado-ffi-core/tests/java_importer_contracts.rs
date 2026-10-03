use reader_parser::parser::js::eval_js;

fn evaluate(script: &str) -> String {
    eval_js(script, "", "https://example.com/").unwrap()
}

#[test]
fn import_class_reuses_package_import_and_supports_function_and_object_facades() {
    let result = evaluate(
        r#"
        const ji = new JavaImporter();
        const chained = ji.importClass(
            Packages.java.lang.String, Packages.android.util.Base64
        ) === ji;
        let encoded;
        with (ji) {
            encoded = Base64.encodeToString(String('test').getBytes('UTF-8'), 2);
        }
        JSON.stringify([chained, ji.importClass === ji.importPackage, encoded]);
        "#,
    );
    assert_eq!(result, r#"[true,true,"dGVzdA=="]"#);
}

#[test]
fn local_imports_preserve_native_globals_and_existing_byte_conversion() {
    let result = evaluate(
        r#"
        const nativeString = String;
        const globals = [globalThis.importClass, globalThis.importPackage, globalThis.URL];
        const ji = new JavaImporter();
        ji.importClass(Packages.java.lang.String, Packages.android.util.Base64);
        JSON.stringify([
            String === nativeString,
            String.fromCharCode(65),
            new String('x') instanceof String,
            globals[0] === globalThis.importClass,
            globals[1] === globalThis.importPackage,
            globals[2] === globalThis.URL,
            java.bytesToStr([65, 66], 'UTF-8')
        ]);
        "#,
    );
    assert_eq!(result, r#"[true,"A",true,true,true,true,"AB"]"#);
}

#[test]
fn constructor_and_package_import_remain_compatible_with_bound_methods() {
    let result = evaluate(
        r#"
        const ji = new JavaImporter(Packages.java.net);
        const importClass = ji.importClass;
        const importPackage = ji.importPackage;
        const classTarget = importClass(Packages.java.lang.String) === ji;
        const packageTarget = importPackage(Packages.android.util) === ji;
        JSON.stringify([
            classTarget, packageTarget,
            ji.URLEncoder.encode('a b', 'UTF-8'),
            ji.String('hello').getBytes('UTF-8').join(','),
            ji.Base64.encodeToString([65], 2)
        ]);
        "#,
    );
    assert_eq!(result, r#"[true,true,"a+b","104,101,108,108,111","QQ=="]"#);
}

#[test]
fn imports_are_isolated_between_instances_and_evaluations() {
    let result = evaluate(
        r#"
        const first = new JavaImporter();
        const second = new JavaImporter();
        first.importClass(Packages.java.lang.String);
        second.importClass(Packages.android.util.Base64);
        JSON.stringify([
            Object.hasOwn(first, 'String'), Object.hasOwn(first, 'Base64'),
            Object.hasOwn(second, 'String'), Object.hasOwn(second, 'Base64')
        ]);
        "#,
    );
    assert_eq!(result, "[true,false,false,true]");
    assert_eq!(
        evaluate("Object.hasOwn(new JavaImporter(), 'String')"),
        "false"
    );
}
