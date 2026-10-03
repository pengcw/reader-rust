//! Bounded MessageDigest compatibility backed by the existing Rust algorithms.
use reader_parser::parser::js::eval_js;
use serde_json::{json, Value};

fn evaluate(script: &str) -> Value {
    let script = format!(
        "const MD = Packages.java.security.MessageDigest;\n\
         const hex = bytes => bytes.map(b => (b & 255).toString(16).padStart(2, '0')).join('');\n{script}"
    );
    let output = eval_js(&script, "", "https://digest.test/").unwrap();
    serde_json::from_str(&output).unwrap()
}

#[test]
fn existing_algorithms_have_known_vectors_lengths_and_canonical_names() {
    let result = evaluate(
        r#"
        ['md5', 'sha1', 'SHA-256', 'sha384', 'SHA-512'].map(name => {
            const md = MD.getInstance(name);
            return [md.getAlgorithm(), md.getDigestLength(), hex(md.digest([97,98,99]))];
        });
    "#,
    );
    assert_eq!(result, json!([
        ["MD5", 16, "900150983cd24fb0d6963f7d28e17f72"],
        ["SHA-1", 20, "a9993e364706816aba3e25717850c26c9cd0d89d"],
        ["SHA-256", 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
        ["SHA-384", 48, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"],
        ["SHA-512", 64, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"]
    ]));
}

#[test]
fn binary_input_keeps_non_utf8_bytes_and_output_is_java_signed_bytes() {
    let result = evaluate(
        r#"
        const md = MD.getInstance('MD5');
        const signed = md.digest([0,-1,-128,127]);
        [hex(signed), hex(md.digest(new Uint8Array([0,255,128,127]))),
         signed.every(b => Number.isInteger(b) && b >= -128 && b <= 127),
         signed.some(b => b < 0)];
    "#,
    );
    assert_eq!(
        result,
        json!([
            "35913419231430075897c28e5e159b65",
            "35913419231430075897c28e5e159b65",
            true,
            true
        ])
    );
}

#[test]
fn updates_accept_single_byte_and_slice_then_digest_resets_state() {
    let result = evaluate(
        r#"
        const md = MD.getInstance('MD5');
        md.update(97); md.update([0,98,99,0], 1, 2);
        [hex(md.digest()), hex(md.digest())];
    "#,
    );
    assert_eq!(
        result,
        json!([
            "900150983cd24fb0d6963f7d28e17f72",
            "d41d8cd98f00b204e9800998ecf8427e"
        ])
    );
}

#[test]
fn digest_input_appends_to_updates_and_reset_discards_them() {
    let result = evaluate(
        r#"
        const md = MD.getInstance('MD5');
        md.update([97]); const appended = hex(md.digest([98,99]));
        md.update([120]); md.reset();
        [appended, hex(md.digest([97,98,99]))];
    "#,
    );
    assert_eq!(
        result,
        json!([
            "900150983cd24fb0d6963f7d28e17f72",
            "900150983cd24fb0d6963f7d28e17f72"
        ])
    );
}

#[test]
fn unsupported_algorithms_overloads_and_invalid_bytes_fail_without_state_loss() {
    let result = evaluate(
        r#"
        const md = MD.getInstance('MD5'); md.update([97]);
        const invalid = [
            () => MD.getInstance('SHA-224'), () => MD.getInstance('MD5', 'provider'),
            () => md.update([98], -1, 1), () => md.update([98], 0, 2),
            () => md.update([1.5]), () => md.update([256]), () => md.update('abc'),
            () => md.update([98], 0), () => md.digest([], 0, 0),
            () => md.digest(98), () => md.reset(1)
        ];
        const rejected = invalid.map(f => {try {f(); return false;} catch (_) {return true;}});
        [rejected, hex(md.digest([98,99]))];
    "#,
    );
    assert_eq!(
        result,
        json!([vec![true; 11], "900150983cd24fb0d6963f7d28e17f72"])
    );
}

#[test]
fn cumulative_byte_budget_rejects_growth_and_digest_releases_budget() {
    let result = evaluate(
        r#"
        const md = MD.getInstance('MD5'); md.update(new Array(16384).fill(97));
        let updateRejected = false, digestRejected = false;
        try {md.update(98);} catch (_) {updateRejected = true;}
        try {md.digest([98]);} catch (_) {digestRejected = true;}
        [updateRejected, digestRejected, md.digest().length, hex(md.digest())];
    "#,
    );
    assert_eq!(
        result,
        json!([true, true, 16, "d41d8cd98f00b204e9800998ecf8427e"])
    );
}

#[test]
fn java_string_encoding_and_importer_reuse_the_same_facade() {
    let result = evaluate(
        r#"
        const imported = new JavaImporter(Packages.java.security);
        const md = imported.MessageDigest.getInstance('MD5');
        [hex(md.digest(new Packages.java.lang.String('七猫小说').getBytes('UTF-8'))),
         java.digestHex('abc', 'MD5')];
    "#,
    );
    assert_eq!(
        result,
        json!([
            "d6e189d1be97baa43ef93a483945b8ac",
            "900150983cd24fb0d6963f7d28e17f72"
        ])
    );
}
