use flate2::{write::DeflateEncoder, write::ZlibEncoder, Compression};
use reader_parser::parser::js::eval_js;
use std::io::Write;

fn compressed(input: &[u8], nowrap: bool) -> Vec<u8> {
    if nowrap {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    } else {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    }
}

#[test]
fn weread_raw_inflate_loop_preserves_binary_and_chunk_boundaries() {
    let plain: Vec<u8> = (0..20000).map(|n| (n % 256) as u8).collect();
    let input = serde_json::to_string(&compressed(&plain, true)).unwrap();
    let output = eval_js(
        &format!(r#"
        const j = new JavaImporter(Packages.java.util.zip, Packages.java.io, Packages.java.nio);
        const inflater = new j.Inflater(true);
        const stream = new j.InflaterInputStream(new j.ByteArrayInputStream({input}), inflater);
        const output = new j.ByteArrayOutputStream();
        const buffer = j.ByteBuffer.allocate(8192).array();
        let count, reads = 0;
        try {{
            while ((count = stream.read(buffer)) !== -1) {{ output.write(buffer, 0, count); reads++; }}
            if (reads !== 3 || stream.read([], 0, 0) !== 0 || stream.available() !== 0) throw new Error('read contract');
            JSON.stringify(output.toByteArray());
        }} finally {{ stream.close(); inflater.end(); output.close(); }}
        "#),
        "", "https://example.com/",
    ).unwrap();
    assert_eq!(serde_json::from_str::<Vec<u8>>(&output).unwrap(), plain);
}

#[test]
fn inflater_defaults_and_ownership_keep_instances_independent() {
    let input = serde_json::to_string(&compressed(b"hello", false)).unwrap();
    let result = eval_js(
        &format!(r#"
        const j = new JavaImporter(Packages.java.util.zip, Packages.java.io);
        const owned = new j.InflaterInputStream(new j.ByteArrayInputStream({input}));
        const inflater = new j.Inflater();
        const shared = new j.InflaterInputStream(new j.ByteArrayInputStream({input}), inflater);
        const text = java.bytesToStr(owned.readAllBytes());
        owned.close(); owned.close(); shared.close();
        let rejected = 0;
        for (const action of [() => owned.read(), () => shared.read(),
            () => new j.Inflater('true'), () => new j.InflaterInputStream([], inflater),
            () => new j.InflaterInputStream(new j.ByteArrayInputStream({input}), inflater, 0)]) {{
            try {{ action(); }} catch (_) {{ rejected++; }}
        }}
        const active = !inflater.ended;
        inflater.end(); inflater.end();
        try {{ new j.InflaterInputStream(new j.ByteArrayInputStream({input}), inflater); }} catch (_) {{ rejected++; }}
        [text, owned.inflater.ended, active, rejected].join('|');
        "#),
        "", "https://example.com/",
    ).unwrap();
    assert_eq!(result, "hello|true|true|6");
}

#[test]
fn inflater_bridge_rejects_truncation_wrong_wrapper_and_expansion_limit() {
    let raw = compressed(b"hello", true);
    let zlib = compressed(b"hello", false);
    for (bytes, nowrap, kind) in [
        (raw[..raw.len() - 1].to_vec(), true, "operation_failed"),
        (zlib, true, "operation_failed"),
        (raw, false, "operation_failed"),
        (
            compressed(&vec![b'a'; 256 * 1024 + 1], true),
            true,
            "limit_exceeded",
        ),
    ] {
        let input = serde_json::to_string(&bytes).unwrap();
        let result = eval_js(
            &format!(
                r#"try {{
                new Packages.java.util.zip.InflaterInputStream(
                    new Packages.java.io.ByteArrayInputStream({input}),
                    new Packages.java.util.zip.Inflater({nowrap}));
                'unexpected success';
            }} catch (error) {{ error.kind; }}"#
            ),
            "",
            "https://example.com/",
        )
        .unwrap();
        assert_eq!(result, kind);
    }
}
