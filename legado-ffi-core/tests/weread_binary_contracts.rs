//! Synthetic WeRead byte/AES/ZIP contract, without accounts or source fixtures.
use aes::Aes128;
use base64::{engine::general_purpose::STANDARD, Engine};
use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use flate2::{write::DeflateEncoder, Compression};
use reader_parser::executor::execute;
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

fn crc_step(mut crc: u32, byte: u8) -> u32 {
    crc ^= u32::from(byte);
    for _ in 0..8 {
        crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb88320 } else { 0 };
    }
    crc
}
fn update_keys(keys: &mut [u32; 3], byte: u8) {
    keys[0] = crc_step(keys[0], byte);
    keys[1] = keys[1]
        .wrapping_add(keys[0] & 255)
        .wrapping_mul(134775813)
        .wrapping_add(1);
    keys[2] = crc_step(keys[2], (keys[1] >> 24) as u8);
}
fn words(output: &mut Vec<u8>, values: &[u16]) {
    for value in values {
        output.extend_from_slice(&value.to_le_bytes());
    }
}
fn dwords(output: &mut Vec<u8>, values: &[u32]) {
    for value in values {
        output.extend_from_slice(&value.to_le_bytes());
    }
}
fn chapter_zip(plain: &[u8], method: u16, encrypted: bool, password: &[u8]) -> Vec<u8> {
    let crc = !plain
        .iter()
        .fold(u32::MAX, |crc, byte| crc_step(crc, *byte));
    let mut data = if method == 8 {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plain).unwrap();
        encoder.finish().unwrap()
    } else {
        plain.to_vec()
    };
    if encrypted {
        let mut keys = [0x12345678, 0x23456789, 0x34567890];
        for byte in password {
            update_keys(&mut keys, *byte);
        }
        let mut header: Vec<u8> = (0..11).collect();
        header.push((crc >> 24) as u8);
        header.extend_from_slice(&data);
        data = header
            .into_iter()
            .map(|byte| {
                let temp = keys[2] | 2;
                let encoded = byte ^ ((temp.wrapping_mul(temp ^ 1) >> 8) as u8);
                update_keys(&mut keys, byte);
                encoded
            })
            .collect();
    }
    let name = b"chapter.xhtml";
    let flags = u16::from(encrypted);
    let sizes = [crc, data.len() as u32, plain.len() as u32];
    let mut zip = Vec::new();
    dwords(&mut zip, &[0x04034b50]);
    words(&mut zip, &[20, flags, method, 0, 0]);
    dwords(&mut zip, &sizes);
    words(&mut zip, &[name.len() as u16, 0]);
    zip.extend_from_slice(name);
    zip.extend_from_slice(&data);
    let offset = zip.len() as u32;
    dwords(&mut zip, &[0x02014b50]);
    words(&mut zip, &[20, 20, flags, method, 0, 0]);
    dwords(&mut zip, &sizes);
    words(&mut zip, &[name.len() as u16, 0, 0, 0, 0]);
    dwords(&mut zip, &[0, 0]);
    zip.extend_from_slice(name);
    let size = zip.len() as u32 - offset;
    dwords(&mut zip, &[0x06054b50]);
    words(&mut zip, &[0, 0, 1, 1]);
    dwords(&mut zip, &[size, offset]);
    words(&mut zip, &[0]);
    zip
}

// The source's byte operations and ZipCrypto update sequence, reduced to one
// generated entry. This is a regression contract, not a general ZIP reader.
const CONTENT_RULE: &str = r#"@js:
const headers = new Packages.java.util.HashMap();
headers.put('X-Contract', 'synthetic');
const response = java.get(java.hexDecodeToString(result), headers);
if (response.statusCode() !== 200) throw new Error('HTTP status');
const keyIv = Packages.java.nio.ByteBuffer.allocate(32).array();
for (let i = 0; i < 32; i++) keyIv[i] = i + 128 > 127 ? i - 128 : i + 128;
const arrays = Packages.java.util.Arrays;
const cipher = Packages.javax.crypto.Cipher.getInstance('AES/CBC/PKCS5Padding');
cipher.init(Packages.javax.crypto.Cipher.DECRYPT_MODE,
    new Packages.javax.crypto.spec.SecretKeySpec(arrays.copyOfRange(keyIv, 0, 16), 'AES'),
    new Packages.javax.crypto.spec.IvParameterSpec(arrays.copyOfRange(keyIv, 16, 32)));
const password = cipher.doFinal(java.base64DecodeToByteArray(response.header('encryptkey')));
const zip = response.bodyAsBytes();
const u16 = at => (zip[at] & 255) | ((zip[at + 1] & 255) << 8);
const u32 = at => (u16(at) | (u16(at + 2) << 16)) >>> 0;
if (u32(0) !== 0x04034b50) throw new Error('ZIP signature');
const start = 30 + u16(26) + u16(28);
let data = arrays.copyOfRange(zip, start, start + u32(18));
if (u16(6) & 1) {
    const table = [];
    for (let i = 0; i < 256; i++) {
        let value = i;
        for (let bit = 0; bit < 8; bit++) value = (value >>> 1) ^ ((value & 1) ? 0xedb88320 : 0);
        table[i] = value >>> 0;
    }
    const step = (crc, value) => ((crc >>> 8) ^ table[(crc ^ value) & 255]) >>> 0;
    let key0 = 0x12345678, key1 = 0x23456789, key2 = 0x34567890;
    const update = value => {
        key0 = step(key0, value);
        key1 = (Math.imul((key1 + (key0 & 255)) | 0, 134775813) + 1) >>> 0;
        key2 = step(key2, key1 >>> 24);
    };
    for (let i = 0; i < password.length; i++) update(password[i] & 255);
    const decoded = arrays.copyOf(data, data.length);
    for (let i = 0; i < data.length; i++) {
        const temp = (key2 | 2) >>> 0;
        const plain = (data[i] & 255) ^ ((Math.imul(temp, temp ^ 1) >>> 8) & 255);
        decoded[i] = plain > 127 ? plain - 256 : plain;
        update(plain);
    }
    data = arrays.copyOfRange(decoded, 12, decoded.length);
}
if (u16(8) === 8) {
    const inflater = new Packages.java.util.zip.Inflater(true);
    const stream = new Packages.java.util.zip.InflaterInputStream(
        new Packages.java.io.ByteArrayInputStream(data), inflater);
    const output = new Packages.java.io.ByteArrayOutputStream();
    const buffer = Packages.java.nio.ByteBuffer.allocate(8192).array();
    try {
        let count;
        while ((count = stream.read(buffer)) !== -1) output.write(buffer, 0, count);
        data = output.toByteArray();
    } finally { stream.close(); inflater.end(); output.close(); }
}
java.bytesToStr(data, 'UTF-8');
"#;

#[test]
fn typed_carrier_http_aes_and_zip_produce_exact_content_once_per_request() {
    let password = b"synthetic-password";
    let key_iv: Vec<u8> = (128..160).collect();
    let mut buffer = vec![0; password.len() + 16];
    buffer[..password.len()].copy_from_slice(password);
    let encrypted_key = cbc::Encryptor::<Aes128>::new_from_slices(&key_iv[..16], &key_iv[16..])
        .unwrap()
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, password.len())
        .unwrap();
    let encrypted_key = STANDARD.encode(encrypted_key);
    // Larger than the JS read buffer, including non-ASCII UTF-8 text.
    let paragraph = "中文正文".repeat(900);
    let html = format!("<html><body><p>{paragraph}</p><p>末段正文</p></body></html>");
    let payloads = [(0, false), (8, false), (8, true)]
        .map(|(method, encrypted)| chapter_zip(html.as_bytes(), method, encrypted, password));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        for (index, payload) in payloads.iter().enumerate() {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "fixture timed out");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() <= 8192);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with(&format!("GET /chapter/{index} ")),
                "{request}"
            );
            assert!(request
                .lines()
                .any(|line| line.eq_ignore_ascii_case("X-Contract: synthetic")));
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nEncryptKey: {encrypted_key}\r\nConnection: close\r\n\r\n", payload.len()).unwrap();
            stream.write_all(payload).unwrap();
        }
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    });
    let source = json!({"bookSourceUrl":base,"enabledCookieJar":false,"ruleContent":{"content":CONTENT_RULE}});
    for index in 0..3 {
        let carrier = format!(
            "data:application/octet-stream;base64,{},{{\"type\":\"bin\"}}",
            STANDARD.encode(format!("{base}/chapter/{index}"))
        );
        let response = execute(
            &source.to_string(),
            &json!({"api":2,"op":"content","params":{"url":carrier},"options":{"timeoutMs":2000}})
                .to_string(),
        );
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(
            response["data"]["content"],
            format!("{paragraph}\n末段正文")
        );
        assert_eq!(response["data"]["pages"], 1);
    }
    server.join().unwrap();
}
