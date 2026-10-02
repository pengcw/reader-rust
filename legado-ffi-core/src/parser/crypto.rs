//! Native crypto using existing dependencies; never retries through a host.
use aes::cipher::{
    block_padding::NoPadding, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut,
    KeyInit, KeyIvInit,
};
use base64::Engine;
use ring::{rand::SystemRandom, signature};
use serde::Deserialize;
use serde_json::{json, Value};

const MAX_AES: usize = 256 * 1024;
const MAX_KEY: usize = 16384;
#[derive(Debug)]
struct Error(&'static str, &'static str);
type Result<T> = std::result::Result<T, Error>;
fn invalid(message: &'static str) -> Error {
    Error("invalid_argument", message)
}

pub(crate) fn symmetric(
    action: &str,
    name: &str,
    key: &[u8],
    iv: &[u8],
    input: &[u8],
) -> Option<Vec<u8>> {
    let name = name.to_ascii_uppercase();
    let fields: Vec<_> = name.split('/').collect();
    if fields.len() != 3
        || fields[0] != "AES"
        || !matches!(fields[1], "CBC" | "ECB")
        || !matches!(fields[2], "PKCS5PADDING" | "PKCS7PADDING" | "NOPADDING")
    {
        return None;
    }
    let decrypt = match action {
        "encrypt" => false,
        "decrypt" => true,
        _ => return None,
    };
    let cbc = fields[1] == "CBC";
    if (cbc && iv.len() != 16) || (!cbc && !iv.is_empty()) {
        return None;
    }
    let padded = fields[2] != "NOPADDING";
    if input.len() > MAX_AES + if decrypt && padded { 16 } else { 0 } {
        return None;
    }
    if (decrypt || !padded) && !input.len().is_multiple_of(16)
        || (decrypt && padded && input.is_empty())
    {
        return None;
    }
    let mut data = input.to_vec();
    if !decrypt && padded {
        let padding = 16 - data.len() % 16;
        data.resize(data.len() + padding, padding as u8);
    }
    macro_rules! transform {
        ($cipher:ty) => {{
            if cbc {
                if decrypt {
                    cbc::Decryptor::<$cipher>::new_from_slices(key, iv)
                        .ok()?
                        .decrypt_padded_mut::<NoPadding>(&mut data)
                        .ok()?;
                } else {
                    let length = data.len();
                    cbc::Encryptor::<$cipher>::new_from_slices(key, iv)
                        .ok()?
                        .encrypt_padded_mut::<NoPadding>(&mut data, length)
                        .ok()?;
                }
            } else {
                let cipher = <$cipher>::new_from_slice(key).ok()?;
                for block in data.chunks_exact_mut(16) {
                    let block = aes::cipher::Block::<$cipher>::from_mut_slice(block);
                    if decrypt {
                        cipher.decrypt_block(block);
                    } else {
                        cipher.encrypt_block(block);
                    }
                }
            }
        }};
    }
    match key.len() {
        16 => transform!(aes::Aes128),
        24 => transform!(aes::Aes192),
        32 => transform!(aes::Aes256),
        _ => return None,
    }
    if decrypt && padded {
        let padding = *data.last()? as usize;
        if padding == 0
            || padding > 16
            || !data[data.len() - padding..]
                .iter()
                .all(|&b| b as usize == padding)
        {
            return None;
        }
        data.truncate(data.len() - padding);
    }
    if decrypt && data.len() > MAX_AES {
        return None;
    }
    Some(data)
}

// Narrow canonical DER reader. Cryptographic private-key validation is ring's job.
struct Der<'a>(&'a [u8]);
impl<'a> Der<'a> {
    fn take(&mut self, tag: u8) -> Result<&'a [u8]> {
        if self.0.len() < 2 || self.0[0] != tag {
            return Err(invalid("invalid RSA DER tag"));
        }
        let first = self.0[1];
        let (length, header) = if first < 128 {
            (first as usize, 2)
        } else {
            let count = (first & 127) as usize;
            if count == 0 || count > 3 || self.0.len() < 2 + count || self.0[2] == 0 {
                return Err(invalid("invalid DER length"));
            }
            let length = self.0[2..2 + count]
                .iter()
                .fold(0usize, |n, &b| n * 256 + b as usize);
            if length < 128 {
                return Err(invalid("noncanonical DER length"));
            }
            (length, 2 + count)
        };
        if length > self.0.len() - header {
            return Err(invalid("truncated DER"));
        }
        let result = &self.0[header..header + length];
        self.0 = &self.0[header + length..];
        Ok(result)
    }
    fn end(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(invalid("trailing DER"))
        }
    }
    fn integer(&mut self) -> Result<&'a [u8]> {
        let bytes = self.take(2)?;
        if bytes.is_empty()
            || bytes[0] & 128 != 0
            || (bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 128 == 0)
        {
            return Err(invalid("invalid RSA integer"));
        }
        Ok(if bytes.len() > 1 && bytes[0] == 0 {
            &bytes[1..]
        } else {
            bytes
        })
    }
    fn version(&mut self) -> Result<()> {
        if self.integer()? == [0] {
            Ok(())
        } else {
            Err(invalid("unsupported RSA version"))
        }
    }
}
fn sequence(bytes: &[u8]) -> Result<Der<'_>> {
    let mut outer = Der(bytes);
    let inner = outer.take(48)?;
    outer.end()?;
    Ok(Der(inner))
}
fn components(bytes: &[u8], private: bool) -> Result<(&[u8], &[u8])> {
    let mut outer = sequence(bytes)?;
    if private {
        outer.version()?;
    }
    let mut algorithm = Der(outer.take(48)?);
    if algorithm.take(6)? != [42, 134, 72, 134, 247, 13, 1, 1, 1] {
        return Err(invalid("RSA algorithm required"));
    }
    if !algorithm.0.is_empty() && !algorithm.take(5)?.is_empty() {
        return Err(invalid("invalid RSA parameters"));
    }
    algorithm.end()?;
    let mut payload = outer.take(if private { 4 } else { 3 })?;
    outer.end()?;
    if !private {
        if payload.first() != Some(&0) {
            return Err(invalid("invalid RSA bit string"));
        }
        payload = &payload[1..];
    }
    let mut rsa = sequence(payload)?;
    if private {
        rsa.version()?;
    }
    let n = rsa.integer()?;
    let e = rsa.integer()?;
    let bits = (n.len() - 1) * 8 + (8 - n[0].leading_zeros() as usize);
    if n[0] == 0 || !(1024..=4096).contains(&bits) || n.last().unwrap() & 1 == 0 {
        return Err(invalid("RSA modulus must be 1024..4096 bits"));
    }
    if e.len() > 5 {
        return Err(invalid("invalid RSA exponent"));
    }
    let exponent = e.iter().fold(0u64, |n, &b| n * 256 + b as u64);
    if !(3..=0x1_ffff_ffff).contains(&exponent) || exponent % 2 == 0 {
        return Err(invalid("invalid RSA exponent"));
    }
    if private {
        for _ in 0..6 {
            if rsa.integer()?.iter().all(|&b| b == 0) {
                return Err(invalid("zero RSA private component"));
            }
        }
    }
    rsa.end()?;
    if private && bits < 2048 {
        return Err(Error(
            "unsupported",
            "RSA private signing requires 2048..4096 bits",
        ));
    }
    Ok((n, e))
}
fn key_bytes(value: Value, private: bool) -> Result<Vec<u8>> {
    if let Some(text) = value.as_str() {
        if text.len() > MAX_KEY {
            return Err(invalid("RSA key too large"));
        }
        let text = text.trim();
        let label = if private { "PRIVATE KEY" } else { "PUBLIC KEY" };
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let body = text
            .strip_prefix(&begin)
            .and_then(|s| s.strip_suffix(&end))
            .ok_or_else(|| invalid("SPKI/PKCS8 PEM required"))?;
        let encoded: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| invalid("invalid key Base64"))
    } else {
        let bytes: Vec<u8> =
            serde_json::from_value(value).map_err(|_| invalid("invalid RSA key bytes"))?;
        if bytes.len() > MAX_KEY {
            return Err(invalid("RSA key too large"));
        }
        Ok(bytes)
    }
}
#[derive(Deserialize)]
struct Request {
    action: String,
    algorithm: String,
    key: Value,
    data: Vec<u8>,
    #[serde(default)]
    signature: Vec<u8>,
}
fn signature_request(input: &str) -> Result<Value> {
    if input.len() > 128 * 1024 {
        return Err(Error("limit_exceeded", "signature request too large"));
    }
    let request: Request =
        serde_json::from_str(input).map_err(|_| invalid("invalid signature request"))?;
    if request.algorithm != "SHA256WITHRSA" {
        return Err(Error("unsupported", "unsupported signature algorithm"));
    }
    let signing = match request.action.as_str() {
        "sign" => true,
        "verify" => false,
        _ => return Err(invalid("invalid signature action")),
    };
    if request.data.len() > 16384 || request.signature.len() > 512 {
        return Err(Error("limit_exceeded", "signature input too large"));
    }
    let key = key_bytes(request.key, signing)?;
    let (n, e) = components(&key, signing)?;
    if signing {
        let pair = signature::RsaKeyPair::from_pkcs8(&key)
            .map_err(|_| invalid("RSA key rejected by ring"))?;
        let mut output = vec![0; pair.public().modulus_len()];
        pair.sign(
            &signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            &request.data,
            &mut output,
        )
        .map_err(|_| Error("operation_failed", "RSA signing failed"))?;
        Ok(json!(output))
    } else {
        let public = signature::RsaPublicKeyComponents { n, e };
        Ok(json!(public
            .verify(
                &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                &request.data,
                &request.signature
            )
            .is_ok()))
    }
}
pub(crate) fn signature_json(input: &str) -> String {
    match signature_request(input) {
        Ok(data) => json!({"ok":true,"data":data}),
        Err(Error(kind, message)) => json!({"ok":false,"error":{"kind":kind,"message":message}}),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut output = vec![tag];
        if body.len() < 128 {
            output.push(body.len() as u8);
        } else if body.len() < 256 {
            output.extend([0x81, body.len() as u8]);
        } else {
            output.extend([0x82, (body.len() >> 8) as u8, body.len() as u8]);
        }
        output.extend(body);
        output
    }
    fn public_key(exponent: &[u8]) -> Vec<u8> {
        let mut modulus = vec![0xff; 128];
        modulus.insert(0, 0);
        let mut rsa = tlv(2, &modulus);
        rsa.extend(tlv(2, exponent));
        let mut bits = vec![0];
        bits.extend(tlv(48, &rsa));
        let mut algorithm = tlv(6, &[42, 134, 72, 134, 247, 13, 1, 1, 1]);
        algorithm.extend(tlv(5, &[]));
        let mut spki = tlv(48, &algorithm);
        spki.extend(tlv(3, &bits));
        tlv(48, &spki)
    }
    #[test]
    fn native_signature_rejects_invalid_der_and_parameters() {
        let key = public_key(&[1, 0, 1]);
        assert!(components(&key, false).is_ok());
        let request = |key: Vec<u8>| {
            json!({"action":"verify", "algorithm":"SHA256WITHRSA",
            "key":key, "data":[], "signature":[]})
            .to_string()
        };
        assert_eq!(
            signature_request(&request(key.clone())).unwrap(),
            json!(false)
        );
        let mut trailing = key.clone();
        trailing.push(0);
        assert!(components(&trailing, false).is_err());
        assert!(components(&key[..key.len() - 1], false).is_err());
        assert!(components(&public_key(&[2]), false).is_err());
        assert!(components(&public_key(&[0, 1, 0, 1]), false).is_err());
        let mut wrong_oid = key.clone();
        let oid = wrong_oid
            .windows(9)
            .position(|b| b == [42, 134, 72, 134, 247, 13, 1, 1, 1])
            .unwrap();
        wrong_oid[oid + 8] = 2;
        assert!(components(&wrong_oid, false).is_err());
        let mut der = Der(&[2, 0x81, 1, 1]);
        assert!(der.integer().is_err());
        assert!(signature_request(&"x".repeat(128 * 1024 + 1)).is_err());
        let result: Value = serde_json::from_str(&signature_json(&request(vec![0]))).unwrap();
        assert_eq!(result["error"]["kind"], "invalid_argument");
    }
    #[test]
    fn native_aes_all_modes_padding_and_limits() {
        let plain = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        for (key, ecb, cbc) in [
            (
                "2b7e151628aed2a6abf7158809cf4f3c",
                "3ad77bb40d7a3660a89ecaf32466ef97",
                "7649abac8119b246cee98e9b12e9197d",
            ),
            (
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "bd334f1d6e45f25ff712a214571fa5cc",
                "4f021db243bc633d7178183a9fa071e8",
            ),
            (
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "f3eed1bdb5d2a03c064b5a7e3db181f8",
                "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
            ),
        ] {
            let key = hex::decode(key).unwrap();
            for (mode, expected) in [("ECB", ecb), ("CBC", cbc)] {
                let iv = if mode == "CBC" { &iv[..] } else { &[] };
                for padding in ["NoPadding", "PKCS5Padding", "PKCS7Padding"] {
                    let name = format!("AES/{mode}/{padding}");
                    let encrypted = symmetric("encrypt", &name, &key, iv, &plain).unwrap();
                    assert_eq!(hex::encode(&encrypted[..16]), expected);
                    assert_eq!(
                        symmetric("decrypt", &name, &key, iv, &encrypted).unwrap(),
                        plain
                    );
                    let empty = symmetric("encrypt", &name, &key, iv, &[]).unwrap();
                    assert!(symmetric("decrypt", &name, &key, iv, &empty)
                        .unwrap()
                        .is_empty());
                }
            }
        }
        let key = [0; 16];
        assert!(symmetric("encrypt", "AES/ECB/NoPadding", &key, &[], &[1]).is_none());
        assert!(symmetric(
            "encrypt",
            "AES/ECB/PKCS5Padding",
            &key,
            &[],
            &vec![0; MAX_AES + 1]
        )
        .is_none());
        assert_eq!(
            hex::encode(symmetric("encrypt", "AES/ECB/PKCS7Padding", &key, &[], &[]).unwrap()),
            "0143db63ee66b0cdff9f69917680151e"
        );
        let bad = symmetric("encrypt", "AES/ECB/NoPadding", &key, &[], &[0; 16]).unwrap();
        assert!(symmetric("decrypt", "AES/ECB/PKCS7Padding", &key, &[], &bad).is_none());
    }
}
