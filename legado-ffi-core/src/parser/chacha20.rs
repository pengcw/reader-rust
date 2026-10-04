//! Bounded ChaCha20-Poly1305 decryption with empty AAD; no host fallback.
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use serde::Deserialize;

const MAX_PLAINTEXT: usize = 256 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    key: Vec<u8>,
    nonce: Vec<u8>,
    data: Vec<u8>,
}

pub(crate) fn decrypt_json(input: &str) -> anyhow::Result<String> {
    // Bound the native parser even if a script bypasses the JS facade.
    anyhow::ensure!(input.len() <= 2 * 1024 * 1024, "ChaCha20 request too large");
    let request: Request = serde_json::from_str(input)?;
    let output = decrypt(&request.key, &request.nonce, request.data)?;
    Ok(serde_json::to_string(&output)?)
}

fn decrypt(key: &[u8], nonce: &[u8], mut data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(key.len() == 32, "ChaCha20 key must be 32 bytes");
    anyhow::ensure!(nonce.len() == 12, "ChaCha20 nonce must be 12 bytes");
    anyhow::ensure!(
        (16..=MAX_PLAINTEXT + 16).contains(&data.len()),
        "invalid ChaCha20 ciphertext size"
    );
    let key = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, key)
            .map_err(|_| anyhow::anyhow!("invalid ChaCha20 key"))?,
    );
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| anyhow::anyhow!("invalid ChaCha20 nonce"))?;
    // Only expose bytes after the provider verifies the complete authentication tag.
    let length = key
        .open_in_place(nonce, Aad::empty(), &mut data)
        .map_err(|_| anyhow::anyhow!("ChaCha20 authentication failed"))?
        .len();
    data.truncate(length);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_plaintext_requires_a_valid_authentication_tag() {
        let key = hex::decode("80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0")
            .unwrap();
        let nonce = hex::decode("4da5bf8dfd5852c1ea12379d").unwrap();
        let mut data = hex::decode("76acb342cf3166a5b63c0c0ea1383c8d").unwrap();
        assert!(decrypt(&key, &nonce, data.clone()).unwrap().is_empty());
        data[0] ^= 1;
        assert!(decrypt(&key, &nonce, data).is_err());
    }

    #[test]
    fn native_boundary_rejects_wrong_sizes_and_invalid_byte_values() {
        assert!(decrypt(&[0; 31], &[0; 12], vec![0; 16]).is_err());
        assert!(decrypt(&[0; 32], &[0; 11], vec![0; 16]).is_err());
        assert!(decrypt(&[0; 32], &[0; 12], vec![0; 15]).is_err());
        assert!(decrypt(&[0; 32], &[0; 12], vec![0; MAX_PLAINTEXT + 17]).is_err());
        assert!(decrypt_json(r#"{"key":[256],"nonce":[],"data":[]}"#).is_err());
        assert!(decrypt_json(&" ".repeat(2 * 1024 * 1024 + 1)).is_err());
    }
}
