//! Bounded AES-GCM with 128-bit tag, 12-byte nonce and empty AAD.
//! Reuses the existing ring dependency; only the Legado source-used JCA subset.
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use serde::Deserialize;

const MAX_PLAINTEXT: usize = 256 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    mode: u8,
    key: Vec<u8>,
    nonce: Vec<u8>,
    data: Vec<u8>,
}

pub(crate) fn execute_json(input: &str) -> anyhow::Result<String> {
    anyhow::ensure!(input.len() <= 2 * 1024 * 1024, "AES-GCM request too large");
    let req: Request = serde_json::from_str(input)?;
    let output = execute(req)?;
    Ok(serde_json::to_string(&output)?)
}

fn execute(req: Request) -> anyhow::Result<Vec<u8>> {
    let algorithm = match req.key.len() {
        16 => &aead::AES_128_GCM,
        32 => &aead::AES_256_GCM,
        _ => anyhow::bail!("AES-GCM supports only 128/256-bit keys"),
    };
    anyhow::ensure!(req.nonce.len() == 12, "AES-GCM nonce must be 12 bytes");
    let encrypt = match req.mode {
        1 => true,
        2 => false,
        _ => anyhow::bail!("AES-GCM mode must be encrypt/decrypt"),
    };
    let mut data = req.data;
    let valid_size = if encrypt {
        data.len() <= MAX_PLAINTEXT
    } else {
        (16..=MAX_PLAINTEXT + 16).contains(&data.len())
    };
    anyhow::ensure!(valid_size, "invalid AES-GCM input size");

    let key = LessSafeKey::new(
        UnboundKey::new(algorithm, &req.key).map_err(|_| anyhow::anyhow!("invalid AES-GCM key"))?,
    );
    let nonce = Nonce::try_assume_unique_for_key(&req.nonce)
        .map_err(|_| anyhow::anyhow!("invalid AES-GCM nonce"))?;
    if encrypt {
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut data)
            .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;
    } else {
        let length = key
            .open_in_place(nonce, Aad::empty(), &mut data)
            .map_err(|_| anyhow::anyhow!("AES-GCM authentication failed"))?
            .len();
        data.truncate(length);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_empty_aes128_gcm_vector_and_tamper_rejection() {
        let encrypt = Request {
            mode: 1,
            key: vec![0; 16],
            nonce: vec![0; 12],
            data: Vec::new(),
        };
        let tag = execute(encrypt).unwrap();
        assert_eq!(hex::encode(&tag), "58e2fccefa7e3061367f1d57a4e7455a");
        assert!(execute(Request {
            mode: 2,
            key: vec![0; 16],
            nonce: vec![0; 12],
            data: tag.clone(),
        })
        .unwrap()
        .is_empty());
        let mut modified = tag;
        modified[0] ^= 1;
        assert!(execute(Request {
            mode: 2,
            key: vec![0; 16],
            nonce: vec![0; 12],
            data: modified,
        })
        .is_err());
    }

    #[test]
    fn invalid_parameters_and_native_json_boundary() {
        assert!(execute(Request {
            mode: 1,
            key: vec![0; 24],
            nonce: vec![0; 12],
            data: vec![1]
        })
        .is_err());
        assert!(execute(Request {
            mode: 2,
            key: vec![0; 32],
            nonce: vec![0; 12],
            data: vec![0; 15]
        })
        .is_err());
        assert!(execute(Request {
            mode: 1,
            key: vec![0; 32],
            nonce: vec![0; 11],
            data: vec![1]
        })
        .is_err());
        assert!(execute_json(r#"{"mode":1,"key":[256],"nonce":[],"data":[]}"#).is_err());
        assert!(execute_json(&"x".repeat(2 * 1024 * 1024 + 1)).is_err());
    }
}
