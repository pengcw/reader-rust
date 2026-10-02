//! Bounded single-member gzip for JS helpers. ZIP remains a host service.
use flate2::{bufread::GzDecoder, write::GzEncoder, Compression};
use std::io::{Read, Write};

pub(crate) const MAX_INPUT: usize = 512 * 1024;
pub(crate) const MAX_OUTPUT: usize = 256 * 1024;

#[derive(Debug, PartialEq)]
pub(crate) enum Error {
    InvalidInput,
    LimitExceeded,
    OperationFailed,
}

impl Error {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_argument",
            Self::LimitExceeded => "limit_exceeded",
            Self::OperationFailed => "operation_failed",
        }
    }
}

pub(crate) fn gunzip(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() > MAX_INPUT {
        return Err(Error::LimitExceeded);
    }
    if !input.starts_with(&[0x1f, 0x8b]) {
        return Err(Error::InvalidInput);
    }
    // bufread does not consume bytes beyond the member; this lets us reject
    // trailing garbage and concatenated members without relying on read-ahead.
    let mut decoder = GzDecoder::new(input);
    let mut output = Vec::new();
    decoder
        .by_ref()
        .take((MAX_OUTPUT + 1) as u64)
        .read_to_end(&mut output)
        .map_err(|_| Error::OperationFailed)?;
    if output.len() > MAX_OUTPUT {
        return Err(Error::LimitExceeded);
    }
    if !decoder.into_inner().is_empty() {
        return Err(Error::OperationFailed);
    }
    Ok(output)
}

pub(crate) fn gzip(input: &[u8]) -> Result<Vec<u8>, Error> {
    // Keeping plaintext within the decode quota guarantees round-trip support.
    if input.len() > MAX_OUTPUT {
        return Err(Error::LimitExceeded);
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(input)
        .map_err(|_| Error::OperationFailed)?;
    let output = encoder.finish().map_err(|_| Error::OperationFailed)?;
    if output.len() > MAX_INPUT {
        return Err(Error::LimitExceeded);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_bounds_crc_truncation_and_trailing_members() {
        for input in [&b""[..], &b"\0\xff\x80\x01"[..], "你好 gzip".as_bytes()] {
            let encoded = gzip(input).unwrap();
            assert_eq!(gunzip(&encoded).unwrap(), input);
            for length in 2..encoded.len() {
                assert!(gunzip(&encoded[..length]).is_err(), "prefix {length}");
            }
            let mut trailing = encoded.clone();
            trailing.extend_from_slice(b"tail");
            assert_eq!(gunzip(&trailing), Err(Error::OperationFailed));
            let mut members = encoded.clone();
            members.extend_from_slice(&encoded);
            assert_eq!(gunzip(&members), Err(Error::OperationFailed));
            let mut damaged = encoded;
            let crc = damaged.len() - 8;
            damaged[crc] ^= 1;
            assert_eq!(gunzip(&damaged), Err(Error::OperationFailed));
        }
        assert_eq!(gunzip(b"invalid"), Err(Error::InvalidInput));
        assert_eq!(gunzip(&vec![0; MAX_INPUT + 1]), Err(Error::LimitExceeded));
        assert_eq!(gzip(&vec![0; MAX_OUTPUT + 1]), Err(Error::LimitExceeded));
        let maximum = vec![b'a'; MAX_OUTPUT];
        assert_eq!(gunzip(&gzip(&maximum).unwrap()).unwrap(), maximum);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&vec![b'a'; MAX_OUTPUT + 1]).unwrap();
        assert_eq!(
            gunzip(&encoder.finish().unwrap()),
            Err(Error::LimitExceeded)
        );
    }
}
