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
