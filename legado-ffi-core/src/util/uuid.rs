/// Generate an RFC 9562 UUID v4 using rand's cryptographically secure thread RNG.
pub(crate) fn generate_uuid_v4() -> String {
    let mut bytes = rand::random::<[u8; 16]>();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let encoded = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &encoded[..8],
        &encoded[8..12],
        &encoded[12..16],
        &encoded[16..20],
        &encoded[20..]
    )
}

#[cfg(test)]
mod tests {
    use super::generate_uuid_v4;

    #[test]
    fn uuid_has_canonical_v4_format() {
        for _ in 0..32 {
            let value = generate_uuid_v4();
            assert_eq!(value.len(), 36);
            for (index, byte) in value.bytes().enumerate() {
                if [8, 13, 18, 23].contains(&index) {
                    assert_eq!(byte, b'-');
                } else {
                    assert!(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
                }
            }
            assert_eq!(value.as_bytes()[14], b'4');
            assert!(matches!(value.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        }
    }
}
