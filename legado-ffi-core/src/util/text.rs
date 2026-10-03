pub fn strip_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn normalize_source_url(input: &str) -> String {
    input
        .chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t'))
        .collect::<String>()
        .trim()
        .to_string()
}

pub fn repair_encoded_url(input: &str) -> String {
    let normalized = normalize_source_url(input);
    if !(normalized.contains("%3F")
        || normalized.contains("%3f")
        || normalized.contains("%26")
        || normalized.contains("%26")
        || normalized.contains("%3D")
        || normalized.contains("%3d"))
    {
        return normalized;
    }

    normalized
        .replace("%3F", "?")
        .replace("%3f", "?")
        .replace("%26", "&")
        .replace("%3D", "=")
        .replace("%3d", "=")
        .replace("%23", "#")
        .replace("%23", "#")
}

// Find a {{...}} terminator without stopping inside JS braces, strings or comments.
pub(crate) fn find_template_close(expression: &str) -> Option<usize> {
    enum State {
        Code,
        Quoted(u8),
        LineComment,
        BlockComment,
    }

    let bytes = expression.as_bytes();
    let mut state = State::Code;
    let mut brace_depth = 0usize;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match state {
            State::Quoted(quote) => {
                if byte == b'\\' {
                    index += 2;
                    continue;
                }
                if byte == quote {
                    state = State::Code;
                }
            }
            State::LineComment => {
                if matches!(byte, b'\n' | b'\r') {
                    state = State::Code;
                }
            }
            State::BlockComment => {
                if byte == b'*' && next == Some(b'/') {
                    state = State::Code;
                    index += 2;
                    continue;
                }
            }
            State::Code => match (byte, next) {
                (b'\'' | b'"' | b'`', _) => state = State::Quoted(byte),
                (b'/', Some(b'/')) => {
                    state = State::LineComment;
                    index += 2;
                    continue;
                }
                (b'/', Some(b'*')) => {
                    state = State::BlockComment;
                    index += 2;
                    continue;
                }
                (b'{', _) => brace_depth += 1,
                (b'}', _) if brace_depth > 0 => brace_depth -= 1,
                (b'}', Some(b'}')) => return Some(index),
                _ => {}
            },
        }
        index += 1;
    }
    // Returned offsets always point to ASCII braces, hence UTF-8 boundaries.
    None
}
