//! Opt-in experiment: rewrite only zero-argument Java-style .length() calls.
//! Uncertain JavaScript grammar is left untouched; never retry a script after execution.
use std::borrow::Cow;

const MEMBER: &str = "[Symbol.for('legado.javaStringLength')]";

pub const RUNTIME: &str = r#"
(() => {
    const key = Symbol.for('legado.javaStringLength');
    Object.defineProperty(Object.prototype, key, {
        configurable: true,
        value() {
            const length = this.length;
            if (typeof length === 'function') return length.call(this);
            if (this instanceof String && typeof length === 'number') return length;
            throw new TypeError('length is not callable');
        }
    });
})();
"#;

pub fn rewrite(source: &str) -> Option<Cow<'_, str>> {
    // Skip the lexer unless the script contains a possible no-argument call.
    if !source.match_indices(".length").any(|(i, _)| length_call_at(source.as_bytes(), i)) {
        return Some(Cow::Borrowed(source));
    }
    let mut edits = Vec::new();
    let mut i = 0;
    scan_code(source.as_bytes(), &mut i, &mut edits, false, 0)?;
    if edits.is_empty() {
        return Some(Cow::Borrowed(source));
    }
    let mut result = String::with_capacity(source.len() + edits.len() * MEMBER.len());
    let mut previous = 0;
    for (start, end) in edits {
        result.push_str(&source[previous..start]);
        result.push_str(MEMBER);
        previous = end;
    }
    result.push_str(&source[previous..]);
    Some(Cow::Owned(result))
}

// Scan a script, or a braced interpolation inside a template, with one lexer.
fn scan_code(b: &[u8], i: &mut usize, edits: &mut Vec<(usize, usize)>, nested: bool, depth: u16) -> Option<()> {
    if depth > 128 { return None; }
    let (mut regex_allowed, mut after_brace) = (true, false);
    let mut control = false;
    let mut parens = Vec::new();
    while *i < b.len() {
        let start = *i;
        match b[*i] {
            b'\'' | b'"' => { skip_string(b, i)?; regex_allowed = false; }
            b'`' => { scan_template(b, i, edits, depth + 1)?; regex_allowed = false; }
            b'/' if b.get(*i+1) == Some(&b'/') => {
                *i += 2;
                while *i < b.len() && b[*i] != b'\n' { *i += 1; }
            }
            b'/' if b.get(*i+1) == Some(&b'*') => {
                *i += 2;
                while *i+1 < b.len() && &b[*i..*i+2] != b"*/" { *i += 1; }
                if *i+1 >= b.len() { return None; }
                *i += 2;
            }
            b'/' if regex_allowed => {
                *i += 1;
                let mut class = false;
                loop {
                    match b.get(*i).copied()? {
                        b'\\' => *i += 2,
                        b'[' => { class = true; *i += 1; }
                        b']' => { class = false; *i += 1; }
                        b'/' if !class => { *i += 1; break; }
                        b'\n' | b'\r' => return None,
                        _ => *i += 1,
                    }
                }
                while b.get(*i).is_some_and(|c| c.is_ascii_alphabetic()) { *i += 1; }
                regex_allowed = false;
            }
            b'/' if after_brace => return None, // May be division or regexp.
            b'{' => { *i += 1; scan_code(b, i, edits, true, depth + 1)?; regex_allowed = false; after_brace = true; }
            b'}' if nested => { *i += 1; return Some(()); }
            b'}' => return None,
            b'.' if length_call_at(b, *i) => {
                edits.push((if start > 0 && b[start-1] == b'?' { start+1 } else { start }, start+7));
                *i += 7;
                regex_allowed = false;
            }
            c if ident(c) => {
                *i += 1;
                while b.get(*i).is_some_and(|c| ident(*c)) { *i += 1; }
                let word = &b[start..*i];
                control = matches!(word, b"if" | b"for" | b"while" | b"with" | b"switch" | b"catch");
                regex_allowed = control || matches!(word, b"return" | b"throw" | b"case" | b"new" | b"typeof" | b"void" | b"delete" | b"await" | b"yield");
            }
            b'(' => { parens.push(control); control = false; *i += 1; regex_allowed = true; }
            b')' => { regex_allowed = parens.pop().unwrap_or(false); *i += 1; }
            b']' | b'.' => { *i += 1; regex_allowed = false; }
            b'+' | b'-' if b.get(*i+1) == Some(&b[*i]) => { *i += 2; regex_allowed = false; }
            c if c.is_ascii_whitespace() => *i += 1,
            _ => { *i += 1; regex_allowed = true; }
        }
        if !b[start].is_ascii_whitespace() && b[start] != b'{' && b[start] != b'/' {
            after_brace = false;
        }
    }
    (!nested).then_some(())
}

// Cheap syntactic candidate check; the lexer decides whether the text is code.
fn length_call_at(b: &[u8], i: usize) -> bool {
    if b.get(i..i+7) != Some(b".length") || b.get(i+7).is_some_and(|c| ident(*c)) {
        return false;
    }
    let mut end = i + 7;
    while b.get(end).is_some_and(|c| c.is_ascii_whitespace()) { end += 1; }
    if b.get(end) != Some(&b'(') { return false; }
    end += 1;
    while b.get(end).is_some_and(|c| c.is_ascii_whitespace()) { end += 1; }
    b.get(end) == Some(&b')')
}

fn ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'$' || c >= 128
}

fn skip_string(bytes: &[u8], at: &mut usize) -> Option<()> {
    let quote = bytes[*at];
    *at += 1;
    while *at < bytes.len() {
        match bytes[*at] {
            b'\\' => *at += 2,
            c if c == quote => { *at += 1; return Some(()); }
            b'\n' | b'\r' => return None,
            _ => *at += 1,
        }
    }
    None
}

// Keep raw template text untouched, but scan its JavaScript interpolations.
fn scan_template(b: &[u8], at: &mut usize, edits: &mut Vec<(usize, usize)>, depth: u16) -> Option<()> {
    if depth > 128 { return None; }
    *at += 1;
    while *at < b.len() {
        match b[*at] {
            b'\\' => *at += 2,
            b'`' => { *at += 1; return Some(()); }
            b'$' if b.get(*at + 1) == Some(&b'{') => {
                *at += 2;
                scan_code(b, at, edits, true, depth + 1)?;
            }
            _ => *at += 1,
        }
    }
    None
}
