use similar::TextDiff;

/// Produce a unified diff between `before` and `after`, split on lines.
///
/// Both inputs are pretty-printed before diffing so the output is
/// human-readable regardless of whether the caller already formatted them.
/// Returns an empty string when the inputs are identical after formatting.
#[must_use]
pub fn diff_html(before: &str, after: &str) -> String {
    let a = crate::pretty_print(before);
    let b = crate::pretty_print(after);
    TextDiff::from_lines(a.as_str(), b.as_str())
        .unified_diff()
        .header("raw", "rendered")
        .to_string()
}
