use scraper::{Html, Selector};

/// Return the outer HTML of every element in `html` that matches `selector`,
/// joined by newlines.  Returns an empty string when nothing matches.
///
/// # Errors
///
/// Returns an error if `selector` is not a valid CSS selector expression.
pub fn select_html(html: &str, selector: &str) -> anyhow::Result<String> {
    let sel = Selector::parse(selector)
        .map_err(|e| anyhow::anyhow!("invalid selector {selector:?}: {e}"))?;
    let doc = Html::parse_document(html);
    let out: Vec<String> = doc.select(&sel).map(|el| el.html()).collect();
    Ok(out.join("\n"))
}
