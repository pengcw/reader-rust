//! HTML parsing and source script extraction.
//!
//! Parses HTML for source script and meta collection before LinkeDOM execution.
//! The rendered document is serialized directly by LinkeDOM, not html5ever.

use anyhow::anyhow;
use html5ever::{
    ParseOpts, parse_document,
    tendril::TendrilSink,
};
use markup5ever_rcdom::{Handle, NodeData, RcDom};

/// The source of a `<script>` element's JavaScript.
pub enum ScriptSource {
    /// Script whose code is inlined in the HTML.
    Inline(String),
    /// Script loaded via a `src` attribute; the value may be relative.
    External(String),
}

/// A parsed HTML document, ready for script extraction and serialization.
pub struct Document {
    dom: RcDom,
}

/// Parse `html` into a [`Document`] using the html5ever HTML5 parser.
pub fn parse(html: &str) -> anyhow::Result<Document> {
    let dom = parse_document(RcDom::default(), ParseOpts::default())
        .from_utf8()
        .read_from(&mut html.as_bytes())
        .map_err(|e| anyhow!("html parse failed: {e:?}"))?;
    Ok(Document { dom })
}

impl Document {
    /// Walk the DOM and return every executable `<script>` in document order.
    ///
    /// Inline scripts carry their text content; external scripts carry the raw
    /// `src` attribute value (which may be relative).  Non-JS types (JSON,
    /// templates, etc.) are skipped.
    pub fn extract_scripts(&self) -> Vec<ScriptSource> {
        let mut out = Vec::new();
        collect_scripts(&self.dom.document, &mut out);
        out
    }
}

/// Insert document.write() output into the rendered LinkeDOM document.
pub(crate) fn inject_written_html(mut html: String, extra: &str) -> String {
    if !extra.is_empty() {
        if let Some(pos) = html.rfind("</body>") {
            html.insert_str(pos, extra);
        } else {
            html.push_str(extra);
        }
    }
    html
}

/// Recursively walk the subtree rooted at `handle`, appending any executable
/// scripts to `out` in document order.
fn collect_scripts(handle: &Handle, out: &mut Vec<ScriptSource>) {
    if let NodeData::Element {
        ref name,
        ref attrs,
        ..
    } = handle.data
        && &name.local == "script"
    {
        let attrs = attrs.borrow();

        // Skip non-JS types (JSON, templates, etc.).
        let type_val = attrs
            .iter()
            .find(|a| &a.name.local == "type")
            .map(|a| a.value.to_string());
        if let Some(ref t) = type_val {
            let t = t.trim().to_ascii_lowercase();
            let executable = match t.as_str() {
                ""
                | "text/javascript"
                | "application/javascript"
                | "module"
                | "text/rocketscript" => true,
                // Modern Cloudflare Rocket Loader rewrites type to "<hex-hash>-text/javascript"
                t => t.ends_with("-text/javascript") || t.ends_with("-application/javascript"),
            };
            if !executable {
                // LinkeDOM's native document retains non-executable script elements.
                return;
            }
        }

        let src = attrs
            .iter()
            .find(|a| &a.name.local == "src")
            .map(|a| a.value.trim().to_string());

        if let Some(src) = src {
            if !src.is_empty() {
                out.push(ScriptSource::External(src));
            }
        } else {
            let mut content = String::new();
            for child in handle.children.borrow().iter() {
                if let NodeData::Text { ref contents } = child.data {
                    content.push_str(&contents.borrow());
                }
            }
            if !content.trim().is_empty() {
                out.push(ScriptSource::Inline(content));
            }
        }
        // Don't recurse into script children.
        return;
    }
    for child in handle.children.borrow().iter() {
        collect_scripts(child, out);
    }
}
