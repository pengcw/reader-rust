# reader-rust Rakers fork notes

Vendored from `rakers` 0.1.7 (MIT). Keep the upstream license and version provenance in `LICENSE` and `Cargo.toml`.

Local changes:

- Port the HTTP client calls to `ureq` 3 so the application can share one ureq major version.
- Set bounded HTTP timeouts and use ureq 3's bounded body-to-string reader.
- Make the CLI (`clap`) and HTML diff helper (`similar`) opt-in features; the reader library uses the renderer API only.

The application invokes `render` only for URL options with `webView: true`. It passes only the configured User-Agent and proxy; source cookies and authorization headers are not forwarded to page scripts/XHR.
