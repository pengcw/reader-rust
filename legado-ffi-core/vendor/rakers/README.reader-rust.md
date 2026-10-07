# reader-rust Rakers fork notes

Vendored from `rakers` 0.1.7 (MIT). Keep the upstream license and version provenance in `LICENSE` and `Cargo.toml`.

Local changes:

- Port the HTTP client calls to `ureq` 3 so the application can share one ureq major version.
- Set bounded HTTP timeouts and use ureq 3's bounded body-to-string reader.
- Make the CLI (`clap`) and HTML diff helper (`similar`) opt-in features; the reader library uses the renderer API only.
- Add an optional host HTTP transport so reader-rust can reuse its existing `HttpClient` and cookie jar for external scripts, `fetch()`, dynamic scripts, and XHR.
- Bound renderer subrequests and Promise/timer draining with render-scoped limits; on `rquickjs 0.8`, Promise jobs use cooperative count/time checks to avoid the known interrupt-in-pending-job hazard.

For URL options with `webView: true`, reader-rust reuses the page request's HTTP client so normal cookie-domain/path rules continue across JavaScript subrequests. Source authorization/private headers are still not blindly forwarded to page-controlled requests.
