# LinkeDOM worker

Version: 0.18.13

Source: https://registry.npmjs.org/linkedom/-/linkedom-0.18.13.tgz

Package integrity: `sha512-ES/o9qotMpzpN2MHs+Iq/JcVoOj8Fa5wiQYrTdFpvAnwXL0g66XHHUc9WUMk6nAlBtGsFQ24ne+SYnvnaQ2FSw==` (verified before extraction).

Upstream worker.js SHA-256: `ea9f1de69b009d210968dd8f4d3f4ecf1095bedf80d389ec83244c1713578288`.

`worker.js` is based on that published worker ESM, with the upstream ISC license retained. The local patch adds MutationObserver `characterData`/`characterDataOldValue` notifications, including detached text nodes and subtree observation, and reuses the existing mutation microtask queue. Text edits no longer masquerade as child-list mutations. The native delivery queue captures its Promise microtask entry point before page scripts run, so page-installed Promise polyfills cannot disable DOM notifications. Runtime resource limits are unchanged.

Patched worker.js SHA-256: `e74188af5024af842310b62d932d1ad3812512067ff7b9428c290bcc5e9a22bd`.

The CSSOM `CSSValue.prototype._getConstructorName()` uses `this.constructor.name` instead of parsing `Function.prototype.toString()`: Terser can produce anonymous function source text, and stripped QuickJS bytecode does not preserve original source. A targeted QuickJS test checks source/minified builds under all four `strip_source` / `strip_debug` combinations.

`worker.min.js` is a reproducible **Terser 5.39.0** minification of that same source (ESM, no tree shaking or intentional feature removal). From `vendor/rakers/` regenerate with:

```sh
npm exec --yes --package=terser@5.39.0 -- terser src/linkedom/worker.js --compress --mangle --module --ecma 2020 --output src/linkedom/worker.min.js
```

Minified worker size: **177264 bytes** (patched source 411739 bytes; 57.0% less). SHA-256: `13ca2a85a30fd5855117ac4a3838a485d9cb4e26a99849bedd422f83756bbd2f`. Verified with cached Terser 5.39.0 offline on 2026-10-13: generated stdout matches the tracked minified file after removing stdout's final newline.
For both 32-bit and 64-bit targets, the Rakers Cargo build script compiles `worker.min.js` into embedded QuickJS bytecode. Cross-architecture ARM32 decoding is currently assumed compatible for the pinned QuickJS version and little-endian targets; device verification is still pending. **No decompression or Node runtime** is required on target devices. The npm tool is used only when regenerating the vendored source. The WebView-only opt-in and existing resource limits are unchanged. LinkeDOM is a limited DOM implementation, not a complete browser.
