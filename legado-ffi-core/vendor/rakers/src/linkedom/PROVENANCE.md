# LinkeDOM worker

Version: 0.18.13

Source: https://registry.npmjs.org/linkedom/-/linkedom-0.18.13.tgz

Package integrity: `sha512-ES/o9qotMpzpN2MHs+Iq/JcVoOj8Fa5wiQYrTdFpvAnwXL0g66XHHUc9WUMk6nAlBtGsFQ24ne+SYnvnaQ2FSw==` (verified before extraction).

worker.js SHA-256: `ea9f1de69b009d210968dd8f4d3f4ecf1095bedf80d389ec83244c1713578288`.

The unmodified published worker ESM remains as `worker.js`, with the upstream ISC license retained.

`worker.min.js` is a reproducible **Terser 5.39.0** minification of that same source (ESM, no tree shaking or intentional feature removal). From `vendor/rakers/` regenerate with:

```sh
npm exec --yes --package=terser@5.39.0 -- terser src/linkedom/worker.js --compress --mangle --module --ecma 2020 --output src/linkedom/worker.min.js
```

Minified worker size: **177020 bytes** (original 411521 bytes; 57.0% less). SHA-256: `0b0f6c5e8f26d953633cb9b7d6a1044cf0f81af6667e3bcf8fd20932ff1e26be`.
The Rust feature-gated QuickJS loader embeds `worker.min.js` directly as JavaScript; **no decompression or Node runtime** is required on target devices. The npm tool is used only when regenerating the vendored source. The WebView-only opt-in and existing resource limits are unchanged. LinkeDOM is a limited DOM implementation, not a complete browser.
