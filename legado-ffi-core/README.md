# Legado FFI Core

本目录是 Legado 阅读器解析扩展的独立 Rust crate，构建 `reader_parser` 动态库。高度为 kinlde 定制优化

```bash
cargo build --locked --release --lib
cargo test --locked
```

Linux 构建产物位于 `target/<target>/release/libreader_parser.so`。需要更新 C 头文件时，在此目录运行：

```bash
cargo run --bin generate_headers
```
