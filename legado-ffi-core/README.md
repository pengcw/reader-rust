# Legado FFI Core

本目录是 Legado 阅读器解析扩展的独立 Rust crate，构建 `reader_parser` 动态库。

```bash
cargo build --locked --release --lib
cargo test --locked
```

Linux 构建产物位于 `target/<target>/release/libreader_parser.so`。需要更新 C 头文件时，在此目录运行：

```bash
cargo run --bin generate_headers
```

跨平台构建配置及辅助脚本也放在本目录。GitHub Actions 工作流保留在仓库根目录的 `.github/workflows/build-ffi.yml`（GitHub 的工作流发现路径要求如此），其 Cargo 构建、打包和 ELF 检查均以本目录为工作目录。
