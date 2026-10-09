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

## 浏览器超时

`reader_execute` 的 `options` 可配置浏览器模式（`preview`、`java.webView` 等）的预算：

| 参数 | 默认值 | 最大值 |
|---|---:|---:|
| `scriptTimeoutMs` | 3000 ms | 30000 ms |
| `renderTimeoutMs` | 30000 ms | 120000 ms |
| `timeoutMs`（HTTP） | 15000 ms | 120000 ms |

未传或传 `0` 使用默认值；超限或 JS 预算大于整页预算时报参数错误。
`scriptTimeoutMs` 是每次脚本执行的预算，受剩余整页预算约束，不是整页累计 JS 时间。
整页预算从 Rakers 渲染阶段开始，不包含初始网页下载；HTTP 独立限时，阻塞宿主调用不能保证由 JS 中断器即时打断。
QuickJS 后端支持脚本中断；Boa 后端当前不能强制执行脚本时间限制。
这些选项不改变普通书源规则 JS 的执行方式，也不改变非浏览器抓取的既有渲染默认值。
