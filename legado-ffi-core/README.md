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

## 用户文本转换

`reader_execute` 的 `toc` / `content` 请求可在 `params` 中携带：

```json
{
  "textTransformDialect": "reader3",
  "textTransformRules": [
    {
      "pattern": "old",
      "replacement": "new",
      "isRegex": false
    }
  ]
}
```

`textTransformDialect` 支持 `reader3`、`legado`、`qread`。调用方必须先完成书籍范围、标题/正文目标、启用状态和规则顺序筛选；Rust 只执行收到的规则，并在目录格式化或正文书源替换完成后进行最终文本转换。未知 dialect、非法规则或执行失败均 fail-open，不应中断阅读。

执行顺序固定为：目录先完成分页、去重、排序和 `formatJs`，再转换最终标题；正文先完成分页、`subContent` 和书源 `replaceRegex`，再转换最终正文。旧的 `params.replaceRules` 不再处理，`reader_eval` 也不再接受 ReplaceRule 数组作为特殊入口，避免保留两套用户规则协议。

当前 Android/qread 的普通字符串与 Java-compatible regex replacement 已支持；`replacement` 以 `@js:` 开头的规则暂时整条跳过，避免在未具备 match-scoped `book/chapter/java` 兼容环境时产生错误替换。Reader3 使用其独立 QuickJS 批量语义，不受此限制。
