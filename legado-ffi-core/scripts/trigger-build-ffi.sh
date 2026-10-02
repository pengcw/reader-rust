#!/bin/bash

# 如果没有传入参数，默认使用当前开发分支
BRANCH="${1:-feature/ffi-lua-parser}"
TARGET="${2:-all}"
DEFAULT_BRANCH="master"
REPO="pengcw/reader-rust"

# 临时切换默认分支
echo "正在临时将 GitHub 默认分支切换为: $BRANCH"
if ! gh repo edit "$REPO" --default-branch "$BRANCH"; then
  echo "❌ 切换默认分支失败，请确保你拥有该仓库的 Admin 权限。"
  exit 1
fi

# 注册 trap：无论脚本是正常退出、报错还是被中断，都会执行还原默认分支的操作
cleanup() {
  echo "正在还原 GitHub 默认分支为: $DEFAULT_BRANCH"
  gh repo edit "$REPO" --default-branch "$DEFAULT_BRANCH"
}
trap cleanup EXIT

# 触发工作流
echo "正在尝试触发 build-ffi.yml 工作流，目标分支: $BRANCH, 选定构建平台: $TARGET"
gh workflow run build-ffi.yml --ref "$BRANCH" -R "$REPO" -f target="$TARGET"

if [ $? -eq 0 ]; then
  echo "✅ 工作流已成功触发！"
  echo "您可以使用以下命令查看运行状态: gh run list --workflow=build-ffi.yml"
else
  echo "❌ 触发工作流失败。"
fi
