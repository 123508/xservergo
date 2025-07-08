#!/bin/bash
# Kitex 服务初始化脚本
# 用于根据 proto 文件生成各服务代码

set -e

# 项目根目录
PROJECT_ROOT=$(cd "$(dirname "$0")/.." && pwd)
# IDL目录
IDL_PATH="$PROJECT_ROOT/idl"
# 应用程序目录
APPS_PATH="$PROJECT_ROOT/apps"
# 项目包名
PROJECT_PKG=github.com/123508/xservergo
# Kitex 生成代码的包路径
KITEX_GEN="$PROJECT_PKG/kitex_gen"

# 检查 kitex 是否安装
if ! command -v kitex &> /dev/null; then
  echo "[ERROR] kitex 未安装，请先安装 kitex: go install github.com/cloudwego/kitex"
  exit 1
fi

# 使用 kitex 命令生成代码
cd "$PROJECT_ROOT"
kitex -module "$PROJECT_PKG" -I="$IDL_PATH" user/user_v1.0.proto

# 生成服务代码

mkdir "$APPS_PATH/user" -p
cd "$APPS_PATH/user"
kitex -module "$PROJECT_PKG" -service xservergo.user -use "$KITEX_GEN" -I "$IDL_PATH" user/user_v1.0.proto
echo "[OK] Kitex user 服务初始化完成。"
