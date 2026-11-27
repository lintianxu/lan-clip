#!/bin/sh
set -eu

WIN_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$WIN_DIR/.." && pwd)
VERSION="3.0.0"
BUILD_DIR="$ROOT_DIR/build"
OUT_EXE="$BUILD_DIR/LanClip-v${VERSION}-Windows-x64.exe"

mkdir -p "$BUILD_DIR"
cd "$WIN_DIR"

echo "1/2 下载依赖并运行 Go 单元测试..."
go test -v ./...

echo "2/2 编译 Windows 64 位单文件绿色托盘程序..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build \
  -trimpath \
  -ldflags="-H=windowsgui -s -w" \
  -o "$OUT_EXE" \
  ./cmd/lanclip

echo "Windows 版本构建完成：$OUT_EXE"
