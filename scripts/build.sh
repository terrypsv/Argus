#!/usr/bin/env bash
# Cross-compile Argus for the common platforms into ./dist
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p dist
echo "Building Argus for all targets..."

build() {
  local os=$1 arch=$2 out=$3
  echo "  -> $out"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags="-s -w" -o "dist/$out" .
}

build linux   amd64 argus-linux-amd64
build linux   arm64 argus-linux-arm64
build darwin  amd64 argus-macos-amd64
build darwin  arm64 argus-macos-arm64
build windows amd64 argus-windows-amd64.exe

echo "Done. Binaries are in ./dist"
