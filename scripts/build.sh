#!/usr/bin/env bash
# Compilation croisee d'Argus vers ./dist, pour les essais locaux.
#
# Les binaires produits ici rapportent la version que Go tire de Git,
# l'etiquette ou le commit, suivie de +dirty si la copie de travail est
# modifiee. Le numero de version n'est injecte que par le workflow de
# publication. Un binaire local qui se declarerait 1.3.0 sans l'etre rendrait
# un rapport irreproductible.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p dist
echo "Compilation pour toutes les cibles..."

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

echo "Termine. Les binaires sont dans ./dist"
