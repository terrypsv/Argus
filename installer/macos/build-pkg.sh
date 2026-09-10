#!/usr/bin/env bash
# Copyright (c) 2026 Terry Passave. All rights reserved.
# Construit le paquet d'installation macOS d'Argus.
#
# Deux etapes: pkgbuild fabrique le composant, productbuild l'habille et produit
# l'assistant que voit l'utilisateur.
#
# Sur la signature: un paquet non signe ni notarie declenche Gatekeeper, qui
# refuse l'ouverture au double-clic. Ce n'est pas un defaut du paquet, c'est le
# regime normal de macOS pour un editeur inconnu. Deux issues, documentees dans
# le README: clic droit puis Ouvrir, ou installation avec installer(8).
#
# Usage: build-pkg.sh <version> <arch> <chemin-du-binaire>
#   ex.: build-pkg.sh 1.3.0 arm64 dist/argus_darwin_arm64

set -euo pipefail

VERSION="${1:?version requise}"
ARCH="${2:?architecture requise (amd64 ou arm64)}"
BINARY="${3:?chemin du binaire requis}"

[ -f "$BINARY" ] || { echo "binaire introuvable: $BINARY" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
STAGE="$(mktemp -d)"
SCRIPTS="$(mktemp -d)"
RES="$(mktemp -d)"
WORK="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$SCRIPTS" "$RES" "$WORK"' EXIT

# --- contenu installe ---
install -d "$STAGE/usr/local/bin"
install -m 0755 "$BINARY" "$STAGE/usr/local/bin/argus"

install -d "$STAGE/usr/local/share/man/man1"
install -m 0644 "$HERE/../man/argus.1" "$STAGE/usr/local/share/man/man1/argus.1"

install -d "$STAGE/usr/local/share/doc/argus"
install -m 0644 "$ROOT/LICENSE" "$STAGE/usr/local/share/doc/argus/LICENSE"
install -m 0755 "$HERE/uninstall.sh" "$STAGE/usr/local/share/doc/argus/uninstall.sh"

# --- apres installation ---
# On rappelle la premiere etape plutot que de la faire: poser une reference
# d'integrite a la place de l'operateur figerait l'etat d'une machine dont
# personne n'a verifie qu'elle etait saine.
cat > "$SCRIPTS/postinstall" <<'EOF'
#!/bin/sh
echo "argus installe dans /usr/local/bin"
echo "premiere etape   argus baseline, puis argus"
echo "desinstallation  sudo /usr/local/share/doc/argus/uninstall.sh"
exit 0
EOF
chmod 0755 "$SCRIPTS/postinstall"

# --- composant ---
pkgbuild \
  --root "$STAGE" \
  --scripts "$SCRIPTS" \
  --identifier "com.steelveil.argus" \
  --version "$VERSION" \
  --install-location "/" \
  "$WORK/argus-component.pkg" >/dev/null

# --- habillage ---
cp "$HERE/resources/background.png"      "$RES/"
cp "$HERE/resources/background-dark.png" "$RES/"
cp "$HERE/resources/welcome.html"        "$RES/"
cp "$HERE/resources/conclusion.html"     "$RES/"
cp "$ROOT/LICENSE"                       "$RES/license.txt"

# La version du pkg-ref doit correspondre a celle du composant, sinon
# l'assistant refuse le paquet.
sed "s/__VERSION__/${VERSION}/" "$HERE/distribution.xml" > "$WORK/distribution.xml"

OUT="argus_${VERSION}_darwin_${ARCH}.pkg"
productbuild \
  --distribution "$WORK/distribution.xml" \
  --resources "$RES" \
  --package-path "$WORK" \
  "$OUT" >/dev/null

echo "$OUT"
