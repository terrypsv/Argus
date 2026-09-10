#!/usr/bin/env bash
# Copyright (c) 2026 Terry Passave. All rights reserved.
# Construit le paquet Debian d'Argus.
#
# Sur Linux, le gestionnaire de paquets est l'experience d'installation: le
# binaire va dans /usr/bin, deja present dans le PATH de tout le monde.
#
# Ce que le paquet NE fait pas, deliberement:
#   - il ne cree aucune reference d'integrite. `argus baseline` reste un geste
#     de l'operateur, pris au moment ou il juge la machine saine. Une reference
#     posee par l'installeur figerait l'etat d'une machine dont personne n'a
#     verifie qu'elle etait propre;
#   - il n'installe aucune tache planifiee. Analyser une machine est une
#     decision, pas un effet de bord d'installation.
#
# Usage: build-deb.sh <version> <arch-deb> <chemin-du-binaire>
#   ex.: build-deb.sh 1.3.0 amd64 dist/argus_linux_amd64

set -euo pipefail

VERSION="${1:?version requise}"
ARCH="${2:?architecture requise (amd64 ou arm64)}"
BINARY="${3:?chemin du binaire requis}"

[ -f "$BINARY" ] || { echo "binaire introuvable: $BINARY" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

install -d "$STAGE/DEBIAN"
install -d "$STAGE/usr/bin"
install -d "$STAGE/usr/share/doc/argus"
install -d "$STAGE/usr/share/man/man1"

install -m 0755 "$BINARY" "$STAGE/usr/bin/argus"

# La taille declaree est celle du contenu installe, en kibioctets: apt s'en sert
# pour annoncer l'espace requis avant d'installer.
INSTALLED_KB="$(du -ks "$STAGE/usr" | cut -f1)"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: argus
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Maintainer: Terry Passave <noreply@trry.fr>
Homepage: https://github.com/terrypsv/Argus
Installed-Size: ${INSTALLED_KB}
Description: bulletin de posture de sécurité d'un poste
 Argus analyse la posture de sécurité d'une machine et la restitue en deux
 notes distinctes, le durcissement et l'intégrité.
 .
 La séparation est délibérée. Le durcissement mesure ce qui n'a pas été fait,
 l'intégrité mesure ce qui a peut-être déjà été fait contre vous. Une seule
 note mélangerait les deux, et un poste bien durci mais compromis se lirait
 comme sain.
 .
 Un constat examiné peut être accepté avec un motif, une date et un auteur. Il
 reste compté à part et n'est jamais confondu avec un contrôle réussi, car un
 renoncement n'est pas une correction.
EOF

cp "$ROOT/LICENSE" "$STAGE/usr/share/doc/argus/copyright"
gzip -9 -n -c "$HERE/../man/argus.1" > "$STAGE/usr/share/man/man1/argus.1.gz"

# Les rapports, la reference d'integrite et les exceptions appartiennent a
# l'operateur: la desinstallation ne les touche pas, elle le rappelle.
cat > "$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
  echo "argus: vos rapports, votre reference d'integrite et vos exceptions sont conserves" >&2
fi
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/postrm"

find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE/usr/share" -type f -exec chmod 0644 {} +
chmod 0755 "$STAGE/usr/bin/argus"

OUT="argus_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT" >/dev/null
echo "$OUT"
