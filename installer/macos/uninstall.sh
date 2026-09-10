#!/bin/sh
# Copyright (c) 2026 Terry Passave. All rights reserved.
# Desinstalle Argus sur macOS.
#
# Apple ne fournit aucun desinstalleur pour les paquets .pkg: le systeme sait
# quels fichiers ont ete poses, mais ne propose rien pour les retirer. Ce script
# comble ce manque en s'appuyant sur l'inventaire tenu par pkgutil, plutot que
# sur une liste ecrite en dur qui divergerait a la premiere version.
#
# Il ne touche a aucun rapport, ni a la reference d'integrite, ni au fichier des
# exceptions: ce sont vos donnees, et la reference en particulier represente un
# jugement pris a un moment donne, qu'aucune desinstallation ne doit effacer.
#
# Usage: sudo /usr/local/share/doc/argus/uninstall.sh

set -eu

PKG="com.steelveil.argus"

if [ "$(id -u)" -ne 0 ]; then
  echo "droits administrateur requis" >&2
  echo "  sudo $0" >&2
  exit 1
fi

if ! pkgutil --pkgs | grep -qx "$PKG"; then
  echo "argus n'est pas installe par paquet sur cette machine"
  exit 0
fi

# On ne retire que les fichiers. Les repertoires comme /usr/local/bin sont
# partages avec d'autres programmes et ne nous appartiennent pas.
pkgutil --files "$PKG" --only-files | while IFS= read -r f; do
  [ -n "$f" ] || continue
  rm -f "/$f"
done

pkgutil --forget "$PKG" >/dev/null

echo "argus retire de cette machine"
echo "vos rapports, votre reference d'integrite et vos exceptions sont conserves"
