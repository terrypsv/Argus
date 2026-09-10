#!/usr/bin/env bash
# Copyright (c) 2026 Terry Passave. All rights reserved.
# Extrait du journal des modifications la section correspondant a une version.
#
# Une note de version doit dire ce qui change pour celui qui utilise l'outil.
# Les titres de commits disent ce qui a ete pousse, ce qui n'est pas la meme
# chose et n'interesse que le depot.
#
# Usage: extract-notes.sh <version> [chemin-du-changelog]

set -euo pipefail

VERSION="${1:?version requise}"
FILE="${2:-CHANGELOG.md}"

[ -f "$FILE" ] || { echo "journal introuvable: $FILE" >&2; exit 1; }

awk -v v="$VERSION" '
  $0 ~ "^## \\[" v "\\]" { found = 1; next }
  found && /^## \[/      { exit }
  found                  { print }
' "$FILE" | sed -e '/./,$!d' | awk '
  { lines[NR] = $0 }
  END {
    last = NR
    while (last > 0 && lines[last] ~ /^[[:space:]]*$/) last--
    for (i = 1; i <= last; i++) print lines[i]
  }
'
