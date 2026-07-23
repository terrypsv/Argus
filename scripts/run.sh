#!/usr/bin/env bash
# Lanceur Argus pour Linux et macOS.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -x ./argus ]; then
    echo "Compilation d'Argus..."
    go build -o argus .
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Relance avec sudo pour une couverture complete..."
    exec sudo "$0" "$@"
fi

if [ ! -f argus-baseline.json ]; then
    echo "Aucune baseline d'integrite trouvee, creation..."
    ./argus baseline
    echo
fi

mkdir -p reports
./argus scan --out ./reports "$@"

echo
echo "Rapports ecrits dans ./reports"