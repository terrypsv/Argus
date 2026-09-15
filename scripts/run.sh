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

# La reference n'est pas creee automatiquement, et c'est delibere: la prendre
# revient a declarer la machine saine. Sur un hote deja compromis, une reference
# posee sans que personne n'ait rien verifie enregistre l'alteration comme
# legitime, et le controle d'integrite cesse de servir a quoi que ce soit.
if [ ! -f argus-baseline.json ]; then
    echo "Note: aucune reference d'integrite sur cette machine."
    echo "      Les controles d'integrite n'auront rien a comparer."
    echo "      Pour la prendre, quand vous jugez la machine saine:"
    echo "        sudo ./argus baseline"
    echo
fi

mkdir -p reports
./argus scan --out ./reports "$@"

echo
echo "Rapports ecrits dans ./reports"