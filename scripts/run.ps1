# Compile et lance Argus depuis PowerShell.
#
# Usage:  .\scripts\run.ps1            compile et analyse
#         .\scripts\run.ps1 -Baseline  enregistre la reference d'integrite
#
# La reference se demande explicitement, elle n'est jamais prise d'office: la
# poser revient a declarer la machine saine.
param(
    [switch]$Baseline,
    [string]$Out = ".\reports"
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Error "Go n'est pas installe. Recuperez-le sur https://go.dev/dl/ puis relancez."
    exit 1
}

Write-Host "Compilation d'argus.exe..." -ForegroundColor Cyan
go build -trimpath -ldflags="-s -w" -o argus.exe .

if ($Baseline) {
    .\argus.exe baseline
} else {
    New-Item -ItemType Directory -Force -Path $Out | Out-Null
    .\argus.exe scan --out $Out
    Write-Host "Rapports ecrits dans $Out" -ForegroundColor Green
}
