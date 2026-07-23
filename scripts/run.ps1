# Build and run Argus on Windows from PowerShell.
# Usage:  .\scripts\run.ps1            (build + scan)
#         .\scripts\run.ps1 -Baseline  (record integrity baseline)
param(
    [switch]$Baseline,
    [string]$Out = ".\reports"
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Error "Go is not installed. Get it from https://go.dev/dl/ then re-run."
    exit 1
}

Write-Host "Building argus.exe..." -ForegroundColor Cyan
go build -trimpath -ldflags="-s -w" -o argus.exe .

if ($Baseline) {
    .\argus.exe baseline
} else {
    New-Item -ItemType Directory -Force -Path $Out | Out-Null
    .\argus.exe scan --out $Out
    Write-Host "Reports written to $Out" -ForegroundColor Green
}
