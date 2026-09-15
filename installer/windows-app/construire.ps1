# Copyright (c) 2026 Terry Passave. Tous droits reserves.
#
# Construit l'installeur d'Argus.
#
# Trois etapes: compiler les deux programmes a embarquer, les deposer dans
# payload, puis compiler l'installeur qui les contient.
#
# Comme pour la console, la CLI Wails n'est pas utilisee: son outillage est
# incompatible avec Go recent, et elle n'apporte rien ici puisque le frontal est
# un fichier HTML statique et que les liaisons sont injectees a l'execution.
#
# Usage: .\construire.ps1 [-Version 1.3.0]

param([string]$Version = "dev")

$ErrorActionPreference = "Stop"
$ici = Split-Path -Parent $MyInvocation.MyCommand.Path
$racine = Resolve-Path (Join-Path $ici "..\..")

function ArreterInstances {
    foreach ($nom in @("argus-installeur", "argus-console", "argus")) {
        foreach ($p in @(Get-Process $nom -ErrorAction SilentlyContinue)) {
            Write-Host "  fermeture de $nom ($($p.Id))" -ForegroundColor DarkGray
            try { Stop-Process -Id $p.Id -Force -ErrorAction Stop; Start-Sleep -Milliseconds 300 }
            catch {
                Write-Host "  impossible d'arreter $nom ($($p.Id))" -ForegroundColor Red
                Write-Host "  depuis une console administrateur: Stop-Process -Id $($p.Id) -Force" -ForegroundColor Yellow
                throw "une instance non arretable bloque la construction"
            }
        }
    }
}

Push-Location $ici
try {
    Write-Host "fermeture des instances en cours" -ForegroundColor DarkGray
    ArreterInstances

    $dateJour = (Get-Date).ToString("yyyy-MM-dd")

    Write-Host "compilation de la ligne de commande" -ForegroundColor DarkGray
    Push-Location $racine
    try {
        go build -ldflags "-X github.com/terrypsv/Argus/internal/engine.Version=$Version" `
                 -o (Join-Path $ici "payload\argus.exe") .
        if ($LASTEXITCODE -ne 0) { throw "la compilation d'argus a echoue" }
    } finally { Pop-Location }

    Write-Host "compilation de l'application de bureau" -ForegroundColor DarkGray
    Push-Location (Join-Path $racine "cmd\argus-console")
    try {
        go build -tags "desktop,production" `
                 -ldflags "-H windowsgui -X main.version=$Version -X main.dateCompilation=$dateJour" `
                 -o (Join-Path $ici "payload\argus-console.exe") .
        if ($LASTEXITCODE -ne 0) { throw "la compilation de la console a echoue" }
    } finally { Pop-Location }

    # Les ressources portent l'icone et surtout le manifeste qui demande les
    # droits administrateur au lancement. Sans lui, l'installeur s'ouvre sans
    # privileges et echoue a la premiere ecriture dans Program Files.
    $syso = Join-Path $ici "rsrc_windows_amd64.syso"
    if (Test-Path $syso) {
        Write-Host "  ressources Windows trouvees (icone et elevation)" -ForegroundColor DarkGray
    } else {
        Write-Host "  aucune ressource: l'installeur ne demandera pas l'elevation" -ForegroundColor Red
        Write-Host "  pour la produire: go-winres make --arch amd64" -ForegroundColor Yellow
    }

    Write-Host "verification du code" -ForegroundColor DarkGray
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw "go vet a echoue" }

    Write-Host "compilation de l'installeur" -ForegroundColor DarkGray
    go build -tags "desktop,production" `
             -ldflags "-H windowsgui -X main.version=$Version" `
             -o "argus-installeur.exe" .
    if ($LASTEXITCODE -ne 0) { throw "la compilation de l'installeur a echoue" }

    $taille = [math]::Round((Get-Item "argus-installeur.exe").Length / 1MB, 1)
    Write-Host ""
    Write-Host "argus-installeur.exe est pret ($taille Mo)" -ForegroundColor Green
    Write-Host "  $ici" -ForegroundColor DarkGray
} finally {
    Pop-Location
}
