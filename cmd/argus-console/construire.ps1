# Copyright (c) 2026 Terry Passave. Tous droits reserves.
#
# Construit la Console Argus sans passer par la CLI Wails.
#
# Pourquoi. La CLI Wails 2.10.1 embarque une version de golang.org/x/tools qui
# ne sait pas lire les donnees de type produites par Go 1.27, et echoue avant
# meme de compiler:
#
#   internal error: package "context" without types was imported from ...
#
# Or elle ne nous apporte rien ici: elle sert a construire un frontal npm, que
# nous n'avons pas, et a generer des liaisons JavaScript, que Wails injecte de
# toute facon a l'execution a partir de l'option Bind. Un go build ordinaire
# produit donc le meme binaire, sans l'outillage qui casse.
#
# Deux marqueurs sont indispensables:
#   desktop,production  selectionnent l'implementation de Wails plutot que son
#                       mode developpement, qui attend un serveur de rechargement
#   -H windowsgui       empeche une fenetre de console noire d'apparaitre
#                       derriere l'application
#
# Usage: .\construire.ps1 [-Version 1.3.0] [-AvecArgus] [-Propre]

param(
    [string]$Version = "dev",
    # Copie argus.exe a cote du binaire produit. La console cherche la ligne de
    # commande a cote d'elle en premier, ce qui reproduit l'etat d'apres
    # installation sans avoir a installer quoi que ce soit.
    [switch]$AvecArgus,
    # Efface les analyses conservees. Pendant les essais, la console rouvre sur
    # la derniere analyse et on croit tester du neuf en regardant du vieux.
    [switch]$Propre
)

$ErrorActionPreference = "Stop"
$ici = Split-Path -Parent $MyInvocation.MyCommand.Path
$racine = Resolve-Path (Join-Path $ici "..\..")

# Windows verrouille un executable en cours d'execution: la compilation echoue,
# ou pire, elle reussit sur l'ancien fichier et on teste une version qu'on croit
# avoir remplacee. On ferme donc avant de construire.
#
# Un cas merite d'etre traite a part: une instance lancee depuis une session
# administrateur ne peut pas etre arretee depuis une session ordinaire. Le
# message par defaut de PowerShell dit "Acces refuse" sans dire quoi faire, et
# la construction s'interrompt en laissant croire a un probleme de code.
function ArreterInstances {
    $bloquants = @()
    foreach ($nom in @("argus-console", "argus")) {
        foreach ($p in @(Get-Process $nom -ErrorAction SilentlyContinue)) {
            Write-Host "  fermeture de $nom ($($p.Id))" -ForegroundColor DarkGray
            try {
                Stop-Process -Id $p.Id -Force -ErrorAction Stop
                Start-Sleep -Milliseconds 300
            } catch {
                $bloquants += $p
            }
        }
    }
    if ($bloquants.Count -gt 0) {
        Write-Host ""
        Write-Host "Impossible d'arreter une instance deja lancee." -ForegroundColor Red
        foreach ($p in $bloquants) {
            Write-Host "  $($p.ProcessName), PID $($p.Id)" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "Elle a ete lancee avec des privileges plus eleves que cette" -ForegroundColor Yellow
        Write-Host "session. Depuis une console administrateur:" -ForegroundColor Yellow
        Write-Host "  Stop-Process -Id $($bloquants[0].Id) -Force" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Sans cela la compilation ecrirait a cote, et vous testeriez" -ForegroundColor Yellow
        Write-Host "l'ancienne version en croyant tester la nouvelle." -ForegroundColor Yellow
        throw "une instance non arretable bloque la construction"
    }
}

Push-Location $ici
try {
    Write-Host "fermeture des instances en cours" -ForegroundColor DarkGray
    ArreterInstances

    if ($Propre) {
        Write-Host "effacement des analyses conservees" -ForegroundColor DarkGray
        Remove-Item "$env:ProgramData\Argus" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:APPDATA\Argus" -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host "verification du code" -ForegroundColor DarkGray
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw "go vet a echoue" }

    # Les ressources Windows, icone et manifeste, vivent dans un fichier .syso
    # que le compilateur ramasse tout seul s'il est present. Son absence n'est
    # pas bloquante: l'application tourne, avec l'icone par defaut de Go.
    $syso = Join-Path $ici "rsrc_windows_amd64.syso"
    if (Test-Path $syso) {
        Write-Host "  ressources Windows trouvees (icone et manifeste)" -ForegroundColor DarkGray
    } else {
        Write-Host "  aucune ressource Windows: l'icone sera celle de Go" -ForegroundColor DarkYellow
        Write-Host "  pour la produire: go-winres make --arch amd64" -ForegroundColor DarkYellow
    }

    Write-Host "compilation de la console" -ForegroundColor DarkGray
    go build -tags "desktop,production" `
             -ldflags "-H windowsgui -X main.version=$Version" `
             -o argus-console.exe .
    if ($LASTEXITCODE -ne 0) { throw "la compilation de la console a echoue" }

    if ($AvecArgus) {
        Write-Host "compilation de la ligne de commande" -ForegroundColor DarkGray
        Push-Location $racine
        try {
            go build -ldflags "-X github.com/terrypsv/Argus/internal/engine.Version=$Version" `
                     -o argus.exe .
            if ($LASTEXITCODE -ne 0) { throw "la compilation d'argus a echoue" }
            Copy-Item argus.exe $ici -Force
        } finally { Pop-Location }
    }

    Write-Host ""
    Write-Host "argus-console.exe est pret" -ForegroundColor Green
    Write-Host "  $ici" -ForegroundColor DarkGray
    if (-not $AvecArgus) {
        Write-Host "  argus.exe doit se trouver a cote, ou dans le PATH" -ForegroundColor DarkGray
    }
} finally {
    Pop-Location
}
