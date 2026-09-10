# Copyright (c) 2026 Terry Passave.
# Reecrit les notes de toutes les releases a partir de CHANGELOG.md.
#
# Une release publiee sans section correspondante retombe sur les titres de
# commits, qui disent ce qui a ete pousse et non ce qui a change. Ce script
# rattrape les releases deja publiees, sans retaguer ni relancer de workflow.
#
# Usage, depuis la racine du depot:
#   .\update-release-notes.ps1 -DryRun    montre ce qui serait ecrit
#   .\update-release-notes.ps1            applique
#   .\update-release-notes.ps1 -Repo terrypsv/Argus

param(
    [switch]$DryRun,
    [string]$Repo = "",
    [string]$Changelog = "CHANGELOG.md"
)

if (-not (Test-Path $Changelog)) {
    Write-Host "journal introuvable: $Changelog" -ForegroundColor Red
    exit 1
}

# Depot deduit de l'origine git si non fourni.
if (-not $Repo) {
    $url = git remote get-url origin 2>$null
    if (-not $url) { Write-Host "depot introuvable, utilisez -Repo" -ForegroundColor Red; exit 1 }
    $Repo = ($url -replace '.*github\.com[:/]', '') -replace '\.git$', ''
}
Write-Host "depot: $Repo`n" -ForegroundColor Cyan

# --- decoupage du journal en sections par version ---
$sections = [ordered]@{}
$current = $null
$buffer = New-Object System.Collections.Generic.List[string]

foreach ($line in (Get-Content $Changelog -Encoding UTF8)) {
    if ($line -match '^##\s+\[([0-9]+\.[0-9]+\.[0-9]+)\]') {
        if ($current) { $sections[$current] = ($buffer -join "`n").Trim() }
        $current = $Matches[1]
        $buffer.Clear()
    }
    elseif ($current) {
        $buffer.Add($line)
    }
}
if ($current) { $sections[$current] = ($buffer -join "`n").Trim() }

Write-Host "sections trouvees dans le journal: $($sections.Count)"

# --- releases publiees ---
$published = gh release list --repo $Repo --limit 100 --json tagName --jq '.[].tagName'
if (-not $published) { Write-Host "aucune release publiee" -ForegroundColor Yellow; exit 0 }

$utf8 = [System.Text.UTF8Encoding]::new($false)
$updated = 0
$skipped = @()

foreach ($tag in $published) {
    $version = $tag -replace '^v', ''
    if (-not $sections.Contains($version)) {
        $skipped += $tag
        continue
    }
    $notes = $sections[$version]

    if ($DryRun) {
        Write-Host "`n=== $tag ===" -ForegroundColor Green
        Write-Host $notes
        continue
    }

    # --notes-file evite tout probleme de guillemets et d'accents en ligne de
    # commande: le texte passe par un fichier ecrit en UTF-8 sans BOM.
    $tmp = Join-Path $env:TEMP "notes-$version.md"
    [System.IO.File]::WriteAllText($tmp, $notes, $utf8)
    gh release edit $tag --repo $Repo --notes-file $tmp | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host ("  OK      {0}" -f $tag) -ForegroundColor Green
        $updated++
    } else {
        Write-Host ("  ECHEC   {0}" -f $tag) -ForegroundColor Red
    }
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}

if ($DryRun) {
    Write-Host "`nSimulation seulement. Relancez sans -DryRun pour appliquer." -ForegroundColor Cyan
} else {
    Write-Host "`n$updated release(s) mise(s) a jour."
}
if ($skipped.Count -gt 0) {
    Write-Host "sans section dans le journal: $($skipped -join ', ')" -ForegroundColor Yellow
}
