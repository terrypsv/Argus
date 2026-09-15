@echo off
setlocal
title Argus - scan de securite
cd /d "%~dp0.."

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Relance en administrateur pour une couverture complete...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

if not exist "argus.exe" (
    echo argus.exe introuvable, compilation en cours...
    go build -o argus.exe .
    if errorlevel 1 (
        echo.
        echo Echec de la compilation. Go est-il installe ?
        pause
        exit /b 1
    )
)

rem La reference n'est pas creee automatiquement, et c'est delibere: la prendre
rem revient a declarer la machine saine. Sur un hote deja compromis, une
rem reference posee sans verification enregistre l'alteration comme legitime.
if not exist "argus-baseline.json" (
    echo Note: aucune reference d integrite sur cette machine.
    echo       Les controles d integrite n auront rien a comparer.
    echo       Pour la prendre, quand vous jugez la machine saine:
    echo         argus.exe baseline
    echo.
)

argus.exe scan --out reports

echo.
echo Rapports ecrits dans le dossier reports.
pause