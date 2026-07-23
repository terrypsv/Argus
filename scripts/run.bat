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

if not exist "argus-baseline.json" (
    echo Aucune baseline d integrite trouvee, creation...
    argus.exe baseline
    echo.
)

argus.exe scan --out reports

echo.
echo Rapports ecrits dans le dossier reports.
pause