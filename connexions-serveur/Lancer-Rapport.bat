@echo off
REM Rapport des connexions SDI / SDIA - a lancer en tant qu'administrateur
REM Usage : Lancer-Rapport.bat [AAAA-MM]   (defaut : mois en cours)
set MOIS=%1
if "%MOIS%"=="" (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Get-RapportConnexions.ps1" -InclureEchecs -Ouvrir
) else (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Get-RapportConnexions.ps1" -Mois %MOIS% -InclureEchecs -Ouvrir
)
pause
