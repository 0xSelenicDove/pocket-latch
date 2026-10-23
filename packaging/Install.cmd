@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Add-AppDevPackage.ps1"
echo.
echo If installation succeeded, open PocketLatch from Start.
pause
