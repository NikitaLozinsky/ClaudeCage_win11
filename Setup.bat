@echo off
:: ClaudeCage 1-Click Administrator Launcher
title ClaudeCage Windows 11 Installer
echo ==========================================================
echo        Starting ClaudeCage Installer (Windows 11)
echo ==========================================================
echo.
echo Requesting Administrator privileges...

powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File \"\"%~dp0Setup-ClaudeCage.ps1\"\"' -Verb RunAs"

exit /b
