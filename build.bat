@echo off
title ClaudeCage Build Pipeline
color 0A
echo ==========================================================
echo        CLAUDECAGE NATIVE BUILD PIPELINE
echo ==========================================================
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Build-ClaudeCage.ps1" %*
echo.
pause
