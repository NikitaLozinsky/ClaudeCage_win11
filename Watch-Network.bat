@echo off
title ClaudeCage - Network Perspective & Live Socket Logger
color 0B
echo Launching ClaudeCage Live Network Audit Logger...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Watch-ClaudeNetworkView.ps1"
pause
