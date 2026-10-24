<#
.SYNOPSIS
    Initialize-SandboxBins.ps1 - Synchronize isolated sandboxed binaries into C:\ClaudeCage\bin.
.DESCRIPTION
    Copies system node.exe and curl.exe to C:\ClaudeCage\bin to isolate Claude CLI child processes
    and MCP servers from host processes, allowing strict WFP Kill Switch rules without affecting
    host node/curl operations.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$CageBin = "C:\ClaudeCage\bin"

if (-not (Test-Path $CageBin)) {
    New-Item -ItemType Directory -Path $CageBin -Force | Out-Null
}

# 1. node.exe
$hostNode = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
if (-not $hostNode -or -not (Test-Path $hostNode)) {
    $hostNode = "C:\Program Files\nodejs\node.exe"
}

if (Test-Path $hostNode) {
    Copy-Item $hostNode (Join-Path $CageBin "node.exe") -Force
    Write-Host "[+] Synchronized node.exe: $hostNode -> $CageBin\node.exe" -ForegroundColor Green
} else {
    Write-Warning "[-] node.exe not found on host system!"
}

# 2. curl.exe
$hostCurl = (Get-Command curl.exe -ErrorAction SilentlyContinue).Source
if (-not $hostCurl -or -not (Test-Path $hostCurl)) {
    $hostCurl = "C:\Windows\System32\curl.exe"
}

if (Test-Path $hostCurl) {
    Copy-Item $hostCurl (Join-Path $CageBin "curl.exe") -Force
    Write-Host "[+] Synchronized curl.exe: $hostCurl -> $CageBin\curl.exe" -ForegroundColor Green
} else {
    Write-Warning "[-] curl.exe not found on host system!"
}

Write-Host "[OK] Sandbox binaries initialized in $CageBin" -ForegroundColor Green
