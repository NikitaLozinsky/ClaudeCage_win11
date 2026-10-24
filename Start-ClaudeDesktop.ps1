<#
.SYNOPSIS
    Start-ClaudeDesktop.ps1 - Secure Anti-Fraud & Kill-Switched Launcher for Claude Desktop.
.DESCRIPTION
    Launches Claude Desktop (Electron) inside the ClaudeCage sandbox:
    1. Verifies AmneziaVPN connection status. Refuses to start if VPN is down (Fail-Closed).
    2. Syncs WFP Kill Switch firewall rules via Sync-ClaudeFirewall.ps1.
    3. Resolves VPN exit node timezone and injects anti-fraud environment (TZ, LANG, LC_ALL).
    4. Injects strict anti-telemetry & anti-WebRTC-leak flags into the Chromium/Electron runtime.
    5. Prepends C:\ClaudeCage\bin to PATH so MCP servers/child processes inherit caged binaries.
#>

[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$CageRoot = "C:\ClaudeCage"
$CageBin  = Join-Path $CageRoot "bin"
$CurlBin  = Join-Path $CageBin "curl.exe"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         CLAUDE CAGE: LAUNCHING CLAUDE DESKTOP            " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check AmneziaVPN Status
Write-Host "[*] [1/5] Checking AmneziaVPN tunnel status..." -ForegroundColor Yellow
$vpnAdapter = Get-NetAdapter | Where-Object {
    ($_.Name -like "*Amnezia*" -or $_.InterfaceDescription -like "*WireGuard*") -and $_.Status -eq "Up"
} | Select-Object -First 1

if (-not $vpnAdapter) {
    Write-Host "`n[FAIL-CLOSED ALERT] AmneziaVPN is NOT connected or tunnel is down!" -ForegroundColor Red
    Write-Host "Claude Desktop launch ABORTED to prevent real IP/telemetry leakage." -ForegroundColor Red
    Write-Host "Please start AmneziaVPN and re-run this launcher.`n" -ForegroundColor Yellow

    # Ensure lockdown rules are engaged if elevated
    $syncScript = Join-Path $CageRoot "Sync-ClaudeFirewall.ps1"
    if (Test-Path $syncScript) {
        try { & $syncScript -Enforce } catch {}
    }
    exit 1
}

Write-Host "    [OK] AmneziaVPN is UP (Interface: $($vpnAdapter.Name))." -ForegroundColor Green

# 2. Sync / Verify WFP Kill Switch Rules
Write-Host "`n[*] [2/5] Verifying WFP Fail-Closed Kill Switch rules..." -ForegroundColor Yellow
$syncScript = Join-Path $CageRoot "Sync-ClaudeFirewall.ps1"
if (Test-Path $syncScript) {
    try {
        & $syncScript -Enforce
        Write-Host "    [OK] Kill Switch rules verified and active." -ForegroundColor Green
    } catch {
        Write-Warning "    [!] Notice: Could not refresh firewall rules directly (may require admin): $_"
    }
}

# 3. Detect VPN Geolocation & Timezone
Write-Host "`n[*] [3/5] Resolving VPN exit node timezone & anti-fraud telemetry..." -ForegroundColor Yellow
$vpnTz = "Europe/Amsterdam"
$vpnCountry = "NL"
$vpnIp = "Unknown"

if (Test-Path $CurlBin) {
    try {
        $ipJson = & $CurlBin -s --connect-timeout 4 https://ipinfo.io/json
        if ($ipJson) {
            $info = $ipJson | ConvertFrom-Json
            if ($info.timezone) { $vpnTz = $info.timezone }
            if ($info.country)  { $vpnCountry = $info.country }
            if ($info.ip)       { $vpnIp = $info.ip }
        }
    } catch {}
}

Write-Host "    VPN Exit IP:       $vpnIp" -ForegroundColor Cyan
Write-Host "    Exit Country:      $vpnCountry" -ForegroundColor Cyan
Write-Host "    Spoofed Timezone:  $vpnTz" -ForegroundColor Cyan

# 4. Inject Anti-Fraud Environment Variables
Write-Host "`n[*] [4/5] Injecting anti-fraud environment parameters..." -ForegroundColor Yellow
$env:TZ = $vpnTz
$env:LANG = "en_US.UTF-8"
$env:LC_ALL = "en_US.UTF-8"
$env:ELECTRON_ENABLE_LOGGING = "false"
$env:PATH = "$CageBin;$env:PATH"

# 5. Locate Claude Desktop Binary & Prepare Flags
Write-Host "`n[*] [5/5] Locating Claude Desktop and preparing Chromium flags..." -ForegroundColor Yellow

$claudeExe = $null

# Check AppX package location
$appx = Get-AppxPackage -Name *Claude* -ErrorAction SilentlyContinue | Select-Object -First 1
if ($appx) {
    $cand = Join-Path $appx.InstallLocation "app\claude.exe"
    if (Test-Path $cand) {
        $claudeExe = $cand
    }
}

if (-not $claudeExe) {
    $standardPaths = @(
        "$env:LOCALAPPDATA\Programs\Claude\Claude.exe",
        "$env:LOCALAPPDATA\AnthropicClaude\Claude.exe",
        "C:\Program Files\Claude\Claude.exe"
    )
    foreach ($p in $standardPaths) {
        if (Test-Path $p) {
            $claudeExe = $p
            break
        }
    }
}

if (-not $claudeExe) {
    Write-Error "[!] Claude Desktop executable not found! Please check installation."
    exit 1
}

Write-Host "    Binary: $claudeExe" -ForegroundColor Cyan

# Anti-Fraud & Anti-Leak Electron Flags
$electronFlags = @(
    # WebRTC leak protection
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--disable-webrtc",
    "--enforce-webrtc-ip-permission-check",

    # Locale & Language spoofing
    "--lang=en-US",
    "--accept-lang=en-US,en;q=0.9",

    # DNS & Network isolation flags
    "--disable-features=SmartMultiHomedResolution,WebRtcHideLocalIpsWithMdns",
    "--disable-background-networking"
)

Write-Host "`n[+] Launching Claude Desktop with Anti-Fraud & KillSwitch protection..." -ForegroundColor Green
$proc = Start-Process -FilePath $claudeExe -ArgumentList $electronFlags -PassThru

Write-Host "    Process ID: $($proc.Id)" -ForegroundColor Green
Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "   CLAUDE DESKTOP IS RUNNING SECURELY INSIDE CLAUDECAGE   " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
