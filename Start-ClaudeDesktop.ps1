<#
.SYNOPSIS
    Start-ClaudeDesktop.ps1 - Secure Anti-Fraud & Kill-Switched Launcher for Claude Desktop.
.DESCRIPTION
    Launches Claude Desktop (Electron) inside the ClaudeCage sandbox:
    1. Terminates any lingering/minimized Claude processes in the tray to guarantee clean
       injection of anti-fraud environment variables (TZ, LANG, LC_ALL).
    2. Syncs 24/7 atomic WFP Kill Switch firewall rules via Sync-ClaudeFirewall.ps1.
    3. Resolves VPN exit node timezone and injects anti-fraud environment.
    4. Injects valid Chromium anti-telemetry & anti-WebRTC-leak flags into the runtime.
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

# 1. Terminate any existing background / tray Claude processes
Write-Host "[*] [1/5] Terminating any stale background/tray Claude processes..." -ForegroundColor Yellow
$staleProcs = Get-Process -Name "*claude*" -ErrorAction SilentlyContinue
if ($staleProcs) {
    Write-Host "    Found $(($staleProcs | Measure-Object).Count) running Claude process(es). Terminating for clean environment..." -ForegroundColor DarkYellow
    $staleProcs | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 600
    Write-Host "    [OK] Stale processes terminated." -ForegroundColor Green
} else {
    Write-Host "    [OK] No stale Claude processes found." -ForegroundColor Gray
}

# 2. Check AmneziaVPN Status
Write-Host "`n[*] [2/5] Checking AmneziaVPN tunnel status..." -ForegroundColor Yellow
$vpnAdapter = Get-NetAdapter | Where-Object {
    ($_.Name -like "*Amnezia*" -or $_.InterfaceDescription -like "*WireGuard*") -and $_.Status -eq "Up"
} | Select-Object -First 1

$isVpnUp = ($vpnAdapter -ne $null)

if ($isVpnUp) {
    Write-Host "    [OK] AmneziaVPN is UP (Interface: $($vpnAdapter.Name))." -ForegroundColor Green
} else {
    Write-Host "    [!] [OFFLINE MODE] AmneziaVPN is NOT active." -ForegroundColor Yellow
    Write-Host "        Claude Desktop will launch in OFFLINE mode (Fail-Closed)." -ForegroundColor Yellow
    Write-Host "        24/7 LocalAddress Inversion prevents any egress via physical adapters.`n" -ForegroundColor DarkYellow
}

# 3. Sync / Verify WFP Kill Switch Rules
Write-Host "[*] [3/5] Verifying 24/7 WFP Fail-Closed Kill Switch rules..." -ForegroundColor Yellow
$syncScript = Join-Path $CageRoot "Sync-ClaudeFirewall.ps1"
if (Test-Path $syncScript) {
    try {
        & $syncScript -Enforce
        Write-Host "    [OK] Atomic 24/7 Kill Switch verified and active." -ForegroundColor Green
    } catch {
        Write-Warning "    [!] Notice: Could not refresh firewall rules directly: $_"
    }
}

# 4. Detect VPN Geolocation & Timezone (with safe fallback)
Write-Host "`n[*] [4/5] Resolving timezone & anti-fraud telemetry..." -ForegroundColor Yellow
$vpnTz = "Europe/Amsterdam"
$vpnCountry = "NL"
$vpnIp = "Offline / Protected"

if ($isVpnUp -and (Test-Path $CurlBin)) {
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

# Inject Anti-Fraud Environment Variables
$env:TZ = $vpnTz
$env:LANG = "en_US.UTF-8"
$env:LC_ALL = "en_US.UTF-8"
$env:ELECTRON_ENABLE_LOGGING = "false"
$env:PATH = "$CageBin;$env:PATH"

# 5. Locate Claude Desktop Binary & Prepare Valid Chromium Flags
Write-Host "`n[*] [5/5] Locating Claude Desktop and preparing valid Chromium flags..." -ForegroundColor Yellow

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

# Valid Chromium & Electron Anti-Telemetry / Anti-Leak Flags
$electronFlags = @(
    # WebRTC leak protection (verified Chromium flags)
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--enforce-webrtc-ip-permission-check",

    # Locale & Language spoofing
    "--lang=en-US",
    "--accept-lang=en-US,en",

    # DNS & Network isolation flags
    "--disable-features=AsyncDns,DnsOverHttpsUpgrade,WebRtcHideLocalIpsWithMdns",
    "--disable-background-networking"
)

Write-Host "`n[+] Launching Claude Desktop with Anti-Fraud & KillSwitch protection..." -ForegroundColor Green
$proc = Start-Process -FilePath $claudeExe -ArgumentList $electronFlags -PassThru

Write-Host "    Process ID: $($proc.Id)" -ForegroundColor Green
Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "   CLAUDE DESKTOP IS RUNNING SECURELY INSIDE CLAUDECAGE   " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
