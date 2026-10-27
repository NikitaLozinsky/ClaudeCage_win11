<#
.SYNOPSIS
    Invoke-ClaudeCLI.ps1 - Secure Anti-Fraud & Kill-Switched Launcher for Claude Code (CLI).
.DESCRIPTION
    Wraps the Claude Code CLI inside the ClaudeCage sandbox:
    1. Universal VPN Auto-Detection: Prioritizes AmneziaVPN, supports any WireGuard/OpenVPN/Tailscale tunnel.
    2. Injects anti-fraud timezone ($env:TZ), locale ($env:LANG), and sets NODE_OPTIONS=--dns-result-order=ipv4first.
    3. Prepends C:\ClaudeCage\bin to PATH so child processes use caged binaries.
    4. Verifies that 24/7 atomic WFP Kill Switch rules are enforced for claude.exe.
    5. Forwards all command line arguments transparently to claude.exe.
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ClaudeArgs
)

$ErrorActionPreference = 'Stop'

$CageRoot = "C:\ClaudeCage"
$CageBin  = Join-Path $CageRoot "bin"
$CurlBin  = Join-Path $CageBin "curl.exe"

function Get-ActiveVpnAdapter {
    $amnezia = Get-NetAdapter | Where-Object { 
        ($_.Name -like "*Amnezia*" -or $_.InterfaceDescription -like "*Amnezia*") -and $_.Status -eq "Up" 
    } | Select-Object -First 1
    if ($amnezia) { return $amnezia }

    $vpn = Get-NetAdapter | Where-Object {
        $_.Status -eq "Up" -and (
            $_.InterfaceDescription -match "WireGuard|Wintun|TUN|TAP|OpenVPN|Tailscale|VPN" -or
            $_.Name -match "VPN|WireGuard|Tailscale|TUN|TAP" -or
            $_.InterfaceType -in @(23, 53, 131)
        )
    } | Select-Object -First 1
    if ($vpn) { return $vpn }

    $defRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
    if ($defRoute) {
        $cand = Get-NetAdapter -InterfaceIndex $defRoute.InterfaceIndex -ErrorAction SilentlyContinue
        if ($cand -and $cand.Virtual -and $cand.InterfaceDescription -notmatch "Hyper-V|VirtualBox|VMware|WSL") {
            return $cand
        }
    }
    return $null
}

# 1. Check VPN Status
$vpnAdapter = Get-ActiveVpnAdapter
$isVpnUp = ($vpnAdapter -ne $null)

if (-not $isVpnUp) {
    Write-Host "[!] [CLAUDECAGE OFFLINE] No active VPN tunnel detected. Running Claude CLI in offline mode (Fail-Closed)." -ForegroundColor DarkYellow
}

# 2. Check / Sync Kill Switch rules
$syncScript = Join-Path $CageRoot "Sync-ClaudeFirewall.ps1"
$existingRules = Get-NetFirewallRule | Where-Object { $_.Group -eq "ClaudeKillSwitch" }
if (-not $existingRules) {
    try { & $syncScript -Enforce } catch {}
}

# 3. Detect VPN Geolocation & Timezone (with safe fallback)
$vpnTz = "Europe/Amsterdam"
if ($isVpnUp -and (Test-Path $CurlBin)) {
    try {
        $ipJson = & $CurlBin -s --connect-timeout 3 https://ipinfo.io/json
        if ($ipJson) {
            $info = $ipJson | ConvertFrom-Json
            if ($info.timezone) { $vpnTz = $info.timezone }
        }
    } catch {}
}

# 4. Inject Anti-Fraud Environment Variables & Node options
$env:TZ = $vpnTz
$env:LANG = "en_US.UTF-8"
$env:LC_ALL = "en_US.UTF-8"
$env:NODE_OPTIONS = "--dns-result-order=ipv4first"
$env:PATH = "$CageBin;$env:PATH"

# 5. Locate Claude CLI Binary
$claudeCliExe = $null
$cliCandidates = @(
    "$env:APPDATA\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe",
    "$env:LOCALAPPDATA\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe"
)

foreach ($cand in $cliCandidates) {
    if (Test-Path $cand) {
        $claudeCliExe = $cand
        break
    }
}

if (-not $claudeCliExe) {
    $cmdSource = (Get-Command claude.cmd -ErrorAction SilentlyContinue).Source
    if ($cmdSource -and (Test-Path $cmdSource)) {
        $claudeCliExe = $cmdSource
    }
}

if (-not $claudeCliExe) {
    Write-Error "[!] Claude Code CLI executable not found!"
    exit 1
}

# Verify Binary is Protected by WFP Kill Switch
$resolvedTarget = [System.IO.Path]::GetFullPath($claudeCliExe)
if ($claudeCliExe -like "*.cmd" -or $claudeCliExe -like "*.bat") {
    $resolvedTarget = [System.IO.Path]::GetFullPath((Join-Path $CageBin "node.exe"))
}
$appFilters = Get-NetFirewallRule -Group "ClaudeKillSwitch" -ErrorAction SilentlyContinue | Get-NetFirewallApplicationFilter
$protectedPrograms = @($appFilters | Select-Object -ExpandProperty Program -Unique | Where-Object { $_ -and $_ -ne "Any" } | ForEach-Object {
    try { [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($_)) } catch { $_ }
})

if ($protectedPrograms -notcontains $resolvedTarget) {
    Write-Host "[!] Claude CLI binary is not yet covered by WFP Kill Switch rules." -ForegroundColor Yellow
    Write-Host "    Requesting Administrator privileges to update firewall rules..." -ForegroundColor Yellow
    $p = Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$syncScript`" -Enforce" -Verb RunAs -PassThru -Wait
    
    # Re-verify
    $appFiltersAfter = Get-NetFirewallRule -Group "ClaudeKillSwitch" -ErrorAction SilentlyContinue | Get-NetFirewallApplicationFilter
    $protectedAfter = @($appFiltersAfter | Select-Object -ExpandProperty Program -Unique | Where-Object { $_ -and $_ -ne "Any" } | ForEach-Object {
        try { [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($_)) } catch { $_ }
    })
    
    if ($protectedAfter -notcontains $resolvedTarget) {
        Write-Error "[SECURITY ALERT] Failed to enforce WFP Kill Switch for Claude CLI! Execution aborted to prevent real IP leak."
        exit 1
    }
}

# 6. Execute Claude CLI with forwarded arguments
& $claudeCliExe @ClaudeArgs
exit $LASTEXITCODE
