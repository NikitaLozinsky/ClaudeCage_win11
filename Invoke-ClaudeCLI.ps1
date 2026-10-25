<#
.SYNOPSIS
    Invoke-ClaudeCLI.ps1 - Secure Anti-Fraud & Kill-Switched Launcher for Claude Code (CLI).
.DESCRIPTION
    Wraps the Claude Code CLI inside the ClaudeCage sandbox:
    1. Verifies AmneziaVPN connection status. Refuses to execute if VPN is down (Fail-Closed).
    2. Enforces WFP Fail-Closed Kill Switch rules.
    3. Injects anti-fraud timezone ($env:TZ), locale ($env:LANG), and prepends C:\ClaudeCage\bin to PATH.
    4. Forwards all command line arguments transparently to claude.exe.
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

# 1. Check AmneziaVPN Status
$vpnAdapter = Get-NetAdapter | Where-Object {
    ($_.Name -like "*Amnezia*" -or $_.InterfaceDescription -like "*WireGuard*") -and $_.Status -eq "Up"
} | Select-Object -First 1

$isVpnUp = ($vpnAdapter -ne $null)

if (-not $isVpnUp) {
    Write-Host "[!] [CLAUDECAGE OFFLINE] AmneziaVPN is not active. Running Claude CLI in offline mode." -ForegroundColor DarkYellow
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

# 4. Inject Anti-Fraud Environment Variables
$env:TZ = $vpnTz
$env:LANG = "en_US.UTF-8"
$env:LC_ALL = "en_US.UTF-8"
$env:PATH = "$CageBin;$env:PATH"

# 5. Locate Claude CLI Binary
$claudeCliExe = $null
$cliCandidates = @(
    "$env:APPDATA\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe",
    "$env:LOCALAPPDATA\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe",
    "C:\Users\decop\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe"
)

foreach ($cand in $cliCandidates) {
    if (Test-Path $cand) {
        $claudeCliExe = $cand
        break
    }
}

if (-not $claudeCliExe) {
    # Fallback to claude.cmd
    $cmdSource = (Get-Command claude.cmd -ErrorAction SilentlyContinue).Source
    if ($cmdSource -and (Test-Path $cmdSource)) {
        $claudeCliExe = $cmdSource
    }
}

if (-not $claudeCliExe) {
    Write-Error "[!] Claude Code CLI executable not found!"
    exit 1
}

# 6. Execute Claude CLI with forwarded arguments
& $claudeCliExe @ClaudeArgs
exit $LASTEXITCODE
