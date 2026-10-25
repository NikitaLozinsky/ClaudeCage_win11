<#
.SYNOPSIS
    Setup-ClaudeCage.ps1 - Automated 1-Click Installer & Deployer for ClaudeCage on Windows 11.
.DESCRIPTION
    Deploys the complete ClaudeCage sandbox environment on any Windows 11 machine:
    1. Verifies Administrator rights (prompts UAC if needed).
    2. Ensures root directory is C:\ClaudeCage (copies files if launched from elsewhere).
    3. Creates a local baseline system snapshot (registry, firewall, profile, DNS) for 1-click rollback.
    4. Provisions isolated sandbox binaries (node.exe, curl.exe) into C:\ClaudeCage\bin.
    5. Applies kernel DNS & IPv6 hardening (NRPT rules, SMHNR disabled, Location Guard).
    6. Deploys 24/7 atomic WFP Fail-Closed Kill Switch rules (LocalAddress Inversion).
    7. Hooks the 'claude' CLI command into the user's PowerShell $PROFILE.
    8. Creates a desktop shortcut 'Claude (Secure Cage)' pointing to the secured launcher.
    9. Executes the comprehensive 9-point security audit (Test-CageLeaks.ps1).
#>

[CmdletBinding()]
param(
    [switch]$SkipTest,
    [switch]$ForceBaseline
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "[!] Administrator privileges required. Requesting elevation..." -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Definition
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
    exit 0
}

Clear-Host
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "     CLAUDECAGE: 1-CLICK AUTOMATED DEPLOYMENT (WIN 11)    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$TargetRoot = "C:\ClaudeCage"
$CurrentDir = $PSScriptRoot

# 1. Ensure installation directory is C:\ClaudeCage
if ($CurrentDir -ne $TargetRoot) {
    Write-Host "`n[*] [1/7] Relocating files from $CurrentDir to $TargetRoot..." -ForegroundColor Yellow
    if (-not (Test-Path $TargetRoot)) {
        New-Item -ItemType Directory -Path $TargetRoot -Force | Out-Null
    }
    Copy-Item -Path "$CurrentDir\*" -Destination $TargetRoot -Recurse -Force
    Set-Location $TargetRoot
    Write-Host "    [OK] Environment relocated to $TargetRoot." -ForegroundColor Green
} else {
    Write-Host "`n[*] [1/7] Verified root directory: $TargetRoot" -ForegroundColor Green
}

Set-Location $TargetRoot

# 2. Local Baseline Snapshot (Unique to this machine)
$BaselineDir = Join-Path $TargetRoot "backups\baseline"
$baselineMarker = Join-Path $BaselineDir "system_baseline_created.txt"

Write-Host "`n[*] [2/7] Checking local system baseline backup..." -ForegroundColor Yellow
if (-not (Test-Path $baselineMarker) -or $ForceBaseline) {
    if (-not (Test-Path $BaselineDir)) {
        New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null
    }

    Write-Host "    Creating initial machine snapshot for Rollback-System.ps1..." -ForegroundColor DarkYellow
    reg export "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" (Join-Path $BaselineDir "Dnscache_Parameters.reg") /y | Out-Null
    reg export "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" (Join-Path $BaselineDir "Tcpip_Parameters.reg") /y | Out-Null
    reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" (Join-Path $BaselineDir "DNSClient_Policies.reg") /y | Out-Null
    reg export "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" (Join-Path $BaselineDir "Tcpip6_Parameters.reg") /y | Out-Null

    if (Test-Path $PROFILE) {
        Copy-Item $PROFILE (Join-Path $BaselineDir "user_profile.ps1") -Force
    } else {
        Set-Content (Join-Path $BaselineDir "profile_did_not_exist.txt") "Profile did not exist at baseline" -Force
    }

    netsh advfirewall export (Join-Path $BaselineDir "firewall_baseline.wfw") | Out-Null
    Get-NetFirewallRule | Select-Object Name, DisplayName, Direction, Action, Enabled, Program | Export-Clixml (Join-Path $BaselineDir "firewall_rules_baseline.xml")
    Get-NetAdapterBinding | Export-Clixml (Join-Path $BaselineDir "adapter_bindings_baseline.xml")
    Get-DnsClientServerAddress | Export-Clixml (Join-Path $BaselineDir "dns_addresses_baseline.xml")

    Set-Content -Path $baselineMarker -Value "Baseline snapshot captured on $env:COMPUTERNAME at $(Get-Date -Format 'o')" -Force
    Write-Host "    [OK] Local machine baseline saved in backups\baseline." -ForegroundColor Green
} else {
    Write-Host "    [OK] Baseline snapshot already exists. Keeping original for rollback safety." -ForegroundColor Gray
}

# 3. Provision Caged Binaries (node.exe & curl.exe)
Write-Host "`n[*] [3/7] Provisioning isolated sandbox binaries in C:\ClaudeCage\bin..." -ForegroundColor Yellow
$initBinsScript = Join-Path $TargetRoot "Initialize-SandboxBins.ps1"
if (Test-Path $initBinsScript) {
    & $initBinsScript
} else {
    $CageBin = Join-Path $TargetRoot "bin"
    if (-not (Test-Path $CageBin)) { New-Item -ItemType Directory -Path $CageBin -Force | Out-Null }
    $nodeSrc = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
    if (-not $nodeSrc) { $nodeSrc = "C:\Program Files\nodejs\node.exe" }
    if (Test-Path $nodeSrc) { Copy-Item $nodeSrc (Join-Path $CageBin "node.exe") -Force }

    $curlSrc = (Get-Command curl.exe -ErrorAction SilentlyContinue).Source
    if (-not $curlSrc) { $curlSrc = "C:\Windows\System32\curl.exe" }
    if (Test-Path $curlSrc) { Copy-Item $curlSrc (Join-Path $CageBin "curl.exe") -Force }
}

# 4. Kernel DNS & Anti-Leak Hardening (NRPT + SMHNR)
Write-Host "`n[*] [4/7] Applying Kernel DNS (NRPT) & Anti-Leak Hardening..." -ForegroundColor Yellow
$dnsScript = Join-Path $TargetRoot "Set-DnsHardening.ps1"
if (Test-Path $dnsScript) {
    & $dnsScript
}

# 5. Enforce 24/7 WFP Fail-Closed Kill Switch (LocalAddress Inversion)
Write-Host "`n[*] [5/7] Deploying 24/7 WFP Kill Switch (LocalAddress Inversion)..." -ForegroundColor Yellow
$syncScript = Join-Path $TargetRoot "Sync-ClaudeFirewall.ps1"
if (Test-Path $syncScript) {
    & $syncScript -Enforce
}

# 6. Setup Shortcuts and Profile Hook
Write-Host "`n[*] [6/7] Configuring CLI profile hook and desktop shortcut..." -ForegroundColor Yellow

# PowerShell profile hook
$hookScript = Join-Path $TargetRoot "Install-ClaudeProfileHook.ps1"
if (Test-Path $hookScript) {
    & $hookScript
}

# Desktop & Start Menu Shortcuts
$shortcutScript = Join-Path $TargetRoot "Install-ClaudeShortcut.ps1"
if (Test-Path $shortcutScript) {
    & $shortcutScript
}

# Set PowerShell execution policy for CurrentUser
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force -ErrorAction SilentlyContinue

# 7. Configure Background Auto-Sync Task (Runs at Startup and Logon)
Write-Host "`n[*] [7/8] Registering Windows Scheduled Task for 24/7 boot synchronization..." -ForegroundColor Yellow
try {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$TargetRoot\Sync-ClaudeFirewall.ps1`" -Enforce"
    $triggers = @(
        (New-ScheduledTaskTrigger -AtStartup),
        (New-ScheduledTaskTrigger -AtLogOn)
    )
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName "ClaudeCage-BootSync" -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
    Write-Host "    [OK] Task 'ClaudeCage-BootSync' registered (triggers at system boot and logon)." -ForegroundColor Green
} catch {
    Write-Warning "    [-] Could not register boot task: $_"
}

# 8. Verification Audit
Write-Host "`n[*] [8/8] Running initial security & leak audit..." -ForegroundColor Yellow
if (-not $SkipTest) {
    $testScript = Join-Path $TargetRoot "Test-CageLeaks.ps1"
    if (Test-Path $testScript) {
        & $testScript -Detailed
    }
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "   CLAUDECAGE INSTALLATION COMPLETE! SYSTEM IS SECURED    " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host @"

  HOW TO USE:
  1. Claude Desktop (GUI):
     Double-click the standard 'Claude' icon on your Desktop or Start Menu (runs securely in cage).

  2. Claude Code (CLI):
     Open any PowerShell terminal and type:
     > claude

  3. Live Traffic Monitor:
     > & "$TargetRoot\Watch-ClaudeCage.ps1"

  4. Emergency 1-Click Rollback:
     > & "$TargetRoot\Rollback-System.ps1"

"@ -ForegroundColor Cyan
