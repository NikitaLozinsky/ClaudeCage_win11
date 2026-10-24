<#
.SYNOPSIS
    Rollback-System.ps1 - Complete rollback script to return system to v0-baseline state.
.DESCRIPTION
    Reverts all changes made by ClaudeCage:
    1. Removes all WFP / Windows Firewall rules in group 'ClaudeKillSwitch'
    2. Restores registry branches from C:\ClaudeCage\backups\baseline\
    3. Restores or cleans up user $PROFILE
    4. Restores network adapter bindings (e.g. IPv6)
    5. Flushes Windows DNS cache
#>

[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Error "[!] Administrator privileges are required to run Rollback-System.ps1. Please run PowerShell as Administrator."
    exit 1
}

$CageRoot = "C:\ClaudeCage"
$BaselineDir = Join-Path $CageRoot "backups\baseline"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   CLAUDE CAGE: SYSTEM ROLLBACK TO BASELINE (v0-baseline) " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Remove all ClaudeCage firewall rules
Write-Host "`n[*] [1/5] Removing ClaudeCage WFP/Firewall rules..." -ForegroundColor Yellow
$rules = Get-NetFirewallRule | Where-Object {
    $_.Group -eq "ClaudeKillSwitch" -or
    $_.Name -like "ClaudeCage*" -or
    $_.DisplayName -like "Claude Cage*"
}

if ($rules) {
    $count = ($rules | Measure-Object).Count
    Write-Host "    Found $count firewall rule(s). Removing..." -ForegroundColor DarkYellow
    $rules | Remove-NetFirewallRule
    Write-Host "    [OK] ClaudeKillSwitch rules removed successfully." -ForegroundColor Green
} else {
    Write-Host "    [OK] No ClaudeKillSwitch firewall rules found." -ForegroundColor Gray
}

# 2. Restore Registry from baseline
Write-Host "`n[*] [2/5] Restoring registry branches from baseline..." -ForegroundColor Yellow
$regFiles = @(
    "DNSClient_Policies.reg",
    "Dnscache_Parameters.reg",
    "Tcpip_Parameters.reg",
    "Tcpip6_Parameters.reg"
)

foreach ($regFile in $regFiles) {
    $fullPath = Join-Path $BaselineDir $regFile
    if (Test-Path $fullPath) {
        Write-Host "    Importing: $regFile" -ForegroundColor DarkYellow
        $proc = Start-Process reg.exe -ArgumentList "import `"$fullPath`"" -Wait -NoNewWindow -PassThru
        if ($proc.ExitCode -eq 0) {
            Write-Host "    [OK] Restored $regFile" -ForegroundColor Green
        } else {
            Write-Warning "    [!] Warning: reg import exited with code $($proc.ExitCode) for $regFile"
        }
    }
}

# Clean specific policy values if baseline policy was empty
$dnsPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (Test-Path $dnsPolicyPath) {
    $policyValues = @("DisableSmartNameResolution", "EnableMulticast")
    foreach ($val in $policyValues) {
        if ((Get-ItemProperty -Path $dnsPolicyPath -Name $val -ErrorAction SilentlyContinue) -ne $null) {
            Remove-ItemProperty -Path $dnsPolicyPath -Name $val -Force -ErrorAction SilentlyContinue
            Write-Host "    Removed DNS policy override '$val'" -ForegroundColor DarkYellow
        }
    }
}

# 3. Restore User $PROFILE
Write-Host "`n[*] [3/5] Restoring user PowerShell profile..." -ForegroundColor Yellow
$profileNoExistMarker = Join-Path $BaselineDir "profile_did_not_exist.txt"
$profileBackupFile   = Join-Path $BaselineDir "user_profile.ps1"

if (Test-Path $profileNoExistMarker) {
    if (Test-Path $PROFILE) {
        # Check if PROFILE contains ClaudeCage hooks
        $content = Get-Content $PROFILE -Raw -ErrorAction SilentlyContinue
        if ($content -match "ClaudeCage|Invoke-ClaudeCLI") {
            Remove-Item $PROFILE -Force
            Write-Host "    [OK] Removed created `$PROFILE (was non-existent at baseline)." -ForegroundColor Green
        } else {
            Write-Host "    [INFO] Existing `$PROFILE retained (did not contain ClaudeCage hook)." -ForegroundColor Gray
        }
    } else {
        Write-Host "    [OK] User `$PROFILE remains non-existent (matches baseline)." -ForegroundColor Gray
    }
} elseif (Test-Path $profileBackupFile) {
    Copy-Item $profileBackupFile $PROFILE -Force
    Write-Host "    [OK] Restored user `$PROFILE from backup." -ForegroundColor Green
}

# 4. Re-enable network adapter bindings (e.g. IPv6)
Write-Host "`n[*] [4/5] Restoring network adapter bindings..." -ForegroundColor Yellow
$adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue
foreach ($adapter in $adapters) {
    $binding = Get-NetAdapterBinding -Name $adapter.Name -ComponentId ms_tcpip6 -ErrorAction SilentlyContinue
    if ($binding -and -not $binding.Enabled) {
        Enable-NetAdapterBinding -Name $adapter.Name -ComponentId ms_tcpip6 -ErrorAction SilentlyContinue
        Write-Host "    [OK] Re-enabled IPv6 on adapter '$($adapter.Name)'" -ForegroundColor Green
    }
}

# 5. Flush DNS Cache
Write-Host "`n[*] [5/6] Flushing DNS client cache..." -ForegroundColor Yellow
Clear-DnsClientCache
Write-Host "    [OK] DNS cache flushed." -ForegroundColor Green

# 6. Restore ExecutionPolicy
Write-Host "`n[*] [6/6] Restoring PowerShell ExecutionPolicy..." -ForegroundColor Yellow
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Undefined -Force -ErrorAction SilentlyContinue
Write-Host "    [OK] ExecutionPolicy restored." -ForegroundColor Green

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "   ROLLBACK COMPLETE: System is back to v0-baseline state  " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
