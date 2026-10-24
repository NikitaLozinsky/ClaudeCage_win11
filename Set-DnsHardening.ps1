<#
.SYNOPSIS
    Set-DnsHardening.ps1 - Enforce anti-leak DNS & IPv6 hardening on Windows 11.
.DESCRIPTION
    Applies strict DNS privacy and leak prevention:
    1. Disables Smart Multi-Homed Name Resolution (SMHNR) to prevent parallel DNS queries across physical interfaces.
    2. Disables LLMNR (Link-Local Multicast Name Resolution) to stop local hostname multicasting.
    3. Configures IPv4 preference over IPv6 (RFC 3484 DisabledComponents = 0x20).
    4. Disables IPv6 binding on physical adapters (Ethernet/Wi-Fi) to eliminate IPv6 bypass leaks.
    5. Flushes the local DNS resolver cache.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Error "[!] Administrator privileges are required to run Set-DnsHardening.ps1."
    exit 1
}

Write-Host "[*] Applying DNS & IPv6 Hardening..." -ForegroundColor Cyan

# 1. SMHNR & LLMNR in Group Policy registry
$dnsPolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $dnsPolicyKey)) {
    New-Item -Path $dnsPolicyKey -Force | Out-Null
}

Set-ItemProperty -Path $dnsPolicyKey -Name "DisableSmartNameResolution" -Value 1 -Type DWord
Write-Host "    [+] Smart Multi-Homed Name Resolution (SMHNR) DISABLED." -ForegroundColor Green

Set-ItemProperty -Path $dnsPolicyKey -Name "EnableMulticast" -Value 0 -Type DWord
Write-Host "    [+] LLMNR Multicast DISABLED." -ForegroundColor Green

# 2. IPv6 Preference / DisabledComponents
$tcpip6Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
if (-not (Test-Path $tcpip6Key)) {
    New-Item -Path $tcpip6Key -Force | Out-Null
}
Set-ItemProperty -Path $tcpip6Key -Name "DisabledComponents" -Value 0x20 -Type DWord
Write-Host "    [+] IPv4 preferred over IPv6 in RFC 3484 policy (0x20)." -ForegroundColor Green

# 3. Disable IPv6 on physical network adapters
$physicalAdapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue
foreach ($adapter in $physicalAdapters) {
    try {
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentId ms_tcpip6 -Confirm:$false -ErrorAction Stop
        Write-Host "    [+] Disabled ms_tcpip6 on physical adapter '$($adapter.Name)'." -ForegroundColor Green
    } catch {
        Write-Warning "    [-] Could not modify adapter binding on '$($adapter.Name)': $_"
    }
}

# 4. Flush DNS resolver cache
Clear-DnsClientCache
Write-Host "    [+] DNS resolver cache cleared." -ForegroundColor Green

Write-Host "[OK] DNS & IPv6 hardening applied successfully." -ForegroundColor Green
