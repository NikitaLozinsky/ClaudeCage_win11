<#
.SYNOPSIS
    Set-DnsHardening.ps1 - Universal kernel-level anti-leak DNS & IPv6 hardening on Windows 11.
.DESCRIPTION
    Applies strict DNS privacy, NRPT kernel policy, and leak prevention:
    1. Installs Name Resolution Policy Table (NRPT) rules via Add-DnsClientNrptRule:
       Forces all DNS queries for Anthropic/Claude domains strictly to the VPN internal DNS
       (auto-detects AmneziaVPN 100.64.0.1, WireGuard, OpenVPN, or custom VPN DNS).
       Prevents svchost.exe (Dnscache) from ever leaking queries to Russian ISP DNS when VPN drops.
    2. Disables Smart Multi-Homed Name Resolution (SMHNR) to stop parallel DNS queries.
    3. Disables LLMNR (Link-Local Multicast Name Resolution).
    4. Configures IPv4 preference over IPv6 (RFC 3484 DisabledComponents = 0x20).
    5. Disables IPv6 binding (ms_tcpip6) on physical network adapters.
    6. Denies Windows Location API access to prevent geolocation telemetry leaks.
    7. Flushes the local DNS resolver cache.
#>

[CmdletBinding()]
param(
    [string]$CustomVpnDns
)

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

Write-Host "[*] Applying Universal DNS & IPv6 Hardening (NRPT + SMHNR + Location Guard)..." -ForegroundColor Cyan

# Detect VPN DNS Server (AmneziaVPN priority, generic VPN fallback)
$targetVpnDns = "100.64.0.1"

if ($CustomVpnDns) {
    $targetVpnDns = $CustomVpnDns
} else {
    # 1. Check AmneziaVPN
    $amnezia = Get-NetAdapter | Where-Object { 
        ($_.Name -like "*Amnezia*" -or $_.InterfaceDescription -like "*Amnezia*") -and $_.Status -eq "Up" 
    } | Select-Object -First 1

    # 2. Check generic VPN / Tunnel
    $vpnAdapter = if ($amnezia) { $amnezia } else {
        Get-NetAdapter | Where-Object {
            $_.Status -eq "Up" -and (
                $_.InterfaceDescription -match "WireGuard|Wintun|TUN|TAP|OpenVPN|Tailscale|VPN" -or
                $_.Name -match "VPN|WireGuard|Tailscale|TUN|TAP" -or
                $_.InterfaceType -in @(23, 53, 131)
            )
        } | Select-Object -First 1
    }

    if ($vpnAdapter) {
        $dnsList = @(Get-DnsClientServerAddress -InterfaceIndex $vpnAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty ServerAddresses) | Where-Object { $_ -ne $null -and $_ -ne "" }
        if ($dnsList.Count -gt 0) {
            $targetVpnDns = $dnsList[0]
        }
        Write-Host "    [i] Detected active VPN adapter '$($vpnAdapter.Name)' -> Tunnel DNS: $targetVpnDns" -ForegroundColor Cyan
    } else {
        Write-Host "    [i] VPN not currently connected. Using standard tunnel DNS: $targetVpnDns" -ForegroundColor DarkGray
    }
}

# 1. NRPT (Name Resolution Policy Table) Enforcement
Write-Host "    [+] Configuring Name Resolution Policy Table (NRPT)..." -ForegroundColor Yellow
$nrptComment = "ClaudeCageNRPT"

$existingNrpt = Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -eq $nrptComment }
if ($existingNrpt) {
    foreach ($r in $existingNrpt) {
        Remove-DnsClientNrptRule -Name $r.Name -Force -ErrorAction SilentlyContinue
    }
    Write-Host "        Removed $(($existingNrpt | Measure-Object).Count) prior NRPT rule(s)." -ForegroundColor DarkGray
}

$targetNamespaces = @(
    ".anthropic.com",
    ".claude.ai",
    ".claude.com",
    ".sentry.io",
    ".stripe.com",
    ".intercom.io",
    ".statsig.com",
    ".statsigapi.net",
    ".featuregates.org",
    ".workos.com",
    ".ipinfo.io"
)

Add-DnsClientNrptRule -Namespace $targetNamespaces `
    -NameServers $targetVpnDns `
    -Comment $nrptComment `
    -DisplayName "ClaudeCage Strict Tunnel DNS Rule" `
    -PassThru | Out-Null

Write-Host "        Installed NRPT rule: domains [$($targetNamespaces -join ', ')] -> $targetVpnDns only." -ForegroundColor Green

# 2. SMHNR & LLMNR in Group Policy registry
$dnsPolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $dnsPolicyKey)) {
    New-Item -Path $dnsPolicyKey -Force | Out-Null
}

Set-ItemProperty -Path $dnsPolicyKey -Name "DisableSmartNameResolution" -Value 1 -Type DWord
Write-Host "    [+] Smart Multi-Homed Name Resolution (SMHNR) DISABLED." -ForegroundColor Green

Set-ItemProperty -Path $dnsPolicyKey -Name "EnableMulticast" -Value 0 -Type DWord
Write-Host "    [+] LLMNR Multicast DISABLED." -ForegroundColor Green

# 2.1 Disable Auto-DoH (DNS-over-HTTPS) & WPAD
$dnscacheParamsKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
if (-not (Test-Path $dnscacheParamsKey)) { New-Item -Path $dnscacheParamsKey -Force | Out-Null }
Set-ItemProperty -Path $dnscacheParamsKey -Name "EnableAutoDoh" -Value 0 -Type DWord -Force
Write-Host "    [+] Windows 11 Native Auto-DoH DISABLED." -ForegroundColor Green

$tcpipParamsKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
if (-not (Test-Path $tcpipParamsKey)) { New-Item -Path $tcpipParamsKey -Force | Out-Null }
Set-ItemProperty -Path $tcpipParamsKey -Name "DisableWpad" -Value 1 -Type DWord -Force
Write-Host "    [+] WPAD Proxy Auto-Discovery DISABLED." -ForegroundColor Green

# 2.2 Enable Strong Host Model (Prevents cross-adapter teardown packet leaks)
Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | Set-NetIPInterface -WeakHostSend Disabled -WeakHostReceive Disabled -ErrorAction SilentlyContinue
Get-NetIPInterface -AddressFamily IPv6 -ErrorAction SilentlyContinue | Set-NetIPInterface -WeakHostSend Disabled -WeakHostReceive Disabled -ErrorAction SilentlyContinue
Write-Host "    [+] Strong Host Model ENABLED on all interfaces." -ForegroundColor Green

# 3. Deny Windows Location API access
$locConsentKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged"
if (-not (Test-Path $locConsentKey)) {
    New-Item -Path $locConsentKey -Force | Out-Null
}
Set-ItemProperty -Path $locConsentKey -Name "Value" -Value "Deny" -Force
Write-Host "    [+] Windows Location API access DENIED for desktop applications." -ForegroundColor Green

# 4. IPv6 Preference / DisabledComponents
$tcpip6Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
if (-not (Test-Path $tcpip6Key)) {
    New-Item -Path $tcpip6Key -Force | Out-Null
}
Set-ItemProperty -Path $tcpip6Key -Name "DisabledComponents" -Value 0x20 -Type DWord
Write-Host "    [+] IPv4 preferred over IPv6 in RFC 3484 policy (0x20)." -ForegroundColor Green

# 5. Disable IPv6 on physical network adapters
$physicalAdapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue
foreach ($adapter in $physicalAdapters) {
    try {
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentId ms_tcpip6 -Confirm:$false -ErrorAction Stop
        Write-Host "    [+] Disabled ms_tcpip6 on physical adapter '$($adapter.Name)'." -ForegroundColor Green
    } catch {
        Write-Warning "    [-] Could not modify adapter binding on '$($adapter.Name)': $_"
    }
}

# 6. Flush DNS resolver cache
Clear-DnsClientCache
Write-Host "    [+] DNS resolver cache cleared." -ForegroundColor Green

Write-Host "[OK] Universal DNS & IPv6 hardening applied successfully." -ForegroundColor Green
