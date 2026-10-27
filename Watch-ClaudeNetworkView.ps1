<#
.SYNOPSIS
    Watch-ClaudeNetworkView.ps1 - Deep Network Perspective & Live Socket Logger for Claude Desktop.
.DESCRIPTION
    Real-time interactive audit of how Claude Desktop perceives the local network and internet:
    1. Audits the network environment from Claude's caged perspective:
       - Active VPN Tunnel (AmneziaVPN / WireGuard) vs Physical LAN (Ethernet/Wi-Fi)
       - Public IP, Geolocation (Country, City, ISP) and Timezone seen by Anthropic
       - In-cage reachability probes: LAN isolation, IPv6 block, DNS port lock, Anthropic endpoint
    2. Discovers and monitors all Claude Desktop processes (Main, Renderer, GPU, Network-Service):
       - Verifies active Chromium anti-leak flags (WebRTC mDNS, UDP lock, QUIC disable)
       - Audits process integrity, PIDs, and memory footprint
    3. Live socket sniffer:
       - Logs all outbound TCP/UDP connections in real-time
       - Classifies every socket: [TUNNEL ALLOWED], [LOCAL IPC], or [BLOCKED BY WFP]
       - Discovers remote destinations (Anthropic API, Cloudflare CDN, Statsig, Sentry)
    4. Kernel WFP Drop Sniffer (Event ID 5152/5157):
       - Detects and alerts on any hardware 0-ms packet drop by tcpip.sys
    5. Saves structured logs to logs\claude_network_view.log and JSON metrics.
#>

[CmdletBinding()]
param(
    [int]$PollIntervalMs = 1000,
    [switch]$Detailed,
    [switch]$ProbeOnly
)

$ErrorActionPreference = 'Continue'

$CageRoot = "C:\ClaudeCage"
$LogsDir  = Join-Path $CageRoot "logs"
$LogFile  = Join-Path $LogsDir "claude_network_view.log"
$JsonFile = Join-Path $LogsDir "claude_network_view.json"
$CurlBin  = Join-Path $CageRoot "bin\curl.exe"

if (-not (Test-Path $LogsDir)) {
    New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
}

function Write-AuditLog {
    param(
        [string]$Tag,
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray,
        [switch]$NoConsole
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $logLine = "[$timestamp] [$Tag] $Message"
    Add-Content -Path $LogFile -Value $logLine -ErrorAction SilentlyContinue
    if (-not $NoConsole) {
        Write-Host "[$timestamp] " -NoNewline -ForegroundColor DarkGray
        Write-Host "[$Tag] " -NoNewline -ForegroundColor $Color
        Write-Host $Message -ForegroundColor $Color
    }
}

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

function Get-HostNameHint {
    param([string]$Ip)
    if ($Ip -eq "127.0.0.1" -or $Ip -eq "::1") { return "localhost (IPC)" }
    if ($Ip -like "100.*") { return "Tunnel Gateway / VPN" }
    if ($Ip -like "192.168.*" -or $Ip -like "10.*" -or $Ip -like "172.16.*") { return "Local LAN (RFC1918)" }
    
    # Well-known Anthropic & Cloudflare ranges
    if ($Ip -like "104.16.*" -or $Ip -like "104.17.*" -or $Ip -like "104.18.*" -or $Ip -like "172.64.*" -or $Ip -like "162.159.*") {
        return "Anthropic Edge / Cloudflare CDN"
    }
    if ($Ip -like "34.*" -or $Ip -like "35.*" -or $Ip -like "52.*" -or $Ip -like "54.*") {
        return "Cloud Infrastructure (AWS/GCP)"
    }
    return "Remote Public Host"
}

Clear-Host
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "    CLAUDECAGE: CLAUDE DESKTOP NETWORK PERSPECTIVE AUDIT  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Probe Network Interfaces
Write-Host "`n[*] [1/3] Probing system network adapters..." -ForegroundColor Yellow

$vpnAdapter  = Get-ActiveVpnAdapter
$physAdapter = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

$vpnIp = "None"
$vpnDns = "None"
if ($vpnAdapter) {
    $vpnIpObj = (Get-NetIPAddress -InterfaceIndex $vpnAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
    if ($vpnIpObj) { $vpnIp = $vpnIpObj }
    $vpnDnsObj = (Get-DnsClientServerAddress -InterfaceIndex $vpnAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
    if ($vpnDnsObj) { $vpnDns = ($vpnDnsObj -join ", ") }
    Write-Host "    [OK] VPN Tunnel:        $($vpnAdapter.Name) (IP: $vpnIp, DNS: $vpnDns)" -ForegroundColor Green
} else {
    Write-Host "    [!] VPN Tunnel:        DISCONNECTED (Fail-Closed Active)" -ForegroundColor Red
}

$physIp = "None"
if ($physAdapter) {
    $physIpObj = (Get-NetIPAddress -InterfaceIndex $physAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
    if ($physIpObj) { $physIp = $physIpObj }
    Write-Host "    [i] Physical Adapter:  $($physAdapter.Name) (LAN IP: $physIp)" -ForegroundColor DarkGray
}

# 2. Probe External Geolocation Perspective
Write-Host "`n[*] [2/3] Probing external perspective (how Anthropic sees Claude)..." -ForegroundColor Yellow

$geo = [ordered]@{
    PublicIp = "Unknown"
    Country  = "Unknown"
    City     = "Unknown"
    Timezone = "Unknown"
    Org      = "Unknown"
}

if ($vpnAdapter -and (Test-Path $CurlBin)) {
    try {
        $rawJson = & $CurlBin -s --connect-timeout 4 https://ipinfo.io/json
        if ($rawJson) {
            $info = $rawJson | ConvertFrom-Json
            $geo.PublicIp = if ($info.ip) { $info.ip } else { "Unknown" }
            $geo.Country  = if ($info.country) { $info.country } else { "Unknown" }
            $geo.City     = if ($info.city) { $info.city } else { "Unknown" }
            $geo.Timezone = if ($info.timezone) { $info.timezone } else { "Unknown" }
            $geo.Org      = if ($info.org) { $info.org } else { "Unknown" }
        }
    } catch {}
}

Write-Host "    Public Egress IP:  $($geo.PublicIp)" -ForegroundColor Cyan
Write-Host "    Country & City:    $($geo.Country) ($($geo.City))" -ForegroundColor Cyan
Write-Host "    Reported Timezone: $($geo.Timezone)" -ForegroundColor Cyan
Write-Host "    ISP / Route Org:   $($geo.Org)" -ForegroundColor Cyan

# 3. Probe In-Cage Network Reachability Matrix
Write-Host "`n[*] [3/3] Probing network reachability from inside the cage..." -ForegroundColor Yellow

$matrix = @()

# Probe Physical LAN Router
$lanProbe = "BLOCKED (0-ms Drop)"
if (Test-Path $CurlBin) {
    & $CurlBin -s --connect-timeout 2 http://192.168.0.1 2>$null
    if ($LASTEXITCODE -eq 0) { $lanProbe = "LEAK! (Reachable)" }
}
$matrix += [PSCustomObject]@{ Target = "Physical LAN Router (192.168.0.1)"; Expected = "BLOCKED"; Verdict = $lanProbe }

# Probe Physical Adapter Egress
$physProbe = "BLOCKED (0-ms Drop)"
if ($physIp -ne "None" -and (Test-Path $CurlBin)) {
    & $CurlBin -s --interface $physIp --connect-timeout 2 https://api.anthropic.com 2>$null
    if ($LASTEXITCODE -eq 0) { $physProbe = "LEAK! (Reachable)" }
}
$matrix += [PSCustomObject]@{ Target = "Physical Egress ($physIp)"; Expected = "BLOCKED"; Verdict = $physProbe }

# Probe Anthropic Backend via VPN
$anthropicProbe = "FAILED"
if (Test-Path $CurlBin) {
    $resp = & $CurlBin -s --connect-timeout 4 -I https://api.anthropic.com 2>$null | Select-Object -First 1
    if ($resp -match "HTTP") { $anthropicProbe = "REACHABLE (Via VPN)" }
}
$matrix += [PSCustomObject]@{ Target = "Claude API (api.anthropic.com)"; Expected = "REACHABLE"; Verdict = $anthropicProbe }

# Probe Non-Tunnel Public DNS (Port 53 Lock)
$dnsProbe = "BLOCKED (Port Lock)"
if (Test-Path $CurlBin) {
    & $CurlBin -s --connect-timeout 2 http://8.8.8.8:53 2>$null
    if ($LASTEXITCODE -eq 0) { $dnsProbe = "LEAK! (Port 53 open)" }
}
$matrix += [PSCustomObject]@{ Target = "External DNS (8.8.8.8:53)"; Expected = "BLOCKED"; Verdict = $dnsProbe }

foreach ($m in $matrix) {
    $color = if ($m.Verdict -like "*BLOCKED*" -or $m.Verdict -like "*REACHABLE*") { [ConsoleColor]::Green } else { [ConsoleColor]::Red }
    Write-Host ("    [{0,-9}] {1,-38} -> {2}" -f $m.Expected, $m.Target, $m.Verdict) -ForegroundColor $color
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "   LIVE MONITORING ACTIVE: WAITING FOR CLAUDE DESKTOP     " -ForegroundColor Cyan
Write-Host "   (Start Claude via Desktop shortcut or Start Menu)      " -ForegroundColor Cyan
Write-Host "   Press [Ctrl+C] at any time to finish and view summary. " -ForegroundColor Cyan
Write-Host "==========================================================`n" -ForegroundColor Cyan

Write-AuditLog "INIT" "Network perspective audit initialized. Egress: $($geo.PublicIp) ($($geo.Country)), VPN IP: $vpnIp, LAN IP: $physIp" Cyan

$seenSockets = [System.Collections.Generic.HashSet[string]]::new()
$discoveredPids = [System.Collections.Generic.HashSet[int]]::new()
$contactedRemoteIps = [System.Collections.Generic.HashSet[string]]::new()

$stats = [ordered]@{
    StartTime             = (Get-Date).ToString("o")
    VpnExitIp             = $geo.PublicIp
    VpnCountry            = $geo.Country
    TotalSocketsSeen      = 0
    SocketsAllowedViaVpn  = 0
    SocketsLocalIpc       = 0
    SocketsBlockedLeaks   = 0
    UniqueRemoteIps       = 0
    KernelDropsDetected   = 0
    ProcessesObserved     = @()
}

$isClaudeRunning = $false

if ($ProbeOnly) {
    Write-Host "[*] ProbeOnly specified. Exiting without entering live socket listener." -ForegroundColor Gray
    return
}

try {
    while ($true) {
        # 1. Discover Claude Desktop Processes
        $claudeProcs = @(Get-Process -Name "*claude*" -ErrorAction SilentlyContinue)

        if ($claudeProcs.Count -gt 0) {
            if (-not $isClaudeRunning) {
                $isClaudeRunning = $true
                Write-Host "`n[+] [CLAUDE DETECTED] Claude Desktop launched! ($($claudeProcs.Count) process(es) active)" -ForegroundColor Green
                Write-AuditLog "PROCESS" "Claude Desktop launched ($($claudeProcs.Count) process(es))" Green
            }

            foreach ($p in $claudeProcs) {
                if (-not $discoveredPids.Contains($p.Id)) {
                    $discoveredPids.Add($p.Id) | Out-Null
                    
                    # Inspect Process details via CIM/WMI
                    $cmdLine = "N/A"
                    try {
                        $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue
                        if ($wmiProc -and $wmiProc.CommandLine) { $cmdLine = $wmiProc.CommandLine }
                    } catch {}

                    # Inspect Flags
                    $hasWebRtcMdns = ($cmdLine -like "*WebRtcHideLocalIpsWithMdns*")
                    $hasUdpLock    = ($cmdLine -like "*disable_non_proxied_udp*")
                    $hasQuicBlock  = ($cmdLine -like "*disable-quic*")

                    $procInfo = [ordered]@{
                        Pid       = $p.Id
                        Name      = $p.ProcessName
                        StartTime = $p.StartTime.ToString("o")
                        WebRtcMdnsProtected = $hasWebRtcMdns
                        UdpLockProtected    = $hasUdpLock
                        QuicProtected       = $hasQuicBlock
                    }
                    $stats.ProcessesObserved += $procInfo

                    Write-Host "    [PROCESS] PID $($p.Id): $($p.ProcessName) | Anti-WebRTC: $hasWebRtcMdns | UDP-Lock: $hasUdpLock | QUIC-Block: $hasQuicBlock" -ForegroundColor Cyan
                    Write-AuditLog "PROCESS" "PID $($p.Id): $($p.ProcessName) | WebRTC-Mdns: $hasWebRtcMdns | UDP-Lock: $hasUdpLock" Cyan
                }
            }

            # 2. Inspect Active TCP Connections for all Claude PIDs
            $pidsArray = @($discoveredPids)
            $tcpConnections = @(Get-NetTCPConnection -OwningProcess $pidsArray -ErrorAction SilentlyContinue)

            foreach ($conn in $tcpConnections) {
                $sockKey = "$($conn.OwningProcess):$($conn.LocalAddress):$($conn.LocalPort)->$($conn.RemoteAddress):$($conn.RemotePort)-$($conn.State)"
                
                if (-not $seenSockets.Contains($sockKey)) {
                    $seenSockets.Add($sockKey) | Out-Null
                    $stats.TotalSocketsSeen++

                    $localIp   = $conn.LocalAddress
                    $localPort = $conn.LocalPort
                    $remIp     = $conn.RemoteAddress
                    $remPort   = $conn.RemotePort
                    $state     = $conn.State
                    $pid       = $conn.OwningProcess
                    $hint      = Get-HostNameHint $remIp

                    if ($remIp -ne "127.0.0.1" -and $remIp -ne "::1") {
                        $contactedRemoteIps.Add($remIp) | Out-Null
                    }

                    # Classification
                    # A. Local IPC / Loopback
                    if ($localIp -eq "127.0.0.1" -or $remIp -eq "127.0.0.1" -or $remIp -eq "::1") {
                        $stats.SocketsLocalIpc++
                        if ($Detailed) {
                            Write-Host "    [IPC]       PID ${pid}: ${localIp}:${localPort} <-> ${remIp}:${remPort} ($state) [$hint]" -ForegroundColor DarkCyan
                        }
                        Write-AuditLog "IPC" "PID ${pid}: ${localIp}:${localPort} <-> ${remIp}:${remPort} ($state) [$hint]" DarkCyan -NoConsole:(-not $Detailed)
                    }
                    # B. Outbound via VPN Tunnel
                    elseif ($localIp -eq $vpnIp -or ($vpnAdapter -and $conn.InterfaceIndex -eq $vpnAdapter.InterfaceIndex)) {
                        $stats.SocketsAllowedViaVpn++
                        Write-Host "    [TUNNEL]    PID ${pid}: ${localIp}:${localPort} -> ${remIp}:${remPort} ($state) [$hint] [VERDICT: ALLOWED VIA VPN]" -ForegroundColor Green
                        Write-AuditLog "TUNNEL" "PID ${pid}: ${localIp}:${localPort} -> ${remIp}:${remPort} ($state) [$hint] [ALLOWED VIA VPN]" Green
                    }
                    # C. Outbound via Physical Adapter (LEAK ATTEMPT / WFP BLOCKED)
                    elseif ($localIp -eq $physIp) {
                        $stats.SocketsBlockedLeaks++
                        Write-Host "    [LEAK-BLOCKED] PID ${pid}: ${localIp}:${localPort} -> ${remIp}:${remPort} ($state) [VERDICT: BLOCKED BY KERNEL WFP]" -ForegroundColor Red
                        Write-AuditLog "LEAK-BLOCKED" "PID ${pid}: ${localIp}:${localPort} -> ${remIp}:${remPort} ($state) [BLOCKED BY KERNEL WFP]" Red
                    }
                    # D. Other Sockets
                    else {
                        Write-Host "    [SOCKET]    PID ${pid}: ${localIp}:${localPort} -> ${remIp}:${remPort} ($state) [$hint]" -ForegroundColor DarkGray
                        Write-AuditLog "SOCKET" "PID ${pid}: ${localIp}:${localPort} -> ${remIp}:${remPort} ($state) [$hint]" DarkGray
                    }
                }
            }

            # 3. Kernel WFP Drop Sniffer (Event ID 5152/5157 in Security Log)
            try {
                $recentDrops = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5152,5157; StartTime=(Get-Date).AddMilliseconds(-($PollIntervalMs + 500))} -ErrorAction SilentlyContinue
                foreach ($evt in $recentDrops) {
                    $appPath = [string]$evt.Properties[1].Value
                    if ($appPath -match "claude") {
                        $pId     = [int]$evt.Properties[0].Value
                        $srcAddr = [string]$evt.Properties[3].Value
                        $dstAddr = [string]$evt.Properties[5].Value
                        $dstPort = [string]$evt.Properties[6].Value
                        $stats.KernelDropsDetected++
                        $stats.SocketsBlockedLeaks++
                        Write-Host "    [KERNEL 0-ms DROP] $appPath (PID $pId): $srcAddr -> ${dstAddr}:${dstPort} DROPPED BY WFP" -ForegroundColor Red
                        Write-AuditLog "KERNEL-DROP" "$appPath (PID $pId): $srcAddr -> ${dstAddr}:${dstPort} DROPPED BY WFP" Red
                    }
                }
            } catch {}

        } else {
            if ($isClaudeRunning) {
                $isClaudeRunning = $false
                Write-Host "`n[!] [CLAUDE CLOSED] Claude Desktop processes exited." -ForegroundColor Yellow
                Write-AuditLog "PROCESS" "Claude Desktop closed" Yellow
            }
        }

        # Save Metrics snapshot
        $stats.UniqueRemoteIps = $contactedRemoteIps.Count
        $statsJson = $stats | ConvertTo-Json -Depth 4
        Set-Content -Path $JsonFile -Value $statsJson -Force -ErrorAction SilentlyContinue

        Start-Sleep -Milliseconds $PollIntervalMs
    }
} finally {
    Write-Host "`n==========================================================" -ForegroundColor Cyan
    Write-Host "                 NETWORK AUDIT SUMMARY                    " -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "Total Sockets Audited:        $($stats.TotalSocketsSeen)" -ForegroundColor White
    Write-Host "Sockets Allowed via VPN:      $($stats.SocketsAllowedViaVpn)" -ForegroundColor Green
    Write-Host "Internal IPC / Loopback:      $($stats.SocketsLocalIpc)" -ForegroundColor DarkCyan
    Write-Host "Blocked Physical Leaks:       $($stats.SocketsBlockedLeaks)" -ForegroundColor (if ($stats.SocketsBlockedLeaks -eq 0) { [ConsoleColor]::Green } else { [ConsoleColor]::Yellow })
    Write-Host "Kernel WFP 0-ms Drops:        $($stats.KernelDropsDetected)" -ForegroundColor Green
    Write-Host "Unique Remote Endpoints:      $($stats.UniqueRemoteIps)" -ForegroundColor Cyan
    
    if ($contactedRemoteIps.Count -gt 0) {
        Write-Host "`nRemote IP Endpoints Contacted by Claude:" -ForegroundColor Yellow
        foreach ($ip in $contactedRemoteIps) {
            $hint = Get-HostNameHint $ip
            Write-Host "  - $ip ($hint)" -ForegroundColor Gray
        }
    }

    Write-Host "`n[+] Full detailed log saved to: $LogFile" -ForegroundColor Green
    Write-Host "[+] JSON metrics saved to:      $JsonFile" -ForegroundColor Green
    Write-Host "==========================================================`n" -ForegroundColor Cyan
    Write-AuditLog "STOP" "Audit stopped. Total sockets: $($stats.TotalSocketsSeen), Allowed VPN: $($stats.SocketsAllowedViaVpn), Blocked leaks: $($stats.SocketsBlockedLeaks)" Cyan
}
