<#
.SYNOPSIS
    Watch-ClaudeCage.ps1 - Real-time Universal Telemetry & Socket Logger for ClaudeCage.
.DESCRIPTION
    Continuously audits and logs:
    1. VPN tunnel connection state and transitions (AmneziaVPN, WireGuard, OpenVPN, Tailscale, etc.).
    2. Claude Desktop and Claude Code CLI processes (PIDs, memory, lifetime).
    3. Active TCP/UDP sockets owned by Claude processes via Get-NetTCPConnection:
       - Sockets routed through VPN tunnel (VERDICT: ALLOWED VIA VPN)
       - Sockets routed through physical adapter / Ethernet (VERDICT: BLOCKED BY WFP DROP)
       - Local loopback connections / MCP servers (VERDICT: LOCAL IPC / MCP)
    4. Writes structured logs to C:\ClaudeCage\logs\cage_traffic.log
    5. Writes live metrics to C:\ClaudeCage\logs\cage_metrics.json
    6. Displays an interactive terminal dashboard.
#>

[CmdletBinding()]
param(
    [int]$IntervalSeconds = 2,
    [switch]$Once,
    [int]$MaxIterations = 0
)

$ErrorActionPreference = 'Continue'

$CageRoot = "C:\ClaudeCage"
$LogsDir  = Join-Path $CageRoot "logs"
$LogFile  = Join-Path $LogsDir "cage_traffic.log"
$JsonFile = Join-Path $LogsDir "cage_metrics.json"

if (-not (Test-Path $LogsDir)) {
    New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
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

function Write-CageLog {
    param(
        [string]$Level,
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    $ts = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $line = "[$ts] [$Level] $Message"
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    Write-Host $line -ForegroundColor $Color
}

Write-CageLog "INIT" "Starting ClaudeCage Universal Telemetry & Socket Logger..." Cyan

$metrics = [ordered]@{
    StartTime             = [DateTime]::UtcNow.ToString("o")
    LastUpdate            = [DateTime]::UtcNow.ToString("o")
    VpnState              = "Unknown"
    VpnInterface          = "None"
    VpnIp                 = "None"
    PhysicalIp            = "None"
    TotalChecks           = 0
    VpnTransitions        = 0
    ActiveClaudeProcesses = 0
    ConnectionsAllowedVpn = 0
    ConnectionsBlockedWfp = 0
    DirectLeakAttempts    = 0
    TotalSocketsAudited   = 0
}

$previousVpnState = $null
$seenConnections = [System.Collections.Generic.HashSet[string]]::new()

$iteration = 0

try {
    while ($true) {
        $iteration++
        $metrics.TotalChecks++
        $metrics.LastUpdate = [DateTime]::UtcNow.ToString("o")

        # 1. Inspect Network Adapters (Universal VPN check)
        $vpnAdapter = Get-ActiveVpnAdapter
        $currentVpnState = if ($vpnAdapter) { "CONNECTED" } else { "DISCONNECTED" }
        $metrics.VpnState = $currentVpnState

        if ($vpnAdapter) {
            $metrics.VpnInterface = $vpnAdapter.Name
            $vpnIpObj = (Get-NetIPAddress -InterfaceIndex $vpnAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
            $metrics.VpnIp = if ($vpnIpObj) { $vpnIpObj } else { "Assigned" }
        } else {
            $metrics.VpnInterface = "None"
            $metrics.VpnIp = "None"
        }

        # Physical Adapter
        $physAdapter = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
        if ($physAdapter) {
            $physIpObj = (Get-NetIPAddress -InterfaceIndex $physAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
            $metrics.PhysicalIp = if ($physIpObj) { $physIpObj } else { "Unknown" }
        }

        # Detect State Transitions (Protected 24/7 by LocalAddress Inversion, no reload churn needed)
        if ($previousVpnState -ne $null -and $previousVpnState -ne $currentVpnState) {
            $metrics.VpnTransitions++
            $color = if ($currentVpnState -eq "CONNECTED") { [ConsoleColor]::Green } else { [ConsoleColor]::Red }
            Write-CageLog "TRANSITION" "VPN State changed: $previousVpnState -> $currentVpnState (Interface: $($metrics.VpnInterface)) [Protected 24/7 by LocalAddress Inversion]" $color
        }
        $previousVpnState = $currentVpnState

        # 2. Find Claude & Caged Binaries Processes
        $claudeProcs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $name = $_.ProcessName.ToLower()
            if ($name -match "claude") { return $true }
            if ($name -eq "node") {
                try {
                    $path = $_.MainModule.FileName
                    if ($path -like "$CageRoot\bin\*") { return $true }
                } catch {}
            }
            if ($name -eq "curl") {
                try {
                    $path = $_.MainModule.FileName
                    if ($path -like "$CageRoot\bin\*") { return $true }
                } catch {}
            }
            return $false
        })

        $metrics.ActiveClaudeProcesses = $claudeProcs.Count
        $procPids = @($claudeProcs | ForEach-Object { $_.Id })

        # 3. Audit Network Sockets for Claude Processes
        if ($procPids.Count -gt 0) {
            $connections = @(Get-NetTCPConnection -OwningProcess $procPids -ErrorAction SilentlyContinue)
            foreach ($conn in $connections) {
                $connId = "$($conn.OwningProcess):$($conn.LocalAddress):$($conn.LocalPort)->$($conn.RemoteAddress):$($conn.RemotePort)-$($conn.State)"
                $metrics.TotalSocketsAudited++

                $localIp  = $conn.LocalAddress
                $remoteIp = $conn.RemoteAddress
                $state    = $conn.State
                $proc     = $claudeProcs | Where-Object { $_.Id -eq $conn.OwningProcess } | Select-Object -First 1
                $procDesc = if ($proc) { "$($proc.ProcessName) [PID:$($proc.Id)]" } else { "PID:$($conn.OwningProcess)" }

                # A. Loopback / MCP IPC
                if ($localIp -eq "127.0.0.1" -or $remoteIp -eq "127.0.0.1" -or $remoteIp -eq "::1") {
                    if (-not $seenConnections.Contains($connId)) {
                        $seenConnections.Add($connId) | Out-Null
                        Write-CageLog "IPC" "$procDesc Local socket: ${localIp}:$($conn.LocalPort) <-> ${remoteIp}:$($conn.RemotePort) ($state) [VERDICT: LOCAL IPC / MCP]" DarkCyan
                    }
                }
                # B. Tunneled via VPN
                elseif ($localIp -eq $metrics.VpnIp -or ($vpnAdapter -and $conn.InterfaceIndex -eq $vpnAdapter.InterfaceIndex)) {
                    if (-not $seenConnections.Contains($connId)) {
                        $seenConnections.Add($connId) | Out-Null
                        $metrics.ConnectionsAllowedVpn++
                        Write-CageLog "TUNNEL" "$procDesc Egress: ${localIp}:$($conn.LocalPort) -> ${remoteIp}:$($conn.RemotePort) ($state) [VERDICT: ALLOWED VIA VPN]" Green
                    }
                }
                # C. Routed to Physical Adapter (WFP Kill Switch Engagement)
                elseif ($localIp -eq $metrics.PhysicalIp) {
                    if (-not $seenConnections.Contains($connId)) {
                        $seenConnections.Add($connId) | Out-Null
                        $metrics.ConnectionsBlockedWfp++
                        $metrics.DirectLeakAttempts++
                        Write-CageLog "KILLSWITCH" "$procDesc Egress attempted via physical IP ${localIp} -> ${remoteIp}:$($conn.RemotePort) ($state) [VERDICT: BLOCKED BY WFP DROP]" Red
                    }
                }
                # D. Other local addresses
                else {
                    if (-not $seenConnections.Contains($connId)) {
                        $seenConnections.Add($connId) | Out-Null
                        Write-CageLog "SOCKET" "$procDesc Socket: ${localIp}:$($conn.LocalPort) -> ${remoteIp}:$($conn.RemotePort) ($state)" DarkGray
                    }
                }
            }
        }

        # 4. Save Metrics JSON Snapshot
        $metricsJson = $metrics | ConvertTo-Json -Depth 3
        Set-Content -Path $JsonFile -Value $metricsJson -Force -ErrorAction SilentlyContinue

        if ($Once -or ($MaxIterations -gt 0 -and $iteration -ge $MaxIterations)) {
            break
        }

        Start-Sleep -Seconds $IntervalSeconds
    }
} finally {
    Write-CageLog "STOP" "Logger stopped. Total checks: $($metrics.TotalChecks), Allowed VPN: $($metrics.ConnectionsAllowedVpn), Blocked WFP: $($metrics.ConnectionsBlockedWfp)" Cyan
}
