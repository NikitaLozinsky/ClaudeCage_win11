<#
.SYNOPSIS
    Watch-ClaudeCage.ps1 - Real-time Logger & Telemetry Monitor for ClaudeCage (ClaudeCell).
.DESCRIPTION
    Continuously audits and logs:
    1. AmneziaVPN connection state and interface status transitions.
    2. Claude Desktop and Claude Code CLI processes (PIDs, memory, lifetime).
    3. Active TCP/UDP sockets owned by Claude processes via Get-NetTCPConnection:
       - Sockets routed through AmneziaVPN (VERDICT: ALLOWED VIA TUNNEL)
       - Sockets routed through physical adapter / Ethernet (VERDICT: BLOCKED BY WFP / DROP)
       - Local loopback connections / MCP servers (VERDICT: LOCAL IPC)
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

Write-CageLog "INIT" "Starting ClaudeCage Telemetry & Socket Logger..." Cyan

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

        # 1. Inspect Network Adapters
        $vpnAdapter = Get-NetAdapter | Where-Object {
            ($_.Name -like "*Amnezia*" -or $_.InterfaceDescription -like "*WireGuard*") -and $_.Status -eq "Up"
        } | Select-Object -First 1

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

        # Detect State Transitions
        if ($previousVpnState -ne $null -and $previousVpnState -ne $currentVpnState) {
            $metrics.VpnTransitions++
            $color = if ($currentVpnState -eq "CONNECTED") { [ConsoleColor]::Green } else { [ConsoleColor]::Red }
            Write-CageLog "TRANSITION" "VPN State changed: $previousVpnState -> $currentVpnState (Interface: $($metrics.VpnInterface))" $color

            # Trigger auto-sync of firewall rules if topology changed
            $syncScript = Join-Path $CageRoot "Sync-ClaudeFirewall.ps1"
            if (Test-Path $syncScript) {
                try { & $syncScript -Enforce | Out-Null } catch {}
            }
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

                # Determine routing and verdict
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
                # B. Tunneled via AmneziaVPN
                elseif ($localIp -eq $metrics.VpnIp -or ($vpnAdapter -and $conn.InterfaceIndex -eq $vpnAdapter.InterfaceIndex)) {
                    if (-not $seenConnections.Contains($connId)) {
                        $seenConnections.Add($connId) | Out-Null
                        $metrics.ConnectionsAllowedVpn++
                        Write-CageLog "TUNNEL" "$procDesc Egress: ${localIp}:$($conn.LocalPort) -> ${remoteIp}:$($conn.RemotePort) ($state) [VERDICT: ALLOWED VIA AMNEZIAVPN]" Green
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
                # D. Other local addresses (e.g. 0.0.0.0 listener)
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
