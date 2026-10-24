<#
.SYNOPSIS
    Sync-ClaudeFirewall.ps1 - WFP Fail-Closed Kill Switch Engine for ClaudeCage.
.DESCRIPTION
    Dynamically configures Windows Filtering Platform (WFP) rules for Claude Desktop and Claude Code CLI:
    - Restricts Claude Desktop (MSIX package and Win32 binary), Claude Code CLI, and caged binaries (node.exe, curl.exe)
      strictly to the AmneziaVPN tunnel interface.
    - Implements Fail-Closed behavior: blocks all traffic on physical/virtual non-VPN interfaces.
    - Blocks outbound IPv6 traffic for caged targets (eliminating IPv6 leak bypass).
    - Blocks direct DNS queries (port 53) to non-VPN ISP DNS servers.
    - If VPN is disconnected, engages Total Lockdown mode (blocks on all interfaces).
#>

[CmdletBinding(DefaultParameterSetName = "Enforce")]
param(
    [Parameter(ParameterSetName = "Enforce")]
    [switch]$Enforce = $true,

    [Parameter(ParameterSetName = "Status")]
    [switch]$Status,

    [Parameter(ParameterSetName = "Remove")]
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Error "[!] Administrator privileges are required to manage Windows Firewall rules."
    exit 1
}

$GroupName = "ClaudeKillSwitch"
$CageRoot  = "C:\ClaudeCage"
$CageBin   = Join-Path $CageRoot "bin"

function Get-CageTargetBinaries {
    $targets = [System.Collections.Generic.List[PSCustomObject]]::new()

    # 1. Caged node.exe & curl.exe
    $sandboxedNode = Join-Path $CageBin "node.exe"
    if (Test-Path $sandboxedNode) {
        $targets.Add([PSCustomObject]@{
            Name              = "Sandboxed-Node"
            Type              = "Binary"
            Path              = $sandboxedNode
            PackageFamilyName = $null
        })
    }

    $sandboxedCurl = Join-Path $CageBin "curl.exe"
    if (Test-Path $sandboxedCurl) {
        $targets.Add([PSCustomObject]@{
            Name              = "Sandboxed-Curl"
            Type              = "Binary"
            Path              = $sandboxedCurl
            PackageFamilyName = $null
        })
    }

    # 2. Claude CLI standalone binary
    $cliCandidates = @(
        "$env:APPDATA\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe",
        "$env:LOCALAPPDATA\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe",
        "C:\Users\decop\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe"
    )
    foreach ($cand in $cliCandidates) {
        if (Test-Path $cand) {
            $targets.Add([PSCustomObject]@{
                Name              = "Claude-CLI"
                Type              = "Binary"
                Path              = $cand
                PackageFamilyName = $null
            })
            break
        }
    }

    # 3. Claude Desktop AppX / MSIX package
    $claudeAppx = Get-AppxPackage -Name *Claude* -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($claudeAppx) {
        $targets.Add([PSCustomObject]@{
            Name              = "Claude-Desktop-MSIX"
            Type              = "PackageFamily"
            Path              = $null
            PackageFamilyName = $claudeAppx.PackageFamilyName
        })

        $appxExe = Join-Path $claudeAppx.InstallLocation "app\claude.exe"
        if (Test-Path $appxExe) {
            $targets.Add([PSCustomObject]@{
                Name              = "Claude-Desktop-AppX-Exe"
                Type              = "Binary"
                Path              = $appxExe
                PackageFamilyName = $null
            })
        }
    }

    # 4. Standard Win32 Claude Desktop installs if present
    $desktopCandidates = @(
        "$env:LOCALAPPDATA\Programs\Claude\Claude.exe",
        "$env:LOCALAPPDATA\AnthropicClaude\Claude.exe",
        "C:\Program Files\Claude\Claude.exe"
    )
    foreach ($cand in $desktopCandidates) {
        if (Test-Path $cand) {
            $targets.Add([PSCustomObject]@{
                Name              = "Claude-Desktop-Win32"
                Type              = "Binary"
                Path              = $cand
                PackageFamilyName = $null
            })
        }
    }

    return $targets
}

function Remove-KillSwitchRules {
    Write-Host "[*] Removing existing rules in group '$GroupName'..." -ForegroundColor DarkYellow
    $existing = Get-NetFirewallRule | Where-Object { $_.Group -eq $GroupName -or $_.Name -like "ClaudeCage*" }
    if ($existing) {
        $existing | Remove-NetFirewallRule
        Write-Host "    [OK] Cleaned up $(($existing | Measure-Object).Count) rule(s)." -ForegroundColor Green
    } else {
        Write-Host "    [OK] No prior rules found." -ForegroundColor Gray
    }
}

function Show-KillSwitchStatus {
    Write-Host "`n==========================================================" -ForegroundColor Cyan
    Write-Host "         CLAUDE CAGE WFP KILL SWITCH STATUS               " -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan

    # Adapters
    $vpnAdapter = Get-NetAdapter | Where-Object {
        ($_.Name -like "*Amnezia*" -or $_.InterfaceDescription -like "*WireGuard*") -and $_.Status -eq "Up"
    } | Select-Object -First 1

    if ($vpnAdapter) {
        Write-Host "`n[+] AmneziaVPN Status: CONNECTED (Interface: $($vpnAdapter.Name), Idx: $($vpnAdapter.InterfaceIndex))" -ForegroundColor Green
        $vpnIps = (Get-NetIPAddress -InterfaceIndex $vpnAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
        Write-Host "    Tunnel IPv4: $($vpnIps -join ', ')" -ForegroundColor Green
    } else {
        Write-Host "`n[!] AmneziaVPN Status: DISCONNECTED / NOT DETECTED" -ForegroundColor Red
    }

    # Physical / Non-VPN adapters
    $nonVpnAdapters = Get-NetAdapter | Where-Object {
        $_.Name -notlike "*Amnezia*" -and $_.InterfaceDescription -notlike "*WireGuard*"
    }
    Write-Host "`n[i] Non-VPN Adapters (Blocked for Caged Processes):" -ForegroundColor Yellow
    foreach ($a in $nonVpnAdapters) {
        $statusCol = if ($a.Status -eq "Up") { "Cyan" } else { "DarkGray" }
        Write-Host "    - $($a.Name) [$($a.InterfaceDescription)] -> Status: $($a.Status)" -ForegroundColor $statusCol
    }

    # Caged Targets
    Write-Host "`n[i] Protected Caged Targets:" -ForegroundColor Yellow
    $targets = Get-CageTargetBinaries
    foreach ($t in $targets) {
        if ($t.Type -eq "PackageFamily") {
            Write-Host "    - [MSIX] $($t.Name) (PackageFamily: $($t.PackageFamilyName))" -ForegroundColor White
        } else {
            Write-Host "    - [BIN]  $($t.Name): $($t.Path)" -ForegroundColor White
        }
    }

    # Active Rules
    $rules = Get-NetFirewallRule | Where-Object { $_.Group -eq $GroupName }
    Write-Host "`n[i] Active ClaudeKillSwitch WFP Rules: $(($rules | Measure-Object).Count)" -ForegroundColor Yellow
    foreach ($r in $rules) {
        Write-Host "    - $($r.DisplayName) -> Action: $($r.Action), Direction: $($r.Direction), Enabled: $($r.Enabled)" -ForegroundColor Gray
    }

    Write-Host "==========================================================`n" -ForegroundColor Cyan
}

if ($Status) {
    Show-KillSwitchStatus
    exit 0
}

if ($Remove) {
    Remove-KillSwitchRules
    Write-Host "[OK] ClaudeKillSwitch rules removed successfully." -ForegroundColor Green
    exit 0
}

# --- ENFORCE KILL SWITCH RULES ---
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       ENFORCING CLAUDE CAGE WFP KILL SWITCH RULES        " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Discover targets
$targets = Get-CageTargetBinaries
if ($targets.Count -eq 0) {
    Write-Warning "[!] No Claude targets or caged binaries found! Run Initialize-SandboxBins.ps1 first."
    exit 1
}

# 2. Check AmneziaVPN status
$vpnAdapter = Get-NetAdapter | Where-Object {
    ($_.Name -like "*Amnezia*" -or $_.InterfaceDescription -like "*WireGuard*") -and $_.Status -eq "Up"
} | Select-Object -First 1

$nonVpnAdapters = Get-NetAdapter | Where-Object {
    $_.Name -notlike "*Amnezia*" -and $_.InterfaceDescription -notlike "*WireGuard*"
}

$nonVpnAliases = @($nonVpnAdapters | ForEach-Object { $_.Name })

# 3. Clean existing rules
Remove-KillSwitchRules

# 4. Apply Fail-Closed Rules
if (-not $vpnAdapter) {
    # TOTAL LOCKDOWN MODE: VPN is down, block target binaries unconditionally on all interfaces!
    Write-Host "`n[!] AMNEZIAVPN IS DOWN! Engaging TOTAL LOCKDOWN for Claude processes." -ForegroundColor Red
    Write-Host "    All outbound connections for Claude and caged binaries are BLOCKED on ALL interfaces." -ForegroundColor Red

    foreach ($t in $targets) {
        $ruleName = "ClaudeCage-Lockdown-$($t.Name)"
        $ruleDisplay = "Claude Cage TOTAL LOCKDOWN: Block $($t.Name)"

        if ($t.Type -eq "PackageFamily") {
            New-NetFirewallRule -Name $ruleName `
                -DisplayName $ruleDisplay `
                -Group $GroupName `
                -Direction Outbound `
                -Action Block `
                -PackageFamilyName $t.PackageFamilyName `
                -Enabled True | Out-Null
        } else {
            New-NetFirewallRule -Name $ruleName `
                -DisplayName $ruleDisplay `
                -Group $GroupName `
                -Direction Outbound `
                -Action Block `
                -Program $t.Path `
                -Enabled True | Out-Null
        }
        Write-Host "    [+] Installed: $ruleDisplay" -ForegroundColor Yellow
    }
} else {
    # VPN IS UP: Block on all non-VPN interfaces, block IPv6, block direct ISP DNS
    Write-Host "`n[+] AmneziaVPN active ($($vpnAdapter.Name)). Configuring interface-isolated Fail-Closed rules." -ForegroundColor Green
    Write-Host "    Non-VPN interfaces blocked: $($nonVpnAliases -join ', ')" -ForegroundColor DarkYellow

    # Collect ISP DNS addresses on physical/non-VPN interfaces to block direct queries
    $ispDnsAddresses = @(Get-DnsClientServerAddress -InterfaceAlias $nonVpnAliases -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty ServerAddresses) | Where-Object { $_ -ne $null -and $_ -ne "" } | Select-Object -Unique

    foreach ($t in $targets) {
        # A. Block outbound on all Non-VPN network interfaces
        $blockAdapterRuleName = "ClaudeCage-BlockPhysical-$($t.Name)"
        $blockAdapterDisplay  = "Claude Cage KillSwitch: Block $($t.Name) on Physical/Non-VPN Adapters"

        if ($t.Type -eq "PackageFamily") {
            New-NetFirewallRule -Name $blockAdapterRuleName `
                -DisplayName $blockAdapterDisplay `
                -Group $GroupName `
                -Direction Outbound `
                -Action Block `
                -PackageFamilyName $t.PackageFamilyName `
                -InterfaceAlias $nonVpnAliases `
                -Enabled True | Out-Null
        } else {
            New-NetFirewallRule -Name $blockAdapterRuleName `
                -DisplayName $blockAdapterDisplay `
                -Group $GroupName `
                -Direction Outbound `
                -Action Block `
                -Program $t.Path `
                -InterfaceAlias $nonVpnAliases `
                -Enabled True | Out-Null
        }
        Write-Host "    [+] Block Non-VPN Interfaces: $($t.Name)" -ForegroundColor Green

        # B. Block outbound IPv6 traffic (prevents IPv6 bypass / leak)
        $blockIpv6RuleName = "ClaudeCage-BlockIPv6-$($t.Name)"
        $blockIpv6Display  = "Claude Cage KillSwitch: Block IPv6 for $($t.Name)"
        $ipv6Subnets       = @("2000::/3", "fc00::/7", "fe80::/10")

        if ($t.Type -eq "PackageFamily") {
            New-NetFirewallRule -Name $blockIpv6RuleName `
                -DisplayName $blockIpv6Display `
                -Group $GroupName `
                -Direction Outbound `
                -Action Block `
                -PackageFamilyName $t.PackageFamilyName `
                -Protocol Any `
                -RemoteAddress $ipv6Subnets `
                -Enabled True | Out-Null
        } else {
            New-NetFirewallRule -Name $blockIpv6RuleName `
                -DisplayName $blockIpv6Display `
                -Group $GroupName `
                -Direction Outbound `
                -Action Block `
                -Program $t.Path `
                -Protocol Any `
                -RemoteAddress $ipv6Subnets `
                -Enabled True | Out-Null
        }
        Write-Host "    [+] Block Outbound IPv6: $($t.Name)" -ForegroundColor Green

        # C. Block direct DNS to ISP DNS servers on non-VPN interfaces
        if ($ispDnsAddresses.Count -gt 0) {
            $blockIspDnsRuleName = "ClaudeCage-BlockISPDNS-$($t.Name)"
            $blockIspDnsDisplay  = "Claude Cage KillSwitch: Block ISP DNS for $($t.Name)"

            if ($t.Type -eq "PackageFamily") {
                New-NetFirewallRule -Name $blockIspDnsRuleName `
                    -DisplayName $blockIspDnsDisplay `
                    -Group $GroupName `
                    -Direction Outbound `
                    -Action Block `
                    -PackageFamilyName $t.PackageFamilyName `
                    -RemoteAddress $ispDnsAddresses `
                    -RemotePort 53 `
                    -Protocol UDP `
                    -Enabled True | Out-Null
            } else {
                New-NetFirewallRule -Name $blockIspDnsRuleName `
                    -DisplayName $blockIspDnsDisplay `
                    -Group $GroupName `
                    -Direction Outbound `
                    -Action Block `
                    -Program $t.Path `
                    -RemoteAddress $ispDnsAddresses `
                    -RemotePort 53 `
                    -Protocol UDP `
                    -Enabled True | Out-Null
            }
            Write-Host "    [+] Block Direct ISP DNS: $($t.Name)" -ForegroundColor Green
        }
    }
}

Write-Host "`n[OK] Claude Cage WFP Kill Switch is ACTIVE and ENFORCED." -ForegroundColor Green
Write-Host "==========================================================`n" -ForegroundColor Cyan
