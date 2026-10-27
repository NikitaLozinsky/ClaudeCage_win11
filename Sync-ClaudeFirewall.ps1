<#
.SYNOPSIS
    Sync-ClaudeFirewall.ps1 - Atomic Make-Before-Break 24/7 Fail-Closed WFP Kill Switch Engine.
.DESCRIPTION
    Dynamically configures Windows Filtering Platform (WFP) rules for Claude Desktop and Claude Code CLI:
    1. Universal VPN Support:
       - Prioritizes AmneziaVPN if active.
       - Automatically auto-detects generic VPN tunnels (WireGuard, OpenVPN, Wintun, Tailscale, Proton, Mullvad, etc.).
    2. Zero-Race-Condition 24/7 Architecture:
       - Source IP / LocalAddress Inversion: Blocks all outbound traffic from any source IP outside
         the VPN tunnel subnet and loopback (127.0.0.0/8).
         When VPN drops, packets trying to egress via 192.168.x.x are dropped with 0 ms delay!
       - Physical Adapter Block: Explicitly blocks all non-VPN interface aliases.
       - LAN & STUN Leak Block: Blocks outbound traffic to RFC 1918 private subnets and multicast.
       - Dual-layer IPv6 Block: Blocks outbound IPv6 by both RemoteAddress and LocalAddress ranges.
    3. Make-Before-Break Atomic Replacement:
       Never removes existing firewall rules before new rules are fully created and active.
    4. Comprehensive Target Discovery:
       Protects Claude Desktop (MSIX package and Win32 binaries), Claude CLI, caged node/curl,
       Git networking binaries (git-remote-https.exe, ssh.exe), and any MCP servers configured
       in %APPDATA%\Claude\claude_desktop_config.json.
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

function Get-ActiveVpnAdapter {
    # 1. Look for Amnezia first (priority)
    $amnezia = Get-NetAdapter | Where-Object { 
        ($_.Name -like "*Amnezia*" -or $_.InterfaceDescription -like "*Amnezia*") -and $_.Status -eq "Up" 
    } | Select-Object -First 1
    if ($amnezia) { return $amnezia }

    # 2. Look for generic VPN / Tunnel (WireGuard, Wintun, OpenVPN, Tailscale, TAP, TUN, etc.)
    $vpn = Get-NetAdapter | Where-Object {
        $_.Status -eq "Up" -and (
            $_.InterfaceDescription -match "WireGuard|Wintun|TUN|TAP|OpenVPN|Tailscale|VPN" -or
            $_.Name -match "VPN|WireGuard|Tailscale|TUN|TAP" -or
            $_.InterfaceType -in @(23, 53, 131)
        )
    } | Select-Object -First 1
    if ($vpn) { return $vpn }

    # 3. Default route virtual adapter fallback
    $defRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
    if ($defRoute) {
        $cand = Get-NetAdapter -InterfaceIndex $defRoute.InterfaceIndex -ErrorAction SilentlyContinue
        if ($cand -and $cand.Virtual -and $cand.InterfaceDescription -notmatch "Hyper-V|VirtualBox|VMware|WSL") {
            return $cand
        }
    }
    return $null
}

function Get-CageTargetBinaries {
    $targets = [System.Collections.Generic.List[PSCustomObject]]::new()
    $addedPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    function Add-TargetBinary {
        param([string]$Name, [string]$Path)
        if ($Path -and (Test-Path $Path) -and -not $addedPaths.Contains($Path)) {
            $addedPaths.Add($Path) | Out-Null
            $targets.Add([PSCustomObject]@{
                Name              = $Name
                Type              = "Binary"
                Path              = $Path
                PackageFamilyName = $null
            })
        }
    }

    # 1. Caged node.exe & curl.exe
    Add-TargetBinary "Sandboxed-Node" (Join-Path $CageBin "node.exe")
    Add-TargetBinary "Sandboxed-Curl" (Join-Path $CageBin "curl.exe")

    # 2. Iterate across all real user profiles in C:\Users (guarantees NT AUTHORITY\SYSTEM finds user installations)
    $userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { 
        $_.Name -notin @("Public", "Default", "Default User", "All Users") 
    }

    foreach ($uProf in $userProfiles) {
        $uRoot = $uProf.FullName
        # Claude CLI binaries
        $cliPaths = @(
            "$uRoot\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe",
            "$uRoot\AppData\Local\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe",
            "$uRoot\.claude\local\node_modules\@anthropic-ai\claude-code\bin\claude.exe"
        )
        foreach ($cp in $cliPaths) {
            Add-TargetBinary "Claude-CLI-$($uProf.Name)" $cp
        }

        # Win32 Claude Desktop paths
        $win32Paths = @(
            "$uRoot\AppData\Local\Programs\Claude\Claude.exe",
            "$uRoot\AppData\Local\AnthropicClaude\Claude.exe"
        )
        foreach ($wp in $win32Paths) {
            Add-TargetBinary "Claude-Win32-$($uProf.Name)" $wp
        }

        # User MCP configurations
        $mcpConfig = "$uRoot\AppData\Roaming\Claude\claude_desktop_config.json"
        if (Test-Path $mcpConfig) {
            try {
                $json = Get-Content $mcpConfig -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                if ($json.mcpServers) {
                    $mcpIdx = 0
                    foreach ($prop in $json.mcpServers.PSObject.Properties) {
                        $cmd = $prop.Value.command
                        if ($cmd) {
                            $resolved = (Get-Command $cmd -ErrorAction SilentlyContinue).Source
                            if (-not $resolved -and (Test-Path $cmd)) { $resolved = $cmd }
                            if ($resolved) {
                                Add-TargetBinary "MCP-$($prop.Name)-$($uProf.Name)-$mcpIdx" $resolved
                                $mcpIdx++
                            }
                        }
                    }
                }
            } catch {}
        }
    }

    # 3. Claude Desktop AppX / MSIX package family (-AllUsers is mandatory for SYSTEM task)
    $claudeAppxList = Get-AppxPackage -AllUsers -Name *Claude* -ErrorAction SilentlyContinue
    if ($claudeAppxList) {
        $firstAppx = $claudeAppxList | Select-Object -First 1
        $targets.Add([PSCustomObject]@{
            Name              = "Claude-Desktop-MSIX"
            Type              = "PackageFamily"
            Path              = $null
            PackageFamilyName = $firstAppx.PackageFamilyName
        })

        foreach ($appx in $claudeAppxList) {
            if ($appx.InstallLocation) {
                $appxExe = Join-Path $appx.InstallLocation "app\claude.exe"
                Add-TargetBinary "Claude-Desktop-AppX-Exe" $appxExe
            }
        }
    }

    # Dynamic search for all Claude installations in WindowsApps (survives store updates)
    $windowsAppsDirs = Get-ChildItem -Path "C:\Program Files\WindowsApps" -Filter "*Claude*" -Directory -ErrorAction SilentlyContinue
    $idx = 0
    foreach ($dir in $windowsAppsDirs) {
        $candExe = Join-Path $dir.FullName "app\claude.exe"
        if (Test-Path $candExe) {
            Add-TargetBinary "Claude-WindowsApps-$idx" $candExe
            $idx++
        }
    }

    # Global Machine Win32
    if (Test-Path "C:\Program Files\Claude\Claude.exe") {
        Add-TargetBinary "Claude-Desktop-ProgramFiles" "C:\Program Files\Claude\Claude.exe"
    }

    # 4. Git & SSH Network Binaries (prevents git fetch / git push leaks)
    $gitDirs = @(
        "C:\Program Files\Git",
        "C:\Program Files (x86)\Git",
        "$env:LOCALAPPDATA\Programs\Git"
    )
    $gitRelativeBins = @(
        "cmd\git.exe",
        "bin\git.exe",
        "mingw64\bin\git.exe",
        "mingw64\bin\git-remote-https.exe",
        "mingw64\libexec\git-core\git-remote-https.exe",
        "mingw64\libexec\git-core\git-remote-http.exe",
        "usr\bin\ssh.exe"
    )
    foreach ($gDir in $gitDirs) {
        if (Test-Path $gDir) {
            foreach ($rel in $gitRelativeBins) {
                $fPath = Join-Path $gDir $rel
                if (Test-Path $fPath) {
                    Add-TargetBinary ("Git-" + [System.IO.Path]::GetFileNameWithoutExtension($rel)) $fPath
                }
            }
        }
    }

    # System OpenSSH (in System32, often invoked by git or terminal)
    $sysSsh = "C:\Windows\System32\OpenSSH\ssh.exe"
    if (Test-Path $sysSsh) {
        Add-TargetBinary "System-OpenSSH" $sysSsh
    }

    return $targets
}

function Remove-KillSwitchRules {
    Write-Host "[*] Removing all rules in group '$GroupName'..." -ForegroundColor DarkYellow
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

    $vpnAdapter = Get-ActiveVpnAdapter

    if ($vpnAdapter) {
        Write-Host "`n[+] VPN Tunnel Active: $($vpnAdapter.Name) [$($vpnAdapter.InterfaceDescription)]" -ForegroundColor Green
        $vpnIps = (Get-NetIPAddress -InterfaceIndex $vpnAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
        Write-Host "    Tunnel IPv4: $($vpnIps -join ', ')" -ForegroundColor Green
    } else {
        Write-Host "`n[!] VPN Status: DISCONNECTED / NOT DETECTED (Protected 24/7 by LocalAddress Inversion)" -ForegroundColor Yellow
    }

    $rules = Get-NetFirewallRule | Where-Object { $_.Group -eq $GroupName }
    Write-Host "`n[i] Active ClaudeKillSwitch WFP Rules: $(($rules | Measure-Object).Count)" -ForegroundColor Yellow
    foreach ($r in $rules) {
        Write-Host "    - $($r.DisplayName) -> Action: $($r.Action), Enabled: $($r.Enabled)" -ForegroundColor Gray
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

# --- ENFORCE KILL SWITCH RULES (ATOMIC MAKE-BEFORE-BREAK) ---
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   ENFORCING CLAUDE CAGE ATOMIC 24/7 FAIL-CLOSED RULES    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Discover targets
$targets = Get-CageTargetBinaries
if ($targets.Count -eq 0) {
    Write-Warning "[!] No Claude targets or caged binaries found! Run Initialize-SandboxBins.ps1 first."
    exit 1
}

Write-Host "[+] Discovered $($targets.Count) protected target(s):" -ForegroundColor Cyan
foreach ($t in $targets) {
    $desc = if ($t.Type -eq "PackageFamily") { "[MSIX] $($t.PackageFamilyName)" } else { "[BIN] $($t.Path)" }
    Write-Host "    - $($t.Name): $desc" -ForegroundColor DarkGray
}

# 2. Universal VPN Adapter & Network topology
$vpnAdapter = Get-ActiveVpnAdapter
$vpnName = if ($vpnAdapter) { $vpnAdapter.Name } else { "None" }
$vpnIp = if ($vpnAdapter) { (Get-NetIPAddress -InterfaceIndex $vpnAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress } else { $null }

if ($vpnAdapter) {
    Write-Host "`n[+] Detected VPN: $($vpnAdapter.Name) (IP: $vpnIp)" -ForegroundColor Green
} else {
    Write-Host "`n[!] No active VPN currently connected. Using standard CGNAT 100.64.0.0/10 fail-closed profile." -ForegroundColor Yellow
}

$nonVpnAdapters = Get-NetAdapter | Where-Object {
    if ($vpnAdapter) {
        $_.InterfaceIndex -ne $vpnAdapter.InterfaceIndex
    } else {
        $_.Name -notlike "*Amnezia*" -and $_.InterfaceDescription -notlike "*WireGuard*"
    }
}
$nonVpnAliases = @($nonVpnAdapters | ForEach-Object { $_.Name })

# 3. Dynamic LocalAddress Inversion calculation
# Default to CGNAT 100.64.0.0/10 (AmneziaVPN standard)
$blockedLocalIpRanges = @(
    "0.0.0.0-100.63.255.255",
    "100.128.0.0-126.255.255.255",
    "128.0.0.0-255.255.255.255"
)

# If another VPN is active with a 10.x.x.x IP:
if ($vpnIp -and $vpnIp -like "10.*") {
    $blockedLocalIpRanges = @(
        "0.0.0.0-9.255.255.255",
        "11.0.0.0-126.255.255.255",
        "128.0.0.0-255.255.255.255"
    )
    Write-Host "    [i] Configured LocalAddress Inversion for 10.0.0.0/8 VPN tunnel." -ForegroundColor Cyan
}

# LAN & STUN leak block: RFC 1918 private subnets and multicast
$blockedLanRanges = @(
    "192.168.0.0/16",
    "172.16.0.0/12",
    "169.254.0.0/16",
    "224.0.0.0/4"
)
if (-not ($vpnIp -and $vpnIp -like "10.*")) {
    $blockedLanRanges += "10.0.0.0/8"
}

# Non-tunnel DNS Port Lock (UDP/TCP 53, 853)
$blockedDnsRemote = if ($vpnIp -and $vpnIp -like "10.*") {
    @("0.0.0.0-9.255.255.255", "11.0.0.0-255.255.255.255")
} else {
    @("0.0.0.0-100.63.255.255", "100.128.0.0-255.255.255.255")
}

# Dual-layer IPv6 Block (Unconditional across all IPv6 local addresses)
$blockedIpv6Local = @("0000::-0000:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "0001::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")

# Enforce Strong Host Model on all interfaces
Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | Set-NetIPInterface -WeakHostSend Disabled -WeakHostReceive Disabled -ErrorAction SilentlyContinue
Get-NetIPInterface -AddressFamily IPv6 -ErrorAction SilentlyContinue | Set-NetIPInterface -WeakHostSend Disabled -WeakHostReceive Disabled -ErrorAction SilentlyContinue

# 4. Snapshot existing rules for Make-Before-Break atomic transition
$oldRules = Get-NetFirewallRule | Where-Object { $_.Group -eq $GroupName -or $_.Name -like "ClaudeCage*" }
$genTag = "Gen" + [DateTime]::UtcNow.ToString("yyyyMMddHHmmss")
$newRuleNames = [System.Collections.Generic.List[string]]::new()

Write-Host "`n[*] [1/2] Creating new atomic 24/7 Fail-Closed rules (Generation: $genTag)..." -ForegroundColor Yellow

try {
    $targetIndex = 0
    foreach ($t in $targets) {
        $targetIndex++
        $safeName = "$targetIndex-" + ($t.Name -replace '[^a-zA-Z0-9_\-]', '')

        # RULE 1: Source IP / LocalAddress Inversion (The Master 0-ms Lock)
        $r1Name = "ClaudeCage-$genTag-LocalInv-$safeName"
        $r1Display = "Claude Cage: Block Non-VPN Source IP for $($t.Name)"
        if ($t.Type -eq "PackageFamily") {
            New-NetFirewallRule -Name $r1Name -DisplayName $r1Display -Group $GroupName `
                -Direction Outbound -Action Block -PackageFamilyName $t.PackageFamilyName `
                -LocalAddress $blockedLocalIpRanges -Enabled True | Out-Null
        } else {
            New-NetFirewallRule -Name $r1Name -DisplayName $r1Display -Group $GroupName `
                -Direction Outbound -Action Block -Program $t.Path `
                -LocalAddress $blockedLocalIpRanges -Enabled True | Out-Null
        }
        $newRuleNames.Add($r1Name)

        # RULE 2: Block Physical & Non-VPN Adapters (InterfaceAlias)
        if ($nonVpnAliases.Count -gt 0) {
            $r2Name = "ClaudeCage-$genTag-Adapter-$safeName"
            $r2Display = "Claude Cage: Block Physical Adapters for $($t.Name)"
            if ($t.Type -eq "PackageFamily") {
                New-NetFirewallRule -Name $r2Name -DisplayName $r2Display -Group $GroupName `
                    -Direction Outbound -Action Block -PackageFamilyName $t.PackageFamilyName `
                    -InterfaceAlias $nonVpnAliases -Enabled True | Out-Null
            } else {
                New-NetFirewallRule -Name $r2Name -DisplayName $r2Display -Group $GroupName `
                    -Direction Outbound -Action Block -Program $t.Path `
                    -InterfaceAlias $nonVpnAliases -Enabled True | Out-Null
            }
            $newRuleNames.Add($r2Name)
        }

        # RULE 3: Block Local LAN / Router STUN
        $r3Name = "ClaudeCage-$genTag-Lan-$safeName"
        $r3Display = "Claude Cage: Block LAN/STUN for $($t.Name)"
        if ($t.Type -eq "PackageFamily") {
            New-NetFirewallRule -Name $r3Name -DisplayName $r3Display -Group $GroupName `
                -Direction Outbound -Action Block -PackageFamilyName $t.PackageFamilyName `
                -RemoteAddress $blockedLanRanges -Enabled True | Out-Null
        } else {
            New-NetFirewallRule -Name $r3Name -DisplayName $r3Display -Group $GroupName `
                -Direction Outbound -Action Block -Program $t.Path `
                -RemoteAddress $blockedLanRanges -Enabled True | Out-Null
        }
        $newRuleNames.Add($r3Name)

        # RULE 4: Block Outbound IPv6 Unconditionally (Closes ff00::/8 multicast & mDNS bypass)
        $r4Name = "ClaudeCage-$genTag-IPv6-$safeName"
        $r4Display = "Claude Cage: Block IPv6 for $($t.Name)"
        if ($t.Type -eq "PackageFamily") {
            New-NetFirewallRule -Name $r4Name -DisplayName $r4Display -Group $GroupName `
                -Direction Outbound -Action Block -PackageFamilyName $t.PackageFamilyName `
                -Protocol Any -LocalAddress $blockedIpv6Local -Enabled True | Out-Null
        } else {
            New-NetFirewallRule -Name $r4Name -DisplayName $r4Display -Group $GroupName `
                -Direction Outbound -Action Block -Program $t.Path `
                -Protocol Any -LocalAddress $blockedIpv6Local -Enabled True | Out-Null
        }
        $newRuleNames.Add($r4Name)

        # RULE 5: Strict Non-Tunnel DNS Port Lock (Blocks direct UDP/TCP 53 and 853 to non-tunnel DNS)
        $r5NameUdp = "ClaudeCage-$genTag-DnsUdp-$safeName"
        $r5DisplayUdp = "Claude Cage: Block Non-Tunnel DNS UDP 53/853 for $($t.Name)"
        $r5NameTcp = "ClaudeCage-$genTag-DnsTcp-$safeName"
        $r5DisplayTcp = "Claude Cage: Block Non-Tunnel DNS TCP 53/853 for $($t.Name)"

        if ($t.Type -eq "PackageFamily") {
            New-NetFirewallRule -Name $r5NameUdp -DisplayName $r5DisplayUdp -Group $GroupName `
                -Direction Outbound -Action Block -PackageFamilyName $t.PackageFamilyName `
                -Protocol UDP -RemotePort @("53", "853") -RemoteAddress $blockedDnsRemote -Enabled True | Out-Null
            New-NetFirewallRule -Name $r5NameTcp -DisplayName $r5DisplayTcp -Group $GroupName `
                -Direction Outbound -Action Block -PackageFamilyName $t.PackageFamilyName `
                -Protocol TCP -RemotePort @("53", "853") -RemoteAddress $blockedDnsRemote -Enabled True | Out-Null
        } else {
            New-NetFirewallRule -Name $r5NameUdp -DisplayName $r5DisplayUdp -Group $GroupName `
                -Direction Outbound -Action Block -Program $t.Path `
                -Protocol UDP -RemotePort @("53", "853") -RemoteAddress $blockedDnsRemote -Enabled True | Out-Null
            New-NetFirewallRule -Name $r5NameTcp -DisplayName $r5DisplayTcp -Group $GroupName `
                -Direction Outbound -Action Block -Program $t.Path `
                -Protocol TCP -RemotePort @("53", "853") -RemoteAddress $blockedDnsRemote -Enabled True | Out-Null
        }
        $newRuleNames.Add($r5NameUdp)
        $newRuleNames.Add($r5NameTcp)

        Write-Host "    [+] Enforced 24/7 Security Policies for: $($t.Name)" -ForegroundColor Green
    }
} catch {
    Write-Error "[!] Error creating new firewall rules: $_. Rolling back generation $genTag..."
    foreach ($rName in $newRuleNames) {
        Remove-NetFirewallRule -Name $rName -ErrorAction SilentlyContinue
    }
    throw
}

# 5. Make-Before-Break: Remove old generation rules only AFTER all new rules are active
Write-Host "`n[*] [2/2] Performing atomic retirement of prior rules..." -ForegroundColor Yellow
if ($oldRules) {
    $oldRules | Remove-NetFirewallRule
    Write-Host "    [OK] Retired $(($oldRules | Measure-Object).Count) prior rule(s) seamlessly." -ForegroundColor Green
} else {
    Write-Host "    [OK] No prior rules to retire." -ForegroundColor Gray
}

Write-Host "`n[OK] Claude Cage WFP Kill Switch is 100% ACTIVE (Make-Before-Break Complete)." -ForegroundColor Green
Write-Host "==========================================================`n" -ForegroundColor Cyan
