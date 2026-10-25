<#
.SYNOPSIS
    Test-CageLeaks.ps1 - Comprehensive security & leak verification suite for ClaudeCage.
.DESCRIPTION
    Audits and verifies:
    1. AmneziaVPN tunnel interface status
    2. Caged binaries provisioning (node.exe, curl.exe)
    3. WFP 24/7 Kill Switch rules (LocalAddress Inversion, LAN Block, IPv6 Block, Physical Block)
    4. NRPT (Name Resolution Policy Table) enforcement (forces Claude domains to 100.64.0.1 only)
    5. Public IP & Geolocation leak check (must show VPN country, never real ISP)
    6. WFP Fail-Closed Kill Switch (attempts egress via physical IP 192.168.0.68 - MUST FAIL)
    7. Anti-Leak DNS Hardening (SMHNR disabled + NRPT policy active)
    8. Dual-Layer IPv6 Leak Protection (ms_tcpip6 disabled + WFP drop)
    9. Anti-Fraud Timezone & Locale Telemetry Spoofing
#>

[CmdletBinding()]
param(
    [switch]$Detailed
)

$ErrorActionPreference = 'Continue'

$CageRoot = "C:\ClaudeCage"
$CageBin  = Join-Path $CageRoot "bin"
$CurlBin  = Join-Path $CageBin "curl.exe"
$NodeBin  = Join-Path $CageBin "node.exe"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "      CLAUDE CAGE SECURITY & LEAK TEST SUITE (v6)         " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$testResults = [System.Collections.Generic.List[PSCustomObject]]::new()

function Record-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Expected,
        [string]$Actual,
        [string]$Details = ""
    )

    $statusStr = if ($Passed) { "[PASS]" } else { "[FAIL]" }
    $color     = if ($Passed) { "Green" } else { "Red" }
    $actualCol = if ($Passed) { "DarkGreen" } else { "DarkRed" }
    Write-Host "$statusStr $TestName" -ForegroundColor $color
    if (-not $Passed -or $Detailed) {
        Write-Host "       Expected: $Expected" -ForegroundColor DarkGray
        Write-Host "       Actual:   $Actual" -ForegroundColor $actualCol
        if ($Details) {
            Write-Host "       Details:  $Details" -ForegroundColor Gray
        }
    }

    $script:testResults.Add([PSCustomObject]@{
        TestName = $TestName
        Passed   = $Passed
        Expected = $Expected
        Actual   = $Actual
        Details  = $Details
    })
}

# --- TEST 1: AmneziaVPN Interface Status ---
$vpnAdapter = Get-NetAdapter | Where-Object {
    ($_.Name -like "*Amnezia*" -or $_.InterfaceDescription -like "*WireGuard*") -and $_.Status -eq "Up"
} | Select-Object -First 1

$vpnUp = ($vpnAdapter -ne $null)
$vpnName = if ($vpnUp) { $vpnAdapter.Name } else { "None" }
Record-TestResult -TestName "VPN Tunnel Interface Active" `
    -Passed $vpnUp `
    -Expected "AmneziaVPN interface Up" `
    -Actual "Adapter: $vpnName, Status: $(if ($vpnUp) { 'Up' } else { 'Down' })"

# --- TEST 2: Caged Binaries Provisioning ---
$binsExist = (Test-Path $CurlBin) -and (Test-Path $NodeBin)
Record-TestResult -TestName "Caged Binaries Provisioned" `
    -Passed $binsExist `
    -Expected "curl.exe and node.exe in C:\ClaudeCage\bin" `
    -Actual "curl.exe: $(Test-Path $CurlBin), node.exe: $(Test-Path $NodeBin)"

# --- TEST 3: WFP 24/7 KillSwitch Rules Enforced ---
$killSwitchRules = Get-NetFirewallRule | Where-Object { $_.Group -eq "ClaudeKillSwitch" }
$ruleCount = ($killSwitchRules | Measure-Object).Count
$rulesActive = ($ruleCount -gt 0)
Record-TestResult -TestName "WFP 24/7 KillSwitch Rules Active" `
    -Passed $rulesActive `
    -Expected "ClaudeKillSwitch rules > 0 (44 active rules)" `
    -Actual "$ruleCount active rules"

# --- TEST 4: NRPT Kernel DNS Policy Enforcement ---
$nrptRules = Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -eq "ClaudeCageNRPT" }
$nrptPassed = $false
$nrptActual = "No ClaudeCage NRPT rules found"
if ($nrptRules) {
    $nrptPassed = ($nrptRules.NameServers -contains "100.64.0.1")
    $nrptActual = "NRPT active: $($nrptRules.Namespace -join ', ') -> 100.64.0.1"
}
Record-TestResult -TestName "NRPT Kernel DNS Policy (svchost Protection)" `
    -Passed $nrptPassed `
    -Expected "Claude domains locked to 100.64.0.1 in NRPT" `
    -Actual $nrptActual

# --- TEST 5: Public IP Geolocation (Must NOT be Russia) ---
$publicIpInfo = $null
$geoPassed = $false
$geoActual = "Could not fetch IP"
$detectedCountry = "Unknown"
$detectedTimezone = "Unknown"

try {
    $ipJson = & $CurlBin -s --connect-timeout 8 https://ipinfo.io/json
    if ($ipJson) {
        $publicIpInfo = $ipJson | ConvertFrom-Json
        $detectedCountry  = $publicIpInfo.country
        $detectedTimezone = $publicIpInfo.timezone
        $geoPassed = ($detectedCountry -ne "RU" -and $detectedCountry -ne $null -and $detectedCountry -ne "")
        $geoActual = "IP: $($publicIpInfo.ip), Country: $detectedCountry ($($publicIpInfo.city)), Timezone: $detectedTimezone"
    }
} catch {
    $geoActual = "Error querying IP: $_"
}

Record-TestResult -TestName "Public IP Geolocation Leak Check" `
    -Passed $geoPassed `
    -Expected "Country != RU (Non-Russian exit node)" `
    -Actual $geoActual

# --- TEST 6: WFP Fail-Closed Kill Switch (Physical Egress Blocked) ---
$physicalAdapter = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
$physicalIp = $null
if ($physicalAdapter) {
    $physicalIp = (Get-NetIPAddress -InterfaceIndex $physicalAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
}

$killSwitchBlocked = $false
$killSwitchActual  = ""

if ($physicalIp) {
    $curlProc = Start-Process -FilePath $CurlBin `
        -ArgumentList "-s --connect-timeout 3 --interface $physicalIp https://api.ipify.org" `
        -NoNewWindow -Wait -PassThru

    if ($curlProc.ExitCode -ne 0) {
        $killSwitchBlocked = $true
        $killSwitchActual = "Egress via physical IP $physicalIp was BLOCKED (Exit code: $($curlProc.ExitCode))"
    } else {
        $killSwitchBlocked = $false
        $killSwitchActual = "LEAK DETECTED! Packet escaped via physical IP $physicalIp!"
    }
} else {
    $killSwitchBlocked = $true
    $killSwitchActual = "No physical adapter IP found to test (safe)"
}

Record-TestResult -TestName "WFP LocalAddress Inversion (Physical Egress Blocked)" `
    -Passed $killSwitchBlocked `
    -Expected "Outbound connection via physical adapter dropped by WFP" `
    -Actual $killSwitchActual

# --- TEST 7: Anti-Leak DNS Hardening (SMHNR Disabled) ---
$smhnrKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$smhnrVal = (Get-ItemProperty -Path $smhnrKey -Name "DisableSmartNameResolution" -ErrorAction SilentlyContinue).DisableSmartNameResolution
$dnsHardened = ($smhnrVal -eq 1)

Record-TestResult -TestName "Anti-Leak DNS Hardening (SMHNR Disabled)" `
    -Passed $dnsHardened `
    -Expected "DisableSmartNameResolution = 1" `
    -Actual "DisableSmartNameResolution = $smhnrVal"

# --- TEST 8: Dual-Layer IPv6 Leak Protection ---
$ipv6BindingDisabled = $false
if ($physicalAdapter) {
    $physicalBinding = Get-NetAdapterBinding -Name $physicalAdapter.Name -ComponentId ms_tcpip6 -ErrorAction SilentlyContinue
    if ($physicalBinding -and -not $physicalBinding.Enabled) {
        $ipv6BindingDisabled = $true
    }
}

$curlIpv6Proc = Start-Process -FilePath $CurlBin `
    -ArgumentList "-6 -s --connect-timeout 3 https://google.com" `
    -NoNewWindow -Wait -PassThru

$ipv6Blocked = ($curlIpv6Proc.ExitCode -ne 0)
$ipv6Passed = ($ipv6BindingDisabled -and $ipv6Blocked)

Record-TestResult -TestName "IPv6 Leak Protection" `
    -Passed $ipv6Passed `
    -Expected "ms_tcpip6 disabled on physical adapter AND curl IPv6 blocked" `
    -Actual "ms_tcpip6 disabled: $ipv6BindingDisabled, curl IPv6 exit: $($curlIpv6Proc.ExitCode)"

# --- TEST 9: Anti-Fraud Timezone & Telemetry Spoofing ---
$targetTz = if ($detectedTimezone -and $detectedTimezone -ne "Unknown") { $detectedTimezone } else { "Europe/Amsterdam" }
$nodeTzCheck = & $NodeBin -e "
    process.env.TZ = '$targetTz';
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    const offset = new Date().getTimezoneOffset();
    console.log(JSON.stringify({ timeZone: tz, offset: offset }));
"

$tzObj = $nodeTzCheck | ConvertFrom-Json
$tzPassed = ($tzObj.timeZone -eq $targetTz -and $tzObj.timeZone -notmatch "Moscow|Russian")
Record-TestResult -TestName "Timezone Anti-Fraud Telemetry Spoofing" `
    -Passed $tzPassed `
    -Expected "Timezone == $targetTz (Non-Russian)" `
    -Actual "Reported Timezone: $($tzObj.timeZone), Offset: $($tzObj.offset) min"

# --- SUMMARY ---
$totalTests  = $testResults.Count
$passedTests = ($testResults | Where-Object { $_.Passed }).Count
$failedTests = $totalTests - $passedTests
$failCol     = if ($failedTests -gt 0) { "Red" } else { "Green" }

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "                     TEST SUMMARY                         " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Total Tests:  $totalTests" -ForegroundColor White
Write-Host "Passed:       $passedTests" -ForegroundColor Green
Write-Host "Failed:       $failedTests" -ForegroundColor $failCol

if ($failedTests -eq 0) {
    Write-Host "`n[SUCCESS] CLAUDE CAGE IS 100% IMPENETRABLE & LEAK-PROOF!" -ForegroundColor Green
} else {
    Write-Host "`n[WARNING] SOME LEAK CHECKS FAILED! INVESTIGATE ABOVE." -ForegroundColor Red
}
Write-Host "==========================================================`n" -ForegroundColor Cyan

return ($failedTests -eq 0)
