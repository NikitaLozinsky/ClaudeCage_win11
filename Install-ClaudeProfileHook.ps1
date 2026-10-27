<#
.SYNOPSIS
    Install-ClaudeProfileHook.ps1 - Connects Invoke-ClaudeCLI into PowerShell $PROFILE.
.DESCRIPTION
    Appends a function hook to the user's PowerShell profile so running 'claude'
    automatically routes through C:\ClaudeCage\Invoke-ClaudeCLI.ps1 with full
    anti-leak and Kill Switch protections.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$profileDir = Split-Path $PROFILE
if (-not (Test-Path $profileDir)) {
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
}

$nativeExe = "C:\ClaudeCage\ClaudeCage.exe"
$useNative = Test-Path $nativeExe

$hookScript = if ($useNative) {
@"

# User Development CLI Environment
function claude {
    & "$nativeExe" cli @args
}
"@
} else {
@"

# User Development CLI Environment
function claude {
    & "C:\ClaudeCage\Invoke-ClaudeCLI.ps1" @args
}
"@
}

$existingContent = ""
if (Test-Path $PROFILE) {
    $existingContent = Get-Content $PROFILE -Raw
}

$regex = "(?s)# (ClaudeCage|User).*?function (claude|claudecage) \{.*?\}(\r?\nfunction claudecage \{.*?\})?"
if ($existingContent -match $regex) {
    $updated = $existingContent -replace $regex, $hookScript.Trim()
    Set-Content -Path $PROFILE -Value $updated -Force
    Write-Host "[+] Updated CLI hook in: $PROFILE" -ForegroundColor Green
} elseif ($existingContent -notmatch "function claude") {
    Add-Content -Path $PROFILE -Value $hookScript
    Write-Host "[+] Installed CLI hook in: $PROFILE" -ForegroundColor Green
} else {
    Write-Host "[i] CLI hook already present in: $PROFILE" -ForegroundColor Gray
}
