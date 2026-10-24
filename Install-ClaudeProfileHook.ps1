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

$hookComment = "# ClaudeCage CLI Isolated Runner Hook"
$hookScript = @"

$hookComment
function claude {
    & "C:\ClaudeCage\Invoke-ClaudeCLI.ps1" @args
}
function claudecage {
    & "C:\ClaudeCage\Invoke-ClaudeCLI.ps1" @args
}
"@

$existingContent = ""
if (Test-Path $PROFILE) {
    $existingContent = Get-Content $PROFILE -Raw
}

if ($existingContent -notmatch "ClaudeCage CLI Isolated Runner Hook") {
    Add-Content -Path $PROFILE -Value $hookScript
    Write-Host "[+] Installed ClaudeCage CLI hook in: $PROFILE" -ForegroundColor Green
} else {
    Write-Host "[i] ClaudeCage hook already present in: $PROFILE" -ForegroundColor Gray
}
