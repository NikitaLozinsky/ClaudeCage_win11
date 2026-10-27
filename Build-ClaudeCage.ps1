<#
.SYNOPSIS
    Build-ClaudeCage.ps1 - Automated Native Compilation & Versioning Pipeline for ClaudeCage.
.DESCRIPTION
    Compiles ClaudeCage into an immutable, standalone native Windows binary (ClaudeCage.exe):
    1. Reads or auto-increments semantic version (version.json / git tag).
    2. Embeds the high-resolution custom icon (icons/ClaudeCage.ico) directly into the PE binary resources.
    3. Statically links and strips debug symbols (-ldflags "-s -w") for tamper resistance.
    4. Archives build into builds/v<version>/ClaudeCage.exe with SHA-256 checksums.
    5. Updates builds/latest/ and builds/manifest.json history.
    6. Deploys binary to C:\ClaudeCage\ClaudeCage.exe.
    7. Updates Desktop and Start Menu shortcuts to point to the compiled .exe.
    8. Updates PowerShell $PROFILE hook to invoke the compiled .exe in CLI mode.
#>

[CmdletBinding()]
param(
    [string]$Version,
    [switch]$NoShortcuts
)

$ErrorActionPreference = 'Stop'

$TargetRoot = "C:\ClaudeCage"
$SrcDir     = Join-Path $TargetRoot "src"
$BuildsDir  = Join-Path $TargetRoot "builds"
$IconsDir   = Join-Path $TargetRoot "icons"
$IconFile   = Join-Path $IconsDir "ClaudeCage.ico"
$VersionFile = Join-Path $TargetRoot "version.json"
$ManifestFile = Join-Path $BuildsDir "manifest.json"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       CLAUDECAGE: NATIVE COMPILATION & BUILD PIPELINE    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Determine Build Version
$currentVer = "6.3.0"
if (Test-Path $VersionFile) {
    try {
        $vJson = Get-Content $VersionFile -Raw | ConvertFrom-Json
        if ($vJson.version) { $currentVer = $vJson.version }
    } catch {}
}

if (-not $Version) {
    # Auto-increment patch version
    $parts = $currentVer.TrimStart('v').Split('.')
    if ($parts.Count -eq 3) {
        $patch = [int]$parts[2] + 1
        $targetVersion = "v$($parts[0]).$($parts[1]).$patch"
    } else {
        $targetVersion = "v$currentVer"
    }
} else {
    $targetVersion = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
}

# Get Git metadata
$gitCommit = "unknown"
try {
    $gitCommit = (git rev-parse --short HEAD 2>$null).Trim()
} catch {}
if (-not $gitCommit) { $gitCommit = "dev" }

$buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Host "`n[*] [1/6] Target Version:   $targetVersion" -ForegroundColor Yellow
Write-Host "    Git Commit:       $gitCommit" -ForegroundColor DarkGray
Write-Host "    Build Timestamp:  $buildDate" -ForegroundColor DarkGray

# 2. Verify Go Compiler and Rsrc Resource Tool
Write-Host "`n[*] [2/6] Verifying toolchain (Go 1.24+ & rsrc)..." -ForegroundColor Yellow
$goCmd = Get-Command go -ErrorAction SilentlyContinue
if (-not $goCmd) {
    Write-Error "[!] Go compiler not found in PATH! Please ensure Go is installed."
    exit 1
}

$rsrcExe = Join-Path $env:USERPROFILE "go\bin\rsrc.exe"
if (-not (Test-Path $rsrcExe)) {
    Write-Host "    Downloading rsrc tool..." -ForegroundColor Yellow
    go install github.com/akavel/rsrc@latest
}
Write-Host "    [OK] Go compiler: $($goCmd.Source)" -ForegroundColor Green
Write-Host "    [OK] Resource tool: $rsrcExe" -ForegroundColor Green

# 3. Generate PE Resource (Embedded Icon)
Write-Host "`n[*] [3/6] Generating PE resources with embedded icon..." -ForegroundColor Yellow
if (-not (Test-Path $IconFile)) {
    # Fallback to claude.ico if ClaudeCage.ico missing
    $IconFile = Join-Path $IconsDir "claude.ico"
}

Push-Location $SrcDir
try {
    $sysoFile = Join-Path $SrcDir "rsrc.syso"
    & $rsrcExe -ico $IconFile -o $sysoFile
    Write-Host "    [OK] Embedded icon: $IconFile -> rsrc.syso" -ForegroundColor Green

    # 4. Compile Native Static Binary
    Write-Host "`n[*] [4/6] Compiling ClaudeCage.exe (stripped, hardened)..." -ForegroundColor Yellow
    $outExe = Join-Path $SrcDir "ClaudeCage.exe"
    if (Test-Path $outExe) { Remove-Item $outExe -Force }

    $ldFlags = "-s -w -X main.Version=$targetVersion -X main.BuildDate=$buildDate -X main.Commit=$gitCommit"
    go build -ldflags $ldFlags -o $outExe

    if (-not (Test-Path $outExe)) {
        Write-Error "[!] Build failed: ClaudeCage.exe not produced."
        exit 1
    }

    $binSize = (Get-Item $outExe).Length
    $binSizeKb = [math]::Round($binSize / 1KB, 1)
    Write-Host "    [OK] Compilation successful! Binary size: $binSizeKb KB ($binSize bytes)" -ForegroundColor Green

} finally {
    # Clean up intermediate syso
    if (Test-Path $sysoFile) { Remove-Item $sysoFile -Force -ErrorAction SilentlyContinue }
    Pop-Location
}

# 5. Versioning & Build Archival
Write-Host "`n[*] [5/6] Archiving build artifacts and computing hashes..." -ForegroundColor Yellow
$versionedDir = Join-Path $BuildsDir $targetVersion
$latestDir    = Join-Path $BuildsDir "latest"

if (-not (Test-Path $versionedDir)) { New-Item -ItemType Directory -Path $versionedDir -Force | Out-Null }
if (-not (Test-Path $latestDir))    { New-Item -ItemType Directory -Path $latestDir -Force | Out-Null }

$versionedExe = Join-Path $versionedDir "ClaudeCage.exe"
$latestExe    = Join-Path $latestDir "ClaudeCage.exe"
$rootExe      = Join-Path $TargetRoot "ClaudeCage.exe"

Copy-Item $outExe $versionedExe -Force
Copy-Item $outExe $latestExe -Force
Copy-Item $outExe $rootExe -Force
Remove-Item $outExe -Force

# Compute SHA-256
$hashObj = Get-FileHash -Path $versionedExe -Algorithm SHA256
$sha256 = $hashObj.Hash
Set-Content -Path (Join-Path $versionedDir "checksums.sha256") -Value "$sha256  ClaudeCage.exe"

Write-Host "    [OK] Stored in:       $versionedExe" -ForegroundColor Green
Write-Host "    [OK] Stored latest:   $latestExe" -ForegroundColor Green
Write-Host "    [OK] Deployed root:   $rootExe" -ForegroundColor Green
Write-Host "    [OK] SHA-256 Hash:    $sha256" -ForegroundColor Cyan

# Update manifest.json
$manifestList = @()
if (Test-Path $ManifestFile) {
    try {
        $manifestList = @(Get-Content $ManifestFile -Raw | ConvertFrom-Json)
    } catch {}
}

$buildEntry = [ordered]@{
    Version   = $targetVersion
    Date      = $buildDate
    Commit    = $gitCommit
    SizeBytes = $binSize
    Sha256    = $sha256
    ExePath   = "builds/$targetVersion/ClaudeCage.exe"
}
$manifestList = @($buildEntry) + @($manifestList | Where-Object { $_.Version -ne $targetVersion })
$manifestList | ConvertTo-Json -Depth 4 | Set-Content $ManifestFile -Force

# Update version.json
[ordered]@{
    version   = $targetVersion
    lastBuild = $buildDate
    lastCommit= $gitCommit
} | ConvertTo-Json | Set-Content $VersionFile -Force

# 6. Shortcut & Profile Integration
if (-not $NoShortcuts) {
    Write-Host "`n[*] [6/6] Updating shortcuts and shell profile to native binary..." -ForegroundColor Yellow

    # Update Desktop & Start Menu Shortcuts
    $wsh = New-Object -ComObject WScript.Shell
    $desktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
    $desktopLnk = Join-Path $desktopPath "Claude.lnk"
    
    $sc = $wsh.CreateShortcut($desktopLnk)
    $sc.TargetPath = $rootExe
    $sc.Arguments = ""
    $sc.WorkingDirectory = $TargetRoot
    $sc.Description = "Claude"
    $sc.IconLocation = "$IconFile,0"
    $sc.Save()
    Write-Host "    [+] Desktop shortcut 'Claude' -> $rootExe" -ForegroundColor Green

    $startMenuPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
    if (Test-Path $startMenuPath) {
        $startLnk = Join-Path $startMenuPath "Claude.lnk"
        $scStart = $wsh.CreateShortcut($startLnk)
        $scStart.TargetPath = $rootExe
        $scStart.Arguments = ""
        $scStart.WorkingDirectory = $TargetRoot
        $scStart.Description = "Claude"
        $scStart.IconLocation = "$IconFile,0"
        $scStart.Save()
        Write-Host "    [+] Start Menu shortcut 'Claude' -> $rootExe" -ForegroundColor Green
    }

    # Update PowerShell Profile Hook (Stealth / Neutral naming)
    if (Test-Path $PROFILE) {
        $profileContent = Get-Content $PROFILE -Raw
        $newHook = @"

# User Development CLI Environment
function claude {
    & "$rootExe" cli @args
}
"@
        if ($profileContent -match "function claude") {
            # Replace old hook with native executable hook
            $regex = "(?s)# (ClaudeCage|User).*?function (claude|claudecage) \{.*?\}(\r?\nfunction claudecage \{.*?\})?"
            if ($profileContent -match $regex) {
                $updatedProfile = $profileContent -replace $regex, $newHook.Trim()
                Set-Content -Path $PROFILE -Value $updatedProfile -Force
                Write-Host "    [+] Updated PowerShell `$PROFILE hook to use native $rootExe" -ForegroundColor Green
            }
        }
    }
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "     BUILD COMPLETE: CLAUDECAGE $targetVersion READY      " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "Binary:  $rootExe" -ForegroundColor White
Write-Host "SHA-256: $sha256" -ForegroundColor Cyan
Write-Host "`nQuick Commands:" -ForegroundColor Yellow
Write-Host "  Launch GUI:  & `"$rootExe`"" -ForegroundColor Gray
Write-Host "  Launch CLI:  & `"$rootExe`" cli --version" -ForegroundColor Gray
Write-Host "  Version:     & `"$rootExe`" version" -ForegroundColor Gray
Write-Host "==========================================================`n" -ForegroundColor Green
