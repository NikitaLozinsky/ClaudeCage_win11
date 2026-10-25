<#
.SYNOPSIS
    Install-ClaudeShortcut.ps1 - Seamless Protected Desktop & Start Menu Shortcut Generator for Claude.
.DESCRIPTION
    Creates or updates the official 'Claude.lnk' shortcut on the Desktop and Start Menu:
    - Points to Start-ClaudeDesktop.ps1 with -WindowStyle Hidden.
    - Uses ultra-crisp 256px official Claude.ico extracted from app assets.
    - Removes redundant '(Secure Cage)' shortcuts to eliminate confusion.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$TargetRoot = "C:\ClaudeCage"
$Launcher   = Join-Path $TargetRoot "Start-ClaudeDesktop.ps1"
$IcoPath    = Join-Path $TargetRoot "claude.ico"

# 1. Ensure 256px Claude.ico exists
if (-not (Test-Path $IcoPath)) {
    Write-Host "[*] Extracting high-resolution Claude icon..." -ForegroundColor Yellow
    $pngCandidates = Get-ChildItem -Path "C:\Program Files\WindowsApps" -Filter "*Square44x44Logo.targetsize-256*.png" -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like "*Claude*" } | Select-Object -First 1

    if ($pngCandidates) {
        $pngBytes = [System.IO.File]::ReadAllBytes($pngCandidates.FullName)
        $ms = New-Object System.IO.MemoryStream
        $bw = New-Object System.IO.BinaryWriter($ms)

        # ICONDIR
        $bw.Write([uint16]0) # Reserved
        $bw.Write([uint16]1) # Type (1=Icon)
        $bw.Write([uint16]1) # Count

        # ICONDIRENTRY
        $bw.Write([byte]0)   # Width (0 = 256px)
        $bw.Write([byte]0)   # Height (0 = 256px)
        $bw.Write([byte]0)   # Color count
        $bw.Write([byte]0)   # Reserved
        $bw.Write([uint16]1) # Planes
        $bw.Write([uint16]32)# BitCount
        $bw.Write([uint32]$pngBytes.Length) # BytesInRes
        $bw.Write([uint32]22)# ImageOffset (6 + 16 = 22)

        # Image Data (PNG)
        $bw.Write($pngBytes)
        [System.IO.File]::WriteAllBytes($IcoPath, $ms.ToArray())
        $bw.Close()
        $ms.Close()
        Write-Host "    [OK] High-resolution claude.ico created." -ForegroundColor Green
    }
}

$wsh = New-Object -ComObject WScript.Shell

# 2. Update Desktop Shortcut
$desktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)

# Remove old (Secure Cage) shortcut to avoid confusion
$oldCageLnk = Join-Path $desktopPath "Claude (Secure Cage).lnk"
if (Test-Path $oldCageLnk) {
    Remove-Item $oldCageLnk -Force -ErrorAction SilentlyContinue
    Write-Host "[*] Cleaned up legacy 'Claude (Secure Cage).lnk' from Desktop." -ForegroundColor Gray
}

# Create / Overwrite standard 'Claude.lnk' on Desktop
$desktopLnk = Join-Path $desktopPath "Claude.lnk"
if (Test-Path $desktopLnk) {
    Remove-Item $desktopLnk -Force -ErrorAction SilentlyContinue
}

$sc = $wsh.CreateShortcut($desktopLnk)
$sc.TargetPath = "powershell.exe"
$sc.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Launcher`""
$sc.WorkingDirectory = $TargetRoot
$sc.Description = "Claude"
if (Test-Path $IcoPath) {
    $sc.IconLocation = "$IcoPath,0"
}
$sc.Save()
Write-Host "[+] Desktop shortcut 'Claude' configured securely." -ForegroundColor Green

# 3. Create / Overwrite Start Menu Shortcut
$startMenuPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
if (Test-Path $startMenuPath) {
    $startLnk = Join-Path $startMenuPath "Claude.lnk"
    if (Test-Path $startLnk) {
        Remove-Item $startLnk -Force -ErrorAction SilentlyContinue
    }
    $scStart = $wsh.CreateShortcut($startLnk)
    $scStart.TargetPath = "powershell.exe"
    $scStart.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Launcher`""
    $scStart.WorkingDirectory = $TargetRoot
    $scStart.Description = "Claude"
    if (Test-Path $IcoPath) {
        $scStart.IconLocation = "$IcoPath,0"
    }
    $scStart.Save()
    Write-Host "[+] Start Menu shortcut 'Claude' configured securely." -ForegroundColor Green
}
