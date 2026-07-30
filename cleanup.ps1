<#
Remove the Android emulator package and Android images used by the lab.

This script intentionally keeps OpenJDK, Python, venv packages, Android
command-line tools, platform-tools, NDK, environment variables, and ADB keys.
Use clean_images.ps1 when only AVD/system/copied images should be removed.

Usage:
  powershell.exe -ExecutionPolicy Bypass -File .\cleanup.ps1
  powershell.exe -ExecutionPolicy Bypass -File .\cleanup.ps1 -Force
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if (-not $env:LOCALAPPDATA) {
    throw "LOCALAPPDATA is not set."
}

$scriptRoot = Split-Path $PSCommandPath -Parent
$sdkRoot = Join-Path $env:LOCALAPPDATA "Android\Sdk"
$sdkManager = Join-Path $sdkRoot "cmdline-tools\latest\bin\sdkmanager.bat"
$avdManager = Join-Path $sdkRoot "cmdline-tools\latest\bin\avdmanager.bat"
$avdHome = if ($env:ANDROID_AVD_HOME) {
    $env:ANDROID_AVD_HOME
}
else {
    Join-Path $env:USERPROFILE ".android\avd"
}

$avdNames = @(
    "android6",
    "android14"
)

$sdkPackages = @(
    "system-images;android-23;google_apis;x86_64",
    "system-images;android-34;google_apis;x86_64",
    "emulator"
)

$copiedImageNames = @(
    "userdata.enc",
    "userdata.dec",
    "userdata.raw",
    "footer.img",
    "encryptionkey.raw",
    "metadata.img",
    "dm-40"
)

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @()
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed ($LASTEXITCODE): $Command $($Arguments -join ' ')"
    }
}

$runningEmulators = @(
    Get-Process -Name "emulator", "qemu-system-x86_64" `
        -ErrorAction SilentlyContinue
)
if ($runningEmulators.Count -gt 0) {
    throw "Close all Android Emulator instances before running cleanup."
}

$copiedImages = @(
    foreach ($name in $copiedImageNames) {
        $path = Join-Path $scriptRoot $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $path
        }
    }
)

$avdsToRemove = @(
    $avdNames | Where-Object {
        (Test-Path -LiteralPath (Join-Path $avdHome "$_.avd")) -or
        (Test-Path -LiteralPath (Join-Path $avdHome "$_.ini"))
    }
)

$packagesToRemove = @()
if (Test-Path -LiteralPath $sdkManager) {
    $installedOutput = @(
        & $sdkManager "--sdk_root=$sdkRoot" "--list_installed" 2>&1
    )
    if ($LASTEXITCODE -ne 0) {
        throw "Could not list installed Android SDK packages."
    }

    $installedPackages = @(
        foreach ($line in $installedOutput) {
            if ([string]$line -match "^\s*([^|]+?)\s*\|") {
                $matches[1].Trim()
            }
        }
    )
    $packagesToRemove = @(
        $sdkPackages | Where-Object { $installedPackages -contains $_ }
    )
}
else {
    Write-Warning "sdkmanager.bat was not found; SDK packages will be skipped."
}

if (
    ($copiedImages.Count -eq 0) -and
    ($avdsToRemove.Count -eq 0) -and
    ($packagesToRemove.Count -eq 0)
) {
    Write-Host "[+] Nothing to remove."
    exit 0
}

Write-Host "The following Android lab emulator assets will be removed:"
foreach ($path in $copiedImages) {
    Write-Host "  Copied image: $path"
}
foreach ($avdName in $avdsToRemove) {
    Write-Host "  AVD image: $avdName"
}
foreach ($package in $packagesToRemove) {
    Write-Host "  SDK package: $package"
}
Write-Host ""
Write-Host "Kept: OpenJDK, Python, venv packages, command-line tools, platform-tools,"
Write-Host "      NDK, environment variables, and ADB keys."

if (-not $Force) {
    $answer = Read-Host "Type DELETE to continue"
    if ($answer -cne "DELETE") {
        Write-Host "[+] Cleanup cancelled."
        exit 0
    }
}

foreach ($path in $copiedImages) {
    Remove-Item -LiteralPath $path -Force
}

foreach ($avdName in $avdsToRemove) {
    if (Test-Path -LiteralPath $avdManager) {
        Invoke-Native $avdManager @("delete", "avd", "--name", $avdName)
    }
    else {
        Remove-Item -LiteralPath (Join-Path $avdHome "$avdName.avd") `
            -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path $avdHome "$avdName.ini") `
            -Force -ErrorAction SilentlyContinue
    }
}

if ($packagesToRemove.Count -gt 0) {
    Invoke-Native $sdkManager (
        @("--sdk_root=$sdkRoot", "--uninstall") + $packagesToRemove
    )
}

Write-Host "[+] Cleanup complete."
