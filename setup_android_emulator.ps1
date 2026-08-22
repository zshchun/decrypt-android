<#
Run from Windows PowerShell. The script requests Administrator privileges
through UAC only to configure Windows Hypervisor Platform.

The emulator and AVDs run on Windows through WHPX. This script installs the
Windows Android SDK, NDK, OpenJDK, Python virtual environment, and lab AVDs.
If the script requests a reboot, restart Windows and run it again.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$EnableWhpxOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdministrator = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if ($EnableWhpxOnly -or $isAdministrator) {
    if (-not $isAdministrator) {
        throw "Administrator privileges are required to configure WHPX."
    }

    Write-Host "[+] Enable Windows Hypervisor Platform"
    $restartRequired = $false
    $feature = Get-WindowsOptionalFeature `
        -Online -FeatureName "HypervisorPlatform"
    if ($feature.State -ne "Enabled") {
        $result = Enable-WindowsOptionalFeature `
            -Online -FeatureName "HypervisorPlatform" -All -NoRestart
        $restartRequired = $restartRequired -or $result.RestartNeeded
    }
    if ($restartRequired) {
        Write-Warning "Restart Windows, then run this script again."
        exit 3010
    }
    if ($EnableWhpxOnly) {
        exit 0
    }
}
else {
    Write-Host "[+] Request Administrator privileges for WHPX"
    $elevationArguments = @(
        "-NoProfile"
        "-ExecutionPolicy"
        "Bypass"
        "-File"
        "`"$PSCommandPath`""
        "-EnableWhpxOnly"
    )

    try {
        $elevatedProcess = Start-Process `
            -FilePath "powershell.exe" `
            -Verb RunAs `
            -ArgumentList $elevationArguments `
            -WorkingDirectory (Split-Path $PSCommandPath -Parent) `
            -Wait `
            -PassThru `
            -ErrorAction Stop
    }
    catch {
        throw "Administrator privilege request was cancelled or failed."
    }

    if ($elevatedProcess.ExitCode -eq 3010) {
        Write-Warning "Restart Windows, then run this script again."
        exit 3010
    }
    if ($elevatedProcess.ExitCode -ne 0) {
        throw "Windows Hypervisor Platform configuration failed."
    }
}

$scriptRoot = Split-Path $PSCommandPath -Parent
$sdkRoot = Join-Path $env:LOCALAPPDATA "Android\Sdk"
$ndkVersion = "29.0.14206865"
$pythonVersion = "3.14"
$labRoot = Join-Path $env:LOCALAPPDATA "AndroidLab"
$venvRoot = Join-Path $labRoot ".venv"
$jdkRoot = Join-Path $labRoot "jdk"
$jdkUrl = "https://aka.ms/download-jdk/microsoft-jdk-21-windows-x64.zip"
$jdkHashUrl = "${jdkUrl}.sha256sum.txt"
$toolsVersion = "15859902"
$toolsHash = "90ae805d20434428bffcb699c290860f19bb5f66a67e6b330067e3de801fb04a"
$toolsUrl = "https://dl.google.com/android/repository/commandlinetools-win-${toolsVersion}_latest.zip"

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

function Get-PythonManagerPath {
    $command = Get-Command pymanager.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $windowsApps = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps"
    $aliasPath = Join-Path $windowsApps "pymanager.exe"
    if (Test-Path -LiteralPath $aliasPath) {
        return $aliasPath
    }

    $packageManager = Get-ChildItem `
        -Path (Join-Path $windowsApps "PythonSoftwareFoundation.PythonManager_*\pymanager.exe") `
        -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    return $packageManager
}

function Set-AvdConfig {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$DataSize
    )

    $lines = @(Get-Content -LiteralPath $Path)
    $keyboardFound = $false
    $dataSizeFound = $false

    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -match "^hw\.keyboard=") {
            $lines[$index] = "hw.keyboard=yes"
            $keyboardFound = $true
        }
        elseif ($lines[$index] -match "^disk\.dataPartition\.size=") {
            $lines[$index] = "disk.dataPartition.size=$DataSize"
            $dataSizeFound = $true
        }
    }

    if (-not $keyboardFound) { $lines += "hw.keyboard=yes" }
    if (-not $dataSizeFound) { $lines += "disk.dataPartition.size=$DataSize" }
    Set-Content -LiteralPath $Path -Value $lines -Encoding ASCII
}

Write-Host "[+] Check x64 virtualization support"
if ([Environment]::OSVersion.Version.Build -lt 19041) {
    throw "This Windows setup requires Windows 10 build 19041 or newer."
}
$processor = Get-CimInstance Win32_Processor | Select-Object -First 1
if ($processor.Architecture -ne 9) {
    throw "The x86_64 Android images require an x64 Windows host."
}
$computerSystem = Get-CimInstance Win32_ComputerSystem
if ($computerSystem.HypervisorPresent) {
    Write-Host "[+] Windows hypervisor is running"
}
elseif ($processor.VirtualizationFirmwareEnabled -eq $false) {
    Write-Warning (
        "Win32_Processor reported VirtualizationFirmwareEnabled=False. " +
        "That flag alone is not conclusive, so the Android Emulator will " +
        "verify WHPX after installation."
    )
}
else {
    Write-Warning (
        "The Windows hypervisor is not running. Restart Windows if WHPX was " +
        "just enabled; the Android Emulator will verify WHPX after installation."
    )
}

Write-Host "[+] Install Microsoft OpenJDK 21 for the current user"
$jdk = Get-ChildItem -LiteralPath $jdkRoot `
    -Directory -Filter "jdk-21*" -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending |
    Select-Object -First 1
if (-not $jdk) {
    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) (
        "microsoft-jdk-" + [Guid]::NewGuid().ToString("N")
    )
    try {
        $archive = Join-Path $tempRoot "jdk.zip"
        $hashFile = Join-Path $tempRoot "jdk.zip.sha256sum.txt"
        $expanded = Join-Path $tempRoot "expanded"
        New-Item -ItemType Directory -Path $tempRoot | Out-Null
        Invoke-WebRequest -UseBasicParsing -Uri $jdkUrl -OutFile $archive
        Invoke-WebRequest -UseBasicParsing -Uri $jdkHashUrl -OutFile $hashFile
        $expectedHash = [regex]::Match(
            (Get-Content -LiteralPath $hashFile -Raw),
            "\b[0-9a-fA-F]{64}\b"
        )
        if (
            (-not $expectedHash.Success) -or
            ((Get-FileHash -Algorithm SHA256 $archive).Hash -ine
                $expectedHash.Value)
        ) {
            throw "Microsoft OpenJDK checksum mismatch."
        }
        Expand-Archive -LiteralPath $archive -DestinationPath $expanded
        $jdk = Get-ChildItem -LiteralPath $expanded `
            -Directory -Filter "jdk-21*" |
            Select-Object -First 1
        if (-not $jdk) {
            throw "Microsoft OpenJDK archive has an unexpected layout."
        }
        New-Item -ItemType Directory -Path $jdkRoot -Force | Out-Null
        Move-Item -LiteralPath $jdk.FullName -Destination $jdkRoot
        $jdk = Get-Item -LiteralPath (Join-Path $jdkRoot $jdk.Name)
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
        }
    }
}
$env:JAVA_HOME = $jdk.FullName
[Environment]::SetEnvironmentVariable("JAVA_HOME", $env:JAVA_HOME, "User")

Write-Host "[+] Install Python 3.14 and Android lab packages"
$pythonManager = Get-PythonManagerPath
if (-not $pythonManager) {
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) {
        throw "Install Microsoft App Installer (winget), then run this script again."
    }
    Invoke-Native $winget.Source @(
        "install", "--exact", "--id", "9NQ7512CXL7T", "--source", "msstore",
        "--accept-package-agreements", "--accept-source-agreements",
        "--disable-interactivity"
    )
    $pythonManager = Get-PythonManagerPath
    if (-not $pythonManager) {
        throw "Python Install Manager was installed but pymanager.exe was not found."
    }
}

Invoke-Native $pythonManager @("install", $pythonVersion)
$python = [string](
    & $pythonManager list --one --format=exe $pythonVersion
)
if ($LASTEXITCODE -ne 0 -or -not $python.Trim()) {
    throw "Could not locate the installed Python $pythonVersion runtime."
}
$python = $python.Trim()

$venvPython = Join-Path $venvRoot "Scripts\python.exe"
if (-not (Test-Path -LiteralPath $venvPython)) {
    Invoke-Native $python @("-m", "venv", $venvRoot)
}
Invoke-Native $venvPython @(
    "-m", "pip", "install", "--no-cache-dir", "--upgrade", "pip"
)
Invoke-Native $venvPython @(
    "-m", "pip", "install", "--no-cache-dir",
    "pycryptodomex", "cryptography", "tqdm", "frida", "frida-tools"
)
Invoke-Native (Join-Path $venvRoot "Scripts\frida-pm.exe") @(
    "install", "frida-java-bridge", "--project-root", (Join-Path $scriptRoot "frida"), "--quiet"
)

Write-Host "[+] Install Android command-line tools"
$commandLineTools = Join-Path $sdkRoot "cmdline-tools\latest"
$sdkManager = Join-Path $commandLineTools "bin\sdkmanager.bat"
if (-not (Test-Path -LiteralPath $sdkManager)) {
    if (Test-Path -LiteralPath $commandLineTools) {
        throw "Incomplete Android command-line tools directory: $commandLineTools"
    }

    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) (
        "android-tools-" + [Guid]::NewGuid().ToString("N")
    )
    try {
        $archive = Join-Path $tempRoot "tools.zip"
        $expanded = Join-Path $tempRoot "expanded"
        New-Item -ItemType Directory -Path $tempRoot | Out-Null
        Invoke-WebRequest -UseBasicParsing -Uri $toolsUrl -OutFile $archive
        if ((Get-FileHash -Algorithm SHA256 $archive).Hash -ine $toolsHash) {
            throw "Android command-line tools checksum mismatch."
        }
        Expand-Archive -LiteralPath $archive -DestinationPath $expanded
        New-Item -ItemType Directory `
            -Path (Split-Path $commandLineTools -Parent) -Force | Out-Null
        Move-Item (Join-Path $expanded "cmdline-tools") $commandLineTools
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
        }
    }
}

$ndkRoot = Join-Path $sdkRoot "ndk\$ndkVersion"
$env:ANDROID_HOME = $sdkRoot
$env:ANDROID_SDK_ROOT = $sdkRoot
$env:ANDROID_LAB_ROOT = $labRoot
$env:ANDROID_NDK_ROOT = $ndkRoot
$env:ANDROID_LAB_VENV = $venvRoot

$sessionPaths = @(
    $scriptRoot,
    (Join-Path $venvRoot "Scripts"),
    (Join-Path $sdkRoot "platform-tools"),
    (Join-Path $sdkRoot "emulator"),
    (Join-Path $commandLineTools "bin"),
    (Join-Path $ndkRoot "toolchains\llvm\prebuilt\windows-x86_64\bin"),
    (Join-Path $env:JAVA_HOME "bin")
)
$legacyNdkRoot = Join-Path $sdkRoot "ndk\21.0.6113669"
$removedSessionPaths = @(
    (Join-Path $legacyNdkRoot "prebuilt\windows-x86_64\bin"),
    (Join-Path $legacyNdkRoot "toolchains\llvm\prebuilt\windows-x86_64\bin")
)
$envPathEntries = @(
    $env:Path -split ";" |
        Where-Object {
            $_ -and
            ($sessionPaths -notcontains $_) -and
            ($removedSessionPaths -notcontains $_)
        }
)
$env:Path = ($sessionPaths + $envPathEntries) -join ";"
Invoke-Native (Join-Path $scriptRoot "env.cmd") @("/persist")

Write-Host "[+] Install emulator, ADB, NDK, and Android images"
@(1..100 | ForEach-Object { "y" }) |
    & $sdkManager "--sdk_root=$sdkRoot" "--licenses"
if ($LASTEXITCODE -ne 0) { throw "Android license acceptance failed." }

$sdkPackages = @(
    "platform-tools",
    "emulator",
    "system-images;android-23;google_apis;x86_64",
    "system-images;android-34;google_apis;x86_64",
    "ndk;$ndkVersion"
)
Invoke-Native $sdkManager (@("--sdk_root=$sdkRoot") + $sdkPackages)

Write-Host "[+] Recreate Android 6 and Android 14 AVDs"
$emulator = Join-Path $sdkRoot "emulator\emulator.exe"
$avdManager = Join-Path $commandLineTools "bin\avdmanager.bat"
$avdHome = if ($env:ANDROID_AVD_HOME) {
    $env:ANDROID_AVD_HOME
}
else {
    Join-Path $env:USERPROFILE ".android\avd"
}
$avds = @(
    @("android6", "system-images;android-23;google_apis;x86_64", "2G"),
    @("android14", "system-images;android-34;google_apis;x86_64", "4G")
)
foreach ($avd in $avds) {
    "no" | & $avdManager create avd --force `
        --name $avd[0] --package $avd[1]
    if ($LASTEXITCODE -ne 0) { throw "Failed to recreate AVD: $($avd[0])" }
    Set-AvdConfig `
        (Join-Path $avdHome "$($avd[0]).avd\config.ini") `
        $avd[2]
}

Write-Host "[+] Validate WHPX, ADB, and AVDs"
& $emulator "-accel-check"
if ($LASTEXITCODE -ne 0) {
    throw (
        "WHPX is installed but not usable. Confirm that Virtualization is " +
        "Enabled in Task Manager, then restart Windows and run this script again."
    )
}
Invoke-Native "adb.exe" @("version")
Invoke-Native "emulator.exe" @("-list-avds")
Invoke-Native "sdkmanager.bat" @("--version")
Invoke-Native "avdmanager.bat" @("list", "avd")
Invoke-Native "python.exe" @("--version")
Invoke-Native "python.exe" @(
    "-c", "from Cryptodome.Cipher import AES; import cryptography, tqdm, frida"
)
Invoke-Native "pip.exe" @("--version")
Invoke-Native "frida.exe" @("--version")
if (-not (Get-Command "frida-ps.exe" -ErrorAction SilentlyContinue)) {
    throw "frida-ps.exe was not found in PATH."
}
if (-not (Get-Command "frida-trace.exe" -ErrorAction SilentlyContinue)) {
    throw "frida-trace.exe was not found in PATH."
}
if (-not (Get-Command "frida-pm.exe" -ErrorAction SilentlyContinue)) {
    throw "frida-pm.exe was not found in PATH."
}
Invoke-Native "clang.exe" @("--version")

Write-Host ""
Write-Host "[+] Installation complete"
Write-Host "Open a new PowerShell window to use the persisted Android lab PATH."
Write-Host "PowerShell emulator commands:"
Write-Host "  emulator @android6"
Write-Host "  emulator @android14"
Write-Host ""
Write-Host "Android lab commands:"
Write-Host "  emulator -list-avds"
Write-Host "  adb version"
Write-Host "  sdkmanager --version"
Write-Host "  avdmanager list avd"
Write-Host "  python --version"
Write-Host "  pip --version"
Write-Host "  frida --version"
Write-Host "  frida-ps --help"
Write-Host "  frida-trace --help"
Write-Host "  frida-pm --help"
Write-Host "  clang --version"
Write-Host ""
Write-Host "Standalone environment setup:"
Write-Host "  env.cmd /persist  # save User PATH and lab variables"
Write-Host "  call env.cmd      # current CMD session only"
