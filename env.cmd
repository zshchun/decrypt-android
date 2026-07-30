@echo off

if not defined LOCALAPPDATA (
    echo LOCALAPPDATA is not set. 1>&2
    exit /b 1
)

if not defined ANDROID_LAB_ROOT set "ANDROID_LAB_ROOT=%LOCALAPPDATA%\AndroidLab"
if not defined ANDROID_LAB_VENV set "ANDROID_LAB_VENV=%ANDROID_LAB_ROOT%\.venv"
if not defined ANDROID_HOME set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
if not defined ANDROID_SDK_ROOT set "ANDROID_SDK_ROOT=%ANDROID_HOME%"
if not defined ANDROID_NDK_ROOT set "ANDROID_NDK_ROOT=%ANDROID_SDK_ROOT%\ndk\21.0.6113669"

set "ANDROID_LAB_BIN=%~dp0"
if "%ANDROID_LAB_BIN:~-1%"=="\" set "ANDROID_LAB_BIN=%ANDROID_LAB_BIN:~0,-1%"

set "ANDROID_LAB_PATH=%ANDROID_LAB_BIN%;%ANDROID_LAB_VENV%\Scripts;%ANDROID_SDK_ROOT%\platform-tools;%ANDROID_SDK_ROOT%\emulator;%ANDROID_SDK_ROOT%\cmdline-tools\latest\bin;%ANDROID_NDK_ROOT%\prebuilt\windows-x86_64\bin;%ANDROID_NDK_ROOT%\toolchains\llvm\prebuilt\windows-x86_64\bin"
if defined JAVA_HOME set "ANDROID_LAB_PATH=%ANDROID_LAB_PATH%;%JAVA_HOME%\bin"
if defined PATH set "PATH=%ANDROID_LAB_PATH%;%PATH%"
if not defined PATH set "PATH=%ANDROID_LAB_PATH%"

if /I "%~1"=="/persist" goto Persist

exit /b 0

:Persist
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $names=@('ANDROID_LAB_ROOT','ANDROID_LAB_VENV','ANDROID_HOME','ANDROID_SDK_ROOT','ANDROID_NDK_ROOT'); foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name,[Environment]::GetEnvironmentVariable($name,'Process'),'User') }; $entries=@($env:ANDROID_LAB_BIN, (Join-Path $env:ANDROID_LAB_VENV 'Scripts'), (Join-Path $env:ANDROID_SDK_ROOT 'platform-tools'), (Join-Path $env:ANDROID_SDK_ROOT 'emulator'), (Join-Path $env:ANDROID_SDK_ROOT 'cmdline-tools\latest\bin'), (Join-Path $env:ANDROID_NDK_ROOT 'prebuilt\windows-x86_64\bin'), (Join-Path $env:ANDROID_NDK_ROOT 'toolchains\llvm\prebuilt\windows-x86_64\bin')); if ($env:JAVA_HOME) { $entries += (Join-Path $env:JAVA_HOME 'bin') }; $userPath=[Environment]::GetEnvironmentVariable('Path','User'); $parts=@($userPath -split ';' | Where-Object { $_ -and ($entries -notcontains $_) }); $newPath=($entries + $parts) -join ';'; [Environment]::SetEnvironmentVariable('Path',$newPath,'User')"
if errorlevel 1 exit /b %ERRORLEVEL%
echo User environment updated. Open a new terminal to use the persisted PATH.
exit /b 0
