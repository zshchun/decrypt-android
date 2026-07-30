@echo off
setlocal

if "%~1"=="" goto Usage
if not "%~2"=="" goto Usage

set "AVD=%~1"
if /I "%AVD%"=="android6" (
    set "USERDATA_OUT=userdata.enc"
    set "KEY_OUT=footer.img"
) else if /I "%AVD%"=="android14" (
    set "USERDATA_OUT=userdata.raw"
    set "KEY_OUT=encryptionkey.raw"
) else (
    goto Usage
)

if not defined QEMU_IMG set "QEMU_IMG=qemu-img.exe"
where /Q "%QEMU_IMG%" 2>nul
if errorlevel 1 (
    if not exist "%QEMU_IMG%" (
        echo error: qemu-img was not found in PATH 1>&2
        exit /b 1
    )
)

tasklist /FI "IMAGENAME eq emulator.exe" /NH 2>nul | find /I "emulator.exe" >nul
if not errorlevel 1 (
    echo error: close all running Android Emulator instances before converting images 1>&2
    exit /b 1
)
tasklist /FI "IMAGENAME eq qemu-system-x86_64.exe" /NH 2>nul | find /I "qemu-system-x86_64.exe" >nul
if not errorlevel 1 (
    echo error: close all running Android Emulator instances before converting images 1>&2
    exit /b 1
)

set "AVD_DIR="
if exist "%CD%\%AVD%\userdata-qemu.img.qcow2" set "AVD_DIR=%CD%\%AVD%"
if not defined AVD_DIR if defined ANDROID_AVD_HOME if exist "%ANDROID_AVD_HOME%\%AVD%.avd\userdata-qemu.img.qcow2" set "AVD_DIR=%ANDROID_AVD_HOME%\%AVD%.avd"
if not defined AVD_DIR if exist "%USERPROFILE%\.android\avd\%AVD%.avd\userdata-qemu.img.qcow2" set "AVD_DIR=%USERPROFILE%\.android\avd\%AVD%.avd"

if not defined AVD_DIR (
    echo error: AVD directory was not found for %AVD% 1>&2
    exit /b 1
)

set "USERDATA_IN=%AVD_DIR%\userdata-qemu.img.qcow2"
set "KEY_IN=%AVD_DIR%\encryptionkey.img.qcow2"

if not exist "%USERDATA_IN%" (
    echo error: missing image: %USERDATA_IN% 1>&2
    exit /b 1
)
if not exist "%KEY_IN%" (
    echo error: missing image: %KEY_IN% 1>&2
    exit /b 1
)

set "SPLIT_DIR=%TEMP%\convert-image-%RANDOM%-%RANDOM%"
mkdir "%SPLIT_DIR%" 2>nul
if errorlevel 1 (
    echo error: failed to create temporary directory: %SPLIT_DIR% 1>&2
    exit /b 1
)

set "SPLIT_VMDK=%SPLIT_DIR%\userdata.vmdk"

echo [+] Convert %USERDATA_IN% -^> split VMDK extents
echo [+] Run: "%QEMU_IMG%" convert -f qcow2 -O vmdk -o subformat=twoGbMaxExtentFlat "%USERDATA_IN%" "%SPLIT_VMDK%"
"%QEMU_IMG%" convert -f qcow2 -O vmdk -o subformat=twoGbMaxExtentFlat "%USERDATA_IN%" "%SPLIT_VMDK%"
if errorlevel 1 (
    set "CONVERT_EXIT=%ERRORLEVEL%"
    goto ConvertFailed
)

echo [+] Merge split VMDK extents -^> %USERDATA_OUT%
copy /B /Y "%SPLIT_DIR%\userdata-f*.vmdk" "%USERDATA_OUT%"
if errorlevel 1 (
    set "CONVERT_EXIT=%ERRORLEVEL%"
    goto ConvertFailed
)

echo [+] Verify %USERDATA_OUT%
"%QEMU_IMG%" compare -f qcow2 -F raw "%USERDATA_IN%" "%USERDATA_OUT%"
if errorlevel 1 (
    set "CONVERT_EXIT=%ERRORLEVEL%"
    goto ConvertFailed
)

rmdir /S /Q "%SPLIT_DIR%"
set "SPLIT_DIR="

echo [+] Convert %KEY_IN% -^> %KEY_OUT%
echo [+] Run: "%QEMU_IMG%" convert -f qcow2 -O raw "%KEY_IN%" "%KEY_OUT%"
"%QEMU_IMG%" convert -f qcow2 -O raw "%KEY_IN%" "%KEY_OUT%"
if errorlevel 1 exit /b %ERRORLEVEL%

echo [+] Done
exit /b 0

:ConvertFailed
if defined SPLIT_DIR if exist "%SPLIT_DIR%" rmdir /S /Q "%SPLIT_DIR%"
exit /b %CONVERT_EXIT%

:Usage
echo Usage: %~nx0 [android6^|android14] 1>&2
exit /b 2
