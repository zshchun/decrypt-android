# Overview
This repository focuses on learning Android Encryption through practical examples.
- Full Disk Encryption (FDE)
- File-Based Encryption (FBE)

# Prerequisite
- Debian/Ubuntu
```sh
sudo apt install e2fsprogs fdisk file tree sqlite3 openssl xxd python3 python3-cryptography python3-tqdm setools
```

# Installation

## Linux / WSL

It has been tested on WSL running the Ubuntu 24.04 distribution.

The instructions below will automatically download the Android emulator and create avd images.
- Android 6.0 for FDE
- Android 14.0 for FBE

```
./setup_android_emulator.sh
```

## Windows

Run the command wrapper from PowerShell. It applies `ExecutionPolicy Bypass`
only to the installer process; it does not change the system or user policy.

```powershell
.\setup_android_emulator.cmd
```

Accept the UAC prompt that enables Windows Hypervisor Platform (WHPX). If the
installer requests a restart, restart Windows and run the command again. If the
final WHPX check fails, confirm that Task Manager's CPU page shows
`Virtualization: Enabled` and that `Windows Hypervisor Platform` is enabled in
Windows Features, then restart Windows.

# FDE
```
$ emulator @android6

$ qemu-img convert -O raw ~/.android/avd/android6.avd/userdata-qemu.img.qcow2 userdata.enc
$ qemu-img convert -O raw ~/.android/avd/android6.avd/encryptionkey.img.qcow2 footer.img

$ ./fde-decrypt.py -i userdata.enc -f footer.img -o userdata.dec
```

# FBE
```
emulator @android14

qemu-img convert -f qcow2 -O raw ~/.android/avd/android14.avd/userdata-qemu.img.qcow2 userdata.raw

adb root
adb pull /metadata/vold/metadata_encryption metadata_encryption

./metadata.py -i userdata.raw -o userdata.enc -k metadata_encryption

debugfs -R stats userdata.enc
debugfs -R 'ls -p /' userdata.enc

./fbe-decrypt.py -i userdata.enc -o dec
```

## Cleanup paths

After completing the lab, close all Android Emulator instances and remove the
following default paths if the Android lab environment is no longer needed.

### Linux

```text
$HOME/.android
$HOME/android
```

### macOS

```text
$HOME/.android
$HOME/Library/Android/sdk
$HOME/.android-lab
```

### Windows

```text
%USERPROFILE%\.android
%LOCALAPPDATA%\Android
%LOCALAPPDATA%\AndroidLab
```
