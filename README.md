# OVerview
This repository focuses on learning Android Encryption through practical examples.
- Full Disk Encryption (FDE)
- File-Based Encryption (FBE)

# Installation
It has been tested on WSL running the Ubuntu 24.04 distribution

The instructions below will automatically download the Android emulator and create avd images.
- Android 6.0 for FDE
- Android 14.0 for FBE

```
./setup_android_emulator.sh
```

# FDE
```
$ emulator @android6

$ qemu-img convert -O raw ~/.android/avd/android6.avd/userdata-qemu.img.qcow2 userdata.enc
$ qemu-img convert -O raw ~/.android/avd/android6.avd/encryptionkey.img.qcow2 footer.img

$ ./fbe-decrypt.py
```

# FBE
```
emulator @android14

qemu-img convert -f qcow2 -O raw ~/.android/avd/android14.avd/userdata-qemu.img.qcow2 userdata.enc

./fbe-decrypt.py
```
