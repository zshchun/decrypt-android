#!/bin/bash
set -e

echo "[+] Install linux packages"
sudo apt install -y git vim curl unzip qemu-utils python3-pycryptodome python3-cryptography python3-tqdm python3-pip sqlite3 e2fsprogs default-jdk ent pulseaudio apktool

echo "[+] Configure environment settings"
export ANDROID_SDK_ROOT=$HOME/android
export PATH=$PATH:$ANDROID_SDK_ROOT/emulator:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/sdk/cmdline-tools/bin

echo "[+] Add bashrc settings"
echo 'export ANDROID_SDK_ROOT=$HOME/android' >> ~/.bashrc
echo 'export PATH=$PATH:$ANDROID_SDK_ROOT/emulator:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/sdk/cmdline-tools/bin' >> ~/.bashrc

echo "[+] Add the user to the KVM group"
sudo gpasswd -a $USER kvm

mkdir -p ~/android/sdk
pushd ~/android/sdk

echo "[+] Download Android command-line tools"
curl https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip -o cmdlinetools-linux.zip
unzip cmdlinetools-linux.zip
rm cmdlinetools-linux.zip

echo "[+] Download android images"
sdkmanager --sdk_root=$ANDROID_SDK_ROOT "emulator" "platform-tools"

echo "[+] Download and creating Android 14.0 image"
sdkmanager --sdk_root=$ANDROID_SDK_ROOT "system-images;android-34;google_apis_playstore;x86_64"
avdmanager create avd -n android14 -k "system-images;android-34;google_apis_playstore;x86_64"
sed -i 's/^\(hw.keyboard\s*=\s*\).*/\1yes/' $HOME/.android/avd/android14.avd/config.ini

echo "[+] Installation complete"
java --version
echo "[+] Requires Java 17+."

popd
