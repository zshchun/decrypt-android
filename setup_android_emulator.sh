#!/bin/bash
set -eo pipefail

SCRIPT_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
NDK_VERSION=29.0.14206865
ANDROID_LAB_VENV=$HOME/.android-lab/.venv

echo "[+] Install linux packages"
sudo apt install -y git vim curl unzip qemu-utils python3-pycryptodome python3-venv python3-cryptography python3-tqdm python3-pip sqlite3 e2fsprogs default-jdk ent pulseaudio apktool netcat-openbsd tree fdisk cryptsetup openssl

echo "[+] Install Frida"
if [ ! -x "$ANDROID_LAB_VENV/bin/python" ]; then
    python3 -m venv "$ANDROID_LAB_VENV"
fi
"$ANDROID_LAB_VENV/bin/python" -m pip install --upgrade pip
"$ANDROID_LAB_VENV/bin/python" -m pip install frida frida-tools
"$ANDROID_LAB_VENV/bin/frida-pm" install --project-root "$SCRIPT_ROOT/frida" --quiet

echo "[+] Configure environment settings"
export ANDROID_HOME=$HOME/android
export ANDROID_NDK_ROOT=$ANDROID_HOME/ndk/$NDK_VERSION
export PATH=$ANDROID_LAB_VENV/bin:$PATH:$ANDROID_HOME/emulator:$ANDROID_HOME/platform-tools:$ANDROID_HOME/sdk/cmdline-tools/bin:$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin

echo "[+] Add bashrc settings"
echo 'export ANDROID_HOME=$HOME/android' >> ~/.bashrc
echo "export ANDROID_NDK_ROOT=\$ANDROID_HOME/ndk/$NDK_VERSION" >> ~/.bashrc
echo 'export ANDROID_LAB_VENV=$HOME/.android-lab/.venv' >> ~/.bashrc
echo 'export PATH=$ANDROID_LAB_VENV/bin:$PATH:$ANDROID_HOME/emulator:$ANDROID_HOME/platform-tools:$ANDROID_HOME/sdk/cmdline-tools/bin:$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin' >> ~/.bashrc

echo "[+] Add the user to the KVM group"
sudo gpasswd -a $USER kvm

mkdir -p ~/android/sdk
pushd ~/android/sdk

echo "[+] Download Android command-line tools"
curl https://dl.google.com/android/repository/commandlinetools-linux-14742923_latest.zip -o cmdlinetools-linux.zip
unzip cmdlinetools-linux.zip
rm cmdlinetools-linux.zip

echo "[+] Accept Android SDK licenses"
sdkmanager --sdk_root="$ANDROID_HOME" --licenses < <(yes)

echo "[+] Download Android tools and NDK"
sdkmanager --sdk_root="$ANDROID_HOME" "emulator" "platform-tools" "ndk;$NDK_VERSION"

echo "[+] Download and creating Android 6.0 image"
sdkmanager --sdk_root="$ANDROID_HOME" "system-images;android-23;google_apis;x86_64"
avdmanager create avd --force -n android6 -k "system-images;android-23;google_apis;x86_64"
sed -i 's/^\(hw.keyboard\s*=\s*\).*/\1yes/' $HOME/.android/avd/android6.avd/config.ini
sed -i 's/^disk\.dataPartition\.size=.*/disk.dataPartition.size=2G/' $HOME/.android/avd/android6.avd/config.ini

echo "[+] Download and creating Android 14.0 image"
sdkmanager --sdk_root="$ANDROID_HOME" "system-images;android-34;google_apis;x86_64"
avdmanager create avd --force -n android14 -k "system-images;android-34;google_apis;x86_64"
sed -i 's/^\(hw.keyboard\s*=\s*\).*/\1yes/' $HOME/.android/avd/android14.avd/config.ini
sed -i 's/^disk\.dataPartition\.size=.*/disk.dataPartition.size=4G/' $HOME/.android/avd/android14.avd/config.ini

echo "[+] Listing Android images"
emulator -list-avds

echo "[+] Installation complete"
java --version
"$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/clang" --version
"$ANDROID_LAB_VENV/bin/python" -c "import frida"
frida --version
command -v frida-ps >/dev/null
command -v frida-trace >/dev/null
command -v frida-pm >/dev/null
echo "[+] Requires Java 17+."

popd
