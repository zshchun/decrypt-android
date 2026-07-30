#!/usr/bin/env bash
set -euo pipefail

TOOLS_VERSION=15859902
TOOLS_HASH="835b62a26162b229b441d1f6d4680383815a270809eb33522c0d480fa5002c4e"
ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}
ANDROID_HOME=$ANDROID_SDK_ROOT
ANDROID_LAB_VENV=${ANDROID_LAB_VENV:-$HOME/.android-lab/.venv}
AVD_HOME=${ANDROID_AVD_HOME:-$HOME/.android/avd}

die() {
  echo "error: $*" >&2
  exit 1
}

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

set_avd_config() {
  local path="$1" key="$2" value="$3"
  local tmp

  [[ -f "$path" ]] || die "AVD config not found: $path"

  tmp="$(mktemp)"
  awk -v prefix="$key=" -v value="$value" '
    index($0, prefix) == 1 { print prefix value; found = 1; next }
    { print }
    END { if (!found) print prefix value }
  ' "$path" > "$tmp"
  mv "$tmp" "$path"
}

write_shell_env() {
  local rc="$1"
  local tmp

  mkdir -p "$(dirname "$rc")"
  touch "$rc"
  tmp="$(mktemp)"

  awk '
    /^# >>> android lab >>>$/ { skip = 1; next }
    /^# <<< android lab <<<$/ { skip = 0; next }
    skip != 1 { print }
  ' "$rc" > "$tmp"

  cat "$tmp" > "$rc"
  cat >> "$rc" <<EOF
# >>> android lab >>>
export ANDROID_HOME="$ANDROID_HOME"
export ANDROID_SDK_ROOT="$ANDROID_SDK_ROOT"
export ANDROID_LAB_VENV="$ANDROID_LAB_VENV"
export JAVA_HOME="$JAVA_HOME"
export PATH="$ANDROID_LAB_VENV/bin:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$JAVA_HOME/bin:$BREW_PREFIX/bin:$BREW_PREFIX/sbin:$E2FSPROGS_PREFIX/bin:$E2FSPROGS_PREFIX/sbin:\$PATH"
# <<< android lab <<<
EOF

  rm -f "$tmp"
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  die "This script is for macOS. Use setup_android_emulator.sh on Linux."
fi

if [[ "$(uname -m)" != "arm64" ]]; then
  die "This script supports Apple silicon Macs only."
fi

if ! command -v brew >/dev/null 2>&1; then
  die "Homebrew is required. Install it from https://brew.sh, then run this script again."
fi

BREW_PREFIX="$(brew --prefix)"
export PATH="$BREW_PREFIX/bin:$BREW_PREFIX/sbin:$PATH"

echo "[+] Install macOS packages"
run brew install openjdk@17 python qemu sqlite e2fsprogs

JAVA_HOME="$(brew --prefix openjdk@17)/libexec/openjdk.jdk/Contents/Home"
E2FSPROGS_PREFIX="$(brew --prefix e2fsprogs)"
export JAVA_HOME
export ANDROID_HOME
export ANDROID_SDK_ROOT
export ANDROID_LAB_VENV
export PATH="$ANDROID_LAB_VENV/bin:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$JAVA_HOME/bin:$E2FSPROGS_PREFIX/bin:$E2FSPROGS_PREFIX/sbin:$PATH"

echo "[+] Install Android lab Python packages"
if [[ ! -x "$ANDROID_LAB_VENV/bin/python" ]]; then
  run python3 -m venv "$ANDROID_LAB_VENV"
fi
run "$ANDROID_LAB_VENV/bin/python" -m pip install --upgrade pip
run "$ANDROID_LAB_VENV/bin/python" -m pip install pycryptodomex cryptography tqdm

echo "[+] Install Android command-line tools"
COMMAND_LINE_TOOLS="$ANDROID_SDK_ROOT/cmdline-tools/latest"
SDKMANAGER="$COMMAND_LINE_TOOLS/bin/sdkmanager"
AVDMANAGER="$COMMAND_LINE_TOOLS/bin/avdmanager"
if [[ ! -x "$SDKMANAGER" ]]; then
  if [[ -e "$COMMAND_LINE_TOOLS" ]]; then
    die "Incomplete Android command-line tools directory: $COMMAND_LINE_TOOLS"
  fi

  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/android-tools.XXXXXX")"
  trap 'rm -rf "$TMP_DIR"' EXIT
  ARCHIVE="$TMP_DIR/commandlinetools.zip"
  TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-mac_arm64-${TOOLS_VERSION}_latest.zip"

  run curl -fL "$TOOLS_URL" -o "$ARCHIVE"
  ACTUAL_HASH="$(shasum -a 256 "$ARCHIVE" | awk '{ print $1 }')"
  if [[ "$ACTUAL_HASH" != "$TOOLS_HASH" ]]; then
    die "Android command-line tools checksum mismatch."
  fi

  mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools"
  run unzip -q "$ARCHIVE" -d "$TMP_DIR"
  run mv "$TMP_DIR/cmdline-tools" "$COMMAND_LINE_TOOLS"
  trap - EXIT
  rm -rf "$TMP_DIR"
fi

echo "[+] Add shell environment settings"
if [[ "${SHELL:-}" == */zsh ]]; then
  SHELL_RC="${ANDROID_LAB_SHELL_RC:-$HOME/.zshrc}"
else
  SHELL_RC="${ANDROID_LAB_SHELL_RC:-$HOME/.bash_profile}"
fi
write_shell_env "$SHELL_RC"

echo "[+] Accept Android SDK licenses"
"$SDKMANAGER" "--sdk_root=$ANDROID_SDK_ROOT" --licenses < <(yes) >/dev/null

echo "[+] Install emulator, ADB, and Android images"
ANDROID6_PACKAGE="system-images;android-23;google_apis;arm64-v8a"
ANDROID14_PACKAGE="system-images;android-34;google_apis;arm64-v8a"
run "$SDKMANAGER" "--sdk_root=$ANDROID_SDK_ROOT" \
  "platform-tools" \
  "emulator" \
  "$ANDROID6_PACKAGE" \
  "$ANDROID14_PACKAGE"

echo "[+] Create Android 6 and Android 14 AVDs"
mkdir -p "$AVD_HOME"
EXISTING_AVDS="$("$ANDROID_SDK_ROOT/emulator/emulator" -list-avds || true)"
if ! printf '%s\n' "$EXISTING_AVDS" | grep -qx "android6"; then
  printf 'no\n' | "$AVDMANAGER" create avd --name android6 --package "$ANDROID6_PACKAGE"
fi
if ! printf '%s\n' "$EXISTING_AVDS" | grep -qx "android14"; then
  printf 'no\n' | "$AVDMANAGER" create avd --name android14 --package "$ANDROID14_PACKAGE"
fi

set_avd_config "$AVD_HOME/android6.avd/config.ini" "hw.keyboard" "yes"
set_avd_config "$AVD_HOME/android6.avd/config.ini" "disk.dataPartition.size" "2G"
set_avd_config "$AVD_HOME/android14.avd/config.ini" "hw.keyboard" "yes"
set_avd_config "$AVD_HOME/android14.avd/config.ini" "disk.dataPartition.size" "4G"

echo "[+] Validate Android tools"
run java --version
run "$ANDROID_SDK_ROOT/platform-tools/adb" version
run "$ANDROID_SDK_ROOT/emulator/emulator" -list-avds
run "$SDKMANAGER" --version
if ! "$ANDROID_SDK_ROOT/emulator/emulator" -accel-check; then
  echo "warning: emulator acceleration check failed. Check macOS Hypervisor.framework support." >&2
fi
run "$ANDROID_LAB_VENV/bin/python" -c "from Cryptodome.Cipher import AES; import cryptography, tqdm"

echo ""
echo "[+] Installation complete"
echo "Shell environment was written to: $SHELL_RC"
echo "Reload it with:"
echo "  source \"$SHELL_RC\""
echo ""
echo "Emulator commands:"
echo "  emulator @android6"
echo "  emulator @android14"
