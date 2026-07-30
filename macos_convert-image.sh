#!/usr/bin/env bash
set -euo pipefail

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  echo "Usage: $0 [android6|android14]" >&2
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  die "this script is for macOS"
fi

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

avd="$1"
case "$avd" in
  android6)
    userdata_out="userdata.enc"
    key_out="footer.img"
    ;;
  android14)
    userdata_out="userdata.raw"
    key_out="encryptionkey.raw"
    ;;
  *)
    usage
    exit 2
    ;;
esac

brew_bin="$(command -v brew || true)"
if [[ -z "$brew_bin" && -x /opt/homebrew/bin/brew ]]; then
  brew_bin=/opt/homebrew/bin/brew
elif [[ -z "$brew_bin" && -x /usr/local/bin/brew ]]; then
  brew_bin=/usr/local/bin/brew
fi
[[ -n "$brew_bin" ]] || die "Homebrew was not found"

if ! qemu_prefix="$("$brew_bin" --prefix qemu 2>/dev/null)"; then
  die "QEMU was not found; install it with: brew install qemu"
fi
qemu_bin="$qemu_prefix/bin"
qemu_img="$qemu_bin/qemu-img"
[[ -x "$qemu_img" ]] || die "qemu-img was not found under: $qemu_bin"

if pgrep -f '(^|/)(emulator|qemu-system-)' >/dev/null 2>&1; then
  die "close all running Android Emulator instances before converting images"
fi

avd_dir="$HOME/.android/avd/$avd.avd"
userdata_in="$avd_dir/userdata-qemu.img.qcow2"
key_in="$avd_dir/encryptionkey.img.qcow2"

[[ -f "$userdata_in" ]] || die "missing image: $userdata_in"
[[ -f "$key_in" ]] || die "missing image: $key_in"
[[ ! -e "$userdata_out" ]] || die "output already exists: $userdata_out"
[[ ! -e "$key_out" ]] || die "output already exists: $key_out"

echo "[+] Convert $userdata_in -> $userdata_out"
printf '[+] Run: %q convert -f qcow2 -O raw %q %q\n' \
  "$qemu_img" "$userdata_in" "$userdata_out"
"$qemu_img" convert -f qcow2 -O raw "$userdata_in" "$userdata_out"

echo "[+] Convert $key_in -> $key_out"
printf '[+] Run: %q convert -f qcow2 -O raw %q %q\n' \
  "$qemu_img" "$key_in" "$key_out"
"$qemu_img" convert -f qcow2 -O raw "$key_in" "$key_out"

echo "[+] Done"
