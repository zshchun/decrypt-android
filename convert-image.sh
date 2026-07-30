#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 [android6|android14]" >&2
}

die() {
  echo "error: $*" >&2
  exit 1
}

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

command -v qemu-img >/dev/null 2>&1 || die "qemu-img was not found in PATH"

if pgrep -f '(^|/)(emulator|qemu-system-)' >/dev/null 2>&1; then
  die "close all running Android Emulator instances before converting images"
fi

avd_dir=""
for candidate in \
  "$PWD/$avd" \
  "${ANDROID_AVD_HOME:-}/$avd.avd" \
  "$HOME/.android/avd/$avd.avd"
do
  if [[ -n "$candidate" && -f "$candidate/userdata-qemu.img.qcow2" ]]; then
    avd_dir="$candidate"
    break
  fi
done

[[ -n "$avd_dir" ]] || die "AVD directory was not found for $avd"

userdata_in="$avd_dir/userdata-qemu.img.qcow2"
key_in="$avd_dir/encryptionkey.img.qcow2"

[[ -f "$userdata_in" ]] || die "missing image: $userdata_in"
[[ -f "$key_in" ]] || die "missing image: $key_in"

echo "[+] Convert $userdata_in -> $userdata_out"
printf '[+] Run: qemu-img convert -f qcow2 -O raw %q %q\n' \
  "$userdata_in" "$userdata_out"
qemu-img convert -f qcow2 -O raw "$userdata_in" "$userdata_out"

echo "[+] Convert $key_in -> $key_out"
printf '[+] Run: qemu-img convert -f qcow2 -O raw %q %q\n' \
  "$key_in" "$key_out"
qemu-img convert -f qcow2 -O raw "$key_in" "$key_out"

echo "[+] Done"
