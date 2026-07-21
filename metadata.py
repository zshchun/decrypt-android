#!/usr/bin/env python3

# @file metadata.py
# @brief Android metadata encryption decryptor for emulator images
# @version 0.1

import argparse
import os
import re
import shutil
import subprocess
import sys
from collections import namedtuple
from pathlib import Path
from struct import unpack

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tqdm import tqdm


GCM_NONCE_BYTES = 12
DATA_UNIT_SIZE_BYTES = 4096
IV_UNIT_MODE = "data-unit"
INITIAL_DUN = 0

Ext4Inspection = namedtuple(
    "Ext4Inspection", ["block_size", "inode_size", "group_count"]
)


class MetadataDecryptError(Exception):
    pass


def require_tqdm():
    return tqdm


def find_debugfs():
    executable = shutil.which("debugfs")
    if executable:
        return executable
    for candidate in ("/usr/sbin/debugfs", "/sbin/debugfs"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise MetadataDecryptError("debugfs not found; install e2fsprogs")


def run_debugfs(path, request):
    image = Path(path).resolve()
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    return subprocess.run(
        [find_debugfs(), "-R", request, os.fspath(image)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def parse_debugfs_integer(output, label):
    match = re.search(rf"^{re.escape(label)}:\s+(\d+)\s*$", output, re.MULTILINE)
    if not match:
        raise MetadataDecryptError(f"debugfs stats omitted {label!r}")
    return int(match.group(1))


def inspect_ext4_image(path):
    """Validate the decrypted ext4 layer through read-only debugfs requests."""
    stats_result = run_debugfs(path, "stats")
    stats = stats_result.stdout
    if not re.search(
            r"^Filesystem magic number:\s+0xEF53\s*$", stats, re.MULTILINE):
        raise MetadataDecryptError(
            f"invalid debugfs stats: {path} is not a decrypted ext4 image"
        )

    block_size = parse_debugfs_integer(stats, "Block size")
    inode_size = parse_debugfs_integer(stats, "Inode size")
    block_count = parse_debugfs_integer(stats, "Block count")
    first_block = parse_debugfs_integer(stats, "First block")
    blocks_per_group = parse_debugfs_integer(stats, "Blocks per group")
    data_blocks = block_count - first_block
    group_count = (data_blocks + blocks_per_group - 1) // blocks_per_group

    root_result = run_debugfs(path, "stat <2>")
    if not re.search(
            r"^Inode:\s+2\s+Type:\s+directory\b",
            root_result.stdout,
            re.MULTILINE):
        raise MetadataDecryptError(f"{path} has no ext4 root directory")

    inspection = Ext4Inspection(block_size, inode_size, group_count)

    print(
        "[+] debugfs ext4 preflight: "
        f"block_size={inspection.block_size}, "
        f"inode_size={inspection.inode_size}, "
        f"groups={inspection.group_count}, root_inode=2"
    )
    return inspection


def resolve_key_dir(path):
    key_dir = Path(path)
    if (key_dir / "encrypted_key").is_file():
        return key_dir
    if (key_dir / "key" / "encrypted_key").is_file():
        return key_dir / "key"
    raise MetadataDecryptError(
        f"{path} does not contain encrypted_key or key/encrypted_key"
    )


def unwrap_emulator_keymaster(encrypted_key, keymaster_blob):
    """Unwrap the metadata key from the Android emulator software blob."""
    if len(keymaster_blob) < 37:
        raise MetadataDecryptError("keymaster_key_blob is too small")

    _version, key_len, padded_key = unpack("<BI32s", keymaster_blob[:37])
    if key_len not in (16, 24, 32):
        raise MetadataDecryptError(f"invalid AES key length in blob: {key_len}")

    nonce = encrypted_key[:GCM_NONCE_BYTES]
    ciphertext_and_tag = encrypted_key[GCM_NONCE_BYTES:]
    try:
        return AESGCM(padded_key[:key_len]).decrypt(
            nonce, ciphertext_and_tag, b""
        )
    except InvalidTag as exc:
        raise MetadataDecryptError("failed to unwrap metadata key") from exc


def load_metadata_key(key_dir):
    """Load the metadata key used by the Android 14 AVD"""
    key_dir = resolve_key_dir(key_dir)
    version_file = key_dir / "version"
    if version_file.exists() and version_file.read_bytes().strip() != b"1":
        raise MetadataDecryptError("unsupported metadata key version")

    encrypted_key = (key_dir / "encrypted_key").read_bytes()
    keymaster_blob = (key_dir / "keymaster_key_blob").read_bytes()
    key = unwrap_emulator_keymaster(encrypted_key, keymaster_blob)

    if len(key) not in (32, 64):
        raise MetadataDecryptError(
            f"metadata key must be 32 or 64 bytes for AES-XTS, got {len(key)}"
        )
    return key


def xts_crypt_unit(key, data, dun, encrypt=False):
    tweak = dun.to_bytes(16, "little")
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    ctx = cipher.encryptor() if encrypt else cipher.decryptor()
    return ctx.update(data) + ctx.finalize()


def decrypt_image(input_file, output_file, key):
    total_size = os.path.getsize(input_file)
    full_units = total_size // DATA_UNIT_SIZE_BYTES
    tail_size = total_size % DATA_UNIT_SIZE_BYTES

    output_path = Path(output_file)
    if Path(input_file).resolve() == output_path.resolve():
        raise MetadataDecryptError("input and output image must be different files")
    if output_path.exists():
        raise MetadataDecryptError(f"{output_file} already exists")

    print(f"[+] Input: {input_file}")
    print(f"[+] Output: {output_file}")
    print(f"[+] Data unit size: {DATA_UNIT_SIZE_BYTES}")
    print(f"[+] IV unit mode: {IV_UNIT_MODE}")
    print(f"[+] DUN offset: {INITIAL_DUN}")
    print(f"[+] Decrypting {full_units} full data units ({total_size} bytes)")

    progress_bar = require_tqdm()
    with open(input_file, "rb") as src, open(output_file, "wb") as dst:
        with progress_bar(
                total=total_size,
                desc="Metadata decrypt",
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
        ) as progress:
            for unit_index in range(full_units):
                unit = src.read(DATA_UNIT_SIZE_BYTES)
                dun = INITIAL_DUN + unit_index
                dst.write(xts_crypt_unit(key, unit, dun, encrypt=False))
                progress.update(len(unit))

            if tail_size:
                tail = src.read(tail_size)
                dst.write(tail)
                progress.update(len(tail))

    if tail_size:
        print(f"[!] Copied trailing {tail_size} bytes unchanged")

    print("[+] Metadata decryption complete")


def decrypt_metadata_image(input_file, output_file, key_dir):
    """Run the fixed educational metadata-decryption pipeline."""
    input_path = os.fspath(input_file)
    output_path = os.fspath(output_file)
    key = load_metadata_key(key_dir)
    print(f"[+] Loaded metadata key ({len(key)} bytes)")
    decrypt_image(input_path, output_path, key)
    inspect_ext4_image(output_path)
    return output_path


def build_parser():
    parser = argparse.ArgumentParser(
        description="Decrypt Android metadata-encrypted userdata images",
        usage=(
            "%(prog)s -i userdata-encrypted.raw -o userdata.enc "
            "-k metadata_encryption"
        ),
    )
    parser.add_argument(
        "-i", "--input-file", required=True,
        help="raw metadata-encrypted userdata image",
    )
    parser.add_argument(
        "-o", "--output-file", required=True,
        help="decrypted output image",
    )
    parser.add_argument(
        "-k",
        "--key-dir",
        required=True,
        help="metadata key directory or its parent, e.g. metadata_encryption/key",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        decrypt_metadata_image(
            args.input_file,
            args.output_file,
            args.key_dir,
        )
        return 0
    except MetadataDecryptError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
