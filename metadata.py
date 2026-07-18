#!/usr/bin/env python3

# @file metadata_decrypt.py
# @brief Android metadata encryption decryptor for emulator images
# @version 0.1

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
from collections import namedtuple
from pathlib import Path


GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
SHA512_BLOCK_BYTES = 128
DATA_UNIT_SIZE_BYTES = 4096
IV_UNIT_MODE = "data-unit"
INITIAL_DUN = 0
NO_KEYSTORE_SECRET = b""

Ext4Inspection = namedtuple(
    "Ext4Inspection", ["block_size", "inode_size", "group_count"]
)

HASH_PREFIX_SECDISCARDABLE = b"Android secdiscardable SHA512"
HASH_PREFIX_KEYGEN = b"Android key wrapping key generation SHA512"


class MetadataDecryptError(Exception):
    pass


def require_crypto():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
    except ModuleNotFoundError as exc:
        raise MetadataDecryptError(
            "missing Python dependency: cryptography "
            "(install python3-cryptography or pip install cryptography)"
        ) from exc
    return Cipher, algorithms, modes, AESGCM, InvalidTag


def require_tqdm():
    try:
        from tqdm import tqdm
    except ModuleNotFoundError as exc:
        raise MetadataDecryptError(
            "missing Python dependency: tqdm "
            "(install python3-tqdm or pip install tqdm)"
        ) from exc
    return tqdm


def hash_with_prefix(prefix, data):
    h = hashlib.sha512()
    h.update(prefix.ljust(SHA512_BLOCK_BYTES, b"\0"))
    h.update(data)
    return h.digest()


def read_bytes(path):
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise MetadataDecryptError(f"failed to read {path}: {exc}") from exc


def find_debugfs():
    executable = shutil.which("debugfs")
    if executable:
        return executable
    for candidate in ("/usr/sbin/debugfs", "/sbin/debugfs"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise MetadataDecryptError("debugfs not found; install e2fsprogs")


def run_debugfs(path, request):
    """Run one read-only debugfs request with stable English output."""
    try:
        image = Path(path).resolve(strict=True)
    except OSError as exc:
        raise MetadataDecryptError(f"ext4 preflight failed for {path}: {exc}") from exc
    if not image.is_file():
        raise MetadataDecryptError(f"ext4 preflight failed for {path}: not a file")

    env = os.environ.copy()
    env["LC_ALL"] = "C"
    try:
        result = subprocess.run(
            [find_debugfs(), "-R", request, os.fspath(image)],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    except OSError as exc:
        raise MetadataDecryptError(f"failed to run debugfs: {exc}") from exc
    if result.returncode:
        detail = result.stderr.strip().replace("\n", "; ")
        suffix = f": {detail}" if detail else ""
        raise MetadataDecryptError(
            f"debugfs {request!r} failed with exit {result.returncode}{suffix}"
        )
    return result


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
        detail = stats_result.stderr.strip().replace("\n", "; ")
        suffix = f": {detail}" if detail else ""
        raise MetadataDecryptError(
            f"ext4 preflight failed for {path}: invalid debugfs stats{suffix}"
        )

    block_size = parse_debugfs_integer(stats, "Block size")
    inode_size = parse_debugfs_integer(stats, "Inode size")
    block_count = parse_debugfs_integer(stats, "Block count")
    first_block = parse_debugfs_integer(stats, "First block")
    blocks_per_group = parse_debugfs_integer(stats, "Blocks per group")
    data_blocks = block_count - first_block
    if data_blocks <= 0 or blocks_per_group <= 0:
        raise MetadataDecryptError(
            f"ext4 preflight failed for {path}: invalid block group geometry"
        )
    group_count = (data_blocks + blocks_per_group - 1) // blocks_per_group

    root_result = run_debugfs(path, "stat <2>")
    if not re.search(
            r"^Inode:\s+2\s+Type:\s+directory\b",
            root_result.stdout,
            re.MULTILINE):
        detail = root_result.stderr.strip().replace("\n", "; ")
        suffix = f": {detail}" if detail else ""
        raise MetadataDecryptError(
            f"ext4 preflight failed for {path}: root inode is not a directory{suffix}"
        )

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


def read_key_dir(path):
    key_dir = resolve_key_dir(path)
    version_file = key_dir / "version"
    if version_file.exists():
        version = version_file.read_bytes().strip()
        if version != b"1":
            raise MetadataDecryptError(
                f"unsupported metadata key version {version!r}; expected b'1'"
            )

    encrypted_key = read_bytes(key_dir / "encrypted_key")
    secdiscardable_path = key_dir / "secdiscardable"
    secdiscardable = read_bytes(secdiscardable_path) if secdiscardable_path.exists() else None

    keymaster_blob = None
    for name in ("keymaster_key_blob", "keymaster_key_blob_upgraded"):
        blob_path = key_dir / name
        if blob_path.exists():
            keymaster_blob = read_bytes(blob_path)
            break

    return {
        "dir": key_dir,
        "encrypted_key": encrypted_key,
        "secdiscardable": secdiscardable,
        "keymaster_blob": keymaster_blob,
    }


def aes_gcm_decrypt(key, encrypted_key):
    _, _, _, AESGCM, InvalidTag = require_crypto()
    if len(encrypted_key) < GCM_NONCE_BYTES + GCM_TAG_BYTES:
        raise MetadataDecryptError("encrypted_key is too small for AES-GCM")
    nonce = encrypted_key[:GCM_NONCE_BYTES]
    ciphertext_and_tag = encrypted_key[GCM_NONCE_BYTES:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext_and_tag, b"")
    except InvalidTag as exc:
        raise MetadataDecryptError("AES-GCM tag check failed while unwrapping key") from exc


def unwrap_emulator_keymaster(encrypted_key, keymaster_blob):
    if not keymaster_blob:
        raise MetadataDecryptError("keymaster_key_blob is required for emulator unwrap mode")

    if len(keymaster_blob) == 32:
        wrapping_key = keymaster_blob
    elif len(keymaster_blob) >= 37:
        version = keymaster_blob[0]
        key_len = int.from_bytes(keymaster_blob[1:5], "little")
        if key_len not in (16, 24, 32):
            raise MetadataDecryptError(
                "unsupported emulator keymaster_key_blob key length "
                f"{key_len} (version {version})"
            )
        wrapping_key = keymaster_blob[5:5 + key_len]
        if len(wrapping_key) != key_len:
            raise MetadataDecryptError("truncated emulator keymaster_key_blob")
    else:
        raise MetadataDecryptError("unsupported emulator keymaster_key_blob format")

    return aes_gcm_decrypt(wrapping_key, encrypted_key)


def unwrap_without_keystore(encrypted_key, secdiscardable, secret):
    if secdiscardable is None:
        secdiscardable_hash = b""
    else:
        secdiscardable_hash = hash_with_prefix(HASH_PREFIX_SECDISCARDABLE, secdiscardable)
    app_id = secdiscardable_hash + secret
    wrapping_key = hash_with_prefix(HASH_PREFIX_KEYGEN, app_id)[:32]
    return aes_gcm_decrypt(wrapping_key, encrypted_key)


def load_metadata_key(key_dir):
    key_data = read_key_dir(key_dir)
    if key_data["keymaster_blob"]:
        key = unwrap_emulator_keymaster(
            key_data["encrypted_key"], key_data["keymaster_blob"]
        )
    else:
        key = unwrap_without_keystore(
            key_data["encrypted_key"],
            key_data["secdiscardable"],
            NO_KEYSTORE_SECRET,
        )

    if len(key) not in (32, 64):
        raise MetadataDecryptError(
            f"metadata key must be 32 or 64 bytes for AES-XTS, got {len(key)}"
        )
    return key


def validate_metadata_key(key):
    if len(key) not in (32, 64):
        raise MetadataDecryptError("AES-XTS key must be 32 or 64 bytes")


def xts_crypt_unit(key, data, dun, encrypt=False):
    Cipher, algorithms, modes, _, _ = require_crypto()
    tweak = dun.to_bytes(16, "little")
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    ctx = cipher.encryptor() if encrypt else cipher.decryptor()
    return ctx.update(data) + ctx.finalize()


def decrypt_image(input_file, output_file, key):
    validate_metadata_key(key)

    total_size = os.path.getsize(input_file)
    full_units = total_size // DATA_UNIT_SIZE_BYTES
    tail_size = total_size % DATA_UNIT_SIZE_BYTES

    output_path = Path(output_file)
    if Path(input_file).resolve() == output_path.resolve():
        raise MetadataDecryptError("input and output image must be different files")
    if output_path.exists() and not output_path.is_file():
        raise MetadataDecryptError("output path must be a regular file")
    if output_path.exists():
        raise MetadataDecryptError(
            f"{output_file} already exists; choose a different -o/--output-file"
        )

    tqdm = require_tqdm()
    print(f"[+] Input: {input_file}")
    print(f"[+] Output: {output_file}")
    print(f"[+] Data unit size: {DATA_UNIT_SIZE_BYTES}")
    print(f"[+] IV unit mode: {IV_UNIT_MODE}")
    print(f"[+] DUN offset: {INITIAL_DUN}")
    print(f"[+] Decrypting {full_units} full data units ({total_size} bytes)")

    with open(input_file, "rb") as src, open(output_file, "wb") as dst:
        with tqdm(
                total=total_size,
                desc="Metadata decrypt",
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
        ) as progress:
            for unit_index in range(full_units):
                unit = src.read(DATA_UNIT_SIZE_BYTES)
                if len(unit) != DATA_UNIT_SIZE_BYTES:
                    raise MetadataDecryptError("short read while decrypting image")
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
