#!/usr/bin/env python3

# @file fbe-decrypt.py
# @brief FBE decryptor for Android 14.0 (android emulator)
# @author Seunghwan Chun <zshchun@gmail.com>
# @version 2

import subprocess
from hashlib import sha256
from hmac import HMAC
from sys import argv, exit
from collections import namedtuple
from argparse import ArgumentParser
from pathlib import Path
from struct import pack, unpack, calcsize
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import metadata

Fscrypt_context_v2 = namedtuple('Fscrypt_context_v2', [
                'ver', 'data_enc_mode', 'name_enc_mode', 'flags',
                'lg2_unit_size', 'rvsd1', 'rvsd2', 'rvsd3',
                'mk_ident', 'nonce'])
master_key = {}
metadata_key = None

FSCRYPT_CONTEXT_FORMAT = '<8B16s16s'
FSCRYPT_CONTEXT_V2 = 2
FSCRYPT_MODE_AES_256_XTS = 1
FSCRYPT_MODE_AES_256_CTS = 4
FSCRYPT_MODE_AES_256_HCTR2 = 10
FSCRYPT_POLICY_FLAGS_PAD_MASK = 0x03
FSCRYPT_POLICY_FLAG_DIRECT_KEY = 0x04
FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 = 0x08
FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32 = 0x10
HKDF_CONTEXT_KEY_IDENTIFIER = 1
HKDF_CONTEXT_PER_FILE_ENC_KEY = 2
AES_BLOCK_SIZE = 16

BBLUE = '\033[94m'
NOCOLOR = '\033[0m'

FSCRYPT_MODE_NAMES = {
    FSCRYPT_MODE_AES_256_XTS: 'AES-256-XTS',
    FSCRYPT_MODE_AES_256_CTS: 'AES-256-CBC-CTS',
    9: 'Adiantum',
    FSCRYPT_MODE_AES_256_HCTR2: 'AES-256-HCTR2',
}

FSCRYPT_PADDING_NAMES = {
    0x00: 'PAD_4',
    0x01: 'PAD_8',
    0x02: 'PAD_16',
    0x03: 'PAD_32',
}


def explain_stage(number, title):
    """Print one numbered stage of the default educational walkthrough."""
    print(BBLUE + f"[{number}/6] {title}" + NOCOLOR, flush=True)


def pause_for_demo():
    """Pause at an educational walkthrough checkpoint."""
    print("Press <Return> to continue")
    input()


def stat(filespec, verbose=False):
    """Get information of file using debugfs

    @param filespec file path or inode
    @return information of the inode (dict)
    """
    if isinstance(filespec, int):
        cmd = f"debugfs -R 'stat <{filespec}>' {args.input_file}"
    else:
        cmd = f"debugfs -R 'stat {filespec}' {args.input_file}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
    lines = result.stdout.split('\n')
    info = lines[0].split()
    ug_size = lines[2].split()
    if verbose:
        print(result.stdout)
    assert info[0] == 'Inode:'
    assert info[2] == 'Type:'
    assert info[4] == 'Mode:'
    assert info[6] == 'Flags:'
    assert ug_size[6] == 'Size:'
    return {'inode':int(info[1]), 'type':info[3], 'mode':info[5], 'flags':int(info[7], 16), 'size':int(ug_size[7])}


def is_encrypted(filespec):
    """Verify if the file is encrypted using debugfs

    @param filespec file path or inode
    @return True if encrypted, False otherwise
    """
    return (stat(filespec)['flags'] & 0x800) == 0x800


def get_inode(filespec):
    """Get an inode number using debugfs

    @param filespec file path or inode
    @return inode number
    """
    return stat(filespec)['inode']


def get_block_size():
    """Get the block size using debugfs

    @return EXT4 Block size
    """
    cmd = f"debugfs -R stats {args.input_file}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
    for line in  result.stdout.split('\n'):
        if line.find('Block size:') != -1:
            block_size = line.split(':')[1].strip()
            print(f"[+] Block size: {block_size}")
            return int(block_size)
    raise Exception('Failed to find block size')


def dump_content(filespec):
    """Dump file content using debugfs

    @param filespec file path or inode
    @return file content
    """
    if isinstance(filespec, int):
        cmd = f"debugfs -R 'cat <{filespec}>' {args.input_file}"
    else:
        cmd = f"debugfs -R 'cat {filespec}' {args.input_file}"
    result = subprocess.run(cmd, shell=True, capture_output=True, check=True)
    return result.stdout


def get_file_content(filespec):
    """Restore FBE ciphertext from the ext4 inspection image.

    metadata.py transforms every block, while dm-default-key skips
    fscrypt-protected file contents. Reapply that transform for these blocks.

    @param filespec file path or inode
    @return encrypted file content
    """
    blocks = get_blocks(filespec)
    buf = b''
    with open(f'{args.input_file}', 'rb') as f:
        for blk in blocks:
            f.seek(blk * block_size)
            block = f.read(block_size)
            if len(block) != block_size:
                raise ValueError(f"short read at physical block {blk}")
            if metadata_key is None:
                raise ValueError("metadata key is not loaded")
            block = metadata.xts_crypt_unit(
                metadata_key, block, blk, encrypt=True
            )
            buf += block
    return buf


def list_xaatr(inode):
    """List extended attributes using debugfs

    @param inode
    @return encrypted file content
    """
    cmd = f"debugfs -R 'ea_list <{inode}>' {args.input_file}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def get_blocks(filespec):
    """Get block numbers of a file

    @param filespec file path or inode
    @return block numbers of an inode
    """

    if isinstance(filespec, int):
        cmd = f"debugfs -R 'blocks <{filespec}>' {args.input_file}"
    else:
        cmd = f"debugfs -R 'blocks {filespec}' {args.input_file}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
    return [int(b) for b in result.stdout.strip().split()]


def get_xaatr(inode, xattr):
    """Get extended attribute of an inode

    @param inode inode
    @param xattr name of a xattr
    @return value of a xattr
    """
    cmd = f"debugfs -R 'ea_get -x <{inode}> {xattr}' {args.input_file}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
    ret = result.stdout.strip()
    if ret.find('=') == -1:
        return b''
    return bytes.fromhex(ret.split('=')[1])


def parse_enc_ctx(enc_ctx):
    expected_size = calcsize(FSCRYPT_CONTEXT_FORMAT)
    if len(enc_ctx) != expected_size:
        raise ValueError(
            f"fscrypt_context_v2 must be {expected_size} bytes, got {len(enc_ctx)}"
        )
    fscrypt_ctx = Fscrypt_context_v2(
        *unpack(FSCRYPT_CONTEXT_FORMAT, enc_ctx)
    )
    if fscrypt_ctx.ver != FSCRYPT_CONTEXT_V2:
        raise ValueError(
            f"unsupported fscrypt context version: {fscrypt_ctx.ver}"
        )
    if any((fscrypt_ctx.rvsd1, fscrypt_ctx.rvsd2, fscrypt_ctx.rvsd3)):
        raise ValueError("fscrypt_context_v2 reserved bytes must be zero")
    return fscrypt_ctx


def fscrypt_flag_names(flags):
    """Return human-readable fscrypt v2 policy flag names."""
    names = [FSCRYPT_PADDING_NAMES[flags & FSCRYPT_POLICY_FLAGS_PAD_MASK]]
    for value, name in (
        (FSCRYPT_POLICY_FLAG_DIRECT_KEY, 'DIRECT_KEY'),
        (FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64, 'IV_INO_LBLK_64'),
        (FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32, 'IV_INO_LBLK_32'),
    ):
        if flags & value:
            names.append(name)
    known = (
        FSCRYPT_POLICY_FLAGS_PAD_MASK
        | FSCRYPT_POLICY_FLAG_DIRECT_KEY
        | FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64
        | FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32
    )
    if flags & ~known:
        names.append(f'UNKNOWN(0x{flags & ~known:02x})')
    return names


def describe_fscrypt_context(fscrypt_ctx, inode=None):
    """Print the on-disk fscrypt_context_v2 fields for teaching."""
    if inode is not None:
        print(f"- Inode: {inode}")
    print(f"- Context size: {calcsize(FSCRYPT_CONTEXT_FORMAT)} bytes")
    print(f"- Version: {fscrypt_ctx.ver} (fscrypt policy v2)")
    data_mode = FSCRYPT_MODE_NAMES.get(
        fscrypt_ctx.data_enc_mode, f'UNKNOWN({fscrypt_ctx.data_enc_mode})'
    )
    name_mode = FSCRYPT_MODE_NAMES.get(
        fscrypt_ctx.name_enc_mode, f'UNKNOWN({fscrypt_ctx.name_enc_mode})'
    )
    print(f"- Contents mode: {fscrypt_ctx.data_enc_mode} ({data_mode})")
    print(f"- Filenames mode: {fscrypt_ctx.name_enc_mode} ({name_mode})")
    print(
        f"- Policy flags: 0x{fscrypt_ctx.flags:02x} "
        f"({', '.join(fscrypt_flag_names(fscrypt_ctx.flags))})"
    )
    if fscrypt_ctx.lg2_unit_size:
        unit_description = f"{1 << fscrypt_ctx.lg2_unit_size} bytes"
    else:
        default_size = globals().get('block_size')
        unit_description = (
            f"filesystem default ({default_size} bytes)"
            if default_size else "filesystem block-size default"
        )
    print(f"- Data unit size: {unit_description}")
    print(f"- Master key identifier: {fscrypt_ctx.mk_ident.hex()}")
    print(f"- Per-inode nonce: {fscrypt_ctx.nonce.hex()}")


def ensure_supported_context(fscrypt_ctx):
    """Reject policy variants this focused emulator lab cannot decrypt."""
    if fscrypt_ctx.data_enc_mode != FSCRYPT_MODE_AES_256_XTS:
        mode = FSCRYPT_MODE_NAMES.get(
            fscrypt_ctx.data_enc_mode, str(fscrypt_ctx.data_enc_mode)
        )
        raise ValueError(f"unsupported contents mode: {mode}")
    if fscrypt_ctx.name_enc_mode != FSCRYPT_MODE_AES_256_CTS:
        mode = FSCRYPT_MODE_NAMES.get(
            fscrypt_ctx.name_enc_mode, str(fscrypt_ctx.name_enc_mode)
        )
        raise ValueError(f"unsupported filenames mode: {mode}")
    key_policy_flags = fscrypt_ctx.flags & ~FSCRYPT_POLICY_FLAGS_PAD_MASK
    if key_policy_flags:
        key_policy_names = fscrypt_flag_names(key_policy_flags)[1:]
        raise ValueError(
            "unsupported fscrypt key/IV policy: "
            + ', '.join(key_policy_names)
        )


def get_fscrypt_context(inode):
    """Read and parse an inode's 40-byte fscrypt v2 xattr."""
    enc_ctx = get_xaatr(inode, 'c')
    return parse_enc_ctx(enc_ctx)


def fscrypt_hkdf(key, context, info, length):
    """Derive one fscrypt v2 HKDF-SHA512 output block."""
    if not 1 <= length <= 64:
        raise ValueError("this fscrypt HKDF helper supports 1..64 output bytes")
    prk = HMAC(b'', key, 'sha512').digest()
    application_info = b'fscrypt\x00' + bytes([context]) + info
    return HMAC(prk, application_info + b'\x01', 'sha512').digest()[:length]


def derive_master_key_identifier(key):
    """Derive the 16-byte identifier used by fscrypt v2 policies."""
    return fscrypt_hkdf(key, HKDF_CONTEXT_KEY_IDENTIFIER, b'', 16)


def derive_per_file_key(key, nonce):
    """Derive the 64-byte AES-256-XTS key for an inode."""
    return fscrypt_hkdf(key, HKDF_CONTEXT_PER_FILE_ENC_KEY, nonce, 64)


def aes_cbc_cts_decrypt(key, ct):
    """Decrypt Linux cts(cbc(aes)) data (RFC 3962 / CBC-CS3)."""
    if len(ct) < AES_BLOCK_SIZE:
        raise ValueError("CBC-CTS ciphertext must be at least 16 bytes")

    def ecb_decrypt(block):
        dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        return dec.update(block) + dec.finalize()

    def xor(left, right):
        return bytes(a ^ b for a, b in zip(left, right))

    if len(ct) == AES_BLOCK_SIZE:
        return ecb_decrypt(ct)

    last_len = len(ct) % AES_BLOCK_SIZE or AES_BLOCK_SIZE
    prefix_len = len(ct) - AES_BLOCK_SIZE - last_len
    prefix_ct = ct[:prefix_len]
    final_full = ct[prefix_len:prefix_len + AES_BLOCK_SIZE]
    stolen_head = ct[prefix_len + AES_BLOCK_SIZE:]

    final_decrypted = ecb_decrypt(final_full)
    penultimate_ct = stolen_head + final_decrypted[last_len:]
    final_plaintext = xor(final_decrypted[:last_len], stolen_head)
    previous_ct = prefix_ct[-AES_BLOCK_SIZE:] if prefix_ct else bytes(16)
    penultimate_plaintext = xor(ecb_decrypt(penultimate_ct), previous_ct)

    prefix_plaintext = b''
    if prefix_ct:
        dec = Cipher(
            algorithms.AES(key), modes.CBC(bytes(AES_BLOCK_SIZE))
        ).decryptor()
        prefix_plaintext = dec.update(prefix_ct) + dec.finalize()
    return prefix_plaintext + penultimate_plaintext + final_plaintext


def get_file_key(inode, verbose=False, fscrypt_ctx=None):
    """Get a FBE file encryption key

    @param inode inode of a file
    @return file encryption key
    """
    fsc = fscrypt_ctx or get_fscrypt_context(inode)
    ensure_supported_context(fsc)
    if fsc.mk_ident not in master_key:
        raise ValueError(
            f"no loaded master key matches identifier {fsc.mk_ident.hex()}"
        )
    mkey = master_key[fsc.mk_ident]
    if verbose:
        print(f"- Matched master key: {mkey.hex()}")
        print("- HKDF info: fscrypt\\0 || context 0x02 || inode nonce")
    file_key = derive_per_file_key(mkey, fsc.nonce)
    if verbose:
        print(f"- Per-inode key: {file_key.hex()}")
    return file_key


def listdir(inode_data, dir_inode=None, decrypt=False, output_dir=None):
    """List a directory

    @param inode_data encrypted or unencrypted directory entries
    @param dir_inode inode of a directory
    @param decrypt process decryption
    @param output_dir directory for recursive encrypted/decrypted file outputs
    @return number of decrypted regular files
    """
    pos = 0
    name_key = None
    decrypted_count = 0
    if decrypt:
        output_dir = Path(output_dir) if output_dir is not None else Path('.')
    if decrypt and dir_inode and is_encrypted(dir_inode):
        directory_context = get_fscrypt_context(dir_inode)
        name_key = get_file_key(
            dir_inode,
            verbose=True,
            fscrypt_ctx=directory_context,
        )
        print(f"- Directory-name key: {name_key[:32].hex()}")
    idx = 0
    entry_fmt = '<IHBB'
    entry_size = calcsize(entry_fmt)
    while pos < len(inode_data):
        entry_start = pos
        if len(inode_data) - entry_start < entry_size:
            raise ValueError(f"short ext4 directory entry at byte {entry_start}")
        inode, rec_len, name_len, file_type \
                = unpack(entry_fmt, inode_data[pos:pos+entry_size])
        if rec_len < entry_size + name_len or entry_start + rec_len > len(inode_data):
            raise ValueError(
                f"invalid ext4 rec_len {rec_len} at byte {entry_start}"
            )

        pos += entry_size
        name = inode_data[pos:pos+name_len]
        pos = entry_start + rec_len
        if inode == 0:
            continue
        idx += 1

        if len(name) >= 16 and decrypt and name_key is not None:
            pt = aes_cbc_cts_decrypt(name_key[:32], name)
            name = pt.rstrip(b'\0').decode()
            print(f"{inode:10d} {rec_len:5d} {name_len:3d} {file_type:3d} {name:12s}", end='')
            if file_type == 2: # directory
                print()
                child_output_dir = output_dir / name
                child_output_dir.mkdir(exist_ok=True)
                child_data = dump_content(inode)
                decrypted_count += listdir(
                    child_data,
                    dir_inode=inode,
                    decrypt=True,
                    output_dir=child_output_dir,
                )
                continue
            if file_type != 1: # regular file
                print("  =>  unsupported file type (skipped)")
                continue

            content = get_file_content(inode)
            content_context = get_fscrypt_context(inode)
            content_key = get_file_key(
                inode,
                verbose=True,
                fscrypt_ctx=content_context,
            )
            info = stat(inode)
            filesize = info['size']
            data_unit_size = (
                1 << content_context.lg2_unit_size
                if content_context.lg2_unit_size else block_size
            )

            encrypted_path = output_dir / f"{name}.enc"
            decrypted_path = output_dir / f"{name}.dec"
            with open(encrypted_path, 'wb') as encrypted_file:
                encrypted_file.write(content)
            buf = aes_xts_decrypt(content_key, content, data_unit_size)
            with open(decrypted_path, 'wb') as decrypted_file:
                decrypted_file.write(buf[:filesize])
            decrypted_count += 1
            print(f'  =>  {decrypted_path} (decrypted)')

        else:
            try:
                name = name.decode()
                print(f"{inode:10d} {rec_len:5d} {name_len:3d} {file_type:3d} {name:12s}")
            except:
                print(f"{inode:10d} {rec_len:5d} {name_len:3d} {file_type:3d} <Encrypted> : {name.hex()}")
    return decrypted_count


def aes_xts_decrypt(key, content, data_unit_size=None):
    """Decrypt the content of a file using AES-XTS

    @param key file encryption key
    @param content file data
    @return decrypted file data
    """
    if data_unit_size is None:
        data_unit_size = block_size
    if data_unit_size < AES_BLOCK_SIZE or len(content) % data_unit_size:
        raise ValueError(
            "AES-XTS content must contain complete filesystem data units"
        )

    pt = bytearray()
    for unit_index in range(len(content) // data_unit_size):
        tweak = unit_index.to_bytes(16, 'little')
        dec = Cipher(algorithms.AES(key), modes.XTS(tweak)).decryptor()
        start = unit_index * data_unit_size
        end = start + data_unit_size
        ct = content[start:end]
        pt.extend(dec.update(ct) + dec.finalize())
    return bytes(pt)


def add_master_key(key):
    """Add master key for FBE decryption

    @param key master key to register
    """
    global master_key
    ident = derive_master_key_identifier(key)
    print(
        f"[+] Found master key\n"
        f"- Key Identifier: {ident.hex()}\n"
        f"- Master key: {key.hex()}"
    )
    master_key[ident] = key
    return ident


def decrypt_key(encrypted_key, key_blob):
    """Unwrap an emulator-lab FBE master key with AES-GCM.

    @param encrypted_key encrypted key data
    @param key_blob keymaster key blob file for key decryption
    @return decrypted master key
    """
    if len(key_blob) < 37:
        raise ValueError(f"emulator key blob is too short: {len(key_blob)} bytes")
    if len(encrypted_key) < 12 + 16:
        raise ValueError(
            f"encrypted key is too short for a GCM nonce and tag: {len(encrypted_key)}"
        )
    _ver, key_len, padded_key = unpack('<BI32s', key_blob[:37])
    if key_len not in (16, 24, 32):
        raise ValueError(f"unsupported AES-GCM key length in blob: {key_len}")
    key = padded_key[:key_len]
    # TODO signature verification
    # hmac(b'IntegrityAssuredBlob0\0', key_blob[:-8])
    # hidden_params = bytes.fromhex('53570200000018000000590200900000000000000000c00200900200000000000000')
    nonce = encrypted_key[:12]
    ct_tag = encrypted_key[12:]
    gcm = AESGCM(key)
    pt = gcm.decrypt(nonce, ct_tag, b'')
    return pt


def load_master_keys():
    """Load the emulator-lab DE master keys from the ext4 view."""
    for prefix in ['unencrypted/key/', '/misc/vold/user_keys/de/0/']:
        encrypted_key = dump_content(prefix + 'encrypted_key')
        secdiscardable = dump_content(prefix + 'secdiscardable')
        keymaster_key_blob = dump_content(prefix + 'keymaster_key_blob')
        print(f"- Key directory: {prefix}")
        print(
            "  encrypted_key / secdiscardable / keymaster_key_blob: "
            f"{len(encrypted_key)} / {len(secdiscardable)} / "
            f"{len(keymaster_key_blob)} bytes"
        )
        print("  emulator blob key -> AES-GCM unwrap -> fscrypt master key")
        key = decrypt_key(encrypted_key, keymaster_key_blob)
        add_master_key(key)


def inspect_target(filespec, verbose=True):
    """Show the inode-to-context-to-key path for one teaching target."""
    info = stat(filespec)
    fscrypt_ctx = get_fscrypt_context(info['inode'])
    if verbose:
        describe_fscrypt_context(fscrypt_ctx, info['inode'])
        explain_stage(4, "Match key identifier and derive the per-inode key")
    ensure_supported_context(fscrypt_ctx)
    target_key = get_file_key(
        info['inode'], verbose=verbose, fscrypt_ctx=fscrypt_ctx
    )
    matched_master_key = master_key[fscrypt_ctx.mk_ident]
    open('master.key', 'wb').write(matched_master_key)
    print("Save master key : matched_master_key")
    return info, fscrypt_ctx


def build_parser():
    """Build the command-line parser."""
    parser = ArgumentParser(description="Android FBE decryptor",
                            usage="%(prog)s -i IMAGE [-o OUTPUT_DIR] [-h]")
    parser.add_argument('-k', dest='key_dir', required=False, default='key',
                        help="key directory from metadata.py")
    parser.add_argument('-i', dest='input_file', required=True,
                        help="ext4 inspection image from metadata.py")
    parser.add_argument('-o', dest='output_dir', default='dec',
                        help=(
                            "root directory for decrypted files "
                            "(default: dec)"
                        ))
    return parser


def main(cli_args=None):
    """Run the Android 14 emulator FBE teaching workflow."""
    global args, block_size, metadata_key
    parser = build_parser()
    args = parser.parse_args(cli_args)
    master_key.clear()
    output_root = Path(args.output_dir)

    explain_stage(1, "Validate the metadata-decrypted ext4 image")
    root_data = stat('/')
    print(f"- Root inode: {root_data['inode']}")
    print(f"- ext4 view and physical block source: {args.input_file}")
    block_size = get_block_size()
    if block_size != metadata.DATA_UNIT_SIZE_BYTES:
        parser.error(
            "this AVD workflow requires matching 4096-byte ext4 and "
            "metadata-encryption data units"
        )
    metadata_key_dir = Path(args.input_file).resolve().parent / args.key_dir
    try:
        metadata_key = metadata.load_metadata_key(metadata_key_dir)
    except metadata.MetadataDecryptError as exc:
        parser.error(str(exc))
    print(
        "- dm-default-key boundary: restore skipped FBE content blocks "
        f"with {metadata_key_dir}"
    )

    explain_stage(2, "Unwrap and identify the device-encrypted master keys")
    load_master_keys()

    target = '/system_de/0'
    if is_encrypted(target):
        print(f"[+] {target} is encrypted")
    pause_for_demo()

    explain_stage(3, "Read the target inode and its fscrypt_context_v2")
    info, _fscrypt_ctx = inspect_target(target)
    data = dump_content(info['inode'])
    print(f"[+] original directory: {target}")
    listdir(data)

    pause_for_demo()
    explain_stage(5, "Decrypt directory names with AES-256-CBC-CTS")
    explain_stage(6, "Decrypt file contents with AES-256-XTS data-unit tweaks")
    print(f"[+] decrypt directory: {target}")
    target_output_dir = output_root.joinpath(*target.strip('/').split('/'))
    target_output_dir.mkdir(parents=True, exist_ok=True)
    decrypted_count = listdir(
        data,
        dir_inode=info['inode'],
        decrypt=True,
        output_dir=target_output_dir,
    )
    print(f"[+] Decrypted {decrypted_count} files under {target_output_dir}")
    return 0


if __name__ == "__main__":
    exit(main())
