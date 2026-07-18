#!/usr/bin/env python3

# @file fde-decrypt.py
# @brief FDE decryptor for Android 6.0 (android emulator)
# @author Seunghwan Chun <zshchun@gmail.com>
# @version 2

import os
import sys
from Cryptodome.Cipher import AES
from argparse import ArgumentParser
from hashlib import scrypt, pbkdf2_hmac, sha256, sha512
from struct import pack, unpack, calcsize
from collections import namedtuple
from time import time
from tqdm import tqdm
import multiprocessing

BGREEN= '\033[92m'
BRED = '\033[91m'
BBLUE = '\033[94m'
NOCOLOR = '\033[0m'

MAGIC = 0xd0b5b1c4
CRYPT_TYPE_PASSWORD = 0
CRYPT_TYPE_DEFAULT = 1
CRYPT_TYPE_PATTERN = 2
CRYPT_TYPE_PIN = 3
sector_size = 512

KDF_PBKDF2 = 1
KDF_SCRYPT = 2
KDF_SCRYPT_KEYMASTER = 5

kdf_type_str = {
    KDF_PBKDF2: "KDF_PBKDF2",
    KDF_SCRYPT: "KDF_SCRYPT",
    KDF_SCRYPT_KEYMASTER: "KDF_SCRYPT_KEYMASTER",
}

FOOTER_FORMAT = '<IHHIIIIQI64sI48s16s2QI4BQ32s2048sI32s'
EXT4_MAGIC_OFFSET = 1024 + 56
EXT4_MAGIC = b'\x53\xef'
DEFAULT_DEMO_SECTORS = (2, 32)

Footer = namedtuple('Footer', ['magic', 'major', 'minor', 'ftr_size',
                               'flags', 'keysize', 'crypt_type', 'fs_size',
                               'failed_decrypt_count', 'crypt_type_name',
                               'reserved', 'master_key', 'salt',
                               'persist_data_off1', 'persist_data_off2',
                               'persist_data_size', 'kdf_type', 'N_factor',
                               'r_factor', 'p_factor', 'encrypted_upto',
                               'hash_first_block', 'keymaster_blob',
                               'keymaster_blob_size', 'scrypted_ik'])


def explain_stage(number, title):
    """Print a numbered walkthrough stage."""
    print(BBLUE + f"[{number}/5] {title}" + NOCOLOR, flush=True)


def get_master_key(pw):
    """Get a master key for Android 6.0 (Marshmallow)

    @param pw password
    @return master key on SUCCESS, False on FAILURE
    """
    if isinstance(pw, int):
        pw = f'{pw:04}'.encode()
    elif isinstance(pw, str):
        pw = pw.encode()

    N = 1 << ftr.N_factor
    r = 1 << ftr.r_factor
    p = 1 << ftr.p_factor

    key_iv = scrypt(pw, salt=ftr.salt, n=N, r=r, p=p,
                    maxmem=128*1024*1024, dklen=32)
    key = key_iv[:16]
    iv = key_iv[16:32]
    c = AES.new(key, AES.MODE_CBC, iv=iv)

    encrypted_key = ftr.master_key[:ftr.keysize]
    decrypted_key = c.decrypt(encrypted_key)

    cal_scrypted_ik = scrypt(key, salt=ftr.salt, n=N, r=r, p=p,
                             maxmem=128*1024*1024, dklen=32)
    # cal_pbkdf2_ik = pbkdf2_hmac('sha256', key, salt, 2000, 32)
    if cal_scrypted_ik == ftr.scrypted_ik:
        print("- Decrypted Master Key:", decrypted_key.hex())
        return decrypted_key
    return False


def decrypt_sector(key, salt, sector, ciphertext):
    """Decrypt data from a sector

    The sector is 512 bytes.

    @param key AES-CBC key
    @param salt salt for ESSIV
    @param sector number of sector
    @param ciphertext encrypted sector data
    @return decrypted sector data
    """
    c = AES.new(salt, AES.MODE_ECB)
    ctr = int.to_bytes(sector, byteorder='little', length=16)
    essiv = c.encrypt(ctr)
    c = AES.new(key, AES.MODE_CBC, iv=essiv)
    return c.decrypt(ciphertext)


def decrypt_disk():
    """Decrypt the entire disk
    """
    input_size = os.path.getsize(args.input_file)
    total_sector = ftr.fs_size
    total_size = total_sector * sector_size
    if total_sector <= 0:
        raise ValueError("footer fs_size must be greater than zero")
    if input_size < total_size:
        raise ValueError(
            f"encrypted input is {input_size} bytes, but footer requires {total_size}"
        )

    salt = sha256(decrypted_key).digest()
    print(f"- Encrypted input size: {input_size}")
    print(f"- FDE mapped size: {total_size} ({total_sector} sectors)")
    with open(args.input_file, 'rb') as encrypted_disk, \
            open(args.output_file, 'wb') as decrypted_disk:
        for sect_idx in tqdm(range(total_sector)):
            block = encrypted_disk.read(sector_size)
            if len(block) != sector_size:
                raise ValueError(f"short read at sector {sect_idx}")
            plaintext = decrypt_sector(decrypted_key, salt, sect_idx, block)
            decrypted_disk.write(plaintext)


def demo_sector(sector):
    """Decrypt one sector and show the ESSIV/ext4 checkpoints."""
    if sector < 0 or sector >= ftr.fs_size:
        raise ValueError(
            f"demo sector {sector} is outside footer fs_size {ftr.fs_size}"
        )

    with open(args.input_file, 'rb') as encrypted_disk:
        encrypted_disk.seek(sector * sector_size)
        ciphertext = encrypted_disk.read(sector_size)
    if len(ciphertext) != sector_size:
        raise ValueError(f"short read at demo sector {sector}")

    essiv_key = sha256(decrypted_key).digest()
    counter = sector.to_bytes(16, byteorder='little')
    essiv = AES.new(essiv_key, AES.MODE_ECB).encrypt(counter)
    plaintext = decrypt_sector(decrypted_key, essiv_key, sector, ciphertext)

    print(f"- Demo sector: {sector} (byte offset {sector * sector_size})")
    print(f"- Sector number as LE128: {counter.hex()}")
    # print(f"- ESSIV: {essiv.hex()}")
    print(f"- ESSIV: {essiv.hex()}")
    print(f"- AES-CBC input/output: {len(ciphertext)} / {len(plaintext)} bytes")

    magic_sector = EXT4_MAGIC_OFFSET // sector_size
    if sector == magic_sector:
        magic_offset = EXT4_MAGIC_OFFSET % sector_size
        magic = plaintext[magic_offset:magic_offset + len(EXT4_MAGIC)]
        status = "PASS" if magic == EXT4_MAGIC else "MISMATCH"
        print(
            f"- ext4 magic @ sector +0x{magic_offset:x}: "
            f"{magic.hex()} (expected {EXT4_MAGIC.hex()}) [{status}]"
        )


def demo_default_sectors():
    """Show the default sector 2 and 3 teaching checkpoints."""
    for sector in DEFAULT_DEMO_SECTORS:
        demo_sector(sector)
        print()


def parse_footer():
    """Parse the footer as a crypt_mnt_ftr

    @return footer parameters
    """

    with open(args.footer_file, 'rb') as footer_file:
        footer_raw = footer_file.read()
    hdr_size = calcsize(FOOTER_FORMAT)
    if len(footer_raw) < hdr_size:
        raise ValueError(
            f"footer is {len(footer_raw)} bytes; crypt_mnt_ftr needs {hdr_size}"
        )

    ftr = Footer(*unpack(FOOTER_FORMAT, footer_raw[:hdr_size]))
    crypt_type_name = ftr.crypt_type_name.decode().rstrip('\0')

    # https://android.googlesource.com/platform/system/vold/+/android-6.0.1_r79/cryptfs.h#88
    assert ftr.magic, "invalid footer magic"
    kdf_name = kdf_type_str.get(ftr.kdf_type, f"UNKNOWN({ftr.kdf_type})")
    encrypted_key = ftr.master_key[:ftr.keysize]
    keymaster_blob = ftr.keymaster_blob[:ftr.keymaster_blob_size]
    print("Header info: crypt_mnt_ftr")
    print(f"- Magic: 0x{ftr.magic:x}")
    print(f"- Version: major={ftr.major}, minor={ftr.minor}")
    print(f"- Footer struct size: {hdr_size}")
    print(f"- Key size: {ftr.keysize}")
    print(f"- Crypt type: {ftr.crypt_type}")
    print(f"- FS size: {ftr.fs_size * 512}")
    print(f"- Crypt type name: {crypt_type_name}")
    print(f"- KDF type: {kdf_name}")
    print(f"- Encrypted DEK: {ftr.master_key.hex()}")
    print(f"- Salt: {ftr.salt.hex()}")
    print(f"- N_factor: {ftr.N_factor}")
    print(f"- r_factor: {ftr.r_factor}")
    print(f"- p_factor: {ftr.p_factor}")
    print(f"- Encrypted upto: {ftr.encrypted_upto}")
    print(f"- hash first block: {ftr.hash_first_block.hex()}")
    print(f"- Keymaster blob size: {ftr.keymaster_blob_size}")
    print(f"- Keymaster blob: {keymaster_blob[:32].hex()}")
    print(f"- Precomputed Scrypted Intermediate Key: {ftr.scrypted_ik.hex()}")
    print()
    assert crypt_type_name == "aes-cbc-essiv:sha256", f"unsupported crypt type {crypt_type_name}"
    assert ftr.kdf_type == KDF_SCRYPT, f"unsupported KDF type {kdf_name}"
    return ftr


def bruteforce_pin():
    """Bruteforce the PIN

    Currently, it supports DEFAULT_PASSWORD and 4-digit PIN

    @return decrypted master key and matching credential
    """
    decrypted_key = False
    pw = None
    if ftr.crypt_type == CRYPT_TYPE_DEFAULT:
        print("- Crypt type: DEFAULT")
        decrypted_key = get_master_key('default_password')
        assert decrypted_key, "default_password did not match with the footer"
        print(BGREEN + "- Found password: default_password" + NOCOLOR)
        pw = 'default_password'
    elif ftr.crypt_type == CRYPT_TYPE_PIN:
        num_cpu = multiprocessing.cpu_count()
        print(f"- Brute force a PIN using {num_cpu} CPUs")
        with multiprocessing.Pool(processes=num_cpu) as pool:
            for idx, result in tqdm(enumerate(pool.imap(get_master_key, range(10000))), total=10000):
                if result:
                    decrypted_key = result
                    pw = f'{idx:04}'
                    pool.terminate()
                    break
        assert decrypted_key, "no 4-digit PIN was found"
        print(BGREEN + f"- Found PIN: {pw}" + NOCOLOR)
    else:
        raise ValueError(f"unsupported CRYPT_TYPE: {ftr.crypt_type}")
    return decrypted_key, pw


def recover_master_key():
    """Prompt for a credential, or use the existing search when left blank."""
    pw = input("Android FDE credential: ")
    if pw == '':
        print("- Empty credential: use the automatic default/PIN search")
        return bruteforce_pin()

    decrypted_key = get_master_key(pw)
    if not decrypted_key:
        raise ValueError("credential did not match the footer verifier")
    print(BGREEN + "- Credential verifier matched" + NOCOLOR)
    return decrypted_key, pw


if __name__ == "__main__":
    parser = ArgumentParser(description="Android FDE decryptor",
                            usage="%(prog)s -i userdata.enc -f footer.img -o userdata.dec [-h]")
    parser.add_argument('-i', dest='input_file', required=True,
                        help="path to the encrypted input image")
    parser.add_argument('-o', dest='output_file', required=True,
                        help="path to the decrypted output image")
    parser.add_argument('-f', dest='footer_file', required=True,
                        help="path to the footer image")
    args = parser.parse_args()

    explain_stage(1, "Parse crypt_mnt_ftr")
    ftr = parse_footer()

    print("Start to recover the disk encryption key (DEK)")
    print("Press <return> to continue")
    input()

    explain_stage(2, "Derive KEK and IV from the credential")
    decrypted_key, _credential = recover_master_key()

    explain_stage(3, "Unwrap the encrypted DEK with AES-CBC")
    print(f"- Decrypted DEK: {decrypted_key.hex()}")

    explain_stage(4, "Compare the precomputed credential verifier")
    print(BGREEN + "- Footer verifier: MATCH" + NOCOLOR + "\n")

    explain_stage(5, "Generate ESSIV and decrypt userdata sectors")
    demo_default_sectors()

    print(f"Start to decrypt disk: {args.input_file}")
    print("Press <return> to continue")
    input()

    decrypt_disk()

    print(f"Decryption was successful on {args.output_file}")
