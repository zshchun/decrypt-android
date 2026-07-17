#!/usr/bin/env python3

# @file fde-decrypt.py
# @brief FDE decryptor for Android 6.0 (android emulator)
# @author Seunghwan Chun <zshchun@gmail.com>
# @version 1.0

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
BBLUE = '"\033[94m"'
NOCOLOR = '\033[0m'

MAGIC = 0xd0b5b1c4
CRYPT_TYPE_PASSWORD = 0
CRYPT_TYPE_DEFAULT = 1
CRYPT_TYPE_PATTERN = 2
CRYPT_TYPE_PIN = 3
sector_size = 512

kdf_type_str = ["Unknown", "KDF_PBKDF2", "KDF_SCRYPT"]

Footer = namedtuple('Footer', ['magic', 'major', 'minor', 'ftr_size',
                               'flags', 'keysize', 'crypt_type', 'fs_size',
                               'failed_decrypt_count', 'crypt_type_name',
                               'reserved', 'master_key', 'salt',
                               'persist_data_off1', 'persist_data_off2',
                               'persist_data_size', 'kdf_type', 'N_factor',
                               'r_factor', 'p_factor', 'encrypted_upto',
                               'hash_first_block', 'keymaster_blob',
                               'keymaster_blob_size', 'scrypted_ik'])


def get_master_key(pw):
    """Get a master key for Android 6.0 (Marshmallow)

    @param pw password
    @return master key on SUCCESS, Flase on FAILURE
    """
    if isinstance(pw, int):
        pw = f'{pw:04}'.encode()
    elif isinstance(pw, str):
        pw = pw.encode()

    N = 1 << ftr.N_factor
    r = 1 << ftr.r_factor
    p = 1 << ftr.p_factor

    key_iv = scrypt(pw, salt=ftr.salt, n=N, r=r, p=p, maxmem=128*1024*1024)
    key = key_iv[:16]
    iv = key_iv[16:32]
    ik = key_iv[32:]
    c = AES.new(key, AES.MODE_CBC, iv=iv)

    encrypted_key = ftr.master_key[:ftr.keysize]
    decrypted_key = c.decrypt(encrypted_key)

    cal_scrypted_ik = scrypt(key, salt=ftr.salt, n=N, r=r, p=p, maxmem=128*1024*1024)[:32]
    # cal_pbkdf2_ik = pbkdf2_hmac('sha256', key, salt, 2000, 32)
    if cal_scrypted_ik == ftr.scrypted_ik:
        print("- Intermediate Key:", ik.hex())
        print("- Decrypted Master Key:", decrypted_key.hex())
        print("- Calculated Scrypted Intermediate Key:", cal_scrypted_ik.hex())
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
    encrypted_disk = open(args.input_file, 'rb')
    decrypted_disk = open(args.output_file, 'wb')
    total_size = os.path.getsize(args.input_file)
    total_sector = total_size // sector_size
    salt = sha256(decrypted_key).digest()
    print(f"- Disk size: {total_size}")
    for sect_idx in tqdm(range(total_sector)):
        block = encrypted_disk.read(sector_size)
        if not block:
            break
        plaintext = decrypt_sector(decrypted_key, salt, sect_idx, block)
        decrypted_disk.write(plaintext)


def parse_footer():
    """Parse the footer as a crypt_mnt_ftr

    @return footer parameters
    """

    footer_raw = open(args.footer_file, 'rb').read()
    hdr_fmt = '<IHHIIIIQI64sI48s16s2QI4BQ32s2048sI32s'
    hdr_size = calcsize(hdr_fmt)

    ftr = Footer(*unpack(hdr_fmt, footer_raw[:hdr_size]))
    crypt_type_name = ftr.crypt_type_name.decode().rstrip('\0')

    # https://android.googlesource.com/platform/system/vold/+/android-6.0.1_r79/cryptfs.h#88
    assert ftr.magic == MAGIC
    print("Header info: crypt_mnt_ftr")
    print(f"- Magic: 0x{ftr.magic:x}")
    print(f"- Version: major={ftr.major}, minor={ftr.minor}")
    print(f"- Key size: {ftr.keysize}")
    print(f"- Crypt type: {ftr.crypt_type}")
    print(f"- FS size: {ftr.fs_size * 512}")
    print(f"- Crypt type name: {crypt_type_name}")
    print(f"- KDF type: {kdf_type_str[ftr.kdf_type]}")
    print(f"- Encrypted master key: {ftr.master_key.hex()}")
    print(f"- Salt: {ftr.salt.hex()}")
    print(f"- N_factor: {ftr.N_factor}")
    print(f"- r_factor: {ftr.r_factor}")
    print(f"- p_factor: {ftr.p_factor}")
    print(f"- Encrypted upto: {ftr.encrypted_upto}")
    print(f"- hash first block: {ftr.hash_first_block.hex()}")
    print(f"- Keymaster blob size: {ftr.keymaster_blob_size}")
    print(f"- Keymaster blob: {ftr.keymaster_blob[:32].hex()}")
    print(f"- Precomputed Scrypted Intermediate Key: {ftr.scrypted_ik.hex()}")
    print()
    assert crypt_type_name == "aes-cbc-essiv:sha256", "unsupported crypt type"
    return ftr


def bruteforce_pin():
    """Bruteforce the PIN

    Currently, it supports DEFAULT_PASSWORD and 4-digit PIN

    @return decrypted master key
    """
    if ftr.crypt_type == CRYPT_TYPE_DEFAULT:
        print("- Crypt type: DEFAULT")
        decrypted_key = get_master_key('default_password')
        assert decrypted_key
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
                    pool.join()
                    break
        print(BGREEN + f"- Found PIN: {pw}" + NOCOLOR)
    else:
        print(f"- Unsupported CRYPT_TYPE: {ftr.crypt_type}")
        sys.exit()
    return decrypted_key


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

    ftr = parse_footer()

    print("Start to get the master key")
    print("Press <return> to continue")
    input()

    decrypted_key = bruteforce_pin()

    print(f"- Decrypted master key: {decrypted_key.hex()}\n")

    print(f"Start to decrypt disk: {args.input_file}")
    print("Press <return> to continue")
    input()

    decrypt_disk()

    print(f"Decryption was successfull on {args.output_file}")
