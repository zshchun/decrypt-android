#!/usr/bin/env python3

# @file fbe-decrypt.py
# @brief FBE decryptor for Android 14.0 (android emulator)
# @author Seunghwan Chun <zshchun@gmail.com>
# @version 0.1

import os
import subprocess
from hmac import HMAC
from sys import argv, exit
from collections import namedtuple
from argparse import ArgumentParser
from struct import pack, unpack, calcsize
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

Fscrypt_context_v2 = namedtuple('Fscrypt_context_v2', [
                'ver', 'data_enc_mode', 'name_enc_mode', 'flags',
                'lg2_unit_size', 'rvsd1', 'rvsd2', 'rvsd3',
                'mk_ident', 'nonce'])
master_key = {}


def stat(filespec, verbose=False):
    """Get information of file using debugfs

    @param filespec file path or inode
    @return information of the inode (dict)
    """
    if isinstance(filespec, int):
        cmd = f"debugfs -R 'stat <{filespec}>' {args.ext4_img}"
    else:
        cmd = f"debugfs -R 'stat {filespec}' {args.ext4_img}"
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
    cmd = f"debugfs -R stats {args.ext4_img}"
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
        cmd = f"debugfs -R 'cat <{filespec}>' {args.ext4_img}"
    else:
        cmd = f"debugfs -R 'cat {filespec}' {args.ext4_img}"
    result = subprocess.run(cmd, shell=True, capture_output=True, check=True)
    return result.stdout


def get_file_content(filespec):
    """Dump file content via blocks

    It reads from encrypted image file

    @param filespec file path or inode
    @return encrypted file content
    """
    blocks = get_blocks(filespec)
    buf = b''
    with open(f'{args.input_file}', 'rb') as f:
        for blk in blocks:
            f.seek(blk * block_size)
            buf += f.read(block_size)
    return buf


def list_xaatr(inode):
    """List extended attributes using debugfs

    @param inode
    @return encrypted file content
    """
    cmd = f"debugfs -R 'ea_list <{inode}>' {args.ext4_img}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def get_blocks(filespec):
    """Get block numbers of a file

    @param filespec file path or inode
    @return block numbers of an inode
    """

    if isinstance(filespec, int):
        cmd = f"debugfs -R 'blocks <{filespec}>' {args.ext4_img}"
    else:
        cmd = f"debugfs -R 'blocks {filespec}' {args.ext4_img}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
    return [int(b) for b in result.stdout.strip().split()]


def get_xaatr(inode, xattr):
    """Get extended attribute of an inode

    @param inode inode
    @param xattr name of a xattr
    @return value of a xattr
    """
    cmd = f"debugfs -R 'ea_get -x <{inode}> {xattr}' {args.ext4_img}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
    ret = result.stdout.strip()
    if ret.find('=') == -1:
        return b''
    return bytes.fromhex(ret.split('=')[1])


def parse_enc_ctx(enc_ctx):
    fscrypt_ctx = Fscrypt_context_v2(*unpack('8B16s16s', enc_ctx))
    return fscrypt_ctx


def aes_cbc_cts_decrypt(key, ct):
    if len(ct) <= 16:
        dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        return dec.update(ct)
    ret = b''
    pos = ((len(ct) + 15) // 16) * 16 - 16
    cbc = Cipher(algorithms.AES(key), modes.CBC(b'\0'*16)).decryptor()
#   TODO Support CTS (Ciphertext Stealing)
#    ecb = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    s1 = ct[pos:]
    s1 += b'\0' * (16 - len(s1))
    s2 = ct[pos-16:pos]
    return ret + cbc.update(s1 + s2)


def get_file_key(inode, verbose=False):
    """Get a FBE file encryption key

    @param inode inode of a file
    @return file encryption key
    """
    enc_ctx = get_xaatr(inode, 'c')
    fsc = parse_enc_ctx(enc_ctx)
    mkey = master_key[fsc.mk_ident]
    nonce = fsc.nonce
    if verbose:
        print("Master key", master_key[fsc.mk_ident].hex())
        print("Nonce", nonce.hex())
    prk = HMAC(b'', mkey, 'sha512').digest()
    h = HMAC(prk,  b'fscrypt\x00', 'sha512')
    h.update(b'\x02')
    h.update(nonce)
    h.update(b'\x01')
    return h.digest()


def listdir(inode_data, dir_inode=None, decrypt=False):
    """List a directory

    @param inode_data encrypted or unencrypted directory entries
    @param dir_inode inode of a directory
    @param decrypt process decryption
    """
    pos = 0
    if decrypt and dir_inode and is_encrypted(dir_inode):
        name_key = get_file_key(dir_inode)
        print("Key", key.hex())
    idx = 0
    entry_fmt = '<IHBB'
    entry_size = calcsize(entry_fmt)
    while pos < len(inode_data):
        inode, rec_len, name_len, file_type \
                = unpack(entry_fmt, inode_data[pos:pos+entry_size])
        if inode == 0:
            break

        idx += 1
        pos += entry_size
        name = inode_data[pos:pos+name_len]
        pos += name_len
        pos = (pos + 3) & ~3

        if len(name) >= 16 and decrypt and dir_inode:
            pt = aes_cbc_cts_decrypt(name_key[:32], name)
            name = pt.decode().rstrip('\0')
            print(f"{inode:10d} {rec_len:5d} {name_len:3d} {file_type:3d} {name:12s}", end='')
            if file_type == 2: # directory
                print()
                continue

            content = get_file_content(inode)
            content_key = get_file_key(inode)
            info = stat(inode)
            filesize = info['size']

            open(name + ".enc", 'wb').write(content)
            buf = aes_xts_decrypt(content_key, content)
            open(name + ".dec", 'wb').write(buf[:filesize])
            print(f'  =>  {name}.dec (decrypted)')

        else:
            try:
                name = name.decode()
                print(f"{inode:10d} {rec_len:5d} {name_len:3d} {file_type:3d} {name:12s}")
            except:
                print(f"{inode:10d} {rec_len:5d} {name_len:3d} {file_type:3d} <Encrypted> : {name.hex()}")


def aes_xts_decrypt(key, content):
    """Decrypt the content of a file using AES-XTS

    @param key file encryption key
    @param content file data
    @return decrypted file data
    """
    pt = b''
    for block_num in range(len(content) // block_size):
        tweak = block_num.to_bytes(16, 'little')
        dec = Cipher(algorithms.AES(key), modes.XTS(tweak)).decryptor()
        start = block_num * block_size
        end = start + block_size
        ct = content[start:end]
        pt += dec.update(ct) + dec.finalize()
    return pt


def add_master_key(key):
    """Add master key for FBE decryption

    @param key master key to register
    """
    global master_key
    # HKDF-SHA512
    prk = HMAC(b'', key, 'sha512').digest()
    fscrypt = b'fscrypt\x00'
    info = b'\x01'
    ctr = b'\x01'
    ident = HMAC(prk, fscrypt + info + ctr, 'sha512').digest()[:16]
    print(f"[+] Found master key\n- Key Identifier: {ident.hex()}\n- Master key: {key.hex()}")
    master_key[ident] = key


def decrypt_key(encrypted_key, key_blob):
    """Decrypt FBE master key through HKDF2-SHA512 method

    @param encrypted_key encrypted key data
    @param key_blob keymaster key blob file for key decryption
    @return decrypted master key
    """
    ver, key_len, key = unpack('<BI32s', key_blob[:37])
    signature = key_blob[-8:]
	# TODO signaature verification
    # hmac(b'IntegrityAssuredBlob0\0', key_blob[:-8])
	# hidden_params = bytes.fromhex('53570200000018000000590200900000000000000000c00200900200000000000000')
    nonce = encrypted_key[:12]
    ct_tag = encrypted_key[12:]
    gcm = AESGCM(key)
    pt = gcm.decrypt(nonce, ct_tag, b'')
    return pt


if __name__ == "__main__":
    parser = ArgumentParser(description="Android FBE decryptor",
                            usage="%(prog)s -i userdata.enc -e dm-40 [-h]")
    parser.add_argument('-i', dest='input_file', required=True,
                        help="path to the encrypted input image")
    parser.add_argument('-e', dest='ext4_img', required=True,
                        help="path to the device mapper image")
    args = parser.parse_args()

    root_data = stat('/')
    inode_data = dump_content(root_data['inode'])
    block_size = get_block_size()

    for prefix in ['unencrypted/key/', '/misc/vold/user_keys/de/0/']:
        encrypted_key = dump_content(prefix + 'encrypted_key')
        secdiscardable = dump_content(prefix + 'secdiscardable')
        keymaster_key_blob = dump_content(prefix + 'keymaster_key_blob')
        # print(len(keymaster_key_blob))
        # print(keymaster_key_blob.hex())
        key = decrypt_key(encrypted_key, keymaster_key_blob)
        add_master_key(key)

    target = '/system_de/0'
    if is_encrypted(target):
        print(f"[+] {target} is encrypted")

    print("Press <Return> to continue")
    input()

    info = stat(target)
    data = dump_content(info['inode'])
    print(f"[+] original directory: {target}")
    listdir(data)
    print("Press <Return> to continue")
    input()

    print(f"[+] decrypt directory: {target}")
    listdir(data, dir_inode=info['inode'], decrypt=True)
