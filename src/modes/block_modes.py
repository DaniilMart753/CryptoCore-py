"""
Block cipher modes of operation (CBC, CFB, OFB, CTR) using AES.
All modes handle IV properly:
- Encryption: generates random IV, prepends to output
- Decryption: reads IV from beginning of input
"""

import os
from Crypto.Cipher import AES
from src.file_io import pkcs7_pad, pkcs7_unpad

BLOCK_SIZE = 16

def encrypt_cbc(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt using CBC mode. Returns IV + ciphertext."""
    iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pkcs7_pad(plaintext)
    ciphertext = cipher.encrypt(padded)
    return iv + ciphertext

def decrypt_cbc(key: bytes, data: bytes) -> bytes:
    """Decrypt using CBC mode. First 16 bytes are IV."""
    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    return pkcs7_unpad(padded)

def encrypt_cfb(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt using CFB mode (no padding needed). Returns IV + ciphertext."""
    iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    ciphertext = cipher.encrypt(plaintext)
    return iv + ciphertext

def decrypt_cfb(key: bytes, data: bytes) -> bytes:
    """Decrypt using CFB mode. First 16 bytes are IV."""
    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    return cipher.decrypt(ciphertext)

def encrypt_ofb(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt using OFB mode (no padding needed). Returns IV + ciphertext."""
    iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher.encrypt(plaintext)
    return iv + ciphertext

def decrypt_ofb(key: bytes, data: bytes) -> bytes:
    """Decrypt using OFB mode. First 16 bytes are IV."""
    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_OFB, iv)
    return cipher.decrypt(ciphertext)

def encrypt_ctr(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt using CTR mode (no padding needed). Returns IV + ciphertext."""
    iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
    ciphertext = cipher.encrypt(plaintext)
    return iv + ciphertext

def decrypt_ctr(key: bytes, data: bytes) -> bytes:
    """Decrypt using CTR mode. First 16 bytes are IV."""
    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
    return cipher.decrypt(ciphertext)
