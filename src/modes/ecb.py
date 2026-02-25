"""
ECB mode implementation using AES from pycryptodome.
"""

from Crypto.Cipher import AES
from file_io import pkcs7_pad, pkcs7_unpad  # убрали точки

def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128 in ECB mode.
    Automatically adds PKCS#7 padding.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pkcs7_pad(plaintext)
    return cipher.encrypt(padded_data)

def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128 in ECB mode.
    Automatically removes PKCS#7 padding.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = cipher.decrypt(ciphertext)
    return pkcs7_unpad(padded_data)
