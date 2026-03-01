"""
Authenticated Encryption using Encrypt-then-MAC paradigm.
Combines CTR mode encryption with HMAC-SHA256 authentication.
"""

import os
from Crypto.Cipher import AES
from src.mac.hmac import HMAC
from src.file_io import write_file, read_file

BLOCK_SIZE = 16
HMAC_SIZE = 32  # SHA-256 output size

def encrypt_then_mac(key_enc: bytes, key_mac: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """
    Encrypt-then-MAC: Encrypt with CTR, then compute HMAC of (ciphertext || AAD).
    
    Args:
        key_enc: 16-byte encryption key
        key_mac: 32-byte HMAC key (can be derived from master key)
        plaintext: Data to encrypt
        aad: Additional authenticated data (optional)
    
    Returns:
        bytes: IV (16) + ciphertext + HMAC (32)
    """
    # 1. Generate random IV
    iv = os.urandom(BLOCK_SIZE)
    
    # 2. Encrypt with CTR mode
    cipher = AES.new(key_enc, AES.MODE_CTR, nonce=iv[:8])
    ciphertext = cipher.encrypt(plaintext)
    
    # 3. Compute HMAC of (ciphertext || AAD)
    hmac_obj = HMAC(key_mac)
    data_to_auth = ciphertext + aad
    tag = hmac_obj.compute(data_to_auth)
    
    # 4. Return IV + ciphertext + tag
    return iv + ciphertext + tag

def decrypt_verify(key_enc: bytes, key_mac: bytes, data: bytes, aad: bytes = b"") -> bytes:
    """
    Decrypt and verify: Check HMAC first, then decrypt if valid.
    
    Args:
        key_enc: 16-byte encryption key
        key_mac: 32-byte HMAC key
        data: IV (16) + ciphertext + HMAC (32)
        aad: Additional authenticated data (optional)
    
    Returns:
        bytes: Decrypted plaintext
    
    Raises:
        Exception: If HMAC verification fails
    """
    # 1. Split data
    if len(data) < BLOCK_SIZE + HMAC_SIZE:
        raise ValueError("Data too short")
    
    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:-HMAC_SIZE]
    received_tag = data[-HMAC_SIZE:]
    
    # 2. Verify HMAC first (do this BEFORE decryption)
    hmac_obj = HMAC(key_mac)
    data_to_auth = ciphertext + aad
    expected_tag = hmac_obj.compute(data_to_auth)
    
    if received_tag != expected_tag:
        raise Exception("AUTHENTICATION FAILED: Data corrupted or wrong key/AAD")
    
    # 3. If verification passed, decrypt
    cipher = AES.new(key_enc, AES.MODE_CTR, nonce=iv[:8])
    plaintext = cipher.decrypt(ciphertext)
    
    return plaintext

def derive_keys(master_key: bytes) -> tuple:
    """
    Derive encryption and MAC keys from a master key.
    Simple key separation using different contexts.
    
    Args:
        master_key: 32-byte master key
    
    Returns:
        tuple: (enc_key, mac_key)
    """
    # Simple KDF: different parts of master key
    # In production, use HKDF, but for simplicity:
    enc_key = master_key[:16]   # First 16 bytes for encryption
    mac_key = master_key[16:]   # Last 16 bytes for MAC
    return enc_key, mac_key
