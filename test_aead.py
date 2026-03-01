#!/usr/bin/env python3
"""
Test authenticated encryption (Encrypt-then-MAC).
"""

import os
from src.modes.aead import encrypt_then_mac, decrypt_verify, derive_keys

def test_aead():
    """Test basic encryption/decryption with authentication."""
    
    # Master key (32 bytes)
    master_key = os.urandom(32)
    enc_key, mac_key = derive_keys(master_key)
    
    print("=" * 60)
    print("AEAD Encrypt-then-MAC Test")
    print("=" * 60)
    
    # Test 1: Normal encryption/decryption
    print("\n1. Normal operation:")
    plaintext = b"Secret message: The password is 'password123'"
    aad = b"metadata: version 1.0"
    
    ciphertext = encrypt_then_mac(enc_key, mac_key, plaintext, aad)
    print(f"   Plaintext size: {len(plaintext)} bytes")
    print(f"   Ciphertext size: {len(ciphertext)} bytes")
    print(f"   (IV:16 + ciphertext:? + HMAC:32)")
    
    decrypted = decrypt_verify(enc_key, mac_key, ciphertext, aad)
    print(f"   Decrypted: {decrypted.decode()}")
    print(f"   Success: {decrypted == plaintext}")
    
    # Test 2: Tampered ciphertext
    print("\n2. Tampering test:")
    tampered = bytearray(ciphertext)
    tampered[20] ^= 0x01  # Flip one bit in ciphertext
    
    try:
        decrypt_verify(enc_key, mac_key, bytes(tampered), aad)
        print("   ❌ FAIL: Tampered data was accepted!")
    except Exception as e:
        print(f"   ✅ PASS: Tampered data rejected: {e}")
    
    # Test 3: Wrong AAD
    print("\n3. Wrong AAD test:")
    wrong_aad = b"metadata: version 2.0"
    
    try:
        decrypt_verify(enc_key, mac_key, ciphertext, wrong_aad)
        print("   ❌ FAIL: Wrong AAD was accepted!")
    except Exception as e:
        print(f"   ✅ PASS: Wrong AAD rejected: {e}")
    
    # Test 4: Wrong key
    print("\n4. Wrong key test:")
    wrong_master = os.urandom(32)
    wrong_enc, wrong_mac = derive_keys(wrong_master)
    
    try:
        decrypt_verify(wrong_enc, wrong_mac, ciphertext, aad)
        print("   ❌ FAIL: Wrong key was accepted!")
    except Exception as e:
        print(f"   ✅ PASS: Wrong key rejected: {e}")

if __name__ == "__main__":
    test_aead()
