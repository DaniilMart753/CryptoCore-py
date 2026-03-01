"""
PBKDF2-HMAC-SHA256 implementation (RFC 2898).
Derives cryptographic keys from passwords.
"""

import os
import struct
from src.mac.hmac import hmac_sha256

class PBKDF2:
    """
    PBKDF2 key derivation function using HMAC-SHA256.
    
    Example:
        kdf = PBKDF2()
        key = kdf.derive(b"password", salt=b"salt", iterations=100000, dklen=32)
    """
    
    def __init__(self, hash_func=hmac_sha256, hash_len=32):
        """
        Initialize PBKDF2 with hash function.
        
        Args:
            hash_func: Underlying PRF (default: HMAC-SHA256)
            hash_len: Output length of hash function in bytes (32 for SHA256)
        """
        self.hash_func = hash_func
        self.hash_len = hash_len
    
    def derive(self, password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
        """
        Derive key using PBKDF2-HMAC-SHA256.
        
        Args:
            password: Password bytes
            salt: Salt bytes (should be random, at least 8-16 bytes)
            iterations: Iteration count (minimum 1000, recommended 100000+)
            dklen: Desired key length in bytes
        
        Returns:
            bytes: Derived key of length dklen
        """
        if iterations < 1:
            raise ValueError("Iterations must be >= 1")
        
        # Number of blocks needed
        blocks_needed = (dklen + self.hash_len - 1) // self.hash_len
        derived = b""
        
        for block in range(1, blocks_needed + 1):
            # U1 = HMAC(password, salt || INT_32_BE(block))
            block_bytes = struct.pack(">I", block)
            u = self.hash_func(password, salt + block_bytes)
            
            # First block value
            block_key = u
            
            # U2..Uc
            for j in range(1, iterations):
                u = self.hash_func(password, u)
                # XOR block_key with u
                xored = bytearray(block_key)
                for k in range(self.hash_len):
                    xored[k] ^= u[k]
                block_key = bytes(xored)
            
            derived += block_key
        
        return derived[:dklen]
    
    def generate_salt(self, length: int = 16) -> bytes:
        """
        Generate random salt.
        
        Args:
            length: Salt length in bytes
        
        Returns:
            bytes: Random salt
        """
        return os.urandom(length)


# Convenience function
def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    """
    PBKDF2-HMAC-SHA256 convenience function.
    
    Args:
        password: Password bytes
        salt: Salt bytes
        iterations: Iteration count
        dklen: Desired key length
    
    Returns:
        bytes: Derived key
    """
    kdf = PBKDF2()
    return kdf.derive(password, salt, iterations, dklen)
