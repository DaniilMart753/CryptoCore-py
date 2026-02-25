"""
Cryptographically Secure Random Number Generator (CSPRNG)
Uses os.urandom() which is cryptographically secure on all major platforms.
"""

import os

def random_bytes(num_bytes: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        num_bytes: Number of random bytes to generate
        
    Returns:
        bytes: Random byte string of length num_bytes
    """
    return os.urandom(num_bytes)

def generate_key() -> bytes:
    """
    Generate a random 16-byte (128-bit) key for AES-128.
    
    Returns:
        bytes: 16 random bytes
    """
    return random_bytes(16)

def generate_iv() -> bytes:
    """
    Generate a random 16-byte initialization vector (IV).
    
    Returns:
        bytes: 16 random bytes
    """
    return random_bytes(16)
