"""
HMAC implementation based on RFC 2104 and RFC 4231.
Uses SHA-256 as the underlying hash function.
"""

from src.hash.sha256 import SHA256

class HMAC:
    """
    HMAC-SHA256 implementation.
    
    Example:
        hmac = HMAC(b"key")
        mac = hmac.compute(b"message")
        is_valid = hmac.verify(b"message", mac)
    """
    
    def __init__(self, key: bytes):
        """
        Initialize HMAC with a key.
        
        Args:
            key: Variable-length key (bytes)
        """
        self.block_size = 64  # SHA-256 block size (512 bits)
        self.hash_size = 32   # SHA-256 output size (256 bits)
        
        # Process key according to RFC 2104
        if len(key) > self.block_size:
            # If key is longer than block size, hash it
            sha = SHA256()
            sha.update(key)
            key = sha.digest()
        
        if len(key) < self.block_size:
            # If key is shorter, pad with zeros
            key = key + b'\x00' * (self.block_size - len(key))
        
        self.key = key
        
        # Precompute inner and outer padded keys
        self.ipad = bytes([x ^ 0x36 for x in self.key])
        self.opad = bytes([x ^ 0x5c for x in self.key])
    
    def compute(self, message: bytes) -> bytes:
        """
        Compute HMAC-SHA256 of message.
        
        Args:
            message: Input message (bytes)
            
        Returns:
            bytes: 32-byte HMAC-SHA256 value
        """
        # Inner hash: H((key ^ ipad) || message)
        inner = SHA256()
        inner.update(self.ipad + message)
        inner_hash = inner.digest()
        
        # Outer hash: H((key ^ opad) || inner_hash)
        outer = SHA256()
        outer.update(self.opad + inner_hash)
        return outer.digest()
    
    def verify(self, message: bytes, mac: bytes) -> bool:
        """
        Verify HMAC-SHA256 of message.
        
        Args:
            message: Input message (bytes)
            mac: Expected HMAC value (bytes)
            
        Returns:
            bool: True if MAC matches, False otherwise
        """
        computed = self.compute(message)
        return computed == mac


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """
    Convenience function to compute HMAC-SHA256.
    
    Args:
        key: HMAC key (bytes)
        message: Input message (bytes)
        
    Returns:
        bytes: 32-byte HMAC-SHA256 value
    """
    hmac = HMAC(key)
    return hmac.compute(message)
