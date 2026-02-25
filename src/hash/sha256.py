"""
SHA-256 implementation from scratch following NIST FIPS 180-4.
No external libraries used - pure Python implementation.
"""

import struct

class SHA256:
    """
    SHA-256 hash algorithm implementation.
    
    Example:
        sha = SHA256()
        sha.update(b"Hello world")
        digest = sha.digest()  # bytes
        hex_digest = sha.hexdigest()  # hex string
    """
    
    # Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    # Round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    def __init__(self):
        """Initialize SHA-256 with initial hash values."""
        self.h = self.H[:]  # Copy initial hash values
        self._message = b""  # Message being processed
        self._length = 0     # Length in bits
    
    def _rotr(self, x, n):
        """Rotate right operation (circular shift)."""
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
    
    def _shr(self, x, n):
        """Shift right operation."""
        return x >> n
    
    def _ch(self, x, y, z):
        """Choose function: (x & y) ^ (~x & z)"""
        return (x & y) ^ ((~x) & z)
    
    def _maj(self, x, y, z):
        """Majority function: (x & y) ^ (x & z) ^ (y & z)"""
        return (x & y) ^ (x & z) ^ (y & z)
    
    def _sigma0(self, x):
        """Sigma0 function: rotr(x,2) ^ rotr(x,13) ^ rotr(x,22)"""
        return self._rotr(x, 2) ^ self._rotr(x, 13) ^ self._rotr(x, 22)
    
    def _sigma1(self, x):
        """Sigma1 function: rotr(x,6) ^ rotr(x,11) ^ rotr(x,25)"""
        return self._rotr(x, 6) ^ self._rotr(x, 11) ^ self._rotr(x, 25)
    
    def _gamma0(self, x):
        """Gamma0 function: rotr(x,7) ^ rotr(x,18) ^ shr(x,3)"""
        return self._rotr(x, 7) ^ self._rotr(x, 18) ^ self._shr(x, 3)
    
    def _gamma1(self, x):
        """Gamma1 function: rotr(x,17) ^ rotr(x,19) ^ shr(x,10)"""
        return self._rotr(x, 17) ^ self._rotr(x, 19) ^ self._shr(x, 10)
    
    def _process_block(self, block):
        """
        Process a single 512-bit (64-byte) block.
        
        Args:
            block: 64-byte block of data
        """
        # Prepare message schedule (80 32-bit words)
        w = [0] * 64
        
        # First 16 words are from the block
        for i in range(16):
            w[i] = struct.unpack(">I", block[i*4:(i+1)*4])[0]
        
        # Extend to 64 words
        for i in range(16, 64):
            w[i] = (self._gamma1(w[i-2]) + w[i-7] + self._gamma0(w[i-15]) + w[i-16]) & 0xFFFFFFFF
        
        # Initialize working variables
        a, b, c, d = self.h[0], self.h[1], self.h[2], self.h[3]
        e, f, g, h = self.h[4], self.h[5], self.h[6], self.h[7]
        
        # Main compression loop
        for i in range(64):
            t1 = (h + self._sigma1(e) + self._ch(e, f, g) + self.K[i] + w[i]) & 0xFFFFFFFF
            t2 = (self._sigma0(a) + self._maj(a, b, c)) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF
        
        # Update hash values
        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + h) & 0xFFFFFFFF
    
    def update(self, data: bytes):
        """
        Update the hash with new data.
        
        Args:
            data: Bytes to add to the hash
        """
        self._message += data
        self._length += len(data) * 8  # Length in bits
        
        # Process complete blocks
        while len(self._message) >= 64:
            block = self._message[:64]
            self._process_block(block)
            self._message = self._message[64:]
    
    def digest(self) -> bytes:
        """
        Return the final hash value as bytes.
        
        Returns:
            bytes: 32-byte SHA-256 hash
        """
        # Make a copy of current state
        h_copy = self.h[:]
        message_copy = self._message
        length_copy = self._length
        
        # Padding: append 0x80, then zeros, then 64-bit length
        padding = b"\x80"
        padding += b"\x00" * ((56 - (len(message_copy) + 1) % 64) % 64)
        padding += struct.pack(">Q", length_copy)
        
        # Process remaining data with padding
        self.update(padding)
        
        # Get final hash
        result = b"".join(struct.pack(">I", h) for h in self.h)
        
        # Restore state
        self.h = h_copy
        self._message = message_copy
        self._length = length_copy
        
        return result
    
    def hexdigest(self) -> str:
        """Return the final hash value as hexadecimal string."""
        return self.digest().hex()

def sha256(data: bytes) -> bytes:
    """
    Convenience function to compute SHA-256 hash of data.
    
    Args:
        data: Input bytes
        
    Returns:
        bytes: 32-byte SHA-256 hash
    """
    sha = SHA256()
    sha.update(data)
    return sha.digest()

def sha256_hex(data: bytes) -> str:
    """
    Convenience function to compute SHA-256 hash as hex string.
    
    Args:
        data: Input bytes
        
    Returns:
        str: Hexadecimal SHA-256 hash (64 chars)
    """
    return sha256(data).hex()
