"""
File I/O utilities for CryptoCore.
Handles reading/writing binary files and PKCS#7 padding.
"""

def read_file(filepath: str) -> bytes:
    """Read file as binary."""
    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except Exception as e:
        raise Exception(f"Error reading file {filepath}: {e}")

def write_file(filepath: str, data: bytes) -> None:
    """Write binary data to file."""
    try:
        with open(filepath, 'wb') as f:
            f.write(data)
    except Exception as e:
        raise Exception(f"Error writing file {filepath}: {e}")

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Add PKCS#7 padding."""
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Remove and verify PKCS#7 padding."""
    if not data:
        raise ValueError("Empty data")
    
    padding_len = data[-1]
    if padding_len > block_size or padding_len == 0:
        raise ValueError("Invalid padding")
    
    # Проверяем что все байты padding'а одинаковые
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding")
    
    return data[:-padding_len]
