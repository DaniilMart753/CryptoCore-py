#!/usr/bin/env python3
"""
Test SHA-256 implementation with NIST test vectors.
"""

from src.hash.sha256 import sha256_hex

# Test vectors from NIST
test_cases = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    (b"Hello, World!", "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"),
]

print("Testing SHA-256 implementation...")
print("-" * 80)

for i, (data, expected) in enumerate(test_cases):
    result = sha256_hex(data)
    status = "✓ PASS" if result == expected else "✗ FAIL"
    print(f"Test {i+1}: {status}")
    print(f"  Input: {data[:50]}{'...' if len(data) > 50 else ''}")
    print(f"  Expected: {expected}")
    print(f"  Got:      {result}")
    if result != expected:
        print(f"  ❌ Test failed!")
    print()
