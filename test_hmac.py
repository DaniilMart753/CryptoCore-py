#!/usr/bin/env python3
"""
Test HMAC-SHA256 implementation with RFC 4231 test vectors.
"""

from src.mac.hmac import hmac_sha256

# Test vectors from RFC 4231 (Section 4.2)
test_cases = [
    # Test Case 1
    {
        'key': bytes.fromhex('0b' * 20),  # 20 bytes of 0x0b
        'data': b'Hi There',
        'expected': 'b0344c61d8db38535ca8afceaf0bf12b881dc20c9833da726e9376c2e32cff7'
    },
    # Test Case 2
    {
        'key': b'Jefe',
        'data': b'what do ya want for nothing?',
        'expected': '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'
    },
    # Test Case 3
    {
        'key': bytes.fromhex('aa' * 20),
        'data': bytes.fromhex('dd' * 50),
        'expected': '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe'
    },
    # Test Case 4
    {
        'key': bytes.fromhex('0102030405060708090a0b0c0d0e0f10111213141516171819'),
        'data': bytes.fromhex('cd' * 50),
        'expected': '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b'
    }
]

print("Testing HMAC-SHA256 with RFC 4231 test vectors...")
print("-" * 80)

for i, test in enumerate(test_cases):
    key = test['key']
    data = test['data']
    expected = test['expected']
    
    # Compute HMAC
    result = hmac_sha256(key, data)
    result_hex = result.hex()
    
    # Check
    status = "✓ PASS" if result_hex == expected else "✗ FAIL"
    print(f"Test {i+1}: {status}")
    print(f"  Key: {key.hex()[:30]}...")
    print(f"  Data: {data[:30]}...")
    print(f"  Expected: {expected}")
    print(f"  Got:      {result_hex}")
    if result_hex != expected:
        print(f"  ❌ Test failed!")
    print()
