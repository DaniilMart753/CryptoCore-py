#!/usr/bin/env python3
"""
Comprehensive HMAC-SHA256 test with RFC 4231 vectors.
Tests all 4 test cases and prints detailed comparison.
"""

from src.mac.hmac import HMAC, hmac_sha256

# RFC 4231 test vectors (Section 4.2)
TEST_VECTORS = [
    {   # Test Case 1
        'key': '0b' * 20,
        'key_desc': '20 bytes of 0x0b',
        'data': 'Hi There',
        'data_desc': 'ASCII string "Hi There"',
        'expected': 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
    },
    {   # Test Case 2
        'key': '4a656665',  # "Jefe" in hex
        'key_desc': 'ASCII "Jefe" (4 bytes)',
        'data': 'what do ya want for nothing?',
        'data_desc': 'ASCII string',
        'expected': '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'
    },
    {   # Test Case 3
        'key': 'aa' * 20,
        'key_desc': '20 bytes of 0xaa',
        'data': 'dd' * 50,
        'data_desc': '50 bytes of 0xdd',
        'expected': '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe'
    },
    {   # Test Case 4
        'key': '0102030405060708090a0b0c0d0e0f10111213141516171819',
        'key_desc': '25-byte key',
        'data': 'cd' * 50,
        'data_desc': '50 bytes of 0xcd',
        'expected': '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b'
    }
]

def hex_or_ascii(data: str, is_hex: bool = False) -> bytes:
    """Convert string to bytes, handling hex if needed."""
    if is_hex:
        return bytes.fromhex(data)
    return data.encode('ascii')

def test_vector(tv):
    """Test a single vector and return (passed, result, expected)."""
    # Prepare data
    key = hex_or_ascii(tv['key'], True)
    
    # Check if data is hex or ascii
    data_is_hex = all(c in '0123456789abcdef' for c in tv['data'].lower())
    data = hex_or_ascii(tv['data'], data_is_hex)
    expected = tv['expected']
    
    # Compute HMAC
    result = hmac_sha256(key, data)
    result_hex = result.hex()
    
    return result_hex == expected, result_hex, expected

def main():
    print("=" * 80)
    print("HMAC-SHA256 TEST SUITE (RFC 4231)")
    print("=" * 80)
    
    all_passed = True
    
    for i, tv in enumerate(TEST_VECTORS, 1):
        print(f"\n--- Test Case {i} ---")
        print(f"Key: {tv['key_desc']}")
        print(f"Data: {tv['data_desc']}")
        
        passed, result, expected = test_vector(tv)
        
        if passed:
            print("✅ PASSED")
        else:
            print("❌ FAILED")
            all_passed = False
        
        print(f"Result:   {result}")
        print(f"Expected: {expected}")
        
        # Show first few bytes comparison
        if result != expected:
            print("\nFirst 16 bytes comparison:")
            print(f"Result:   {result[:32]}")
            print(f"Expected: {expected[:32]}")
    
    print("\n" + "=" * 80)
    if all_passed:
        print("✅ ALL TESTS PASSED! HMAC-SHA256 implementation is correct.")
    else:
        print("❌ SOME TESTS FAILED. Need to fix implementation.")
    print("=" * 80)

if __name__ == '__main__':
    main()
