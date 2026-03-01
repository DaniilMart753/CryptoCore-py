#!/usr/bin/env python3
"""
Test PBKDF2-HMAC-SHA256 with RFC 6070 test vectors.
"""

from src.kdf.pbkdf2 import pbkdf2_hmac_sha256

# RFC 6070 test vectors (правильные значения!)
test_vectors = [
    {   # Test Case 1
        'password': b"password",
        'salt': b"salt",
        'iterations': 1,
        'dklen': 20,
        'expected': "120fb6cffcf8b32c43e7225256c4f837a86548c9"
    },
    {   # Test Case 2
        'password': b"password",
        'salt': b"salt",
        'iterations': 2,
        'dklen': 20,
        'expected': "ae4d0c95af6b46d32d0adff928f06dd02a303f8e"
    },
    {   # Test Case 3
        'password': b"password",
        'salt': b"salt",
        'iterations': 4096,
        'dklen': 20,
        'expected': "c5e478d59288c841aa530db6845c4c8d962893a0"
    },
    {   # Test Case 4
        'password': b"passwordPASSWORDpassword",
        'salt': b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
        'iterations': 4096,
        'dklen': 25,
        'expected': "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c"
    },
    {   # Test Case 5
        'password': b"pass\0word",
        'salt': b"sa\0lt",
        'iterations': 4096,
        'dklen': 16,
        'expected': "89b69d0516f829893c696226650a8687"
    }
]

print("=" * 70)
print("PBKDF2-HMAC-SHA256 TEST SUITE (RFC 6070)")
print("=" * 70)

for i, tv in enumerate(test_vectors, 1):
    print(f"\n--- Test Case {i} ---")
    print(f"Iterations: {tv['iterations']}")
    print(f"DKLen: {tv['dklen']} bytes")
    
    try:
        result = pbkdf2_hmac_sha256(
            tv['password'],
            tv['salt'],
            tv['iterations'],
            tv['dklen']
        )
        
        result_hex = result.hex()
        expected = tv['expected']
        
        # Проверяем длину
        print(f"Result length: {len(result)} bytes (expected {tv['dklen']})")
        
        # Сравниваем
        if result_hex == expected:
            print(f"Status: ✓ PASS")
        else:
            print(f"Status: ✗ FAIL")
            print(f"Expected: {expected}")
            print(f"Got:      {result_hex}")
            
            # Побайтовое сравнение для отладки
            print("\nFirst 20 bytes comparison:")
            for j in range(0, min(40, len(expected), len(result_hex)), 2):
                e_byte = expected[j:j+2]
                r_byte = result_hex[j:j+2]
                marker = "✓" if e_byte == r_byte else "✗"
                print(f"  {j//2:2d}: {e_byte} vs {r_byte} {marker}")
            
    except Exception as e:
        print(f"ERROR: {e}")

print("\n" + "=" * 70)
