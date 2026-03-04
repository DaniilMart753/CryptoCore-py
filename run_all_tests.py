#!/usr/bin/env python3
import subprocess

print("Запуск всех тестов...")

tests = [
    ("HMAC", "python test_hmac.py"),
    ("AEAD", "python test_aead.py"),
    ("PBKDF2", "python test_pbkdf2.py"),
]

for name, cmd in tests:
    print(f"\n▶ {name}")
    result = subprocess.run(cmd, shell=True)
    if result.returncode == 0:
        print(f"  OK")
    else:
        print(f"  ОШИБКА")

print("\nВсе тесты выполнены")
