#!/usr/bin/env python3
"""
CLI parser for CryptoCore.
Handles command-line arguments for encryption/decryption.
"""

import argparse
import sys
from file_io import read_file, write_file
from modes.ecb import encrypt_ecb, decrypt_ecb

def parse_args():
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        description="CryptoCore - cryptographic operations tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--algorithm', required=True, choices=['aes'],
                        help='Algorithm to use (only aes for now)')
    
    parser.add_argument('--mode', required=True, choices=['ecb'],
                        help='Mode of operation (only ecb for now)')
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--encrypt', action='store_true',
                       help='Encrypt the input file')
    group.add_argument('--decrypt', action='store_true',
                       help='Decrypt the input file')
    
    parser.add_argument('--key', required=True,
                        help='Encryption key in hexadecimal (32 chars for 16 bytes)')
    
    parser.add_argument('--input', required=True,
                        help='Input file path')
    
    parser.add_argument('--output',
                        help='Output file path (default: input.enc for encrypt, input.dec for decrypt)')
    
    args = parser.parse_args()
    
    # Валидация ключа
    if len(args.key) != 32:
        parser.error(f"Key must be 32 hex chars (16 bytes), got {len(args.key)}")
    
    try:
        bytes.fromhex(args.key)
    except ValueError:
        parser.error("Key must be valid hexadecimal")
    
    # Стандартное имя выходного файла
    if not args.output:
        if args.encrypt:
            args.output = args.input + '.enc'
        else:
            args.output = args.input + '.dec'
    
    return args

def main():
    """Main CLI entry point."""
    args = parse_args()
    
    # Конвертируем ключ из hex в байты
    key = bytes.fromhex(args.key)
    
    try:
        # Читаем входной файл
        data = read_file(args.input)
        print(f"Read {len(data)} bytes from {args.input}")
        
        # Выполняем операцию
        if args.encrypt:
            print("Encrypting...")
            result = encrypt_ecb(key, data)
        else:
            print("Decrypting...")
            result = decrypt_ecb(key, data)
        
        # Записываем результат
        write_file(args.output, result)
        print(f"Success! Wrote {len(result)} bytes to {args.output}")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
