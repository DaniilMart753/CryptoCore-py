#!/usr/bin/env python3
"""
CLI parser for CryptoCore.
Handles command-line arguments for encryption/decryption.
"""

import sys
import os
import argparse

# Добавляем путь к корневой папке проекта
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.file_io import read_file, write_file
from src.modes import (
    encrypt_ecb, decrypt_ecb,
    encrypt_cbc, decrypt_cbc,
    encrypt_cfb, decrypt_cfb,
    encrypt_ofb, decrypt_ofb,
    encrypt_ctr, decrypt_ctr
)

def parse_args():
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        description="CryptoCore - cryptographic operations tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--algorithm', required=True, choices=['aes'],
                        help='Algorithm to use')
    
    parser.add_argument('--mode', required=True, 
                        choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'],
                        help='Mode of operation')
    
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

def get_mode_function(mode: str, operation: str):
    """Return appropriate encryption/decryption function for the mode."""
    modes = {
        'ecb': (encrypt_ecb, decrypt_ecb),
        'cbc': (encrypt_cbc, decrypt_cbc),
        'cfb': (encrypt_cfb, decrypt_cfb),
        'ofb': (encrypt_ofb, decrypt_ofb),
        'ctr': (encrypt_ctr, decrypt_ctr),
    }
    enc_func, dec_func = modes[mode]
    return enc_func if operation == 'encrypt' else dec_func

def main():
    """Main CLI entry point."""
    args = parse_args()
    
    # Конвертируем ключ из hex в байты
    key = bytes.fromhex(args.key)
    
    try:
        # Читаем входной файл
        data = read_file(args.input)
        print(f"Read {len(data)} bytes from {args.input}")
        
        # Получаем нужную функцию
        func = get_mode_function(args.mode, 'encrypt' if args.encrypt else 'decrypt')
        
        # Выполняем операцию
        print(f"{'Encrypting' if args.encrypt else 'Decrypting'} in {args.mode.upper()} mode...")
        result = func(key, data)
        
        # Записываем результат
        write_file(args.output, result)
        print(f"Success! Wrote {len(result)} bytes to {args.output}")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
