# Руководство пользователя

## Установка
git clone https://github.com/DaniilMart753/CryptoCore-py.git

cd CryptoCore-py

python3 -m venv venv

source venv/bin/activate

pip install pycryptodome

## Шифрование с ключом
python src/cli.py --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input file.txt

## Шифрование без ключа
python src/cli.py --algorithm aes --mode cbc --encrypt --input file.txt

## Расшифровка
python src/cli.py --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --input file.txt.enc

## SHA-256
python -c "from src.hash.sha256 import sha256_hex; print(sha256_hex(b'hello'))"

## HMAC
python -c "from src.mac.hmac import hmac_sha256; print(hmac_sha256(b'key', b'data').hex())"

## PBKDF2
python -c "from src.kdf.pbkdf2 import pbkdf2_hmac_sha256; print(pbkdf2_hmac_sha256(b'password', b'salt', 1000, 32).hex())"

## Тестыpython test_hmac_full.py
python test_aead.py

python test_pbkdf2.py

python run_all_tests.py
