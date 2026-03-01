# Руководство пользователя

## Установка
```bash
git clone https://github.com/DaniilMart753/CryptoCore-py.git
cd CryptoCore-py
python3 -m venv venv
source venv/bin/activate
pip install pycryptodome

# Команды

## Шифрование с ключом
python src/cli.py --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input file.txt

## Шифрование без ключа (ключ сгенерируется автоматически)
python src/cli.py --algorithm aes --mode cbc --encrypt --input file.txt

## Расшифровка
python src/cli.py --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --input file.txt.enc

## Тесты
python test_hmac_full.py
python test_aead.py
python test_pbkdf2.py
