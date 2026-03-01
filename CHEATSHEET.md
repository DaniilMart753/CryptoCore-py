# ПОЛНАЯ ПАМЯТКА ПО ПРОЕКТУ

## Клонирование
git clone https://github.com/DaniilMart753/CryptoCore-py.git

cd CryptoCore-py

## Виртуальное окружение
python3 -m venv venv

source venv/bin/activate

## Установка библиотеки
pip install pycryptodome

## Создание тестового файла
echo "Текст тестового файла" > test.txt

## Проверка структуры (что должно быть в папке)
ls -la
#### Должны быть: src/, README.md, USERGUIDE.md, test_*.py

## Запуск всех тестов
python run_all_tests.py

## Шифрование с ключом
python src/cli.py --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input test.txt

## Проверка, что файл зашифровался
ls -la test.txt.enc

## Расшифровка
python src/cli.py --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --input test.txt.enc --output test_decrypted.txt

## Проверка расшифровки
cat test_decrypted.txt

diff test.txt test_decrypted.txt

## Шифрование без ключа (генерация ключа)
python src/cli.py --algorithm aes --mode cbc --encrypt --input test.txt --output test_random.enc

## SHA-256 хеш
python -c "from src.hash.sha256 import sha256_hex; print(sha256_hex(b'hello'))"

## HMAC
python -c "from src.mac.hmac import hmac_sha256; print(hmac_sha256(b'key', b'data').hex())"

## PBKDF2
python -c "from src.kdf.pbkdf2 import pbkdf2_hmac_sha256; print(pbkdf2_hmac_sha256(b'password', b'salt', 1000, 32).hex())"

## Просмотр документации
cat README.md

cat USERGUIDE.md

cat API.md

## Если что-то пошло не так (очистка и переустановка)
rm -rf venv

python3 -m venv venv

source venv/bin/activate

pip install pycryptodome
