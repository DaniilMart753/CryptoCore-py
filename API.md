# API документация

## file_io.py
`read_file(path)` — читает файл, возвращает bytes
`write_file(path, data)` — записывает bytes в файл
`pkcs7_pad(data)` — добавляет паддинг
`pkcs7_unpad(data)` — убирает паддинг

## csprng.py
`random_bytes(n)` — n случайных байт
`generate_key()` — 16 байт для AES ключа
`generate_iv()` — 16 байт для вектора

## hash/sha256.py
`sha256(data)` — хеш данных
`sha256_hex(data)` — хеш в hex

## mac/hmac.py
`hmac_sha256(key, data)` — HMAC код

## kdf/pbkdf2.py
`pbkdf2_hmac_sha256(password, salt, iterations, dklen)` — ключ из пароля

## modes/
`encrypt_ecb(key, data)`, `decrypt_ecb(key, data)`
`encrypt_cbc(key, data)`, `decrypt_cbc(key, data)`
`encrypt_cfb(key, data)`, `decrypt_cfb(key, data)`
`encrypt_ofb(key, data)`, `decrypt_ofb(key, data)`
`encrypt_ctr(key, data)`, `decrypt_ctr(key, data)`
`encrypt_then_mac(key_enc, key_mac, data, aad)`
`decrypt_verify(key_enc, key_mac, data, aad)`
