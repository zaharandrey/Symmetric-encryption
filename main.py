import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hmac

# Пароль
password = b'kuchrahaz'

# Генерація солі
salt = os.urandom(16)

# Генерація ключа
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,  # 256 біт для AES-256
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(password)

# Генерація IV
iv = os.urandom(16)  # 128 біт для AES

# Дані для шифрування
data = b'Confidential data that needs encryption.'

# Шифрування
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

# Додавання padding
padder = padding.PKCS7(128).padder()
padded_data = padder.update(data) + padder.finalize()

# Шифрування даних
encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

# Генерація HMAC
h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
h.update(encrypted_data)
mac = h.finalize()

# Збереження результатів у файл
with open('encrypted_data.txt', 'w') as file:
    file.write(f"Salt: {salt.hex()}\n")
    file.write(f"IV: {iv.hex()}\n")
    file.write(f"Encrypted Data: {encrypted_data.hex()}\n")
    file.write(f"HMAC: {mac.hex()}\n")

# Вивід результатів
print(f"Ключ: {key.hex()}")
print(f"IV: {iv.hex()}")
print(f"Зашифровані дані: {encrypted_data.hex()}")
print(f"HMAC: {mac.hex()}")



