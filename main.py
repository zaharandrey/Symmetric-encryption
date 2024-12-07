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


"C:\Users\LENOVO\PycharmProjects\symmetric encryption\.venv\Scripts\python.exe" "C:\Users\LENOVO\PycharmProjects\symmetric encryption\main.py" 
Ключ: c5c9cf6c2a1694cc1cf4d7281d0ddb662fb0736fa70c6e2ed5a2fbd4492dd6e5
IV: bf680d6af3b690af598d8b365a6462cc
Зашифровані дані: bc86ca7eb1c50568d0b69678fd3aee19cc531eb2e47ef898b77fcda2972d050d53b2f8aae583f90a158436c7cc3f8309
HMAC: 0c081916aba915af75fe9e112163b80afa78afd6a99a9ca4f986e3cab16aa703

Process finished with exit code 0




# Приклад коду для рошифрування зашифрованих данних

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hmac

# Пароль
password = b'kuchrahaz'

# Завантаження солі, IV, зашифрованих даних та HMAC з файлу
with open('encrypted_data.txt', 'r') as file:
    salt = bytes.fromhex(file.readline().split(': ')[1].strip())
    iv = bytes.fromhex(file.readline().split(': ')[1].strip())
    encrypted_data = bytes.fromhex(file.readline().split(': ')[1].strip())
    mac = bytes.fromhex(file.readline().split(': ')[1].strip())

# Генерація ключа
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,  # 256 біт для AES-256
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(password)

# Перевірка HMAC
h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
h.update(encrypted_data)
h.verify(mac)

# Дешифрування
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()

# Дешифрування даних
decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

# Видалення padding
unpadder = padding.PKCS7(128).unpadder()
unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

# Виведення результатів
print(f"Розшифровані дані: {unpadded_data.decode('utf-8')}")


"C:\Users\LENOVO\PycharmProjects\Data decryption\.venv\Scripts\python.exe" "C:\Users\LENOVO\PycharmProjects\Data decryption\main.py" 
Розшифровані дані: Confidential data that needs encryption.

Process finished with exit code 0

