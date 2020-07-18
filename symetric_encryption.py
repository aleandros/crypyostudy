from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

key = os.urandom(16)
aes_cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
aes_encryptor = aes_cipher.encryptor()
aes_decryptor = aes_cipher.decryptor()
