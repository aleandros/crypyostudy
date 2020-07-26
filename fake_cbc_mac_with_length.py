# Better than fake_cbc_mac.py, but still, use a library implementation instead
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# CBC-MAC considerations:
# 1. If using AES-CBC for data, do not use the same key for encryption
#    and MAC
# 2. IV should be set to 0
def cbc_mac(message, key):
    aes_cipher = Cipher(algorithms.AES(key),
                        modes.CBC(bytes(16)),  # IV set to 0
                        backend=default_backend())
    aes_encryptor = aes_cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message)
    padded_message_with_length = len(message).to_bytes(4, "big") + padded_message
    ciphertext = aes_encryptor.update(padded_message_with_length)
    return ciphertext[-16:]
