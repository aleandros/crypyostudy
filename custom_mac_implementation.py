from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import hashlib


class Encryptor:
    def __init__(self, key, nonce) -> None:
        aes_context = Cipher(
            algorithms.AES(key), modes.CTR(nonce), backend=default_backend()
        )
        self.encryptor = aes_context.encryptor()
        self.hasher = hashlib.sha256()

    def update_encryptor(self, plaintext):
        ciphertext = self.encryptor.update(plaintext)
        self.hasher.update(plaintext)
        return ciphertext

    def finalize_encryptor(self):
        return self.encryptor.finalize() + self.hasher.digest()


class Decryptor:
    def __init__(self, key, nonce, ciphered_message) -> None:
        aes_context = Cipher(
            algorithms.AES(key), modes.CTR(nonce), backend=default_backend()
        )
        self.decryptor = aes_context.decryptor()
        self.hasher = hashlib.sha256()
        self.ciphertext = ciphered_message[: len(ciphered_message) - 32]
        self.expected_hash = ciphered_message[-32:]

    def decrypt(self):
        plaintext = self.decryptor.update(self.ciphertext) + self.decryptor.finalize()
        self.hasher.update(plaintext)
        digest = self.hasher.digest()
        if digest == self.expected_hash:
            return plaintext
        else:
            raise Exception("Content mismatch")


key = os.urandom(32)
nonce = os.urandom(16)
manager = Encryptor(key, nonce)
ciphertext = manager.update_encryptor(b"Hi Bob, this is Alice !")
ciphertext += manager.finalize_encryptor()

decryptor = Decryptor(key, nonce, ciphertext)
message = decryptor.decrypt()
# Succesful case: unmodified message
print(message)

# Modifying the ciphertext
ciphertext = ciphertext[:5] + bytes([(ciphertext[5] + 1)]) + ciphertext[6:]
decryptor = Decryptor(key, nonce, ciphertext)
try:
    decryptor.decrypt()
except:
    print("Message was modified")

