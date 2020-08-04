from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os


class EncryptionManager:
    def __init__(self):
        key = os.urandom(32)
        iv = os.urandom(16)
        aes_context = Cipher(
            algorithms.AES(key), modes.CBC(iv), backend=default_backend()
        )
        self.encryptor = aes_context.encryptor()
        self.decryptor = aes_context.decryptor()
        self.padder = padding.PKCS7(128).padder()
        self.unpadder = padding.PKCS7(128).unpadder()

    def update_encryptor(self, plaintext):
        return self.encryptor.update(self.padder.update(plaintext))

    def finalize_encryptor(self):
        return self.encryptor.update(self.padder.finalize()) + self.encryptor.finalize()

    def update_decryptor(self, ciphertext):
        return self.unpadder.update(self.decryptor.update(ciphertext))

    def finalize_decryptor(self):
        return (
            self.unpadder.update(self.decryptor.finalize()) + self.unpadder.finalize()
        )


if __name__ == "__main__":
    manager = EncryptionManager()

    plaintexts = [b"SHORT", b"MEDIUM MEDIUM MEDIUM", b"LONG LONG LONG LONG LONG LONG"]

    ciphertexts = []

    for m in plaintexts:
        ciphertexts.append(manager.update_encryptor(m))
    ciphertexts.append(manager.finalize_encryptor())

    for c in ciphertexts:
        print("Recovered", manager.update_decryptor(c))
    print("Recovered", manager.finalize_decryptor())

    print("As individidual messages")
    for m in plaintexts:
        manager = EncryptionManager()
        cipher = manager.update_encryptor(m)
        cipher += manager.finalize_encryptor()
        recovered = manager.update_decryptor(cipher)
        recovered += manager.finalize_decryptor()
        print("Recovered", recovered)
