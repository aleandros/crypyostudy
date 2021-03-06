#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import time
import os


class RSAEncryptor:
    def __init__(self, public_key, max_encrypt_size):
        self._public_key = public_key
        self._max_encrypt_size = max_encrypt_size

    def update(self, plaintext):
        ciphertext = b""
        for offset in range(0, len(plaintext), self._max_encrypt_size):
            ciphertext += self._public_key.encrypt(
                plaintext[offset : offset + self._max_encrypt_size],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        return ciphertext

    def finalize(self):
        return b""


class RSADecryptor:
    def __init__(self, private_key, max_decrypt_size):
        self._private_key = private_key
        self._max_decrypt_size = max_decrypt_size

    def update(self, ciphertext):
        plaintext = b""
        for offset in range(0, len(ciphertext), self._max_decrypt_size):
            plaintext += self._private_key.decrypt(
                ciphertext[offset : offset + self._max_decrypt_size],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        return plaintext

    def finalize(self):
        return b""


class RSAAlgorithm:
    def __init__(self):
        self.name = "RSA Encryption"

    def get_cipher_pair(self):
        rsa_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        max_plaintext_size = 190  # Considering OAEP padding
        max_ciphertext_size = 256
        rsa_public_key = rsa_private_key.public_key()
        return (
            RSAEncryptor(rsa_public_key, max_plaintext_size),
            RSADecryptor(rsa_private_key, max_ciphertext_size),
        )


class AESCTRAlgorithm:
    def __init__(self):
        self.name = "AES-CTR"

    def get_cipher_pair(self):
        key = os.urandom(32)
        nonce = os.urandom(16)
        aes_context = Cipher(
            algorithms.AES(key), modes.CTR(nonce), backend=default_backend()
        )
        return aes_context.encryptor(), aes_context.decryptor()


class RandomDataGenerator:
    def __init__(self, max_size, chunk_size):
        self._max_size = max_size
        self._chunk_size = chunk_size
        self._ciphertexts = []
        self._encryption_times = [0, 0]
        self._decryption_times = [0, 0]

    def plaintexts(self):
        self._encryption_times[0] = time.time()
        for i in range(0, self._max_size, self._chunk_size):
            yield os.urandom(self._chunk_size)

    def ciphertexts(self):
        self._decryption_times[0] = time.time()
        for ciphertext in self._ciphertexts:
            yield ciphertext

    def record_ciphertext(self, c):
        self._ciphertexts.append(c)
        self._encryption_times[1] = time.time()

    def record_recovertext(self, r):
        self._decryption_times[1] = time.time()

    def encryption_time(self):
        return self._encryption_times[1] - self._encryption_times[0]

    def decryption_time(self):
        return self._decryption_times[1] - self._decryption_times[0]


def test_encryption(algorithm, test_data):
    encryptor, decryptor = algorithm.get_cipher_pair()
    for plaintext in test_data.plaintexts():
        ciphertext = encryptor.update(plaintext)
        test_data.record_ciphertext(ciphertext)
    last_ciphertext = encryptor.finalize()
    test_data.record_ciphertext(last_ciphertext)

    for ciphertext in test_data.ciphertexts():
        recovertext = decryptor.update(ciphertext)
        test_data.record_recovertext(recovertext)
    last_recovertext = decryptor.finalize()
    test_data.record_recovertext(last_recovertext)


test_algorithms = [RSAAlgorithm(), AESCTRAlgorithm()]
data_size = 100 * 1024 * 1024  # 100MiB
chunk_sizes = [1 * 1024, 4 * 1024, 16 * 1024, 1024 * 1024]
stats = {algorithm.name: {} for algorithm in test_algorithms}
for chunk_size in chunk_sizes:
    for algorithm in test_algorithms:
        test_data = RandomDataGenerator(data_size, chunk_size)
        test_encryption(algorithm, test_data)
        stats[algorithm.name][chunk_size] = (
            test_data.encryption_time(),
            test_data.decryption_time(),
        )
