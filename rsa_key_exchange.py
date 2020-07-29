import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend


# Needless to say, this is insecure, example code
class TransmissionManager:
    def __init__(self, send_private_key, recv_public_key):
        self.send_private_key = send_private_key
        self.recv_public_key = recv_public_key
        self.ekey = os.urandom(32)
        self.mkey = os.urandom(32)
        self.iv = os.urandom(16)

        self.encryptor = Cipher(
            algorithms.AES(self.ekey),
            modes.CTR(self.iv),
            backend=default_backend()
        )

        self.mac = hmac.HMAC(
            self.mkey,
            hashes.SHA256(),
            backend=default_backend()
        )

    def initialize(self):
        data = self.ekey + self.iv + self.mkey
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(data)
        data_digest = h.finalize()

        signature = self.send_private_key.sign(
            data_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        ciphertext = self.recv_public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        ciphertext += signature
        self.mac.update(ciphertext)
        return ciphertext

    def update(self, plaintext):
        ciphertext = self.encryptor.update(plaintext)
        self.mac.update(ciphertext)
        return ciphertext

    def finalize(self):
        return self.mac.finalize()

