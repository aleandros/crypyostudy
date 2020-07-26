# In the Encrypt-Then-MAC approach, which is suggested, the MAC is calculated
# over the ciphertext, not the plaintext.
# This is because we don't want attacker to mess with the ciphertext,
# which some attacks can be based on.
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import os


class HMACEncryptor:
    def __init__(self, key, nonce, hmac_key) -> None:
        aes_context = Cipher(
            algorithms.AES(key), modes.CTR(nonce), backend=default_backend()
        )
        self.encryptor = aes_context.encryptor()
        self.hasher = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        self.ciphertext = bytearray([])

    def update_encryptor(self, plaintext):
        self.ciphertext += self.encryptor.update(plaintext)

    def finalize_encryptor(self):
        self.ciphertext += self.encryptor.finalize()
        self.hasher.update(self.ciphertext)
        return self.ciphertext + self.hasher.finalize()


class HMACDecryptor:
    def __init__(self, key, nonce, hmac_key, ciphered_message) -> None:
        aes_context = Cipher(
            algorithms.AES(key), modes.CTR(nonce), backend=default_backend()
        )
        self.decryptor = aes_context.decryptor()
        self.hasher = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        self.ciphertext = ciphered_message[: len(ciphered_message) - 32]
        self.expected_hash = ciphered_message[-32:]

    def decrypt(self):
        self.hasher.update(self.ciphertext)
        digest = self.hasher.finalize()
        plaintext = self.decryptor.update(self.ciphertext) + self.decryptor.finalize()
        if digest == self.expected_hash:
            return plaintext
        else:
            raise Exception("Content mismatch")


key = os.urandom(32)
nonce = os.urandom(16)
hmac_key = os.urandom(32)
manager = HMACEncryptor(key, nonce, hmac_key)
manager.update_encryptor(b"Hi Bob, this is Alice !")
ciphertext = manager.finalize_encryptor()

decryptor = HMACDecryptor(key, nonce, hmac_key, ciphertext)
message = decryptor.decrypt()
# Succesful case: unmodified message
print(message)

# Modifying the ciphertext
ciphertext = ciphertext[:5] + bytes([(ciphertext[5] + 1)]) + ciphertext[6:]
decryptor = HMACDecryptor(key, nonce, hmac_key, ciphertext)
try:
    decryptor.decrypt()
except:
    print("Message was modified")
