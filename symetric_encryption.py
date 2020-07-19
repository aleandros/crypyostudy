from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

key = os.urandom(16)
aes_cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()) # ECB is INSECURE
aes_encryptor = aes_cipher.encryptor()
aes_decryptor = aes_cipher.decryptor()
message = b"abcd" * 4 # must be multiple of key
encrypted_data = aes_encryptor.update(message) 
print(f"m = '{message}'")
print(f"c = '{encrypted_data}'")
print(f"decrypted = '{aes_decryptor.update(encrypted_data)}'")

# With padding
from cryptography.hazmat.primitives import padding

key = os.urandom(32)
iv = os.urandom(16)

aes_cypher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
aes_encryptor = aes_cipher.encryptor()
aes_decryptor = aes_cipher.decryptor()

padder = padding.PKCS7(128).padder()
unpadder = padding.PKCS7(128).unpadder()

plaintexts = [
    b"SHORT",
    b"MEDIUM MEDIUM MEDIUM",
    b"LONG LONG LONG LONG LONG LONG"
]

ciphertexts = []

for m in plaintexts:
    padded_message = padder.update(m)
    ciphertexts.append(aes_encryptor.update(padded_message))

ciphertexts.append(aes_encryptor.update(padder.finalize()))

for c in ciphertexts:
    padded_message = aes_decryptor.update(c)
    print("recovered", unpadder.update(padded_message))

print("recovered", unpadder.finalize())