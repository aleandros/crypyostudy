# Fake CBC-MAC that should not be used in production
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os


def broken_cbc_mac_1(message, key, pad=True):
    aes_cipher = Cipher(algorithms.AES(key),
                        modes.CBC(bytes(16)),
                        backend=default_backend())
    aes_encryptor = aes_cipher.encryptor()

    if pad:
        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(message) + padder.finalize()
    elif len(message) % 16 == 0:
        padded_message = message
    else:
        raise Exception("Unpadded input not a multiple of 16")

    ciphertext = aes_encryptor.update(padded_message)
    return ciphertext[-16:]


key = os.urandom(32)


def prepend_attack(original, prepend_message, key):
    # This basically works because A xor B xor B == A.
    # Since prepend_message  chained with the (prepend_message xor
    # cbc_mac_1(prepend_message)), will cancel, the same
    # mac si produced, but with different content.
    assert len(prepend_message) % 16 == 0
    prepend_mac = broken_cbc_mac_1(prepend_message, key, pad=False)
    new_first_block = bytearray(original[:16])
    for i in range(16):
        new_first_block[i] ^= prepend_mac[i]
    new_first_block = bytes(new_first_block)
    return prepend_message + new_first_block + original[16:]


original_message = b"attack the enemy forces at dawn!"
prepend_message = b"do not attack. (End of message, padding follows)"
new_message = prepend_attack(original_message, prepend_message, key)
mac1 = broken_cbc_mac_1(original_message, key)
mac2 = broken_cbc_mac_1(new_message, key)
print("Original Message and mac:", original_message, mac1.hex())
print("New message and mac     :", new_message, mac2.hex())
if mac1 == mac2:
    print("\tTwo messages with the same MAC. Attack succeeded!")
