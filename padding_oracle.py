from typing import SupportsComplex
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


def sslv3_pad(msg):
    pad_needed = (16 - (len(msg) % 16)) - 1
    padding = pad_needed.to_bytes(pad_needed + 1, "big")
    return msg + padding


def sslv3_unpad(padded_msg):
    padding_len = padded_msg[-1] + 1
    return padded_msg[:-padding_len]


class Oracle:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def accept(self, ciphertext):
        aes_cipher = Cipher(
            algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend()
        )
        decryptor = aes_cipher.decryptor()
        plaintext = decryptor.update(ciphertext)
        plaintext += decryptor.finalize()
        return plaintext[-1] == 15


# Assumes last ciphertext block is a full block of SSLV3 padding
def lucky_get_one_byte(iv, ciphertext, block_number, oracle):
    block_start = block_number * 16
    block_end = block_start + 16
    block = ciphertext[block_start:block_end]

    mod_ciphertext = ciphertext[:-16] + block
    if not oracle.accept(mod_ciphertext):
        return False, None

    second_to_last = ciphertext[-32:-16]
    intermediate = second_to_last[-1] ^ 15

    if block_number == 0:
        prev_block = iv
    else:
        prev_block = ciphertext[block_start - 16 : block_start]

    return True, intermediate ^ prev_block[-1]


message = b"this is message-and i like it so"


def padded(message, block, shifted):
    block_start = block * 16
    block_end = block_start + 16
    block = message[block_start:block_end]
    modified_block = (b"x" * shifted) + block[0 : 16 - shifted]
    new_message = message[:block_start] + modified_block + message[block_end:]
    return sslv3_pad(new_message)


def recover_block(n):
    success_count = 0
    result = ""
    while success_count < 16:
        key = os.urandom(32)
        iv = os.urandom(16)
        encryptor = Cipher(
            algorithms.AES(key), modes.CBC(iv), backend=default_backend()
        ).encryptor()
        padded_message = padded(message, n, success_count)
        ciphertext = encryptor.update(padded_message)
        ciphertext += encryptor.finalize()

        oracle = Oracle(key, iv)
        success, value = lucky_get_one_byte(iv, ciphertext, n, oracle)
        if success:
            result += chr(value)
            success_count += 1
    return result[::-1]


print(recover_block(0) + recover_block(1))

