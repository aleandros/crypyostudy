#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, sys, struct
import getpass

READ_SIZE = 4096


def encrypt_file(plainpath, cipherpath, password):
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1, backend=default_backend())
    key = kdf.derive(password)

    iv = os.urandom(12)

    encryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv), backend=default_backend()
    ).encryptor()

    associated_data = iv + salt

    encryptor.authenticate_additional_data(associated_data)

    with open(cipherpath, "wb+") as fcipher:
        fcipher.write(b"\x00" * (12 + 16 + 16))

        with open(plainpath, "rb") as fplain:
            for plaintext in iter(lambda: fplain.read(READ_SIZE), b""):
                ciphertext = encryptor.update(plaintext)
                fcipher.write(ciphertext)
            ciphertext = encryptor.finalize()
            fcipher.write(ciphertext)

        header = associated_data + encryptor.tag
        fcipher.seek(0, 0)
        fcipher.write(header)


def decrypt_file(cipherpath, plainpath, password):
    with open(cipherpath, "rb") as fcipher:
        associated_data = fcipher.read(12 + 16)

        iv = associated_data[0:12]
        salt = associated_data[12:28]

        # Derive the same password with salt
        kdf = Scrypt(
            salt=salt, length=32, n=2 ** 14, r=8, p=1, backend=default_backend()
        )

        key = kdf.derive(password)

        # GCM tags are always 16 bytes
        tag = fcipher.read(16)

        decryptor = Cipher(
            algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()
        ).decryptor()

        decryptor.authenticate_additional_data(associated_data)

        with open(plainpath, "wb+") as fplain:
            for ciphertext in iter(lambda: fcipher.read(READ_SIZE), b""):
                plaintext = decryptor.update(ciphertext)
                fplain.write(plaintext)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit(f"Usage: {sys.argv[0]} <encrypt/decrypt> IN_PATH [OUT_PATH]")

    action = sys.argv[1]

    if action not in ["encrypt", "decrypt"]:
        raise SystemExit("Invalid action. Allowed: encrypt, decrypt")

    inpath = sys.argv[2]

    if len(sys.argv) > 3:
        outpath = sys.argv[3]
    elif action == "decrypt" and inpath.endswith(".enc"):
        outpath = inpath[:-4]
    elif action == "decrypt":
        outpath = inpath
    else:
        outpath = inpath + ".enc"

    if not os.path.isfile(inpath):
        raise SystemExit(f"{inpath} is not an existing file")

    if os.path.isfile(outpath):
        raise SystemExit(f"{outpath} already exists")

    password = bytes(getpass.getpass(), "utf-8")
    if action == "encrypt":
        encrypt_file(inpath, outpath, password)
    else:
        decrypt_file(inpath, outpath, password)
