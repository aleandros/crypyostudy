#!/usr/bin/env python3
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding


def dump_packet(p):
    for k, v in p.items():
        if isinstance(v, bytes):
            p[k] = list(v)
    return json.dumps(p).encode("utf-8")


def load_packet(json_data):
    p = json.loads(json_data)
    for k, v in p.items():
        if isinstance(v, list):
            p[k] = bytes(v)
    return p


def derive_key(password):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
        backend=default_backend(),
    ).derive(password.encode())


def encrypt(data, key):
    encryptor = Cipher(
        algorithms.AES(key), modes.CBC(b"\x00" * 16), backend=default_backend()
    ).encryptor()

    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(data) + padder.finalize()
    return encryptor.update(padded_message) + encryptor.finalize()


def decrypt(encrypted_data, key):
    decryptor = Cipher(
        algorithms.AES(key), modes.CBC(b"\x00" * 16), backend=default_backend()
    ).decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    padded_message = decryptor.update(encrypted_data) + decryptor.finalize()
    return unpadder.update(padded_message) + unpadder.finalize()
