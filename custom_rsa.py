#!/usr/bin/env python3
# Custom RSA is a bad idea (any custom crypto is a bad idea). The following omits padding.
#
# Encryption: c = m^e % n
# Decryption: m = c^d % n
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import gmpy2
import argparse
import logging


def simple_rsa_encrypt(m, public_key):
    numbers = public_key.public_numbers()
    return gmpy2.powmod(m, numbers.e, numbers.n)


def simple_rsa_decrypt(c, private_key):
    numbers = private_key.private_numbers()
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)


def int_to_bytes(i):
    i = int(i)
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder="big")


# Note that  for binary data, this loses leading zeros, which
# is solved with padding
def bytes_to_int(b):
    return int.from_bytes(b, byteorder="big")


def load_public_key(path):
    with open(path, "rb") as handler:
        return serialization.load_pem_public_key(
            handler.read(), backend=default_backend()
        )


def load_private_key(path):
    with open(path, "rb") as handler:
        return serialization.load_pem_private_key(
            handler.read(), backend=default_backend(), password=None
        )


def generate_keys(args):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),  # Only for this time
    )

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(args.private_key_path, "wb+") as handler:
        logging.info(f"Storing private key in {args.private_key_path}")
        handler.write(private_key_bytes)
    with open(args.public_key_path, "wb+") as handler:
        logging.info(f"Storing public key in {args.public_key_path}")
        handler.write(public_key_bytes)


def encrypt_handler(args):
    public_key = load_public_key(args.public_key_path)
    with open(args.source, "rb") as plaintext_handler:
        data = bytes_to_int(plaintext_handler.read())
        ciphertext = simple_rsa_encrypt(data, public_key)
        ciphertext_bytes = int_to_bytes(ciphertext)

        with open(args.dest, "wb") as ciphertext_handler:
            ciphertext_handler.write(ciphertext_bytes)


def decrypt_handler(args):
    private_key = load_private_key(args.private_key_path)
    with open(args.source, "rb") as ciphertext_handler:
        data = bytes_to_int(ciphertext_handler.read())
        plaintext = simple_rsa_decrypt(data, private_key)
        plaintext_bytes = int_to_bytes(plaintext)

        with open(args.dest, "wb") as plaintext_handler:
            plaintext_handler.write(plaintext_bytes)


parser = argparse.ArgumentParser(
    description="Test program for simple (and frakly, insecure), RSA encryption"
)
parser.add_argument("--public-key-path", default="output/key.pub", type=str)
parser.add_argument("--private-key-path", default="output/key", type=str)
subparsers = parser.add_subparsers()

generator_parser = subparsers.add_parser(
    "generate", description="Generate public and private RSA keys"
)
generator_parser.set_defaults(func=generate_keys)

encrypt_parser = subparsers.add_parser("encrypt", description="Encrypt the given data")
encrypt_parser.add_argument("--source", required=True)
encrypt_parser.add_argument("--dest", required=True)
encrypt_parser.set_defaults(func=encrypt_handler)

decrypt_parser = subparsers.add_parser("decrypt", description="Decrypt the given data")
decrypt_parser.add_argument("--source", required=True)
decrypt_parser.add_argument("--dest", required=True)
decrypt_parser.set_defaults(func=decrypt_handler)

args = parser.parse_args()
args.func(args)
