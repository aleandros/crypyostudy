#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import os


class ECDHExchange:
    def __init__(self, curve):
        self._curve = curve
        # generate an ephemeral private key for use in the exchange.
        self._private_key = ec.generate_private_key(curve, default_backend())
        self.enc_key = None
        self.mac_key = None

    def get_public_bytes(self):
        public_key = self._private_key.public_key()
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return raw_bytes

    def generate_session_key(self, peer_bytes):
        peer_public_key = serialization.load_pem_public_key(
            peer_bytes, backend=default_backend()
        )
        shared_key = self._private_key.exchange(ec.ECDH(), peer_public_key)

        # derive 64 bytes of key material for 2 32 byte keys
        key_material = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=None,
            backend=default_backend(),
        ).derive(shared_key)

        # get the encryption key
        self.enc_key = key_material[:32]

        # derive a MAC key
        self.mac_key = key_material[32:64]


if __name__ == "__main__":
    exchange = ECDHExchange(ec.SECP384R1)
    pid = os.getpid()
    public_key_path = f"output/{pid}_pk"
    print("CURRENT OS PID:", pid)
    with open(public_key_path, "wb") as f:
        f.write(exchange.get_public_bytes())

    peer_pid = input("Type pid of peer to continue: ")
    peer_key_path = f"output/{peer_pid}_pk"

    with open(peer_key_path, "rb") as f:
        peer_bytes = f.read()

    exchange.generate_session_key(peer_bytes)

    print(exchange.enc_key.hex())
    print(exchange.mac_key.hex())
