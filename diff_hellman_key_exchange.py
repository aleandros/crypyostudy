#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

parameters = dh.generate_parameters(
    generator=2, key_size=1024, backend=default_backend()
)
private_key = parameters.generate_private_key()

# In real handshake, peer public key would be received from the other
# party. For this example we'll generate another private key and
# get a public key from that. In a DH handshake, both peers
# must agree on a common set of parameters.
peer_public_key = parameters.generate_private_key().public_key()
shared_key = private_key.exchange(peer_public_key)

# Perform key derivation
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"handshake data",
    backend=default_backend(),
).derive(shared_key)
