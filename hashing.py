#!/usr/bin/env python

import hashlib
from hashlib import scrypt

# Hash interface is the same
x = hashlib.sha256()
x.update(b"alice")
print(x.hexdigest())

# You can do it all at once
md5hasher = hashlib.md5(b"alice")
print(md5hasher.hexdigest())

# You can do it step by step
md5hasher = hashlib.md5()
md5hasher.update(b"a")
md5hasher.update(b"l")
md5hasher.update(b"i")
md5hasher.update(b"c")
md5hasher.update(b"e")
print(md5hasher.hexdigest())

# Secure password hashing

import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# Generate random salt
salt = os.urandom(16)

scrypt_config = {
    "salt": salt,
    "length": 32,
    "n": 2 ** 14,
    "r": 8,
    "p": 1,
    "backend": default_backend(),
}

kdf = Scrypt(**scrypt_config)
key = kdf.derive(b"my great password")

# Scrypt instances can only be used once
kdf2 = Scrypt(**scrypt_config)
try:
    kdf2.verify(b"blblblbl", key)
except:
    print("Wrong password")

kdf3 = Scrypt(**scrypt_config)
kdf3.verify(b"my great password", key)
print("success!")
