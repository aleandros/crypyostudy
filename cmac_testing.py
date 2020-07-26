from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
import os

key = os.urandom(32)
c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
c.update(b"message to authenticate")
print(c.finalize().hex())
