from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

key = b"correctHorseBatteryStaple"
h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
h.update(b"hello world")
print(h.finalize().hex())
