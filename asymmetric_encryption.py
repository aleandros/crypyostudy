from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)

# Public key is derived from private key
public_key = private_key.public_key()

# Serialize keys to PEM format so they can be stored in disk
private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),  # Only for this time
)

public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# Revert serialized representations back to binary so they can be used by algorithms
private_key = serialization.load_pem_private_key(
    private_key_bytes, backend=default_backend(), password=None
)

public_key = serialization.load_pem_public_key(
    public_key_bytes, backend=default_backend()
)
