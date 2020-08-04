from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

data = b"this is example data to be signed"
signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
public_key = private_key.public_key()
public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
print("If you read this, message verification was successful")
