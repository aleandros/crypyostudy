# SUPER important:
# MACs are recommended to be used in a encrypt-then-sign scheme
# but signatures care about plaintext authenticity (not only integrity).
# Thus, the signature must be linked to the plaintaxt in order to ensure
# that it was created by the Private Key holder.
# In summary: for RSA signatures, use sign-then-encrypt.
# There are more paranoid schemes such as sign-then-encrypt-then-sign-again
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
public_key = private_key.public_key()

message = b"Alice, this is Bob. Meet me at dawn"
# Note the padding.
# OAEP is recommended for encryption, but PSS for signatures
signature = private_key.sign(
    message,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256(),
)

public_key.verify(
    signature,
    message,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256(),
)
print("Verification passed! It would have thrown an exception otherwise")
