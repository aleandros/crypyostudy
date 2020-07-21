from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def main():
    message = b"test"

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    public_key = private_key.public_key()

    ciphertext1 = public_key.encrypt(
        message,
        padding.OAEP(  # cryptography module does not allow RSA without padding
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,  # Does not affect security
        ),
    )

    # DO NOT USE PKCS #1 v1.5 - Insecure
    ciphertext2 = public_key.encrypt(message, padding.PKCS1v15())

    recovered1 = private_key.decrypt(
        ciphertext1,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,  # Does not affect security
        ),
    )

    recovered2 = private_key.decrypt(ciphertext2, padding.PKCS1v15())

    # Note that every time the script is executed, the ciphertext
    # changes
    print("OAEP padding:")
    print("Ciphertext:", ciphertext1.hex())
    print("Recovered:", recovered1)
    print("PKCS #1 v1.5 padding:")
    print("Ciphertext:", ciphertext2.hex())
    print("Recovered:", recovered2)


if __name__ == "__main__":
    main()
