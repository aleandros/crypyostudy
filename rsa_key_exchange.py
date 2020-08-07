import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend


class ReceiverManager:
    def __init__(self, send_public_key, recv_private_key):
        self.send_public_key = send_public_key
        self.recv_private_key = recv_private_key
        # This is mostly a waste of memory. In a real escenario we would likely
        # only store bytes that had not been encrypted
        self.recv_buffer = bytes()
        self.header_received = False
        self.buffer_position = 0

    def _initialize(self):
        header = self.recv_buffer[:512]
        data = header[:-256]
        signature = header[-256:]

        plaintext = self.recv_private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        self.send_public_key.verify(
            signature,
            plaintext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        self.ekey = plaintext[:32]
        self.iv = plaintext[32:48]
        self.mkey = plaintext[48:]

        self.decryptor = Cipher(
            algorithms.AES(self.ekey), modes.CTR(self.iv), backend=default_backend()
        ).decryptor()

        self.mac = hmac.HMAC(self.mkey, hashes.SHA256(), backend=default_backend())
        self.mac.update(header)
        self.header_received = True
        self.buffer_position = 512

    def update(self, data):
        self.recv_buffer += data
        decrypted = b""

        if not self.header_received and len(self.recv_buffer) >= 512:
            self._initialize()

        if self.header_received and len(self.recv_buffer) - self.buffer_position > 32:
            chunk = self.recv_buffer[self.buffer_position : -32]
            self.buffer_position += len(chunk)
            decrypted += self.decryptor.update(chunk)
            self.mac.update(chunk)

        return decrypted

    def finalize(self):
        self.mac.verify(self.recv_buffer[-32:])


# Needless to say, this is insecure, example code
class TransmissionManager:
    def __init__(self, send_private_key, recv_public_key):
        self.send_private_key = send_private_key
        self.recv_public_key = recv_public_key
        self.ekey = os.urandom(32)
        self.mkey = os.urandom(32)
        self.iv = os.urandom(16)

        self.encryptor = Cipher(
            algorithms.AES(self.ekey), modes.CTR(self.iv), backend=default_backend()
        ).encryptor()

        self.mac = hmac.HMAC(self.mkey, hashes.SHA256(), backend=default_backend())

    def initialize(self):
        data = self.ekey + self.iv + self.mkey

        signature = self.send_private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        ciphertext = self.recv_public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        ciphertext += signature
        self.mac.update(ciphertext)
        return ciphertext

    def update(self, plaintext):
        ciphertext = self.encryptor.update(plaintext)
        self.mac.update(ciphertext)
        return ciphertext

    def finalize(self):
        return self.mac.finalize()


sender_private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
sender_public_key = sender_private_key.public_key()

receiver_private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
receiver_public_key = receiver_private_key.public_key()

# Of course these would be isolated from one another
tx = TransmissionManager(sender_private_key, receiver_public_key)
rx = ReceiverManager(sender_public_key, receiver_private_key)
buffer = rx.update(tx.initialize() + tx.update(b"omg!"))
buffer += rx.update(
    tx.update(
        b" I hope this is waaaaaaay longer than 32 bytes otherwise I'll be pissed."
    )
)
buffer += rx.update(tx.update(b" This is it!"))
buffer += rx.update(tx.update(b" and more stuff!") + tx.finalize())
rx.finalize()
print(buffer)
