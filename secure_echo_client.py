#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import asyncio
import os
import sys
import getpass


class EchoClientProtocol(asyncio.Protocol):
    def __init__(self, message, password, on_conn_lost):
        self.message = message
        self.on_conn_lost = on_conn_lost

        key_material = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=None,
            backend=default_backend(),
        ).derive(password)
        self._client_write_key = key_material[:32]
        self._client_read_key = key_material[32:]

    def connection_made(self, transport):
        plaintext = self.message.encode()
        nonce = os.urandom(12)
        ciphertext = ChaCha20Poly1305(self._client_write_key).encrypt(
            nonce, plaintext, b""
        )
        transport.write(nonce + ciphertext)
        print("Encrypted data sent: {!r}".format(self.message))

    def data_received(self, data):
        nonce, ciphertext = data[:12], data[12:]
        plaintext = ChaCha20Poly1305(self._client_read_key).decrypt(
            nonce, ciphertext, b""
        )
        print("Decrypted response from server: {!r}".format(plaintext.decode()))

    def connection_lost(self, exc):
        print("The server closed the connection")
        self.on_conn_lost.set_result(True)


async def main(message, password):
    loop = asyncio.get_running_loop()
    on_conn_lost = loop.create_future()
    transport, protocol = await loop.create_connection(
        lambda: EchoClientProtocol(message, password, on_conn_lost), "127.0.0.1", 8888
    )
    try:
        await on_conn_lost
    except:
        transport.close()


if __name__ == "__main__":
    message = sys.argv[1]
    password = getpass.getpass().encode("utf-8")
    asyncio.run(main(message, password))
