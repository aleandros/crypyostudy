#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import asyncio
import os
import getpass
import subprocess


class EchoServerProtocol(asyncio.Protocol):
    def __init__(self, password):
        key_material = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=None,
            backend=default_backend(),
        ).derive(password)

        self._server_read_key = key_material[:32]
        self._server_write_key = key_material[32:]

    def connection_made(self, transport):
        peername = transport.get_extra_info("peername")
        print(f"Connection from {peername}")
        self.transport = transport

    def data_received(self, data):
        nonce, ciphertext = data[:12], data[12:]
        plaintext = ChaCha20Poly1305(self._server_read_key).decrypt(
            nonce, ciphertext, b""
        )
        message = plaintext.decode()
        print("Decrypted message from client: {!r}".format(message))
        print("Echo back message: {!r}".format(message))
        reply_nonce = os.urandom(12)
        ciphertext = ChaCha20Poly1305(self._server_write_key).encrypt(
            reply_nonce, plaintext, b""
        )
        self.transport.write(reply_nonce + ciphertext)

        print("Close the client socket")
        self.transport.close()


async def main(password):
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: EchoServerProtocol(password), "127.0.0.1", 8888
    )
    print(f"Serving on {server.sockets[0].getsockname()}")
    await server.serve_forever()


if __name__ == "__main__":
    password = getpass.getpass().encode("utf-8")
    asyncio.run(main(password))
