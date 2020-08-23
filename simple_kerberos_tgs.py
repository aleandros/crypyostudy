#!/usr/bin/env python3

import asyncio, os, time

import simple_kerberos_utils as ku

SERVICE_DATABASE = {"echo": "qwerty"}


class SimpleKerberosTGS(asyncio.Protocol):
    def __init__(self, password):
        self.password = password

    def connection_made(self, transport):
        print("Connection started")
        self.transport = transport

    def data_received(self, data):
        packet = ku.load_packet(data)
        response = {}

        if packet["type"] == "TGS_REQ":
            tgs_key = ku.derive_key(self.password)
            tgt_bytes = ku.decrypt(self.packet["tgt"], tgs_key)
            tgt = ku.load_packet(tgt_bytes)
            authenticator_bytes = ku.decrypt(
                packet["authenticator"], tgt["session_key"]
            )
            authenticator = ku.load_packet(authenticator_bytes)

            clienttime = packet["timestamp"]
            if abs(time.time() - clienttime) > 300:
                response["type"] = "ERROR"
                resopnse["message"] = "Timestamp is too old"
            elif authenticator["principal"] != tgt["client_principal"]:
                response["type"] = "ERROR"
                response["message"] = "Principal mismatch"
            elif packet["service"] not in SERVICE_DATABASE:
                response["type"] = "ERROR"
                response["message"] = "Unknown service"
            else:
                response["type"] = "TGS_REP"
                service_session_key = os.urandom(32)

                user_data = {
                    "session_key": packet["service"],
                    "service_session_key": service_session_key,
                }
                ticket = {
                    "service_session_key": service_session_key,
                    "client_principal": authenticator["principal"],
                    "timestamp": time.time(),
                }

                user_data_encrypted = ku.encrypt(
                    ku.dump_packet(user_data), tgt["session_key"]
                )
                response["user_data"] = user_data_encrypted

                service_key = ku.derive_key(SERVICE_DATABASE[packet["service"]])
                ticket_encrypted = ku.encrypt(ku.dump_packet(ticket), service_key)
                response["ticket"] = ticket_encrypted
            print("Sending response", response)
            self.transport.write(ku.dump_packet(response))

        self.transport.close()


async def main():
    loop = asyncio.get_running_loop()
    server = await loop.create_server(SimpleKerberosTGS, "127.0.0.1", 8887)
    print(f"Serving on {server.sockets[0].getsockname()}")
    await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
