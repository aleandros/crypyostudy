#!/usr/bin/env python3

import asyncio, os, time

import simple_kerberos_utils as ku

USER_DATABASE = {
    "johndoe": "123456",
    "janedoe": "password",
    "h_world": "123456789",
    "tgs": "sunshine",
}


class SimpleKerberosAS(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        packet = ku.load_packet(data)
        response = {}

        if packet["type"] == "AS_REQ":
            clienttime = packet["timestamp"]
            if abs(time.time() - clienttime) > 300:
                response["type"] = "ERROR"
                resopnse["message"] = "Timestamp is too old"
            elif packet["principal"] not in USER_DATABASE:
                response["type"] = "ERROR"
                response["message"] = "Unknown principal"
            else:
                response["type"] = "AS_REP"
                session_key = os.urandom(32)

                user_data = {"session_key": session_key}
                tgt = {
                    "session_key": session_key,
                    "client_principal": packet["principal"],
                    "timestamp": time.time(),
                }

                user_key = ku.derive_key(USER_DATABASE[packet["principal"]])
                user_data_encrypted = ku.encrypt(ku.dump_packet(user_data), user_key)
                response["user_data"] = user_data_encrypted

                tgs_key = ku.derive_key(USER_DATABASE["tgs"])
                tgt_encrypted = ku.encrypt(ku.dump_packet(tgt), tgs_key)
                response["tgt"] = tgt_encrypted
            self.transport.write(ku.dump_packet(response))

        print("Login response sent")
        self.transport.close()


async def main():
    loop = asyncio.get_running_loop()
    server = await loop.create_server(SimpleKerberosAS, "127.0.0.1", 8888)
    print(f"Serving on {server.sockets[0].getsockname()}")
    await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
