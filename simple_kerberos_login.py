#!/usr/bin/env python3

import simple_kerberos_utils as ku
import asyncio, time


class SimpleKerberosLogin(asyncio.Protocol):
    def __init__(self, username, password, on_login, on_conn_lost):
        self.username = username
        self.password = password
        self.on_login = on_login
        self.session_key = None
        self.tgt = None
        self.on_conn_lost = on_conn_lost

    def connection_made(self, transport):
        self.transport = transport
        request = {
            "type": "AS_REQ",
            "principal": self.username,
            "timestamp": time.time(),
        }
        self.transport.write(ku.dump_packet(request))

    def data_received(self, data):
        packet = ku.load_packet(data)

        if packet["type"] == "AS_REP":
            user_data_encrypted = packet["user_data"]
            user_key = ku.derive_key(self.password)
            user_data_bytes = ku.decrypt(user_data_encrypted, user_key)
            user_data = ku.load_packet(user_data_bytes)
            self.session_key = user_data["session_key"]
            self.tgt = packet["tgt"]
        elif packet["type"] == "ERROR":
            print("ERROR: {}".format(packet["message"]))
        self.transport.close()

    def connection_lost(self, exc):
        self.on_login(self.session_key, self.tgt, self.on_conn_lost)
