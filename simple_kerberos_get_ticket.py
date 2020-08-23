#!/usr/bin/env python3
import asyncio
import time
import simple_kerberos_utils as ku


class SimpleKerberosGetTicket(asyncio.Protocol):
    def __init__(self, username, service, session_key, tgt, on_ticket):
        self.username = username
        self.service = service
        self.session_key = session_key
        self.tgt = tgt
        self.on_ticket = on_ticket

        self.server_session_key = None
        self.ticket = None

    def connection_made(self, transport):
        print("TGS connection made")
        self.transport = transport
        authenticator = {"principal": self.username, "timestamp": time.time()}
        authenticator_encrypted = ku.encrypt(
            ku.dump_packet(authenticator), self.session_key
        )
        request = {
            "type": "TGS_REQ",
            "service": self.service,
            "authenticator": authenticator_encrypted,
            "tgt": self.tgt,
        }
        self.transport.write(ku.dump_packet(request))

    def data_received(self, data):
        packet = ku.load_packet(data)

        if packet["type"] == "TGS_REP":
            user_data_encrypted = packet["user_data"]
            user_data_bytes = ku.decrypt(user_data_encrypted, self.session_key)
            user_data = ku.load_packet(user_data_bytes)
            self.server_session_key = user_data["service_session_key"]
            self.ticket = packet["ticket"]
        elif packet["type"] == "ERROR":
            print("ERROR: {}".format(packet["message"]))

    def connection_lost(self, exc):
        self.on_ticket(self.server_session_key, self.tgt)
