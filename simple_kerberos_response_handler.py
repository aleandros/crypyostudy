#!/usr/bin/env python3

import asyncio

from simple_kerberos_get_ticket import SimpleKerberosGetTicket


class ResponseHandler:
    def __init__(self, username):
        self.username = username

    def on_login(self, session_key, tgt, callback):
        if session_key is None:
            print("Login failed")
            asyncio.get_event_loop().stop()
            return

        service = input("Logged into Simple Kerberos. Enter a service name: ")
        get_ticket_factory = lambda: SimpleKerberosGetTicket(
            self.username, service, session_key, tgt, self.on_ticket
        )

        coro = asyncio.get_event_loop().create_connection(
            get_ticket_factory, "127.0.0.1", 8887
        )
        asyncio.get_event_loop().create_task(coro)
        callback.set_result(True)

    def on_ticket(self, service_session_key, ticket):
        if service_session_key is None:
            print("Login failed")
            asyncio.get_event_loop().stop()

        print("Got a server session key:", service_session_key.hex())
        asyncio.get_event_loop().stop()
