#!/usr/bin/env python3

import asyncio
from simple_kerberos_login import SimpleKerberosLogin
from simple_kerberos_response_handler import ResponseHandler

username = "h_world"
password = "123456789"


async def main():
    loop = asyncio.get_running_loop()
    response_handler = ResponseHandler(username)
    on_conn_lost = loop.create_future()
    login_factory = lambda: SimpleKerberosLogin(
        username, password, response_handler.on_login, on_conn_lost
    )
    transport, _ = await loop.create_connection(login_factory, "127.0.0.1", 8888)

    try:
        await on_conn_lost
    except:
        transport.close()


if __name__ == "__main__":
    asyncio.run(main())
