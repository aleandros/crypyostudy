#!/usr/bin/env python3

import http.client

conn = http.client.HTTPConnection("127.0.0.1", 8888)
conn.set_tunnel("www.example.com")
conn.request("GET", "/")
r1 = conn.getresponse()
print(r1.read().decode())
