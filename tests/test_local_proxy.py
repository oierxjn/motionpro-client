# -*- coding: utf-8 -*-
"""local_proxy 单测：SOCKS5/HTTP 全流程（本地 echo/origin 服务，不碰外网）。"""
import asyncio
import base64
import struct
import unittest

from local_proxy import ProxyListener, ProxyServer


async def echo_server():
    """本地 echo: 收到什么回什么。"""
    async def handle(r, w):
        try:
            while True:
                data = await r.read(65536)
                if not data:
                    break
                w.write(data)
                await w.drain()
        except ConnectionError:
            pass
        finally:
            w.close()
    srv = await asyncio.start_server(handle, '127.0.0.1', 0)
    return srv, srv.sockets[0].getsockname()[1]


async def origin_server(responses: list):
    """本地 origin http: 记录请求行, 回 canned 响应。"""
    seen = []

    async def handle(r, w):
        head = await r.readuntil(b'\r\n\r\n')
        seen.append(head.split(b'\r\n')[0])
        w.write(responses[min(len(seen), len(responses)) - 1])
        await w.drain()
        w.close()
    srv = await asyncio.start_server(handle, '127.0.0.1', 0)
    return srv, srv.sockets[0].getsockname()[1], seen


class TestProxy(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.echo, self.echo_port = await echo_server()
        self.proxy = ProxyServer([
            ProxyListener('socks5', '127.0.0.1', 0),
            ProxyListener('socks5', '127.0.0.1', 0, user='u1', password='p1'),
            ProxyListener('http', '127.0.0.1', 0, user='u1', password='p1'),
        ])
        await self.proxy.start()
        self.s5_port = self.proxy.endpoints[0][1]
        self.s5_auth_port = self.proxy.endpoints[1][1]
        self.http_port = self.proxy.endpoints[2][1]

    async def asyncTearDown(self):
        await self.proxy.stop()
        self.echo.close()

    # ---- SOCKS5 ----
    async def test_socks5_noauth_connect_relay(self):
        r, w = await asyncio.open_connection('127.0.0.1', self.s5_port)
        w.write(b'\x05\x01\x00')
        await w.drain()
        self.assertEqual(await r.readexactly(2), b'\x05\x00')

        req = b'\x05\x01\x00\x01' + b'\x7f\x00\x00\x01' + struct.pack('>H', self.echo_port)
        w.write(req)
        await w.drain()
        reply = await r.readexactly(10)
        self.assertEqual(reply[1], 0)                      # REP_OK
        w.write(b'hello-echo')
        await w.drain()
        self.assertEqual(await r.readexactly(10), b'hello-echo')
        w.close()

    async def test_socks5_domain_atyp(self):
        r, w = await asyncio.open_connection('127.0.0.1', self.s5_port)
        w.write(b'\x05\x01\x00')
        await w.drain()
        await r.readexactly(2)
        req = (b'\x05\x01\x00\x03' + bytes([len('localhost')]) + b'localhost' +
               struct.pack('>H', self.echo_port))
        w.write(req)
        await w.drain()
        reply = await r.readexactly(10)            # 完整应答: VER REP RSV ATYP BND(4) PORT(2)
        self.assertEqual(reply[1], 0)
        w.write(b'ping')
        await w.drain()
        self.assertEqual(await r.readexactly(4), b'ping')
        w.close()

    async def test_socks5_auth_required_ok(self):
        r, w = await asyncio.open_connection('127.0.0.1', self.s5_auth_port)
        w.write(b'\x05\x02\x00\x02')
        await w.drain()
        self.assertEqual(await r.readexactly(2), b'\x05\x02')
        w.write(b'\x01\x02u1\x02p1')
        await w.drain()
        self.assertEqual(await r.readexactly(2), b'\x01\x00')

        w.write(b'\x05\x01\x00\x01' + b'\x7f\x00\x00\x01' + struct.pack('>H', self.echo_port))
        await w.drain()
        self.assertEqual((await r.readexactly(4))[1], 0)
        w.close()

    async def test_socks5_auth_bad_password_rejected(self):
        r, w = await asyncio.open_connection('127.0.0.1', self.s5_auth_port)
        w.write(b'\x05\x01\x02')
        await w.drain()
        self.assertEqual(await r.readexactly(2), b'\x05\x02')
        w.write(b'\x01\x02u1\x03bad')
        await w.drain()
        self.assertEqual(await r.readexactly(2), b'\x01\x01')   # status != 0
        w.close()

    async def test_socks5_auth_method_rejected_when_no_auth_offered(self):
        r, w = await asyncio.open_connection('127.0.0.1', self.s5_auth_port)
        w.write(b'\x05\x01\x00')                            # 只提供 no-auth
        await w.drain()
        self.assertEqual(await r.readexactly(2), b'\x05\xff')
        w.close()

    # ---- HTTP ----
    async def test_http_connect_relay(self):
        auth = base64.b64encode(b'u1:p1').decode()
        r, w = await asyncio.open_connection('127.0.0.1', self.http_port)
        w.write((f'CONNECT 127.0.0.1:{self.echo_port} HTTP/1.1\r\n'
                 f'Proxy-Authorization: Basic {auth}\r\n\r\n').encode())
        await w.drain()
        status = await r.readuntil(b'\r\n\r\n')
        self.assertIn(b'200 Connection established', status)
        w.write(b'tunnel-data')
        await w.drain()
        self.assertEqual(await r.readexactly(11), b'tunnel-data')
        w.close()

    async def test_http_407_without_auth(self):
        r, w = await asyncio.open_connection('127.0.0.1', self.http_port)
        w.write(b'CONNECT 127.0.0.1:80 HTTP/1.1\r\n\r\n')
        await w.drain()
        status = await r.readuntil(b'\r\n\r\n')
        self.assertIn(b'407', status.split(b'\r\n')[0])
        w.close()

    async def test_http_absolute_form_forwarded(self):
        origin, oport, seen = await origin_server([b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi'])
        auth = base64.b64encode(b'u1:p1').decode()
        r, w = await asyncio.open_connection('127.0.0.1', self.http_port)
        w.write((f'GET http://127.0.0.1:{oport}/some/path?x=1 HTTP/1.1\r\n'
                 f'Proxy-Authorization: Basic {auth}\r\n'
                 f'Host: 127.0.0.1:{oport}\r\n\r\n').encode())
        await w.drain()
        resp = await r.readuntil(b'\r\n\r\n')
        self.assertIn(b'200 OK', resp)
        body = await r.readexactly(2)
        self.assertEqual(body, b'hi')
        w.close()
        origin.close()
        self.assertEqual(seen[0], f'GET /some/path?x=1 HTTP/1.1'.encode())


if __name__ == '__main__':
    unittest.main()
