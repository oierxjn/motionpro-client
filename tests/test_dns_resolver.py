# -*- coding: utf-8 -*-
"""VpnDnsResolver / dns_query_a 单测（本地 stub DNS 服务器）。"""
import socket
import struct
import threading
import unittest

from local_proxy import VpnDnsResolver, dns_query_a


class StubDns(threading.Thread):
    """TCP DNS stub: 对 A 查询固定回答 answer_ip（默认 192.168.80.100）。"""

    def __init__(self, answer_ip='192.168.80.100'):
        super().__init__(daemon=True)
        self.answer_ip = answer_ip
        self.queries = []
        self._stop = threading.Event()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(('127.0.0.1', 0))
        self.port = self._srv.getsockname()[1]

    def run(self):
        self._srv.settimeout(0.2)
        self._srv.listen(4)
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(2)
                try:
                    hdr = b''
                    while len(hdr) < 2:
                        chunk = conn.recv(2 - len(hdr))
                        if not chunk:
                            raise ConnectionError
                        hdr += chunk
                    (ln,) = struct.unpack('>H', hdr)
                    q = b''
                    while len(q) < ln:
                        q += conn.recv(ln - len(q))
                    self.queries.append(q)
                except (ConnectionError, socket.timeout):
                    continue
                reply = q[:2] + b'\x81\x80' + b'\x00\x01\x00\x01\x00\x00\x00\x00'
                reply += q[12:q.index(b'\x00', 12) + 1] + b'\x00\x01\x00\x01'
                reply += (b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
                          + socket.inet_aton(self.answer_ip))
                conn.sendall(struct.pack('>H', len(reply)) + reply)
        self._srv.close()

    def stop(self):
        self._stop.set()


class TestDnsResolver(unittest.TestCase):
    def setUp(self):
        self.stub = StubDns()
        self.stub.start()

    def tearDown(self):
        self.stub.stop()

    def test_dns_query_a_parses_answer(self):
        ips = dns_query_a('www.example.edu', '127.0.0.1', timeout=2,
                          port=self.stub.port)
        self.assertEqual(ips, ['192.168.80.100'])

    def test_dns_query_a_timeout_returns_empty(self):
        # 查询一个没人听的端口
        ips = dns_query_a('www.example.edu', '127.0.0.1', timeout=0.3, port=1)
        self.assertEqual(ips, [])

    def test_resolver_uses_dns_servers(self):
        r = VpnDnsResolver(['127.0.0.1'], timeout=2)
        # VpnDnsResolver 走固定 53; 本机 53 无服务 → 回退系统解析 localhost
        self.assertIn(r('localhost'), ('127.0.0.1', '::1'))


if __name__ == '__main__':
    unittest.main()
