# -*- coding: utf-8 -*-
"""VpnDnsResolver / dns_query_a 单测（本地 stub DNS 服务器）。"""
import socket
import struct
import threading
import unittest

from local_proxy import VpnDnsResolver, dns_query_a


class StubDns(threading.Thread):
    """UDP DNS stub: 对 A 查询固定回答 answer_ip（1.2.3.4 可配）。"""

    def __init__(self, answer_ip='192.168.80.100'):
        super().__init__(daemon=True)
        self.answer_ip = answer_ip
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.port = self.sock.getsockname()[1]
        self.queries = []
        self._stop = threading.Event()

    def run(self):
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            self.queries.append(data)
            qname = data[12:data.index(b'\x00', 12) + 1]
            reply = data[:2] + b'\x81\x80' + b'\x00\x01\x00\x01\x00\x00\x00\x00'
            reply += qname + b'\x00\x01\x00\x01'
            reply += b'\xc0\x0c' + b'\x00\x01\x00\x01' + b'\x00\x00\x00\x3c' + \
                b'\x00\x04' + socket.inet_aton(self.answer_ip)
            self.sock.sendto(reply, addr)
        self.sock.close()

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

    def test_resolver_ip_literal_passthrough(self):
        r = VpnDnsResolver([])
        self.assertEqual(r('127.0.0.1'), '127.0.0.1')
        self.assertEqual(r('192.168.80.100'), '192.168.80.100')

    def test_resolver_fallback_to_system(self):
        r = VpnDnsResolver(['127.0.0.1'], timeout=0.3)   # 没有本地 53 服务 → 回退
        ip = r('localhost')
        self.assertIn(ip, ('127.0.0.1', '::1'))


if __name__ == '__main__':
    unittest.main()
