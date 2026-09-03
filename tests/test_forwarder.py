# -*- coding: utf-8 -*-
"""forwarder 单测：FrameDemuxer 纯逻辑 + Forwarder 双线程搬运（mock 传输/TUN）。"""
import queue
import socket
import struct
import threading
import time
import unittest

from forwarder import Forwarder, FrameDemuxer

# 实测抓到的 class-1 keepalive 回显帧（20B, byte[9]=0xff）
KA_ECHO = bytes.fromhex('450000140000000000ff00000001000000000000')


def ip4_pkt(total_len=None, proto=17, body=b'\x11' * 8):
    hdrlen = 20
    total = total_len if total_len is not None else hdrlen + len(body)
    ih = struct.pack('>BBHHHBBH', 0x45, 0, total, 1, 0, 64, proto, 0)
    ih += b'\x0a\x00\x00\x01' + b'\x0a\x00\x00\x02'
    ih = ih[:10] + b'\x00\x00' + ih[12:]          # 校验和置 0（demux 不校验）
    return ih + body


def ctrl_frame(cls: int, payload: bytes = b'') -> bytes:
    total = 20 + len(payload)
    return (bytes([0x45, 0x00]) + struct.pack('>H', total) + b'\x00' * 4 +
            bytes([0x00, 0xFF, 0x00, 0x00]) + struct.pack('>H', cls) +
            b'\x00\x00' + b'\x00' * 4 + payload)


class TestFrameDemuxer(unittest.TestCase):
    def setUp(self):
        self.d = FrameDemuxer()

    def test_keepalive_echo(self):
        evs = self.d.feed(KA_ECHO)
        self.assertEqual(evs, [('ctrl', 1, KA_ECHO)])

    def test_ctrl_class6(self):
        f = ctrl_frame(6, b'{"mptoken": 123}')
        evs = self.d.feed(f)
        self.assertEqual(evs, [('ctrl', 6, f)])

    def test_bare_ip(self):
        p = ip4_pkt()
        self.assertEqual(self.d.feed(p), [('ip', p)])

    def test_two_frames_one_feed(self):
        p = ip4_pkt()
        evs = self.d.feed(KA_ECHO + p)
        self.assertEqual(evs, [('ctrl', 1, KA_ECHO), ('ip', p)])

    def test_split_across_feeds(self):
        p = ip4_pkt()
        self.assertEqual(self.d.feed(p[:7]), [])
        self.assertEqual(self.d.feed(p[7:21]), [])
        self.assertEqual(self.d.feed(p[21:]), [('ip', p)])

    def test_ipv6_passthrough(self):
        # 40B 固定头: version(1B)+4B+payload_len(2B)+next_hdr(1B)+hop(1B)+src16+dst16
        p = b'\x60' + b'\x00' * 3 + struct.pack('>H', 8) + b'\x11' + b'\x00' * 33 + b'x' * 8
        self.assertEqual(len(p), 48)
        self.assertEqual(self.d.feed(p), [('ip', p)])

    def test_unknown_head_dropped(self):
        evs = self.d.feed(b'\x73\xff\x00\x10' + b'\x00' * 16)   # 0x7x: 非 v4/v6
        self.assertEqual(evs, [])
        self.assertGreater(self.d.dropped, 0)

    def test_bad_length_dropped(self):
        evs = self.d.feed(b'\x45\x00\x00\x03' + b'\x00' * 16)
        self.assertEqual(evs, [])
        self.assertGreater(self.d.dropped, 0)


class MockTransport:
    """最小传输接口打桩：send_app / recv_app / sock.settimeout"""

    def __init__(self):
        self.inbox = queue.Queue()      # 模拟网关方向数据
        self.sent = []                  # 客户端方向发出的数据
        self.eof = False
        self.lock = threading.Lock()
        class _Sock:
            def settimeout(self, t):
                pass
        self.sock = _Sock()

    def send_app(self, data):
        with self.lock:
            self.sent.append(data)

    def recv_app(self):
        if self.eof:
            raise EOFError('mock closed')
        try:
            return self.inbox.get(timeout=0.2)
        except queue.Empty:
            raise socket.timeout()

    def close_eof(self):
        self.eof = True


class MockTun:
    def __init__(self):
        self.out = queue.Queue()        # read() 产出的包（上行）
        self.written = []               # write() 收到的包（下行）
        self.lock = threading.Lock()

    def read(self, n=65536, timeout=1.0):
        try:
            return self.out.get(timeout=timeout)
        except queue.Empty:
            return b''

    def write(self, pkt):
        with self.lock:
            self.written.append(pkt)

    def inject(self, pkt):
        self.out.put(pkt)


class TestForwarder(unittest.TestCase):
    def setUp(self):
        self.tr = MockTransport()
        self.tun = MockTun()
        self.dead = threading.Event()
        self.dead_why = []
        self.fwd = Forwarder(self.tr, self.tun, keepalive_interval=0.1,
                             on_dead=lambda why: (self.dead_why.append(why),
                                                  self.dead.set()))
        self.fwd.start()

    def tearDown(self):
        self.fwd.stop()

    def wait_dead(self, timeout=3.0):
        return self.dead.wait(timeout)

    def test_tunnel_to_tun(self):
        p = ip4_pkt()
        self.tr.inbox.put(p)
        for _ in range(50):
            if self.tun.written:
                break
            time.sleep(0.02)
        self.assertEqual(self.tun.written, [p])
        self.assertEqual(self.fwd.stats['rx_pkts'], 1)

    def test_tun_to_tunnel(self):
        p = ip4_pkt()
        self.tun.inject(p)
        for _ in range(50):
            if self.tr.sent:
                break
            time.sleep(0.02)
        self.assertIn(p, self.tr.sent)
        self.assertGreater(self.fwd.stats['tx_pkts'], 0)

    def test_keepalive_sent_and_echo_counted(self):
        self.tr.inbox.put(KA_ECHO)
        for _ in range(100):
            if self.fwd.stats['ka_sent'] >= 1 and self.fwd.stats['ka_echo'] >= 1:
                break
            time.sleep(0.02)
        self.assertGreaterEqual(self.fwd.stats['ka_sent'], 1)
        self.assertGreaterEqual(self.fwd.stats['ka_echo'], 1)

    def test_eof_fires_on_dead_once(self):
        p = ip4_pkt()
        self.tr.inbox.put(p)          # 确保接收线程已跑过一轮
        time.sleep(0.1)
        self.tr.close_eof()
        self.assertTrue(self.wait_dead(), 'EOF 未触发 on_dead')
        time.sleep(0.2)
        self.assertEqual(len(self.dead_why), 1)
        self.assertIn('EOF', self.dead_why[0])

    def test_keepalive_no_echo_fires_dead(self):
        # 不喂任何回显; interval=0.1, 3 miss ≈ 0.3s
        self.assertTrue(self.wait_dead(timeout=3.0), 'keepalive 超时未触发 on_dead')
        self.assertIn('keepalive', self.dead_why[0])


if __name__ == '__main__':
    unittest.main()
