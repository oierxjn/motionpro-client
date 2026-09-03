# -*- coding: utf-8 -*-
"""
Forwarder — 隧道 ↔ TUN 的 IP 包搬运 + keepalive + 断线检测。

解耦约定（便于标准化替换/调试）：
- 不依赖具体 TUN 实现，只依赖 TunDevice 接口：read(n, timeout) / write(pkt) / close()
  （见 tun_dev.py；测试可传任意同形 mock）。
- 不依赖 ExactTLS 具体类，只依赖最小传输接口：send_app(bytes) / recv_app() -> bytes
  / sock（可选，用于接收超时；缺失时退化为阻塞 recv）。
- 帧解复用独立为 FrameDemuxer（纯逻辑、无 IO，可独立单测）。

帧语义（PROTOCOL_NOTES.md # 线上帧语义最终版 / # Round 8）：
- 控制帧: 20B 头，byte[9]==0xff（网关硬校验位），[2:4]=BE 总长，[12:14]=BE class；
  class-1 keepalive → 网关原样回显；class-4/6 属连接期，数据期见到只计数。
- 裸 IP 包: byte[9]=协议号(1/6/17/...)，[2:4]=BE IP 总长，整包直通 TUN。
- 校验和：内核与网关两侧都已算好，本层【严禁重算】，只搬运。
"""
import logging
import socket
import threading
import time

from mp_client import ctrl

log = logging.getLogger('forwarder')

# 连续 N 个 keepalive 周期收不到回显 → 判定隧道死亡
KA_MAX_MISS = 3
RECV_TIMEOUT = 1.0          # 接收线程单次 recv 超时（也决定 stop 响应粒度）


class FrameDemuxer:
    """把隧道 TLS 流上的 record 载荷切成 ('ctrl', class, raw) / ('ip', pkt) 事件。

    1 record ≈ 1 帧，但实现按长度字段防御性切分（多帧粘连/跨 record 残片均可）。
    控制帧与裸 IP 包都以 0x45 0x00 开头，只能靠 byte[9] 区分，不能看头两字节。
    """

    def __init__(self):
        self.buf = b''
        self.dropped = 0

    def feed(self, data: bytes) -> list:
        self.buf += data
        out = []
        while True:
            n = len(self.buf)
            if n < 4:
                break
            ver = self.buf[0] >> 4
            if ver == 4:
                total = int.from_bytes(self.buf[2:4], 'big')
                minhd = 20
            elif ver == 6:
                if n < 6:
                    break
                total = 40 + int.from_bytes(self.buf[4:6], 'big')
                minhd = 40
            else:
                # 数据期不应出现非 IP 头（字母消息等属连接期，由 VpnService 处理）
                log.warning('demux: drop %dB unknown head %s', n, self.buf[:20].hex())
                self.dropped += n
                self.buf = b''
                break
            if total < minhd:
                log.warning('demux: bad length %d (ver=%d), drop buffer', total, ver)
                self.dropped += n
                self.buf = b''
                break
            if n < total:
                break
            pkt, self.buf = self.buf[:total], self.buf[total:]
            if pkt[0] >> 4 == 4 and pkt[9] == 0xff:
                cls = int.from_bytes(pkt[12:14], 'big')
                out.append(('ctrl', cls, pkt))
            else:
                out.append(('ip', pkt))
        return out


class Forwarder:
    """3 线程搬运：tunnel→tun、tun→tunnel、keepalive。

    on_dead 回调由任意一个线程在判定隧道死亡时触发【恰好一次】，
    由装配层（proxy_serve）负责重连编排 —— 本类不自行重连。
    """

    def __init__(self, transport, tun, keepalive_interval: int = 30, on_dead=None):
        self.transport = transport
        self.tun = tun
        self.keepalive_interval = keepalive_interval
        self.on_dead = on_dead

        self._stop = threading.Event()
        self._dead_fired = False
        self._dead_lock = threading.Lock()
        self._send_lock = threading.Lock()      # send_app 可能来自两个线程
        self._demux = FrameDemuxer()
        self._last_echo = time.monotonic()
        self._threads: list[threading.Thread] = []
        self.stats = {'tx_pkts': 0, 'rx_pkts': 0, 'rx_ctrl': 0,
                      'ka_sent': 0, 'ka_echo': 0, 'dropped': 0}

    # ---- 生命周期 ----
    def start(self):
        for name, fn in (('tunnel->tun', self._pump_tunnel_to_tun),
                         ('tun->tunnel', self._pump_tun_to_tunnel),
                         ('keepalive', self._keepalive_loop)):
            t = threading.Thread(target=fn, name='fwd-' + name, daemon=True)
            t.start()
            self._threads.append(t)
        log.info('forwarder started (keepalive=%ss)', self.keepalive_interval)

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(timeout=3)
        log.info('forwarder stopped: %s', self.stats)

    # ---- 内部 ----
    def _send(self, data: bytes):
        with self._send_lock:
            self.transport.send_app(data)

    def _fire_dead(self, why: str):
        with self._dead_lock:
            if self._dead_fired:
                return
            self._dead_fired = True
        log.warning('tunnel dead: %s', why)
        if self.on_dead:
            try:
                self.on_dead(why)
            except Exception:
                log.exception('on_dead callback failed')

    def _set_recv_timeout(self):
        sock = getattr(self.transport, 'sock', None)
        if sock is not None:
            try:
                sock.settimeout(RECV_TIMEOUT)
            except OSError:
                pass

    def _pump_tunnel_to_tun(self):
        self._set_recv_timeout()
        while not self._stop.is_set():
            try:
                data = self.transport.recv_app()
            except socket.timeout:
                continue
            except EOFError as e:
                self._fire_dead('EOF %s' % e)
                return
            except OSError as e:
                if not self._stop.is_set():
                    self._fire_dead('socket %s' % e)
                return
            for ev in self._demux.feed(data):
                if ev[0] == 'ip':
                    self.stats['rx_pkts'] += 1
                    try:
                        self.tun.write(ev[1])
                    except OSError as e:
                        log.error('tun.write failed: %s', e)
                else:
                    _, cls, raw = ev
                    self.stats['rx_ctrl'] += 1
                    if cls == 1:
                        self.stats['ka_echo'] += 1
                        self._last_echo = time.monotonic()
                    else:
                        log.debug('ctrl class=%d len=%d (ignored)', cls, len(raw))

    def _pump_tun_to_tunnel(self):
        while not self._stop.is_set():
            try:
                pkt = self.tun.read(65536, timeout=RECV_TIMEOUT)
            except TypeError:
                pkt = self.tun.read(65536)          # 简化实现可不支持 timeout
            except OSError as e:
                if not self._stop.is_set():
                    log.error('tun.read failed: %s', e)
                    self._fire_dead('tun %s' % e)
                return
            if not pkt:
                continue
            self.stats['tx_pkts'] += 1
            try:
                self._send(pkt)
            except (OSError, EOFError) as e:
                self._fire_dead('send %s' % e)
                return

    def _keepalive_loop(self):
        """每 interval 发 class-1；连续 KA_MAX_MISS 个周期无回显 → 判死。"""
        while not self._stop.wait(self.keepalive_interval):
            if time.monotonic() - self._last_echo > KA_MAX_MISS * self.keepalive_interval:
                self._fire_dead('keepalive no echo x%d' % KA_MAX_MISS)
                return
            try:
                self._send(ctrl(1))
                self.stats['ka_sent'] += 1
                log.debug('keepalive sent (%d)', self.stats['ka_sent'])
            except (OSError, EOFError) as e:
                self._fire_dead('ka send %s' % e)
                return
