# -*- coding: utf-8 -*-
"""
VpnService — 隧道服务类：把 mp_client.py 演示 main() 的建立流程固化为可重复调用。

职责边界（解耦约定，供替换/打桩调试）：
- 只负责「控制面 + 隧道建立 + 会话生命周期」：
    login → 清 stale → 重登 → vpnd 指纹 TLS 握手 → an_welcome.js → vpntunnel(201)
    → P(0x50)/Q(common JSON) → T(0x54)/U(net JSON) → class-6 mptoken → 长期运行 → logout。
- 不触碰 TUN / 路由 / 代理 —— 那些是 tun_dev / routes / local_proxy / proxy_serve 的职责。
- 上层只依赖 connect() 返回的 TunnelState：其中 tls 满足最小传输接口
    send_app(bytes) / recv_app() -> bytes / sock（可被任何同形实现替换）。

协议细节见 PROTOCOL_NOTES.md（# 最终确认 / # Round 7 / # Round 8）。
凭据与设备标识来自 config.py（经 mp_client 模块加载）。
"""
import json
import logging
import re
import struct
import time
from dataclasses import dataclass, field

from mp_client import CFG, HOST, ExactTLS, ctrl, ip4, do_login
from proto_client import AgConnection

log = logging.getLogger('vpn')


# ---------------------------------------------------------------- 工具
def le_int_to_ip(v) -> str:
    """U JSON 里的 IP 是小端 int 编码（72530799 → 111.187.82.4）；字符串则原样返回。"""
    if isinstance(v, str):
        return v
    return '.'.join(str(b) for b in ip4(int(v)))


def read_http_response(t: ExactTLS, timeout: float = 10.0):
    """在隧道 TLS 流上读一条 HTTP 响应 → (status_line, body)。"""
    hdr = t.read_until(b'\r\n\r\n', timeout)
    m = re.search(rb'Content-Length: (\d+)', hdr, re.I)
    body = t.read_exact(int(m.group(1)), timeout) if m else b''
    status = hdr.split(b'\r\n')[0].decode('iso-8859-1', 'replace')
    return status, body


# ---------------------------------------------------------------- 会话状态
@dataclass
class TunnelState:
    """connect() 的产物 —— proxy_serve 装配层唯一需要认识的对象。"""
    tls: ExactTLS                    # 隧道传输：send_app/recv_app（1 record ≈ 1 帧/1 包）
    conn: AgConnection               # 控制面 HTTP 连接（logout 用）
    session: str
    vip: str                         # 虚拟 IP（点分）
    mask: str
    dns: list = field(default_factory=list)
    include_routes: list = field(default_factory=list)
    exclude_routes: list = field(default_factory=list)
    common_cfg: dict = field(default_factory=dict)
    net_cfg: dict = field(default_factory=dict)
    keepalive_interval: int = 30
    mptoken: int = 0


# ---------------------------------------------------------------- 服务
class VpnService:
    """可重复 connect()/reconnect()/shutdown() 的隧道会话管理。"""

    def __init__(self, host: str = None):
        self.host = host or CFG['server']
        self.state: TunnelState | None = None

    # ---- 内部步骤（与 mp_client.main() 逐字节对齐） ----
    def _clear_stale_session(self):
        """先登录一次并立刻 logout，清掉服务器上陈旧的 VIP 租约。"""
        conn0, _ = do_login()
        conn0.request('GET', '/prx/000/http/localhost/logout')
        log.info('stale session cleared')
        try:
            conn0.tls.close()
        except Exception:
            pass
        time.sleep(2)

    def _login(self):
        conn, sess = do_login(welcome=False)
        log.info('cookie ok (%s=%s...)', conn.session_name[:12] if hasattr(conn, 'session_name') else 'ANsession', sess[:8])
        return conn, sess

    def _tunnel_welcome(self, t: ExactTLS, sess: str):
        t.send_app(b'GET /prx/000/http/localhost/an_welcome.js HTTP/1.1\r\n'
                   b'Host: ' + self.host.encode() +
                   b'\r\nCookie: ANStandalone=true;ANsession5301755367574550=' +
                   sess.encode() + b'\r\n\r\n')
        status, _ = read_http_response(t, 10)
        log.info('welcome status: %s', status)

    def _tunnel_vpntunnel(self, t: ExactTLS, sess: str):
        """vpnd L3 模板（get_config.c FUN_1005cc10）：缺 cpuid/hostname/PAYLOAD-IP-VERSION → 200/L4。"""
        req = ('GET /prx/000/http/localhost/vpntunnel HTTP/1.1\r\nHost: %s\r\n' % self.host +
               'Cookie: ANStandalone=true;ANsession5301755367574550=' + sess + '\r\n'
               'x-devtype: 1\r\nappid: SSPVPN\r\n'
               'clientid: ' + CFG['clientid'] + '\r\n'
               'cpuid: ' + CFG['cpuid'] + '\r\nhostname: ' + CFG['hostname'] +
               '\r\nPAYLOAD-IP-VERSION: 6\r\n\r\n')
        t.send_app(req.encode())
        status, _ = read_http_response(t, 10)
        log.info('tunnel status: %s', status)
        if ' 201' not in status:
            raise RuntimeError('vpntunnel refused: %s' % status)

    def _read_msg(self, t: ExactTLS, timeout: float = 10.0):
        """16B 字母消息头 [type][11x00][len:4LE@12] + payload → (type, payload)。"""
        head = t.read_exact(16, timeout)
        mtype = head[0]
        dlen = int.from_bytes(head[12:16], 'little')
        return mtype, (t.read_exact(dlen, timeout) if dlen else b'')

    def _negotiate_common(self, t: ExactTLS) -> dict:
        t.send_app(bytes([0x50]) + bytes(15))
        mtype, payload = self._read_msg(t)
        if mtype != 0x51:
            raise RuntimeError('common config: expect Q(0x51), got %#x' % mtype)
        common = json.loads(payload.rstrip(b'\x00'))
        log.info('common config: keepalive=%s netpool_flag=%s',
                 common.get('keepalive_interval'), common.get('netpool_flag'))
        return common

    def _negotiate_net(self, t: ExactTLS) -> dict:
        # T 消息逐字节对齐真实客户端 (get_config.c:1579):
        # [16:20]=0(无旧vip) [20:24]=首个适配器IP [24:28]=0(新会话非重连) [40:46]=网卡 MAC
        tmsg = bytearray(48)
        tmsg[0] = 0x54
        tmsg[12:16] = struct.pack('<I', 0x20)
        tmsg[20:24] = bytes(int(x) for x in CFG['ras_ip'].split('.'))
        tmsg[24:28] = struct.pack('<I', 0)
        tmsg[40:46] = bytes.fromhex(CFG['mac'])
        t.send_app(bytes(tmsg))
        mtype, payload = self._read_msg(t)
        if mtype != 0x55:
            raise RuntimeError('net config: expect U(0x55), got %#x' % mtype)
        net = json.loads(payload.rstrip(b'\x00'))
        dns = [le_int_to_ip(d) for s in net.get('dns_servers', [])
               for d in s.get('ipv4', [])]
        log.info('net config: vip=%s mask=%s dns=%s',
                 le_int_to_ip(net.get('client_ipv4', 0)),
                 le_int_to_ip(net.get('client_ipv4_mask', 0)),
                 dns)
        return net

    def _get_mptoken(self, t: ExactTLS) -> int:
        t.send_app(ctrl(6))
        t.sock.settimeout(3)
        r = t.recv_app()
        if r and b'mptoken' in r:
            m = re.search(rb'"mptoken"\s*:\s*"?(\d+)', r)
            if m:
                tok = int(m.group(1))
                log.info('mptoken: %d', tok)
                return tok
        log.warning('mptoken: no reply (继续, 数据面不依赖)')
        return 0

    # ---- 对外生命周期 ----
    def connect(self) -> TunnelState:
        """完整建立一次隧道会话（顺序与 mp_client.main() 一致）。"""
        self._clear_stale_session()
        conn, sess = self._login()
        t = ExactTLS(host=self.host)
        try:
            t.handshake()
            self._tunnel_welcome(t, sess)
            self._tunnel_vpntunnel(t, sess)
            common = self._negotiate_common(t)
            net = self._negotiate_net(t)
            token = self._get_mptoken(t)
        except Exception:
            try:
                t.sock.close()
            except Exception:
                pass
            raise
        st = TunnelState(
            tls=t, conn=conn, session=sess,
            vip=le_int_to_ip(net.get('client_ipv4', 0)),
            mask=le_int_to_ip(net.get('client_ipv4_mask', 0)),
            dns=[le_int_to_ip(d) for s in net.get('dns_servers', [])
                 for d in s.get('ipv4', [])],
            include_routes=net.get('include_network_resource', []),
            exclude_routes=net.get('exclude_network_resource', []),
            common_cfg=common, net_cfg=net,
            keepalive_interval=int(common.get('keepalive_interval', 30)),
            mptoken=token,
        )
        self.state = st
        log.info('tunnel up: vip=%s/%s keepalive=%ss', st.vip, st.mask, st.keepalive_interval)
        return st

    def reconnect(self) -> TunnelState:
        """断线重连：释放旧会话 → 重新 connect()（VIP 可能变化）。"""
        old = self.state
        if old:
            try:
                old.conn.request('GET', '/prx/000/http/localhost/logout')
            except Exception:
                pass
            try:
                old.tls.sock.close()
            except Exception:
                pass
            self.state = None
            time.sleep(1)
        return self.connect()

    def shutdown(self):
        """logout 释放 VIP 租约并关闭连接（不登出会粘租约）。"""
        st = self.state
        if not st:
            return
        self.state = None
        try:
            st.conn.request('GET', '/prx/000/http/localhost/logout')
            log.info('logged out')
        except Exception as e:
            log.warning('logout failed: %s', e)
        for c in (st.tls.sock, getattr(st.conn, 'tls', None)):
            try:
                c.close()
            except Exception:
                pass
