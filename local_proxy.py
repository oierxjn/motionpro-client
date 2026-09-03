# -*- coding: utf-8 -*-
"""
local_proxy — 内建 asyncio 代理服务端（SOCKS5 + HTTP），零第三方依赖。

解耦约定：
- 本模块不依赖 VPN 任何代码（可单独调试: `uv run local_proxy.py --socks5 127.0.0.1:11080`）。
- 上游连接走普通 socket.connect，由系统路由表决定去向 —— 全隧道模式下即进入 VPN；
  可选 bind_ip 绑定源地址（如 TUN VIP）。
- 标准替换：任何 SOCKS5/HTTP 代理（pproxy/sing-box/...）都是本组件的等价替代，
  只要出口走本机路由；proxy_serve 只调用 start()/stop() 两个方法。

协议范围：
- SOCKS5(RFC 1928): 无认证 / 用户名密码(0x02)，仅 CONNECT(CMD 1)；ATYP v4/domain/v6。
- HTTP: CONNECT 隧道 + 绝对形式请求（转发时改写为 origin-form 并 Connection: close）。
"""
import asyncio
import base64
import hmac
import logging
import socket
import struct
from dataclasses import dataclass

log = logging.getLogger('proxy')

SOCKS_VER = 5
# SOCKS5 应答码
REP_OK, REP_GENERAL, REP_UNREACHABLE, REP_REFUSED, REP_CMD, REP_ATYP = 0, 1, 3, 5, 7, 8


@dataclass
class ProxyListener:
    mode: str                       # 'socks5' | 'http'
    host: str = '0.0.0.0'
    port: int = 1080
    user: str = ''
    password: str = ''

    @property
    def need_auth(self) -> bool:
        return bool(self.user)


class ProxyServer:
    """多监听代理组件：start()/stop() 由装配层调用。"""

    def __init__(self, listeners: list, bind_ip: str = ''):
        if isinstance(listeners, ProxyListener):
            listeners = [listeners]
        self.listeners = listeners
        self.bind_ip = bind_ip          # 上游连接源地址（空 = 跟随路由表）
        self._servers: list[asyncio.AbstractServer] = []
        self._handlers: set[asyncio.Task] = set()

    # ---- 生命周期 ----
    async def start(self):
        for L in self.listeners:
            srv = await asyncio.start_server(
                lambda r, w, L=L: self._spawn(r, w, L), L.host, L.port)
            self._servers.append(srv)
            port = srv.sockets[0].getsockname()[1]
            log.info('%s proxy listening on %s:%d%s',
                     L.mode.upper(), L.host, port,
                     ' (auth)' if L.need_auth else ' (NO AUTH)')
        for s in self._servers:
            asyncio.create_task(s.serve_forever())

    def _spawn(self, r, w, L):
        t = asyncio.create_task(self._handle(r, w, L))
        self._handlers.add(t)
        t.add_done_callback(self._handlers.discard)

    async def stop(self):
        for s in self._servers:
            s.close()
        for s in self._servers:
            try:
                await asyncio.wait_for(s.wait_closed(), timeout=3)
            except (Exception, asyncio.TimeoutError):
                pass
        for t in list(self._handlers):              # 掐掉残存连接（断线收尾）
            t.cancel()
        self._servers.clear()
        log.info('proxy stopped')

    @property
    def endpoints(self) -> list:
        """[(host, port), ...] 实际监听地址（port=0 时返回真实分配端口）。"""
        return [s.sockets[0].getsockname()[:2] for s in self._servers]

    # ---- 分发 ----
    async def _handle(self, reader, writer, L: ProxyListener):
        try:
            if L.mode == 'socks5':
                await self._handle_socks5(reader, writer, L)
            else:
                await self._handle_http(reader, writer, L)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception:
            log.exception('handler error')
        finally:
            writer.close()

    # ---- 上游 ----
    async def _connect(self, host: str, port: int):
        """→ (reader, writer)；bind_ip 绑定源地址（空 = 跟随路由表）。"""
        local = (self.bind_ip, 0) if self.bind_ip else None
        return await asyncio.wait_for(
            asyncio.open_connection(host, port, local_addr=local), timeout=15)

    @staticmethod
    async def _relay(a, b):
        """双向搬运，a/b 均为 (reader, writer) 对；一方 EOF/断开即收尾两端。"""
        ra, wa = a
        rb, wb = b

        async def _pipe(src, dst):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, asyncio.CancelledError, OSError):
                pass
        t1 = asyncio.create_task(_pipe(ra, wb))
        t2 = asyncio.create_task(_pipe(rb, wa))
        done, pending = await asyncio.wait({t1, t2},
                                           return_when=asyncio.FIRST_COMPLETED)
        for p in pending:
            p.cancel()
        for x in (wa, wb):
            try:
                x.close()
            except Exception:
                pass

    # ---- SOCKS5 ----
    async def _socks_negotiate(self, r, w, L: ProxyListener) -> bool:
        ver, n = await r.readexactly(2)
        if ver != SOCKS_VER:
            return False
        methods = await r.readexactly(n)
        if L.need_auth:
            if 0x02 not in methods:
                w.write(bytes([SOCKS_VER, 0xFF]))
                await w.drain()
                return False
            w.write(bytes([SOCKS_VER, 0x02]))
            await w.drain()
            await r.readexactly(1)                      # subneg ver
            ulen = (await r.readexactly(1))[0]
            uname = await r.readexactly(ulen)
            plen = (await r.readexactly(1))[0]
            passwd = await r.readexactly(plen)
            ok = (hmac.compare_digest(uname, L.user.encode()) and
                  hmac.compare_digest(passwd, L.password.encode()))
            w.write(b'\x01' + bytes([0 if ok else 1]))
            await w.drain()
            return ok
        if 0x00 not in methods:
            w.write(bytes([SOCKS_VER, 0xFF]))
            await w.drain()
            return False
        w.write(bytes([SOCKS_VER, 0x00]))
        await w.drain()
        return True

    async def _socks_request(self, r):
        _, cmd, _, atyp = await r.readexactly(4)
        if atyp == 1:
            host = socket.inet_ntoa(await r.readexactly(4))
        elif atyp == 3:
            ln = (await r.readexactly(1))[0]
            host = (await r.readexactly(ln)).decode('utf-8', 'replace')
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, await r.readexactly(16))
        else:
            raise ValueError('atyp %d' % atyp)
        (port,) = struct.unpack('>H', await r.readexactly(2))
        return cmd, host, port

    @staticmethod
    def _socks_reply(w, rep: int, bound=None):
        try:
            if bound and bound[0]:
                bnd = socket.inet_aton(bound[0]) if ':' not in bound[0] \
                    else socket.inet_aton('0.0.0.0')
            else:
                bnd = socket.inet_aton('0.0.0.0')
            port = (bound[1] if bound else 0) or 0
            w.write(bytes([SOCKS_VER, rep, 0, 1]) + bnd + struct.pack('>H', port))
        except (ConnectionError, OSError):
            pass

    async def _handle_socks5(self, r, w, L: ProxyListener):
        if not await self._socks_negotiate(r, w, L):
            return
        cmd, host, port = await self._socks_request(r)
        if cmd != 1:                                    # 仅 CONNECT
            self._socks_reply(w, REP_CMD)
            return
        try:
            up_r, up_w = await self._connect(host, port)
        except Exception:
            log.debug('upstream refused: %s:%d', host, port)
            self._socks_reply(w, REP_REFUSED)
            return
        log.info('socks5 %s:%d connected', host, port)
        self._socks_reply(w, REP_OK, up_w.get_extra_info('sockname'))
        await self._relay((r, w), (up_r, up_w))

    # ---- HTTP ----
    async def _http_auth_ok(self, head: bytes, L: ProxyListener) -> bool:
        if not L.need_auth:
            return True
        want = 'Basic ' + base64.b64encode(
            ('%s:%s' % (L.user, L.password)).encode()).decode()
        for line in head.split(b'\r\n'):
            if line.lower().startswith(b'proxy-authorization:'):
                got = line.split(b':', 1)[1].strip().decode('iso-8859-1')
                return hmac.compare_digest(got, want)
        return False

    async def _handle_http(self, r, w, L: ProxyListener):
        head = await r.readuntil(b'\r\n\r\n')
        if not await self._http_auth_ok(head, L):
            w.write(b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                    b'Proxy-Authenticate: Basic realm="motionpro-proxy"\r\n'
                    b'Content-Length: 0\r\n\r\n')
            await w.drain()
            return
        lines = head.split(b'\r\n')
        method, target, ver = lines[0].decode('iso-8859-1').split(' ', 2)

        if method.upper() == 'CONNECT':                 # authority-form
            host, _, port_s = target.rpartition(':')
            port = int(port_s or 443)
            try:
                up_r, up_w = await self._connect(host, port)
            except Exception:
                w.write(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
                await w.drain()
                return
            w.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            await w.drain()
            log.info('http CONNECT %s:%d established', host, port)
            await self._relay((r, w), (up_r, up_w))

        else:                                           # absolute-form → origin-form
            from urllib.parse import urlsplit
            sp = urlsplit(target)
            host = sp.hostname or ''
            port = sp.port or (443 if sp.scheme == 'https' else 80)
            if not host:
                w.write(b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n')
                await w.drain()
                return
            path = sp.path or '/'
            if sp.query:
                path += '?' + sp.query
            filtered = [('%s %s %s' % (method, path, ver)).encode('iso-8859-1')]
            for ln in lines[1:]:
                low = ln.lower()
                if (low.startswith(b'proxy-authorization') or
                        low.startswith(b'proxy-connection') or
                        low.startswith(b'connection')):
                    continue
                filtered.append(ln)
            filtered.append(b'Connection: close')
            try:
                up_r, up_w = await self._connect(host, port)
            except Exception:
                w.write(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
                await w.drain()
                return
            up_w.write(b'\r\n'.join(filtered) + b'\r\n\r\n')
            await up_w.drain()
            log.info('http %s %s:%d%s', method, host, port, path)
            await self._relay((r, w), (up_r, up_w))


# ---------------------------------------------------------------- 独立调试入口
def main():
    import argparse
    ap = argparse.ArgumentParser(description='standalone proxy (debug)')
    ap.add_argument('--socks5', default='127.0.0.1:11080')
    ap.add_argument('--http', default='127.0.0.1:18080')
    ap.add_argument('--user', default='')
    ap.add_argument('--password', default='')
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(message)s')

    def parse(spec):
        h, _, p = spec.rpartition(':')
        return h or '127.0.0.1', int(p)

    ls = []
    if args.socks5:
        h, p = parse(args.socks5)
        ls.append(ProxyListener('socks5', h, p, args.user, args.password))
    if args.http:
        h, p = parse(args.http)
        ls.append(ProxyListener('http', h, p, args.user, args.password))

    async def run():
        srv = ProxyServer(ls)
        await srv.start()
        try:
            await asyncio.Event().wait()
        finally:
            await srv.stop()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
