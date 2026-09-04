# -*- coding: utf-8 -*-
"""
proxy_serve — MotionPro 代理服务端装配入口。

五个解耦组件的装配与编排（各组件均可独立替换/调试）：
    VpnService   vpn_service.py   隧道控制面/生命周期      (connect/reconnect/shutdown)
    TunDevice    tun_dev.py       TUN 设备 (wintun/linux)  (open/read/write/set_ip/close)
    RouteManager routes.py        防环+默认路由+回滚        (apply_full/rollback)
    Forwarder    forwarder.py     隧道<->TUN 搬运+keepalive (start/stop/on_dead)
    ProxyServer  local_proxy.py   SOCKS5/HTTP 代理          (start/stop)

启动顺序（顺序敏感）: 隧道 → TUN+IP → 防环路由+默认路由 → 搬运 → 代理监听。
重连: Forwarder 判死 → 回调 → rollback 路由 → vpn.reconnect → 新 VIP 重配 → 重启搬运。
退出: 停代理 → 停搬运 → 回滚路由 → 关 TUN → logout（释放 VIP 租约）。

用法:
    uv run proxy_serve.py                 # 完整服务（需管理员/root）
    uv run proxy_serve.py --check-only    # 仅验证隧道控制面（无 TUN/路由/代理）
    uv run proxy_serve.py --route-dry-run # 路由命令只打印不执行
"""
import argparse
import asyncio
import logging
import sys
import threading

from forwarder import Forwarder
from local_proxy import ProxyListener, ProxyServer, VpnDnsResolver
from mp_client import CFG
from routes import RouteManager
from tun_dev import create_tun
from vpn_service import VpnService

log = logging.getLogger('serve')

MAX_RECONNECT_ATTEMPTS = 5


def _parse_listen(spec: str, default_host: str):
    host, _, port = spec.rpartition(':')
    return (host or default_host), int(port)


def build_listeners(cfg: dict) -> list:
    """从 config 装配监听；非回环监听必须配置认证（防裸奔）。"""
    ls = []
    for key, mode in (('proxy_socks', 'socks5'), ('proxy_http', 'http')):
        spec = cfg.get(key)
        if not spec:
            continue
        host, port = _parse_listen(str(spec), '0.0.0.0')
        ls.append(ProxyListener(mode, host, port,
                                str(cfg.get('proxy_user', '')),
                                str(cfg.get('proxy_pass', ''))))
    for L in ls:
        loopback = L.host in ('127.0.0.1', '::1', 'localhost')
        if not loopback and not L.need_auth:
            raise SystemExit(
                '拒绝启动: %s 监听 %s:%d 但未配置 proxy_user/proxy_pass —— '
                '开放监听必须带认证，或改绑 127.0.0.1' % (L.mode, L.host, L.port))
    if not ls:
        raise SystemExit('config 未配置 proxy_socks / proxy_http 监听')
    return ls


class Supervisor:
    """组件装配 + 重连编排 + 清理。"""

    def __init__(self, cfg: dict):
        self.cfg = dict(cfg)
        self.vpn = VpnService()
        self.rm = RouteManager(dry_run=bool(cfg.get('route_dry_run')))
        self.tun = None
        self.fwd = None
        self.proxy = None
        self.state = None
        self.bind_ip = ''               # 上游绑定源 IP（split 模式自动=VIP）
        self.resolver = None            # 隧道 DNS 解析器（重连后刷新）
        self._stop_evt = threading.Event()
        self._reconnect_evt = threading.Event()

    # ---- 启动（阻塞部分, 在 asyncio 循环外调用） ----
    def bring_up_tunnel(self):
        """隧道 → TUN → 路由 → 搬运。"""
        self.state = self.vpn.connect()
        st = self.state
        self.tun = create_tun(self.cfg.get('tun_kind') or None)
        self.tun.open(self.cfg.get('tun_name', 'mptun0'),
                      int(self.cfg.get('tun_mtu', 1400)))
        self.tun.set_ip(st.vip, st.mask)
        self._apply_routes(st)
        if self.cfg.get('route_mode', 'full') == 'split' and not self.cfg.get('proxy_bind_ip'):
            # split 模式下出口流量必须以 VIP 为源才能命中分段路由
            self.bind_ip = st.vip
            log.info('split 模式: 上游自动绑定 VIP %s', st.vip)
        else:
            self.bind_ip = str(self.cfg.get('proxy_bind_ip', '') or '')
        if self.cfg.get('vpn_dns_resolve', True):
            # 用隧道 DNS 解析域名: 校园边界对 VPN 池单向 NAT, 公网解析的
            # 地址回包源不匹配; 网关自己的 DNS 给内网地址才能连通(官方同款)
            self.resolver = VpnDnsResolver(st.dns,
                                           timeout=float(self.cfg.get('vpn_dns_timeout', 8)))
            log.info('域名解析走隧道 DNS %s (timeout=%ss)',
                     st.dns, self.cfg.get('vpn_dns_timeout', 8))
        self._start_forwarder(st)
        return st

    def _apply_routes(self, st):
        alias = getattr(self.tun, 'alias', None) or self.tun.name
        ifindex = getattr(self.tun, 'ifindex', None)
        if self.cfg.get('route_mode', 'full') == 'split':
            # 防环仍然必做: 网关 IP 固定走物理网卡
            gw_ip = self.rm.resolve_ip(self.vpn.host)
            phy_gw, phy_if = self.rm.default_gateway()
            if not phy_gw and not phy_if:
                raise OSError('未找到物理默认路由，拒绝装配（防环失败会导致隧道自环）')
            self.rm.add_host_route(gw_ip, gw=phy_gw, iface=phy_if)
            for cidr in self.cfg.get('route_include', []) or []:
                log.info('split route: %s → tun', cidr)
                self.rm.add_subnet_route(cidr, gw=st.vip,
                                         iface=ifindex if ifindex else alias)
        else:
            self.rm.apply_full(self.vpn.host, st.vip, mask=st.mask,
                               tun_iface_alias=alias, tun_ifindex=ifindex)

    def _start_forwarder(self, st):
        if self.fwd:
            self.fwd.stop()
        self.fwd = Forwarder(st.tls, self.tun,
                             keepalive_interval=st.keepalive_interval,
                             on_dead=self._on_dead)
        self.fwd.start()

    # ---- Forwarder 回调（来自搬运线程） ----
    def _on_dead(self, why: str):
        log.warning('tunnel dead: %s → 触发重连', why)
        self._reconnect_evt.set()

    # ---- asyncio 侧 ----
    async def run(self, run_for: float = 0):
        """启动代理监听并驻留; 处理重连事件; finally 清理。run_for>0 时定时自停。"""
        loop = asyncio.get_running_loop()
        if sys.platform != 'win32':                    # Linux: SIGTERM 优雅退出
            import signal
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, self.request_stop)
        deadline = loop.time() + run_for if run_for else None
        self.proxy = ProxyServer(build_listeners(self.cfg),
                                 bind_ip=self.bind_ip,
                                 resolver=self.resolver)
        await self.proxy.start()
        for host, port in self.proxy.endpoints:
            print('[*] 代理已就绪: %s:%d' % (host, port))
        try:
            while True:
                if self._stop_evt.is_set():
                    break
                if deadline and loop.time() >= deadline:
                    log.info('run_for 到时, 自动停止')
                    break
                if self._reconnect_evt.is_set():
                    self._reconnect_evt.clear()
                    await self._do_reconnect()
                await asyncio.sleep(0.5)
        finally:
            await self.teardown()

    async def _do_reconnect(self):
        for attempt in range(1, MAX_RECONNECT_ATTEMPTS + 1):
            try:
                await asyncio.to_thread(self._rebuild)
                log.info('reconnect ok (attempt %d)', attempt)
                return
            except Exception as e:
                delay = min(60, 2 ** attempt)
                log.error('reconnect attempt %d failed: %s → %ds 后重试',
                          attempt, e, delay)
                await asyncio.sleep(delay)
        log.critical('重连 %d 次全部失败, 停止服务', MAX_RECONNECT_ATTEMPTS)
        self._stop_evt.set()

    def _rebuild(self):
        """重连全套（阻塞, 运行在线程池）: 停搬运 → 回滚路由 → 新会话 → 重配。"""
        if self.fwd:
            self.fwd.stop()
        self.rm.rollback()
        self.state = self.vpn.reconnect()
        self.tun.set_ip(self.state.vip, self.state.mask)
        self._apply_routes(self.state)
        if self.cfg.get('vpn_dns_resolve', True):
            self.resolver = VpnDnsResolver(self.state.dns)
        self._start_forwarder(self.state)

    async def teardown(self):
        log.info('shutting down...')
        if self.fwd:
            self.fwd.stop()
        if self.proxy:
            await self.proxy.stop()
        self.rm.rollback()
        if self.tun:
            self.tun.close()
        await asyncio.to_thread(self.vpn.shutdown)
        log.info('clean exit')

    def request_stop(self):
        self._stop_evt.set()


# ---------------------------------------------------------------- 入口
def setup_logging(log_file: str):
    fmt = '%(asctime)s %(levelname)s %(name)s: %(message)s'
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding='utf-8'))
    logging.basicConfig(level=logging.INFO, format=fmt, handlers=handlers)


def main():
    ap = argparse.ArgumentParser(description='MotionPro proxy server')
    ap.add_argument('--check-only', action='store_true',
                    help='仅验证隧道控制面（login→201→PQTU→mptoken→logout）')
    ap.add_argument('--route-dry-run', action='store_true',
                    help='路由命令只打印不执行（调试）')
    ap.add_argument('--run-for', type=float, default=0, metavar='SECONDS',
                    help='运行 N 秒后优雅自停（0=一直运行; 供测试/受控部署）')
    args = ap.parse_args()

    setup_logging(CFG.get('log_file', ''))
    log.info('gateway=%s user=%s', CFG['server'], CFG['user'])

    if args.check_only:
        svc = VpnService()
        st = svc.connect()
        print('[OK] vip=%s/%s dns=%s keepalive=%ss mptoken=%d'
              % (st.vip, st.mask, st.dns, st.keepalive_interval, st.mptoken))
        svc.shutdown()
        return

    sup = Supervisor(CFG)
    if args.route_dry_run:
        sup.cfg['route_dry_run'] = True
    sup.bring_up_tunnel()
    print('[*] 隧道就绪 vip=%s/%s' % (sup.state.vip, sup.state.mask))
    try:
        # Ctrl+C → run() 的 finally 负责全部清理, asyncio.run 返回即清理完毕
        asyncio.run(sup.run(run_for=args.run_for))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
