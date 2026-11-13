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

from forwarder import Forwarder, broadcast_of
from local_proxy import ProxyListener, ProxyServer, VpnDnsResolver
from mp_client import CFG
from routes import RouteManager, fake_gateway_ip
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
    """组件装配 + 重连编排 + 清理。

    phase 状态机（供面板/外部控制只读）:
        idle → connecting → up ⇄ reconnecting → up
              ↑______stopping ←______|
    隧道的连接/断开可在运行期通过 bg_connect()/tunnel_down() 控制，
    代理监听与（可选）Web 面板独立于隧道存活。"""

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
        self.phase = 'idle'
        self.last_error = ''
        self.connected_since = None     # monotonic（断开/重连时重置）
        self._stop_evt = threading.Event()
        self._reconnect_evt = threading.Event()

    # ---- 启动（阻塞部分, 在 asyncio 循环外调用） ----
    def bring_up_tunnel(self):
        """隧道 → TUN → 路由 → 搬运。失败时 phase 回到 idle 并记录 last_error。"""
        self.phase = 'connecting'
        self.last_error = ''
        try:
            self.state = self.vpn.connect()
            st = self.state
            if self.tun is None:
                self.tun = create_tun(self.cfg.get('tun_kind') or None)
                self.tun.open(self.cfg.get('tun_name', 'mptun0'),
                              int(self.cfg.get('tun_mtu', 1400)))
            self.tun.set_ip(st.vip, st.mask)
            if hasattr(self.tun, 'add_static_neighbor'):
                # 0/0 下一跳(假网关)挂永久 ARP 条目, 否则内核 ARP 无应答 → 单播黑洞
                self.tun.add_static_neighbor(fake_gateway_ip(st.vip, st.mask))
            self._apply_routes(st)
            if self.cfg.get('route_mode', 'full') == 'split' or \
                    self.cfg.get('deploy_mode', 'host') == 'container':
                # split: 出口流量必须以 VIP 为源才能命中分段路由;
                # container: 上游绑定 VIP 为源, 与容器 eth0 IP 的回包按源地址分流
                self.bind_ip = st.vip
                log.info('上游自动绑定 VIP %s', st.vip)
            else:
                self.bind_ip = str(self.cfg.get('proxy_bind_ip', '') or '')
            if self.cfg.get('vpn_dns_resolve', True):
                # 用隧道 DNS 解析域名: 校园边界对 VPN 池单向 NAT, 公网解析的
                # 地址回包源不匹配; 网关自己的 DNS 给内网地址才能连通(官方同款)
                self.resolver = VpnDnsResolver(st.dns,
                                               timeout=float(self.cfg.get('vpn_dns_timeout', 8)))
                log.info('域名解析走隧道 DNS %s (timeout=%ss)',
                         st.dns, self.cfg.get('vpn_dns_timeout', 8))
            if self.proxy is not None:
                # 面板重连后 VIP 会变: 代理按「每条连接」读取这两个属性, 这里
                # 同步刷新, 否则上游 socket 仍绑旧 VIP → Cannot assign requested
                # address, 代理在重连后全部 502/拒绝
                self.proxy.bind_ip = self.bind_ip
                self.proxy.resolver = self.resolver
            self._start_forwarder(st)
            import time as _time
            self.connected_since = _time.monotonic()
            self.phase = 'up'
            return st
        except Exception as e:
            self.last_error = '%s: %s' % (type(e).__name__, e)
            self.phase = 'idle'
            log.exception('隧道建立失败: %s (回滚残留状态)', e)
            self._cleanup_failed_bring_up()
            raise

    def _cleanup_failed_bring_up(self):
        """建隧道中途失败后尽力恢复一致状态（路由/TUN/网关会话/引用）。

        不清理的话面板重试会踩到残留：半开 TUN、已存在的路由、面板快照
        显示陈旧 VIP。清理失败只告警，不覆盖原始异常。"""
        try:
            self._tunnel_down_sync()
        except Exception as e:
            log.warning('失败清理未完全(忽略): %s', e)

    def _apply_routes(self, st):
        alias = getattr(self.tun, 'alias', None) or self.tun.name
        ifindex = getattr(self.tun, 'ifindex', None)
        deploy_mode = self.cfg.get('deploy_mode', 'host')
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
        elif deploy_mode == 'container':
            # 容器 netns 全隧道: 0/0 只作用于容器内, 源地址分流保回包
            self.rm.apply_container_full(self.vpn.host, st.vip,
                                         tun_iface_alias=alias)
        else:
            self.rm.apply_full(self.vpn.host, st.vip, mask=st.mask,
                               tun_iface_alias=alias, tun_ifindex=ifindex)

    def _start_forwarder(self, st):
        if self.fwd:
            self.fwd.stop()
        self._fwd_gen = getattr(self, '_fwd_gen', 0) + 1
        gen = self._fwd_gen
        self.fwd = Forwarder(st.tls, self.tun,
                             keepalive_interval=st.keepalive_interval,
                             on_dead=lambda why, _g=gen: self._on_dead(why, _g),
                             local_broadcast=broadcast_of(st.vip, st.mask))
        self.fwd.start()

    # ---- Forwarder 回调（来自搬运线程） ----
    def _on_dead(self, why: str, gen: int = 0):
        """世代守卫: 被拆除隧道的旧 Forwarder 线程会迟到触发死亡回调
        (旧 fd 关闭后的 EBADF 等), 不得作用于新隧道。"""
        if gen != getattr(self, '_fwd_gen', 0):
            log.info('忽略已拆除隧道的迟到死亡回调(gen=%d != %d): %s',
                     gen, self._fwd_gen, why)
            return
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
                    if self.phase == 'up':
                        await self._do_reconnect()
                    # phase 非 up(如面板已手动断开)时丢弃事件, 不自动重连
                await asyncio.sleep(0.5)
        finally:
            await self.teardown()

    async def _do_reconnect(self):
        self.phase = 'reconnecting'
        for attempt in range(1, MAX_RECONNECT_ATTEMPTS + 1):
            try:
                await asyncio.to_thread(self._rebuild)
                log.info('reconnect ok (attempt %d)', attempt)
                self.phase = 'up'
                import time as _time
                self.connected_since = _time.monotonic()
                return
            except Exception as e:
                delay = min(60, 2 ** attempt)
                self.last_error = '%s: %s' % (type(e).__name__, e)
                log.error('reconnect attempt %d failed: %s → %ds 后重试',
                          attempt, e, delay)
                await asyncio.sleep(delay)
        log.critical('重连 %d 次全部失败', MAX_RECONNECT_ATTEMPTS)
        self.phase = 'idle'
        if not getattr(self, 'panel_endpoint', None):
            self._stop_evt.set()     # 无面板: 按原行为退出进程
        # 有面板: 保持面板存活, 用户可在面板重试连接

    def _rebuild(self):
        """重连全套（阻塞）: 整体拆除旧隧道（含 TUN/路由/会话）→ 重新 bring_up。
        不在旧 TUN 上原地重配——实测会 EBUSY; 复用 bring_up 的已验证路径。"""
        self._tunnel_down_sync()
        self.bring_up_tunnel()

    async def teardown(self):
        log.info('shutting down...')
        self.phase = 'stopping'
        await self.tunnel_down()
        if self.proxy:
            await self.proxy.stop()
        self.phase = 'idle'
        log.info('clean exit')

    def _tunnel_down_sync(self):
        """拆隧道（阻塞）: 停搬运 → 回滚路由 → 关 TUN → logout。"""
        if self.fwd:
            self.fwd.stop()
            self.fwd = None
        # 拆除即升代: 旧 forwarder 之后迟到的死亡回调一律拒绝——
        # 即使新 forwarder 尚未启动（bring_up 失败停在半路）也不会误触发重连
        self._fwd_gen = getattr(self, '_fwd_gen', 0) + 1
        self.rm.rollback()
        if self.tun:
            self.tun.close()
            self.tun = None
        self.vpn.shutdown()
        self.state = None
        self.resolver = None
        self.connected_since = None

    async def tunnel_down(self):
        """仅拆隧道（TUN/路由/会话），代理与面板保持运行（面板用）。"""
        await asyncio.to_thread(self._tunnel_down_sync)

    def snapshot(self) -> dict:
        """面板/监控用运行状态快照（只读, 线程安全约读）。"""
        import time as _time
        st = self.state
        snap = {
            'phase': self.phase,
            'last_error': self.last_error,
            'uptime_sec': (int(_time.monotonic() - self.connected_since)
                           if self.connected_since else None),
            'deploy_mode': self.cfg.get('deploy_mode', 'host'),
            'route_mode': self.cfg.get('route_mode', 'full'),
            'proxy_endpoints': [('%s:%d' % ep) for ep in self.proxy.endpoints]
                               if self.proxy else [],
            'panel': self.panel_endpoint if hasattr(self, 'panel_endpoint') else '',
        }
        if st:
            snap.update(vip=st.vip, mask=st.mask, dns=st.dns,
                        keepalive_interval=st.keepalive_interval,
                        mptoken=st.mptoken)
        else:
            snap.update(vip=None, mask=None, dns=[], keepalive_interval=None,
                        mptoken=None)
        snap['forwarder'] = dict(self.fwd.stats) if self.fwd else None
        return snap

    async def bg_connect(self):
        """面板「连接」按钮：后台线程建隧道，完成/失败更新 phase。"""
        if self.phase != 'idle':
            return
        task = asyncio.create_task(asyncio.to_thread(self.bring_up_tunnel))

        def _done(t: asyncio.Task):
            try:
                t.result()      # bring_up_tunnel 已自行管理 phase/last_error
            except Exception:
                pass
        task.add_done_callback(_done)

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
    ap.add_argument('--no-panel', action='store_true',
                    help='禁用 Web 控制面板')
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

    panel_listen = '' if args.no_panel else \
        str(CFG.get('panel_listen', '127.0.0.1:9090') or '')
    try:
        if panel_listen:
            serve_with_panel(sup, panel_listen, args.run_for)
        else:
            sup.bring_up_tunnel()
            print('[*] 隧道就绪 vip=%s/%s' % (sup.state.vip, sup.state.mask))
            asyncio.run(sup.run(run_for=args.run_for))
    except KeyboardInterrupt:
        pass


def serve_with_panel(sup, listen: str, run_for: float):
    """面板优先启动（隧道失败/断开时面板仍可用），随后后台建隧道。"""
    import uvicorn
    from web_panel import create_app, panel_auth

    host, port = _parse_listen(listen, '127.0.0.1')
    auth = panel_auth(sup.cfg, host)
    sup.panel_endpoint = '%s:%d' % (host, port)
    app, _ring = create_app(sup, auth=auth)
    loopback = host in ('127.0.0.1', '::1', 'localhost')
    log.info('Web 面板: http://%s:%d %s', host, port,
             '(回环, 免认证)' if loopback else '(已启用 Basic 认证)')

    config = uvicorn.Config(app, host=host, port=port,
                            log_level='warning', access_log=False)
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None   # 让 Supervisor 接管信号

    async def _serve():
        panel_task = asyncio.create_task(server.serve())
        try:
            await asyncio.to_thread(sup.bring_up_tunnel)
            print('[*] 隧道就绪 vip=%s/%s' % (sup.state.vip, sup.state.mask))
        except Exception as e:
            # 建隧道失败不退出: 面板保持可用, 可点「连接」重试
            log.error('隧道建立失败: %s (面板保持可用, 可重试连接)', e)
        await sup.run(run_for=run_for)
        server.should_exit = True
        try:
            await asyncio.wait_for(panel_task, timeout=5)
        except Exception:
            pass

    asyncio.run(_serve())


if __name__ == '__main__':
    main()
