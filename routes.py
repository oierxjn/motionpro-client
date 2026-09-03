# -*- coding: utf-8 -*-
"""
routes — 路由装配与清理（防环是"不做必死"项）。

解耦约定：
- RouteManager 不依赖任何 VPN 组件；runner/platform 可注入（测试/调试），
  dry_run 模式只打印将要执行的命令。
- 装配层（proxy_serve）标准用法：
    rm = RouteManager()
    rm.apply_full(gw_host, vip, tun_iface)   # 内部: 解析网关IP → 防环 /32 → 默认路由
    ...
    rm.rollback()                            # 反序回滚全部已添加路由
- 分段模式用 add_subnet_route() 替代 apply_full() 的默认路由。

平台细节：
- Windows: 查询用 PowerShell(Get-NetRoute)，增删用 route add/delete；
  0/0 防环优先级 = route metric(1) + TUN 子接口 metric(1)，确保压过物理默认路由。
- Linux: `ip route`；默认路由以更高 metric 加在同一 main 表，不污染策略路由。
"""
import logging
import platform
import re
import socket
import subprocess

log = logging.getLogger('routes')


def _dec(b: bytes) -> str:
    """子进程输出解码：先 utf-8 后 gbk（中文 Windows 的 route/netsh 是本地码页）。"""
    for enc in ('utf-8', 'gbk'):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            continue
    return b.decode('utf-8', 'replace')


# ---------------------------------------------------------------- 纯解析函数（可单测）
_ROW_DEFAULT = re.compile(
    r'^0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+'
    r'(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s*$')


def parse_win_default_gw(route_print_output: str):
    """`route print -4` 输出 → 最低 metric 的默认路由 (gw_ip, iface_addr) 或 None。

    locale 无关：不依赖表头文本（中文 Windows 表头是本地化的），
    只匹配 5 列的活动路由行（持久路由只有 4 列，自动跳过）。"""
    best = None
    for line in route_print_output.splitlines():
        m = _ROW_DEFAULT.match(line.strip())
        if m:
            cand = (m.group(1), m.group(2), int(m.group(3)))
            if best is None or cand[2] < best[2]:
                best = cand
    if best is None:
        return None
    return best[0], best[1]


def parse_linux_default_gw(ip_route_output: str):
    """`ip route show default` 输出 → (gw_ip, dev) 或 (None, dev)。"""
    for line in ip_route_output.splitlines():
        if line.startswith('default'):
            toks = line.split()
            gw = toks[toks.index('via') + 1] if 'via' in toks else None
            dev = toks[toks.index('dev') + 1] if 'dev' in toks else None
            return gw, dev
    return None


# ---------------------------------------------------------------- 管理器
class RouteManager:
    def __init__(self, dry_run: bool = False, platform_name: str = None,
                 runner=None, resolver=None):
        self.dry_run = dry_run
        self.platform = platform_name or ('windows' if platform.system() == 'Windows' else 'linux')
        self._runner = runner or self._subprocess_runner
        self._resolver = resolver or self._socket_resolve
        self._applied: list[list[str]] = []     # 已生效命令对应的 undo 命令组（倒序回滚）

    # ---- 执行层 ----
    @staticmethod
    def _subprocess_runner(cmd: list):
        r = subprocess.run(cmd, capture_output=True)
        return r.returncode, _dec(r.stdout or b''), _dec(r.stderr or b'')

    @staticmethod
    def _socket_resolve(host: str) -> str:
        return socket.getaddrinfo(host, 443)[0][4][0]

    def _run(self, cmd: list, undo: list = None):
        rc, out, err = self._runner(cmd)
        if rc != 0:
            raise OSError(rc, '命令失败: %s\n%s' % (' '.join(cmd), (err or out).strip()))
        log.info('route: %s', ' '.join(cmd))
        if undo:
            self._applied.append(undo)
        return rc, out, err

    def _run_dry(self, cmd: list, undo: list = None):
        log.info('[dry-run] %s', ' '.join(cmd))
        if undo:
            self._applied.append(undo)
        return 0, '', ''

    def _exec(self, cmd: list, undo: list = None):
        if self.dry_run:
            return self._run_dry(cmd, undo)
        return self._run(cmd, undo)

    # ---- 查询（只读, 不受 dry_run 影响） ----
    def resolve_ip(self, host: str) -> str:
        return self._resolver(host)

    def default_gateway(self):
        """当前物理默认路由 → (gw_ip, iface)；必须在添加隧道路由【之前】查询。"""
        if self.platform == 'windows':
            rc, out, _ = self._runner(['route', 'print', '-4'])
            return parse_win_default_gw(out)
        rc, out, _ = self._runner(['ip', 'route', 'show', 'default'])
        gw, dev = parse_linux_default_gw(out) or (None, None)
        return gw, dev

    # ---- 高层装配 ----
    def set_interface_metric(self, iface_alias: str, metric: int):
        """Windows: 压低 TUN 子接口 metric，保证 0/0 生效（Linux 由 route metric 控制）。"""
        if self.platform != 'windows':
            return
        self._exec(['netsh', 'interface', 'ipv4', 'set', 'subinterface', iface_alias,
                    'metric=%d' % metric, 'store=active'])

    def add_host_route(self, ip: str, gw: str = None, iface=None, metric: int = 1):
        """ip/32 → 指定网关（防环核心: 网关 IP 必须走物理网卡）。
        iface 传 int(接口索引) 才会追加 `if`；字符串(IP/接口名)仅作展示。"""
        if self.platform == 'windows':
            cmd = ['route', 'add', ip, 'mask', '255.255.255.255', gw, 'metric', str(metric)]
            undo = ['route', 'delete', ip, 'mask', '255.255.255.255']
            if isinstance(iface, int):
                cmd += ['if', str(iface)]
        else:
            cmd = ['ip', 'route', 'add', '%s/32' % ip]
            if gw:
                cmd += ['via', gw]
            if iface:
                cmd += ['dev', iface]
            undo = ['ip', 'route', 'del', '%s/32' % ip]
        self._exec(cmd, undo)

    def add_default_route(self, gw: str = None, iface=None, metric: int = 1):
        """0.0.0.0/0 → TUN（gw=TUN 内 VIP; on-link）。"""
        if self.platform == 'windows':
            cmd = ['route', 'add', '0.0.0.0', 'mask', '0.0.0.0', gw, 'metric', str(metric)]
            undo = ['route', 'delete', '0.0.0.0', 'mask', '0.0.0.0', gw]
            if iface is not None:
                cmd += ['if', str(iface)]
        else:
            cmd = ['ip', 'route', 'add', 'default', 'metric', str(metric)]
            if gw:
                cmd += ['via', gw]
            if iface:
                cmd += ['dev', iface]
            undo = ['ip', 'route', 'del', 'default', 'metric', str(metric)]
        self._exec(cmd, undo)

    def add_subnet_route(self, cidr: str, gw: str = None, iface=None, metric: int = 1):
        """split 模式: 指定网段进隧道。"""
        if self.platform == 'windows':
            dst, mlen = cidr.split('/')
            mask_int = (0xFFFFFFFF << (32 - int(mlen))) & 0xFFFFFFFF
            mask = '.'.join(str((mask_int >> s) & 0xFF) for s in (24, 16, 8, 0))
            cmd = ['route', 'add', dst, 'mask', mask, gw or '', 'metric', str(metric)]
            undo = ['route', 'delete', dst, 'mask', mask]
            if iface is not None:
                cmd += ['if', str(iface)]
        else:
            cmd = ['ip', 'route', 'add', cidr, 'metric', str(metric)]
            if gw:
                cmd += ['via', gw]
            if iface:
                cmd += ['dev', iface]
            undo = ['ip', 'route', 'del', cidr]
        self._exec(cmd, undo)

    def apply_full(self, gw_host: str, vip: str, tun_iface_alias: str = None,
                   tun_ifindex=None, tun_metric: int = 1):
        """全隧道装配（顺序敏感）:
        1. 先取物理默认路由 → 2. 网关 IP /32 固定走物理网关（防环）→ 3. 0/0 走 TUN。
        Windows 需要 tun_ifindex(int)；Linux 用 tun_iface_alias(dev 名)。
        返回 (gw_ip, phy_gw, phy_iface) 供重连/日志使用。
        """
        gw_ip = self.resolve_ip(gw_host)
        phy_gw, phy_iface = self.default_gateway()
        if not phy_gw and not phy_iface:
            raise OSError('未找到物理默认路由，拒绝装配（防环失败会导致隧道自环）')
        log.info('apply_full: gw=%s via phy(%s, %s) → tun vip=%s',
                 gw_ip, phy_gw, phy_iface, vip)
        self.add_host_route(gw_ip, gw=phy_gw, iface=phy_iface, metric=1)
        if self.platform == 'windows':
            if not tun_ifindex:
                raise OSError('Windows 需要 TUN 接口索引(tun_ifindex)才能加 0/0 路由')
            self.set_interface_metric(tun_iface_alias, tun_metric)
            self.add_default_route(gw=vip, iface=tun_ifindex, metric=tun_metric)
        else:
            self.add_default_route(iface=tun_iface_alias, metric=tun_metric)
        return gw_ip, phy_gw, phy_iface

    def rollback(self):
        """倒序回滚全部已添加路由（幂等: 单条失败只告警，继续清理其余）。"""
        while self._applied:
            undo = self._applied.pop()
            if self.dry_run:
                log.info('[dry-run] %s', ' '.join(undo))
                continue
            try:
                rc, out, err = self._runner(undo)
                log.info('rollback: %s (rc=%d)', ' '.join(undo), rc)
            except OSError as e:
                log.warning('rollback failed: %s %s', undo, e)
