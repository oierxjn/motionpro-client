# -*- coding: utf-8 -*-
"""routes 单测：解析函数 + RouteManager 命令编排（fake runner/resolver，不动系统路由）。"""
import unittest

from routes import RouteManager, parse_linux_default_gw, parse_win_default_gw

# 中文 Windows 实测样例: 本地化表头 + On-link 行 + 持久路由(4列) + 双默认路由
ROUTE_PRINT = """
===========================================================================
接口列表
  5...xx ... Intel(R) Wi-Fi
===========================================================================
IPv4 路由表
===========================================================================
活动路由:
网络目标        网络掩码          网关       接口   跃点数
          0.0.0.0          0.0.0.0         198.51.100.1     192.0.2.100   9291
          0.0.0.0          0.0.0.0     192.0.2.1      198.51.100.23     30
        127.0.0.0        255.0.0.0            在链路上         127.0.0.1    331
===========================================================================
永久路由:
          0.0.0.0          0.0.0.0         198.51.100.1   9256
"""


class TestParsers(unittest.TestCase):
    def test_win_default_gw_picks_lowest_metric(self):
        self.assertEqual(parse_win_default_gw(ROUTE_PRINT), ('192.0.2.1', '198.51.100.23'))

    def test_win_default_gw_none(self):
        self.assertIsNone(parse_win_default_gw('no table here'))

    def test_linux_default_gw(self):
        self.assertEqual(parse_linux_default_gw('default via 10.0.0.1 dev eth0 metric 100'),
                         ('10.0.0.1', 'eth0'))
        self.assertEqual(parse_linux_default_gw('default dev tun0 scope link'),
                         (None, 'tun0'))
        self.assertIsNone(parse_linux_default_gw('10.0.0.0/8 dev eth0'))


class FakeRunner:
    """记录命令，返回 canned 输出。"""

    def __init__(self, outputs=None):
        self.commands = []
        self.outputs = outputs or {}

    def __call__(self, cmd):
        self.commands.append(list(cmd))
        rc, out = self.outputs.get(' '.join(cmd), (0, ''))
        return rc, out, ''


class TestRouteManager(unittest.TestCase):
    RESOLVER = lambda self, host: '202.120.190.1'

    def _rm(self, platform_name='windows', outputs=None):
        fr = FakeRunner(outputs)
        rm = RouteManager(platform_name=platform_name, runner=fr,
                          resolver=lambda host: '202.120.190.1')
        return rm, fr

    def test_windows_apply_full(self):
        rm, fr = self._rm('windows', {'route print -4': (0, ROUTE_PRINT)})
        gw_ip, phy_gw, phy_if = rm.apply_full('vpn.example.cn', '111.187.82.10',
                                              tun_iface_alias='mptun0', tun_ifindex=74)
        self.assertEqual(gw_ip, '202.120.190.1')
        self.assertEqual(phy_gw, '192.0.2.1')
        cmds = [' '.join(c) for c in fr.commands]
        self.assertEqual(cmds[0], 'route print -4')
        # 防环: 网关 IP /32 走物理网关（iface 是 IP 字符串, 不追加 if）
        self.assertEqual(cmds[1],
                         'route add 202.120.190.1 mask 255.255.255.255 192.0.2.1 metric 1')
        self.assertEqual(cmds[2],
                         'netsh interface ipv4 set subinterface mptun0 metric=1 store=active')
        # 0/0 走 TUN（需要 int ifindex）
        self.assertEqual(cmds[3],
                         'route add 0.0.0.0 mask 0.0.0.0 111.187.82.10 metric 1 if 74')

    def test_windows_apply_full_requires_ifindex(self):
        rm, _ = self._rm('windows', {'route print -4': (0, ROUTE_PRINT)})
        with self.assertRaises(OSError):
            rm.apply_full('vpn.example.cn', '111.187.82.10', tun_iface_alias='mptun0')

    def test_linux_apply_full(self):
        rm, fr = self._rm('linux',
                          {'ip route show default': (0, 'default via 10.0.0.1 dev eth0\n')})
        gw_ip, phy_gw, phy_if = rm.apply_full('gw.example', '10.7.0.1', tun_iface_alias='mptun0')
        self.assertEqual((phy_gw, phy_if), ('10.0.0.1', 'eth0'))
        cmds = [' '.join(c) for c in fr.commands]
        self.assertEqual(cmds[0], 'ip route show default')
        self.assertEqual(cmds[1], 'ip route add 202.120.190.1/32 via 10.0.0.1 dev eth0')
        self.assertEqual(cmds[2], 'ip route add default metric 1 dev mptun0')

    def test_rollback_reverses_order(self):
        rm, fr = self._rm('linux')
        rm.add_host_route('1.2.3.4', gw='10.0.0.1', iface='eth0')
        rm.add_default_route(iface='mptun0', metric=5)
        rm.rollback()
        dels = [' '.join(c) for c in fr.commands[-2:]]
        self.assertEqual(dels, ['ip route del default metric 5', 'ip route del 1.2.3.4/32'])
        self.assertEqual(len(rm._applied), 0)

    def test_failure_raises_and_records_nothing(self):
        rm, fr = self._rm('windows', {
            'route add 1.2.3.4 mask 255.255.255.255 10.0.0.1 metric 1': (1, 'err')})
        with self.assertRaises(OSError):
            rm.add_host_route('1.2.3.4', gw='10.0.0.1')
        self.assertEqual(len(rm._applied), 0)

    def test_subnet_route_mask(self):
        rm, fr = self._rm('windows')
        rm.add_subnet_route('202.120.190.0/24', gw='111.187.82.10', iface=74)
        self.assertEqual(fr.commands[0],
                         ['route', 'add', '202.120.190.0', 'mask', '255.255.255.0',
                          '111.187.82.10', 'metric', '1', 'if', '74'])

    def test_dry_run_records_undo(self):
        rm = RouteManager(dry_run=True, platform_name='linux',
                          runner=FakeRunner(), resolver=lambda h: '1.1.1.1')
        rm.add_subnet_route('202.120.190.0/24', iface='mptun0')
        self.assertEqual(len(rm._applied), 1)
        rm.rollback()
        self.assertEqual(len(rm._applied), 0)


if __name__ == '__main__':
    unittest.main()
