# -*- coding: utf-8 -*-
"""web_panel 单测：LogRing 环形缓冲 + panel_auth 认证规则 + Supervisor 快照。"""
import logging
import unittest
from types import SimpleNamespace

from web_panel import LogRing, attach_ring, panel_auth


class TestLogRing(unittest.TestCase):
    def setUp(self):
        self.ring = LogRing(maxlen=5)
        self.log = logging.getLogger('test.ring')
        self.log.setLevel(logging.INFO)
        self.log.addHandler(self.ring)
        self.log.propagate = False

    def tearDown(self):
        self.log.removeHandler(self.ring)

    def test_tail_returns_recent_lines(self):
        for i in range(3):
            self.log.info('line-%d', i)
        self.assertEqual(len(self.ring.tail(10)), 3)
        self.assertIn('line-2', self.ring.tail(10)[-1])

    def test_maxlen_evicts_oldest(self):
        for i in range(8):
            self.log.info('n-%d', i)
        lines = self.ring.tail(100)
        self.assertEqual(len(lines), 5)
        self.assertIn('n-7', lines[-1])
        self.assertNotIn('n-0', ''.join(lines))

    def test_tail_clamps_n(self):
        self.log.info('x')
        self.assertEqual(len(self.ring.tail(1)), 1)

    def test_attach_ring_idempotent(self):
        r1 = attach_ring()
        r2 = attach_ring()
        self.assertIs(r1, r2)
        logging.getLogger().removeHandler(r1)


class TestPanelAuth(unittest.TestCase):
    CFG = {'proxy_user': 'mp', 'proxy_pass': 'pw',
           'panel_user': 'admin', 'panel_pass': 'secret'}

    def test_loopback_no_auth(self):
        for h in ('127.0.0.1', '::1', 'localhost'):
            self.assertEqual(panel_auth(self.CFG, h), ('', ''))

    def test_nonloopback_prefers_panel_creds(self):
        self.assertEqual(panel_auth(self.CFG, '0.0.0.0'), ('admin', 'secret'))

    def test_nonloopback_falls_back_to_proxy_creds(self):
        cfg = {'proxy_user': 'mp', 'proxy_pass': 'pw'}
        self.assertEqual(panel_auth(cfg, '0.0.0.0'), ('mp', 'pw'))

    def test_nonloopback_without_creds_raises(self):
        with self.assertRaises(SystemExit):
            panel_auth({}, '0.0.0.0')


class TestSupervisorSnapshot(unittest.TestCase):
    def test_snapshot_idle_shape(self):
        from proxy_serve import Supervisor
        sup = Supervisor({'server': 'x.example', 'user': 'u', 'password': 'p'})
        s = sup.snapshot()
        self.assertEqual(s['phase'], 'idle')
        self.assertIsNone(s['vip'])
        self.assertIsNone(s['forwarder'])
        self.assertEqual(s['proxy_endpoints'], [])
        self.assertIn('last_error', s)

    def test_bring_up_failure_sets_phase_and_error(self):
        from proxy_serve import Supervisor
        sup = Supervisor({'server': 'invalid.invalid', 'user': 'u',
                          'password': 'p', 'deploy_mode': 'host'})
        try:
            sup.bring_up_tunnel()
        except Exception:
            pass
        self.assertEqual(sup.phase, 'idle')
        self.assertNotEqual(sup.last_error, '')

    def test_bring_up_failure_cleans_partial_setup(self):
        """bring_up 中途失败: 残留被清理（TUN 关闭/state 清空），
        否则面板重试踩到半开 TUN/陈旧 VIP（DebianServer EBUSY 回路根因）。"""
        from proxy_serve import Supervisor
        sup = Supervisor({'server': 'x.example', 'user': 'u', 'password': 'p'})
        closed = []
        st = SimpleNamespace(vip='10.7.0.1', mask='255.255.255.0', dns=[],
                             keepalive_interval=30, mptoken=1, tls=None)
        sup.vpn = SimpleNamespace(connect=lambda: st, shutdown=lambda: None)
        sup.tun = SimpleNamespace(set_ip=lambda ip, m: None,
                                  close=lambda: closed.append(1))

        def _boom(_st):
            raise RuntimeError('route boom')
        sup._apply_routes = _boom
        with self.assertRaises(RuntimeError):
            sup.bring_up_tunnel()
        self.assertEqual(sup.phase, 'idle')
        self.assertIn('route boom', sup.last_error)
        self.assertEqual(closed, [1])           # TUN 已关闭
        self.assertIsNone(sup.tun)
        self.assertIsNone(sup.state)            # 快照不再显示陈旧 VIP


class TestOnDeadGeneration(unittest.TestCase):
    """迟到回调世代守卫: 被拆除隧道的旧 Forwarder 不得触发新隧道重连。"""

    def _sup(self):
        from proxy_serve import Supervisor
        return Supervisor({'server': 'x.example', 'user': 'u', 'password': 'p'})

    def test_stale_gen_ignored(self):
        sup = self._sup()
        sup._fwd_gen = 2
        sup._on_dead('stale EBADF', gen=1)          # 旧世代
        self.assertFalse(sup._reconnect_evt.is_set())

    def test_current_gen_triggers(self):
        sup = self._sup()
        sup._fwd_gen = 2
        sup._on_dead('EOF', gen=2)                  # 当前世代
        self.assertTrue(sup._reconnect_evt.is_set())

    def test_default_gen_zero_matches_fresh(self):
        sup = self._sup()                            # 未启动过 forwarder → gen 0
        sup._on_dead('EOF')                          # gen 缺省 0
        self.assertTrue(sup._reconnect_evt.is_set())

    def test_teardown_bumps_generation(self):
        """拆隧道即升代: 新 forwarder 启动前（bring_up 半路失败）的死亡回调也被拒绝。"""
        sup = self._sup()
        sup._fwd_gen = 3
        sup.fwd = None
        sup.tun = None
        sup.rm = SimpleNamespace(rollback=lambda: None)
        sup.vpn = SimpleNamespace(shutdown=lambda: None)
        sup._tunnel_down_sync()
        self.assertEqual(sup._fwd_gen, 4)
        sup._on_dead('late EBADF', gen=3)            # 旧世代
        self.assertFalse(sup._reconnect_evt.is_set())
