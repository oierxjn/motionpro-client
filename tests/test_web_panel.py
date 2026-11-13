# -*- coding: utf-8 -*-
"""web_panel 单测：LogRing 环形缓冲 + panel_auth 认证规则 + Supervisor 快照。"""
import logging
import unittest

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
