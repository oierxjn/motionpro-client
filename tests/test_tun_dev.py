# -*- coding: utf-8 -*-
"""tun_dev 单测：工具函数与双平台可加载性（不创建真实适配器）。"""
import platform
import unittest

import tun_dev
from tun_dev import LinuxTun, TunDevice, WintunTun, create_tun, find_wintun_dll, mask_to_prefix


class TestHelpers(unittest.TestCase):
    def test_mask_to_prefix(self):
        self.assertEqual(mask_to_prefix('255.255.255.0'), 24)
        self.assertEqual(mask_to_prefix('255.255.224.0'), 19)
        self.assertEqual(mask_to_prefix('255.255.255.255'), 32)
        self.assertEqual(mask_to_prefix('0.0.0.0'), 0)

    def test_find_wintun_dll_missing_returns_none_or_str(self):
        r = find_wintun_dll(cfg_value='Z:\\definitely\\not\\here.dll')
        self.assertTrue(r is None or (isinstance(r, str) and r.endswith('.dll')))

    def test_find_wintun_dll_explicit(self):
        import os
        import tempfile
        fd, path = tempfile.mkstemp(suffix='.dll')
        os.close(fd)
        try:
            self.assertEqual(find_wintun_dll(cfg_value=path), path)
        finally:
            os.unlink(path)

    def test_factory_by_platform(self):
        t = create_tun()
        if platform.system() == 'Windows':
            self.assertIsInstance(t, WintunTun)
        else:
            self.assertIsInstance(t, LinuxTun)

    def test_factory_bad_kind(self):
        with self.assertRaises(ValueError):
            create_tun('nope')

    def test_abstract_interface(self):
        for m in ('open', 'read', 'write', 'set_ip', 'close'):
            self.assertTrue(hasattr(TunDevice, m))


class TestLinuxTunClose(unittest.TestCase):
    """LinuxTun.close 必须先 ip link del: 仅 close fd 时, 阻塞在 os.read()
    的搬运线程会占住设备, 下次 TUNSETIFF 同名设备 EBUSY (重连回路根因)。"""

    def _tun(self, calls):
        t = LinuxTun()
        t._run_ip = lambda args: calls.append(args)
        t.fd = None                       # 不触碰真实 fd
        return t

    def test_close_deletes_interface(self):
        calls = []
        self._tun(calls).close()
        self.assertEqual(calls, [['link', 'del', 'dev', 'mptun0']])

    def test_close_swallows_missing_interface(self):
        t = LinuxTun()

        def _boom(args):
            raise OSError(2, 'No such device')
        t._run_ip = _boom
        t.fd = None
        t.close()                         # 接口不存在时不抛出


if __name__ == '__main__':
    unittest.main()
