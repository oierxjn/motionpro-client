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


if __name__ == '__main__':
    unittest.main()
