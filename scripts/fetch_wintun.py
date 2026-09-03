#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""下载并解包 wintun.dll 到 vendor/wintun/（已在 .gitignore，二进制不入库）。

用法: uv run scripts/fetch_wintun.py [--url <zip 链接>]
默认: https://www.wintun.net/builds/wintun-0.14.1.zip （官方发行包）
"""
import argparse
import platform
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_URL = 'https://www.wintun.net/builds/wintun-0.14.1.zip'
ARCH_DIR = {'AMD64': 'amd64', 'ARM64': 'arm64', 'x86': 'x86'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', default=DEFAULT_URL)
    args = ap.parse_args()

    arch = ARCH_DIR.get(platform.machine().upper())
    if not arch:
        sys.exit('未知架构: %s' % platform.machine())

    dest_root = REPO / 'vendor' / 'wintun'
    dll_dest = dest_root / 'wintun' / 'bin' / arch / 'wintun.dll'
    if dll_dest.exists():
        print('已存在: %s' % dll_dest)
        return

    zip_path = dest_root / 'wintun.zip'
    dest_root.mkdir(parents=True, exist_ok=True)
    print('下载 %s ...' % args.url)
    urllib.request.urlretrieve(args.url, zip_path)
    with zipfile.ZipFile(zip_path) as z:
        # 兼容 zip 内顶层目录名（wintun/bin/<arch>/wintun.dll）
        names = [n for n in z.namelist() if n.endswith('wintun.dll') and ('/%s/' % arch) in n]
        if not names:
            sys.exit('zip 中未找到 %s 的 wintun.dll' % arch)
        for n in names:
            out = dest_root / n
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(z.read(n))
            print('解包: %s' % out)
    zip_path.unlink()
    print('OK: %s' % dll_dest if dll_dest.exists() else 'OK (路径见上)')


if __name__ == '__main__':
    main()
