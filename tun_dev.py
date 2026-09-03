# -*- coding: utf-8 -*-
"""
tun_dev — TUN 设备封装（Windows wintun / Linux /dev/net/tun 双实现）。

解耦约定：
- 上层（forwarder）只依赖 TunDevice 抽象接口：
    open(name, mtu) / read(n, timeout) / write(pkt) / set_ip(ip, mask) / close()
- wintun 路径需要管理员权限创建适配器；Linux 需要 root / CAP_NET_ADMIN。
- wintun.dll 获取：uv run scripts/fetch_wintun.py（落盘 vendor/wintun/，已 gitignore），
  或用 MP_WINTUN_DLL 环境变量 / config 'wintun_dll' 指定既有 DLL。
- 平台专属模块（ctypes.wintypes / fcntl）一律延迟导入，保证本模块双平台可加载。

参考: https://www.wintun.net/ (Wintun 0.14.1 API)。
"""
import logging
import os
import platform
import socket
import struct
import subprocess
from abc import ABC, abstractmethod

log = logging.getLogger('tun')

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------- 工具
def mask_to_prefix(mask: str) -> int:
    """255.255.224.0 → 19"""
    return sum(bin(int(x)).count('1') for x in mask.split('.'))


def find_wintun_dll(cfg_value: str = None) -> str | None:
    """按优先级找 wintun.dll：显式指定 > 环境变量 > vendor 常见布局 > PATH。"""
    arch = {'AMD64': 'amd64', 'ARM64': 'arm64', 'x86': 'x86'}.get(platform.machine().upper(), 'amd64')
    candidates = []
    if cfg_value:
        candidates.append(cfg_value)
    if os.environ.get('MP_WINTUN_DLL'):
        candidates.append(os.environ['MP_WINTUN_DLL'])
    for root in (os.path.join(REPO_ROOT, 'vendor', 'wintun'),
                 os.path.join(REPO_ROOT, 'vendor')):
        candidates.append(os.path.join(root, 'wintun', 'bin', arch, 'wintun.dll'))
        candidates.append(os.path.join(root, 'bin', arch, 'wintun.dll'))
        candidates.append(os.path.join(root, 'wintun.dll'))
    candidates.append('wintun.dll')          # 让系统按 PATH 搜
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def _dec(b: bytes) -> str:
    """子进程输出解码：先 utf-8 后 gbk（中文 Windows 的 netsh/ip 是本地码页）。"""
    for enc in ('utf-8', 'gbk'):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            continue
    return b.decode('utf-8', 'replace')


# ---------------------------------------------------------------- 抽象接口
class TunDevice(ABC):
    name: str = 'mptun0'
    mtu: int = 1400

    @abstractmethod
    def open(self, name: str = 'mptun0', mtu: int = 1400) -> None: ...

    @abstractmethod
    def read(self, n: int = 65536, timeout: float = None) -> bytes:
        """读一个 IP 包；超时/无数据返回 b''。"""

    @abstractmethod
    def write(self, pkt: bytes) -> int: ...

    @abstractmethod
    def set_ip(self, ip: str, mask: str) -> None: ...

    @abstractmethod
    def close(self) -> None: ...


def create_tun(kind: str = None) -> TunDevice:
    """工厂：按 kind 或平台默认选择实现（便于测试注入 mock）。"""
    kind = kind or ('wintun' if platform.system() == 'Windows' else 'linux')
    if kind == 'wintun':
        return WintunTun()
    if kind == 'linux':
        return LinuxTun()
    raise ValueError('unknown tun kind: %s' % kind)


# ---------------------------------------------------------------- Windows wintun
class WintunTun(TunDevice):
    ADAPTER_TYPE = 'MotionProProxy'
    RING_CAPACITY = 0x400000                # 4 MiB
    INFINITE = 0xFFFFFFFF
    WAIT_OBJECT_0 = 0

    def __init__(self):
        self.dll_path = None
        self._win = None
        self._wt = None                      # ctypes.wintypes（延迟导入）
        self._adapter = None                 # WINTUN_ADAPTER_HANDLE
        self._session = None                 # WINTUN_SESSION_HANDLE
        self._read_event = None
        self.ifindex = None
        self.alias = None

    # -- ctypes 绑定（wintun 0.14.x 签名） --
    def _load(self):
        import ctypes
        import ctypes.wintypes as wt
        self._wt = wt
        self.dll_path = find_wintun_dll()
        if not self.dll_path:
            raise OSError('wintun.dll 未找到：先运行 `uv run scripts/fetch_wintun.py`，'
                          '或设 MP_WINTUN_DLL 指向既有 DLL')
        w = ctypes.WinDLL(self.dll_path, use_last_error=True)
        C, W = ctypes.c_void_p, wt.DWORD
        # 0.14.x 官方签名: WINTUN_ADAPTER_HANDLE WintunCreateAdapter(Name, TunnelType, RequestedGUID)
        # 失败返回 NULL，错误码经 GetLastError()
        w.WintunCreateAdapter.argtypes = [wt.LPCWSTR, wt.LPCWSTR, C]
        w.WintunCreateAdapter.restype = C
        w.WintunCloseAdapter.argtypes = [C]
        w.WintunStartSession.argtypes = [C, W]
        w.WintunStartSession.restype = C
        w.WintunEndSession.argtypes = [C]
        w.WintunGetReadWaitEvent.argtypes = [C]
        w.WintunGetReadWaitEvent.restype = wt.HANDLE
        w.WintunReceivePacket.argtypes = [C, ctypes.POINTER(W)]
        w.WintunReceivePacket.restype = C
        w.WintunReleaseReceivePacket.argtypes = [C, C]
        w.WintunAllocateSendPacket.argtypes = [C, W]
        w.WintunAllocateSendPacket.restype = C
        w.WintunSendPacket.argtypes = [C, C]
        w.WintunGetAdapterLUID.argtypes = [C, ctypes.POINTER(ctypes.c_ulonglong)]
        self._win = w

    def open(self, name: str = 'mptun0', mtu: int = 1400):
        import ctypes
        self.name, self.mtu = name, mtu
        self._load()
        w = self._win
        adapter = w.WintunCreateAdapter(name, self.ADAPTER_TYPE, None)
        if not adapter:
            code = ctypes.get_last_error()
            raise OSError(code, 'WintunCreateAdapter failed (需要管理员权限): '
                               '[%d] %s' % (code, ctypes.FormatError(code)))
        self._adapter = adapter
        luid = ctypes.c_ulonglong()
        w.WintunGetAdapterLUID(adapter, ctypes.byref(luid))
        self._luid_to_alias_index(luid.value)
        self._session = w.WintunStartSession(adapter, self.RING_CAPACITY)
        if not self._session:
            self.close()
            raise OSError('WintunStartSession failed')
        self._read_event = w.WintunGetReadWaitEvent(self._session)
        log.info('wintun adapter %r up (ifindex=%s alias=%s mtu=%d)',
                 name, self.ifindex, self.alias, mtu)

    def _luid_to_alias_index(self, luid_value: int):
        import ctypes
        import ctypes.wintypes as wt
        iphlpapi = ctypes.WinDLL('iphlpapi')
        luid = ctypes.c_ulonglong(luid_value)
        if hasattr(iphlpapi, 'ConvertInterfaceLuidToIndex'):
            idx = wt.ULONG()
            iphlpapi.ConvertInterfaceLuidToIndex.argtypes = [
                ctypes.POINTER(ctypes.c_ulonglong), ctypes.POINTER(wt.ULONG)]
            iphlpapi.ConvertInterfaceLuidToIndex(ctypes.byref(luid), ctypes.byref(idx))
            self.ifindex = int(idx.value)
        alias = ctypes.create_unicode_buffer(256)
        iphlpapi.ConvertInterfaceLuidToAlias.argtypes = [
            ctypes.POINTER(ctypes.c_ulonglong), wt.LPWSTR, ctypes.c_size_t]
        iphlpapi.ConvertInterfaceLuidToAlias(ctypes.byref(luid), alias, 256)
        self.alias = alias.value or self.name

    def _run_netsh(self, args: list):
        cmd = ['netsh'] + args
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            raise OSError(r.returncode, 'netsh failed: %s %s' %
                          (' '.join(cmd), _dec(r.stderr or r.stdout or b'').strip()))
        log.debug('netsh ok: %s', ' '.join(cmd))

    def set_ip(self, ip: str, mask: str):
        n = self.alias or self.name
        self._run_netsh(['interface', 'ip', 'set', 'address', 'name=' + n,
                         'static', ip, mask])
        self._run_netsh(['interface', 'ipv4', 'set', 'subinterface', n,
                         'mtu=%d' % self.mtu, 'store=active'])
        log.info('tun %s set ip %s/%s', n, ip, mask)

    def read(self, n: int = 65536, timeout: float = None) -> bytes:
        import ctypes
        ms = self.INFINITE if timeout is None else max(0, int(timeout * 1000))
        if ctypes.windll.kernel32.WaitForSingleObject(
                self._read_event, ms) != self.WAIT_OBJECT_0:
            return b''
        size = self._wt.DWORD()
        ptr = self._win.WintunReceivePacket(self._session, ctypes.byref(size))
        if not ptr:
            return b''                        # 竞态: 事件已触发但队列空
        try:
            return ctypes.string_at(ptr, size.value)
        finally:
            self._win.WintunReleaseReceivePacket(self._session, ptr)

    def write(self, pkt: bytes) -> int:
        import ctypes
        ptr = self._win.WintunAllocateSendPacket(self._session, len(pkt))
        if not ptr:
            raise OSError('WintunAllocateSendPacket failed')
        ctypes.memmove(ptr, pkt, len(pkt))
        self._win.WintunSendPacket(self._session, ptr)
        return len(pkt)

    def close(self):
        if self._session:
            self._win.WintunEndSession(self._session)
            self._session = None
        if self._adapter:
            self._win.WintunCloseAdapter(self._adapter)
            self._adapter = None
            log.info('wintun adapter closed')


# ---------------------------------------------------------------- Linux
class LinuxTun(TunDevice):
    TUNSETIFF = 0x400454CA
    IFF_TUN, IFF_NO_PI = 0x0001, 0x1000

    def __init__(self):
        self.fd = None
        self.ifindex = None

    def open(self, name: str = 'mptun0', mtu: int = 1400):
        import fcntl                          # POSIX 专属，延迟导入
        self.name, self.mtu = name, mtu
        if not os.path.exists('/dev/net/tun'):
            raise OSError('缺少 /dev/net/tun (需内核 tun 模块)')
        self.fd = os.open('/dev/net/tun', os.O_RDWR)
        ifr = struct.pack('16sH22s', name.encode(), self.IFF_TUN | self.IFF_NO_PI, b'')
        fcntl.ioctl(self.fd, self.TUNSETIFF, ifr)
        self.ifindex = socket.if_nametoindex(name)
        self._run_ip(['link', 'set', 'dev', name, 'mtu', str(mtu)])
        log.info('tun %s opened (ifindex=%s mtu=%d)', name, self.ifindex, mtu)

    def _run_ip(self, args: list):
        cmd = ['ip'] + args
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            raise OSError(r.returncode, 'ip failed: %s %s' %
                          (' '.join(cmd), _dec(r.stderr or r.stdout or b'').strip()))

    def set_ip(self, ip: str, mask: str):
        n = self.name
        self._run_ip(['addr', 'replace', '%s/%d' % (ip, mask_to_prefix(mask)), 'dev', n])
        self._run_ip(['link', 'set', 'dev', n, 'up'])
        log.info('tun %s set ip %s/%s', n, ip, mask)

    def read(self, n: int = 65536, timeout: float = None) -> bytes:
        # 阻塞读（不支持 timeout; 关闭依赖 daemon 线程退出）
        return os.read(self.fd, n)

    def write(self, pkt: bytes) -> int:
        return os.write(self.fd, pkt)

    def close(self):
        if self.fd:
            try:
                os.close(self.fd)
            finally:
                self.fd = None
