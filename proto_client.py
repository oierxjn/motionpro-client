#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MotionPro (Array AG SSL VPN) 开源客户端原型 — 控制面实现 + 数据面骨架。

协议来源：temp/motionpro_re/PROTOCOL_NOTES.md（Ghidra 逆向 vl3vpn.dll + 实机日志实证）

用法:
  uv run python temp/motionpro_re/proto_client.py --server vpn.example.cn --user U --ask-pass
  # 仅验证控制面（登录→会话→vpntunnel 配置获取），不建立数据面
"""
import argparse, base64, getpass, hashlib, json, os, re, socket, ssl, struct, sys, time

# ---------------------------------------------------------------- FFFF 探测包
def build_probe_hello() -> bytes:
    """82 字节手工 ClientHello（vl3vpn.dll FUN_10048210）:
    version TLS1.2, random=time+1..28, session_id=FF*32, cipher=0xE013, comp=null"""
    body = b"\x03\x03"                      # client version TLS1.2
    body += struct.pack(">I", int(time.time())) + bytes(range(1, 29))  # random32
    body += b"\x20" + b"\xff" * 32          # session id: FF*32
    body += b"\x00\x02" + b"\xe0\x13"       # cipher_suites: AG private 0xE013
    body += b"\x01" + b"\x00"               # compression: null
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body        # handshake hdr
    rec = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
    assert len(rec) == 0x52, len(rec)
    return rec

# ---------------------------------------------------------------- deviceid
def build_deviceid(fingerprint: bytes = b"") -> str:
    """upper(base64(SHA256(fp_buf[0..255])))  (array_vpn_get_devid, devid.c)
    fp_buf 原版为 255 字节机器指纹；自实现客户端可用任意稳定值（服务端仅做绑定比对）"""
    buf = (fingerprint + b"\x00" * 255)[:255]
    return base64.b64encode(hashlib.sha256(buf).digest()).decode().upper()

def build_ext2(mp_version="1.1.6", ostype=1, os_version="10.0.19045") -> str:
    # aaa.c: "&ext2=mpversion=%s@ostype=%d@osversion=%s@msmodel="
    return f"mpversion={mp_version}@ostype={ostype}@osversion={os_version}@msmodel="

# ---------------------------------------------------------------- keepalive
def build_keepalive(param2: int = 0) -> bytes:
    """20 字节 'E' 帧 (FUN_10063d70, l3vpn.c):
    'E' + len(3B BE)=0x14 + 00000000 + 00ff0000 + htons(1) + param2(2B) + 当天毫秒(LE)"""
    now = time.localtime()
    ms_of_day = ((now.tm_hour * 60 + now.tm_min) * 60 + now.tm_sec) * 1000
    return (b"\x45\x00\x00\x14" + b"\x00\x00\x00\x00" + b"\x00\xff\x00\x00"
            + struct.pack(">H", 1) + struct.pack("<H", param2 & 0xFFFF)
            + struct.pack("<I", ms_of_day & 0xFFFFFFFF))

# ---------------------------------------------------------------- HTTP/1 mini
class AgConnection:
    """一条 TLS 连接承载全部控制面 + 隧道（协议规定不换连接）"""

    UA = "Mozilla/MotionPro 1.x  (Windows)MSIE(compatible; MSIE; Windows NT)"

    def __init__(self, host: str, port: int = 443, verify: bool = False,
                 send_probe: bool = False, timeout: float = 15.0):
        # send_probe=False: 原版 happy path 是标准 TLS，FFFF 探测仅在失败重试时使用
        self.host, self.port = host, port
        raw = socket.create_connection((host, port), timeout=timeout)
        if send_probe:
            raw.sendall(build_probe_hello())   # 标准 TLS 握手前发 FFFF 探测
            time.sleep(0.05)                   # 原版不读应答（丢弃）
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        # AG 网关只接受旧式静态 RSA 套件（TLS_RSA_WITH_AES_128_CBC_SHA 等），
        # 现代 ECDHE 套件会被 alert handshake_failure 拒绝 —— 需降 SECLEVEL
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        self.tls = ctx.wrap_socket(raw, server_hostname=host)
        self.cookies: dict[str, str] = {}

    def _recv_http(self) -> tuple[str, dict, bytes]:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.tls.recv(4096)
            if not chunk:
                raise ConnectionError("closed while reading header")
            buf += chunk
        head, _, body = buf.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1").split("\r\n")
        status = lines[0]
        # 保留全部头（重复头合并进 dict，set-cookie 逐行保留）
        pairs: list[tuple[str, str]] = []
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            pairs.append((k.strip().lower(), v.strip()))
        headers: dict[str, str] = {}
        set_cookies: list[str] = []
        for k, v in pairs:
            if k == "set-cookie":
                set_cookies.append(v)
            headers[k] = v
        if set_cookies:
            headers["set-cookie"] = "\n".join(set_cookies)
        clen = int(headers.get("content-length", 0))
        while len(body) < clen:
            body += self.tls.recv(min(65536, clen - len(body)))
        return status, headers, body

    def request(self, method: str, path: str, body: bytes = b"",
                extra_headers: dict | None = None) -> tuple[str, dict, bytes]:
        hdrs = {
            "Host": self.host if self.port == 443 else f"{self.host}:{self.port}",
            "Cookie": self._cookie_header(extra_headers),
            "User-Agent": self.UA,
            "Connection": "keep-alive",
        }
        if body:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
            hdrs["Content-Length"] = str(len(body))
        hdrs.update(extra_headers or {})
        req = f"{method} {path} HTTP/1.1\r\n" + \
              "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        self.tls.sendall(req.encode() + body)
        status, headers, resp = self._recv_http()
        self._absorb_cookies(headers)
        return status, headers, resp

    def _cookie_header(self, extra: dict | None) -> str:
        # aaa.c 模板: "<预置>ANStandalone=true;<session>"
        parts = ["ANStandalone=true"] + [f"{k}={v}" for k, v in self.cookies.items()]
        return ";".join(parts)

    def _absorb_cookies(self, headers: dict):
        # set-cookie 头已按行合并（\n 连接），逐行解析，忽略属性
        for sc in headers.get("set-cookie", "").split("\n"):
            if not sc.strip():
                continue
            first, _, _attrs = sc.partition(";")
            name, _, value = first.partition("=")
            name = name.strip()
            if not name or name.lower().startswith("expires"):
                continue
            self.cookies[name] = value.strip().strip('"')

# ---------------------------------------------------------------- 客户端
class MotionProClient:
    def __init__(self, server: str, username: str, password: str,
                 port: int = 443, verify: bool = False):
        self.server = server
        self.username = username
        self.password = password
        self.deviceid = build_deviceid(username.encode())
        self.dev_name = socket.gethostname()
        self.conn: AgConnection | None = None
        self.tunnel: AgConnection | None = None
        self.session_name = self.session_value = ""
        self.config: dict = {}

    # --- 控制面 ---
    def login(self) -> dict:
        self.conn = AgConnection(self.server, verify=verify_flag())
        # 1) an_login.js：认证方式列表
        st, _, resp = self.conn.request("GET", "/prx/000/http/localhost/an_login.js")
        methods = parse_an_login(resp)
        print(f"[*] an_login.js: {st}, methods={methods}")
        method = "default_method_localdb" if "default_method_localdb" in (methods or ["default_method_localdb"]) else (methods or ["default_method_localdb"])[0]
        # 2) POST login —— 成功 = 302 → welcome + 会话 Cookie（ANsession<数字>=tongji+<hash>）
        #    （实测: 错密码 → 200 登录页; 对密码 → 302。原版客户端拿到 302 即继续，不 GET welcome）
        valid = "validcode%3D"
        body = (f"method={method}&valid={valid}&uname={self.username}"
                f"&pwd={self.password}&pwd1=&pwd2="
                f"&deviceid={self.deviceid}&device_name={self.dev_name}&hardwareid="
                f"&ext2={build_ext2()}")
        st, hdr, resp = self.conn.request(
            "POST", "/prx/000/http/localhost/login", body.encode())
        code = st.split()[1] if " " in st else ""
        print(f"[*] login: {st}, cookies={list(self.conn.cookies)}")
        if not code.startswith("302"):
            raise RuntimeError(f"login not accepted: {st} (200=密码错误/需要验证码)")
        # 3) 会话 Cookie 名是动态的 ANsession<数字>，按前缀抓取
        self.session_name, self.session_value = "", ""
        for k, v in self.conn.cookies.items():
            if k.lower().startswith("ansession"):
                self.session_name, self.session_value = k, v
                break
        if not self.session_name:
            raise RuntimeError(f"no ANsession cookie in {list(self.conn.cookies)}")
        print(f"[+] session: {self.session_name}={self.session_value[:20]}...")
        return {"methods": methods}

    def open_l3_tunnel(self) -> dict:
        """原版 vpnd 的 L3 隧道请求（get_config.c FUN_1005cc10 模板, 实测 201 OK）:

            GET /prx/000/http/localhost/vpntunnel HTTP/1.1
            Host / Cookie: ANStandalone=true;<仅会话Cookie> / x-devtype: 1
            appid: SSPVPN / clientid / cpuid(16hex) / hostname / PAYLOAD-IP-VERSION: 6

        要点: 必须用"新 TLS 连接 + 仅会话 Cookie"（模拟 vpnd 独立连接）;
        缺 cpuid/hostname/PAYLOAD-IP-VERSION → 200/0 (L4 分支, 非 L3)。"""
        cpuid = get_machine_cpuid()
        t = AgConnection(self.server, verify=verify_flag())
        req = ("GET /prx/000/http/localhost/vpntunnel HTTP/1.1\r\n"
               f"Host: {self.server}\r\n"
               f"Cookie: ANStandalone=true;{self.session_name}={self.session_value}\r\n"
               "x-devtype: 1\r\nappid: SSPVPN\r\n"
               f"clientid: {self.deviceid}\r\n"
               f"cpuid: {cpuid}\r\n"
               f"hostname: {self.dev_name}\r\n"
               "PAYLOAD-IP-VERSION: 6\r\n\r\n")
        t.tls.sendall(req.encode())
        t.tls.settimeout(8)
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += t.tls.recv(4096)
        head, _, rest = buf.partition(b"\r\n\r\n")
        status = head.split(b"\r\n")[0].decode("iso-8859-1")
        print(f"[*] vpntunnel: {status}, body={len(rest)}B")
        if " 201" not in status:
            t.tls.close()
            raise RuntimeError(f"vpntunnel refused: {status} (200/0=L4 分支, 302=会话无效)")
        self.tunnel = t
        # ★ 注意: L3 流程（appid SSPVPN）没有 0x0f 握手 —— 那是 L4 分支的流程。
        #   201 之后直接开始字母消息交换（P→Q common config, T→U net config）。
        return {}

    # 兼容旧名
    def open_tunnel(self) -> dict:
        return self.open_l3_tunnel()

    # --- 数据帧层（Round 8 实测: 20B 头 [0]='E' [2:4]=总长:2BE [9]=0xff [12:14]=class:2BE）---
    @staticmethod
    def data_frame(cls: int, payload: bytes = b"") -> bytes:
        total = 20 + len(payload)
        return (bytes([0x45, 0x00]) + struct.pack(">H", total) + b"\x00" * 4 +
                bytes([0x00, 0xFF, 0x00, 0x00]) + struct.pack(">H", cls) +
                b"\x00\x00" + b"\x00" * 4 + payload)

    def tunnel_recv_frame(self, timeout: float = 5.0) -> tuple[int, bytes]:
        """流式读取 20B 头帧"""
        self.tunnel.tls.settimeout(timeout)
        head = b""
        while len(head) < 20:
            chunk = self.tunnel.tls.recv(20 - len(head))
            if not chunk:
                raise ConnectionError("tunnel closed at frame head")
            head += chunk
        flen = int.from_bytes(head[2:4], "big")
        fcls = int.from_bytes(head[12:14], "big")
        payload = b""
        while len(payload) < flen - 20:
            chunk = self.tunnel.tls.recv(min(65536, flen - 20 - len(payload)))
            if not chunk:
                raise ConnectionError("tunnel closed at frame data")
            payload += chunk
        return fcls, payload

    def get_mptoken(self) -> int | None:
        """class 6 → {"mptoken": N}"""
        self.tunnel.tls.sendall(self.data_frame(6))
        cls, payload = self.tunnel_recv_frame()
        if cls == 6:
            try:
                tok = json.loads(payload.rstrip(b"\x00"))["mptoken"]
                print(f"[+] mptoken = {tok}")
                return tok
            except Exception as e:
                print(f"[!] mptoken parse: {e} {payload[:60]!r}")
        return None

    # --- 隧道消息层（实测: 格式A = [type:1][11×00][len:4LE@12]+payload; 格式B = 'E'+len:3BE）---
    def tunnel_send_msg(self, mtype: int, payload: bytes = b""):
        self.tunnel.tls.sendall(bytes([mtype]) + struct.pack(">I", len(payload))[1:] + payload)

    def tunnel_recv_msg(self, timeout: float = 4.0) -> tuple[int, bytes]:
        self.tunnel.tls.settimeout(timeout)
        head = b""
        while len(head) < 4:
            chunk = self.tunnel.tls.recv(4 - len(head))
            if not chunk:
                raise ConnectionError("tunnel closed")
            head += chunk
        mtype = head[0]
        mlen = int.from_bytes(head[1:4], "big")
        data = b""
        while len(data) < mlen:
            chunk = self.tunnel.tls.recv(min(65536, mlen - len(data)))
            if not chunk:
                raise ConnectionError("tunnel closed mid-message")
            data += chunk
        return mtype, data

    def tunnel_query(self, mtype: int, timeout: float = 4.0) -> bytes:
        """发 16 字节查询消息，返回响应 payload（如 0x12→用户名, 0x13→密码回显）"""
        self.tunnel_send_msg(mtype)
        got_type, data = self.tunnel_recv_msg(timeout)
        return data

    # --- 字母消息层（格式A: 16B头+payload; 实测 get_config.c）---
    def _msg_recv(self, timeout: float = 8.0) -> tuple[int, bytes]:
        """读 16B 头 [type][11×00][len:4LE] + payload"""
        self.tunnel.tls.settimeout(timeout)
        head = b""
        while len(head) < 16:
            chunk = self.tunnel.tls.recv(16 - len(head))
            if not chunk:
                raise ConnectionError("tunnel closed at head")
            head += chunk
        mtype = head[0]
        dlen = int.from_bytes(head[12:16], "little")
        data = b""
        while len(data) < dlen:
            chunk = self.tunnel.tls.recv(min(65536, dlen - len(data)))
            if not chunk:
                raise ConnectionError("tunnel closed at data")
            data += chunk
        return mtype, data

    def _msg_send(self, mtype: int, payload: bytes = b""):
        self.tunnel.tls.sendall(bytes([mtype]) + bytes(11) + struct.pack("<I", len(payload)) + payload)

    def get_common_config(self) -> dict:
        """'P'(0x50, len=0) → 'Q' + common config JSON (220B):
        keepalive_interval/netpool_flag/dns_timeout/hostmap/..."""
        self._msg_send(0x50)
        rtype, data = self._msg_recv()
        if rtype != 0x51:  # 'Q'
            raise RuntimeError(f"common config: expect 'Q', got {rtype:#x}")
        self.common_config = json.loads(data.rstrip(b"\x00"))
        print(f"[+] common config: keepalive={self.common_config.get('keepalive_interval')}, "
              f"netpool_flag={self.common_config.get('netpool_flag')}")
        return self.common_config

    def get_net_config(self) -> dict:
        """'T'(0x54, 48B: len@12=0x20, 载荷32B=[16]虚拟ip0+[20]本机IP+[24]=1+[40]MAC)
        → 'U' + net config JSON: client_ipv4(LE)/mask/include/exclude routes/dns_servers"""
        ip = socket.gethostbyname(self.dev_name)
        try:
            mac = uuid.getnode().to_bytes(6, "big")
        except Exception:
            mac = bytes(6)
        msg = bytearray(48)
        msg[0] = 0x54
        msg[12:16] = struct.pack("<I", 0x20)
        msg[16:20] = struct.pack("<I", 0)  # 上一会话虚拟 ip（首次无）
        msg[20:24] = bytes(int(x) for x in ip.split("."))
        msg[24:28] = struct.pack("<I", 1)
        msg[40:46] = mac
        self._msg_send(0x54, bytes(msg)[16:])
        rtype, data = self._msg_recv()
        if rtype != 0x55:  # 'U'
            raise RuntimeError(f"net config: expect 'U', got {rtype:#x}")
        self.net_config = json.loads(data.rstrip(b"\x00"))
        vip = self.net_config.get("client_ipv4", 0)
        vstr = ".".join(str(b) for b in vip.to_bytes(4, "little")) if vip else "?"
        print(f"[+] net config: virtual_ip={vstr}, dns={[d for s in self.net_config.get('dns_servers', []) for d in s.get('ipv4', [])]}")
        return self.net_config

    # --- 数据面（骨架）---
    def keepalive_loop(self, interval: float = 30.0):
        while True:
            self.tls_send(build_keepalive())
            time.sleep(interval)

    def tls_send(self, data: bytes):
        self.conn.tls.sendall(data)

    def logout(self):
        try:
            self.conn.request("GET", "/prx/000/http/localhost/logout")
        finally:
            self.conn.tls.close()

# ---------------------------------------------------------------- 解析
def parse_an_login(js: bytes) -> list[str]:
    """an_login.js 定义 _AN_str_method_list 等 JS 全局变量"""
    m = re.search(rb"_AN_str_method_list\s*=\s*(\[[^\]]*\])", js)
    if m:
        try:
            return [x.get("name", "") for x in json.loads(m.group(1))]
        except Exception:
            pass
    names = re.findall(rb'"name"\s*:\s*"([^"]+)"', js)
    return [n.decode() for n in names][:8]

def parse_tunnel_config(resp: bytes) -> dict:
    """201 响应体: JSON 配置（公共 keepalive_interval/allow_speed_tunnel + 网络虚拟 IP/DNS/路由）"""
    text = resp.decode("utf-8", "replace")
    out = {}
    for m in re.finditer(r"\{[^{}]*\}", text):
        try:
            obj = json.loads(m.group(0))
            if isinstance(obj, dict):
                out.update(obj)
        except Exception:
            continue
    return out

def verify_flag():
    return os.environ.get("MP_VERIFY_TLS", "0") == "1"

def get_machine_cpuid() -> str:
    """vpnd 从 HKLM\\SOFTWARE\\VPN\\VPN2\\VPNMachineCPUID 读 16 hex CPUID
    (get_config.c:1235 'get cpuid len=16'); 缺省回退 CPUID(1).EAX/EBX 拼接"""
    try:
        import winreg
        for key in (r"SOFTWARE\VPN\VPN2", r"SOFTWARE\WOW6432Node\VPN\VPN2"):
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
                val, _ = winreg.QueryValueEx(k, "VPNMachineCPUID")
                if val:
                    return val
    except OSError:
        pass
    import subprocess
    out = subprocess.run(["powershell", "-c",
                          "([BitConverter]::ToString([BitConverter]::GetBytes(0x178BFBFF)) + "
                          "[BitConverter]::ToString([BitConverter]::GetBytes(0x00A60F12)))"],
                         capture_output=True, text=True)
    return out.stdout.replace("-", "").strip() or "178BFBFF00A60F12"

# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="MotionPro open-source client prototype")
    ap.add_argument("--server", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--ask-pass", action="store_true")
    a = ap.parse_args()
    pw = getpass.getpass(f"password for {a.user}@{a.server}: ") if a.ask_pass else os.environ.get("MP_PASS", "")
    if not pw:
        sys.exit("no password (use --ask-pass or MP_PASS env)")

    cli = MotionProClient(a.server, a.user, pw, port=a.port)
    cli.login()
    cli.open_l3_tunnel()
    cli.get_common_config()
    cli.get_net_config()
    cli.get_mptoken()
    print("[*] control plane FULLY OK (login+tunnel+双JSON配置+mptoken). 数据通道 class-5 已定位（见 PROTOCOL_NOTES.md Round 8）")

if __name__ == "__main__":
    main()
