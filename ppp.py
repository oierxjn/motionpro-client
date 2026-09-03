#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PPP 数据面 — 面向 Array AG 网关的裸 PPP HDLC 帧栈（RE: vl3vpn.dll sstp.c / PROTOCOL_NOTES.md）

帧格式: ff 03 <protocol:2B BE> <payload>
协议号: LCP=0xC021  PAP=0xC023  IPCP=0x8021  IPv4=0x0021  IPCPv6=0x8057  LCP-Echo 同 LCP
控制面: 'E' keepalive 帧（20B，见 proto_client.build_keepalive）与数据帧同流复用
"""
import struct

FFFRAME = b"\xff\x03"
PROTO_LCP, PROTO_PAP, PROTO_IPCP, PROTO_IPV4, PROTO_IPV6CP = 0xC021, 0xC023, 0x8021, 0x0021, 0x8057

# LCP codes
CFG_REQ, CFG_ACK, CFG_NAK, CFG_REJ = 1, 2, 3, 4
ECHO_REQ, ECHO_REPLY = 9, 10
# IPCP option
OPT_IPADDR = 3
# PAP codes
PAP_REQ, PAP_OK, PAP_NAK = 1, 2, 3


def frame(proto: int, payload: bytes) -> bytes:
    return FFFRAME + struct.pack(">H", proto) + payload

def parse(frame_bytes: bytes):
    """→ (proto, payload) or None（含 'E' keepalive 等非 PPP 数据由上层过滤）"""
    if len(frame_bytes) < 4 or frame_bytes[:2] != FFFRAME:
        return None
    return struct.unpack(">H", frame_bytes[2:4])[0], frame_bytes[4:]


def _cp(code: int, ident: int, options: bytes) -> bytes:
    return struct.pack(">BBH", code, ident, 4 + len(options)) + options

def _opt(typ: int, data: bytes) -> bytes:
    return bytes([typ, 2 + len(data)]) + data


# ---------------- LCP ----------------
def lcp_config_request(ident: int, mru: int = 1400, magic: int = 0x12345678) -> bytes:
    opts = _opt(1, struct.pack(">H", mru)) + _opt(3, struct.pack(">I", magic)) + _opt(5, b"mp-open")
    return _cp(CFG_REQ, ident, opts)

def lcp_ack(ident: int, req_body: bytes) -> bytes:
    """对端 Configure-Request → Ack（原样回显 options）"""
    return _cp(CFG_ACK, ident, req_body)

def lcp_echo_reply(ident: int, magic: int, data: bytes) -> bytes:
    return _cp(ECHO_REPLY, ident, struct.pack(">I", magic) + data)


# ---------------- PAP ----------------
def pap_auth_request(ident: int, user: str, password: str) -> bytes:
    u, p = user.encode(), password.encode()
    body = bytes([len(u)]) + u + bytes([len(p)]) + p
    return struct.pack(">BBH", PAP_REQ, ident, 4 + len(body)) + body


# ---------------- IPCP ----------------
def ipcp_config_request(ident: int, ip: str = "0.0.0.0") -> bytes:
    return _cp(CFG_REQ, ident, _opt(OPT_IPADDR, socket_inet_aton(ip)))

def ipcp_apply_nak_ip(req_payload: bytes, ip: str) -> bytes:
    """把 Config-Nak 里的 IP 填回 Request 的 option 3"""
    ipb = socket_inet_aton(ip)
    out = bytearray(req_payload)
    i = 4
    while i < len(out) - 1:
        typ, ln = out[i], out[i + 1]
        if typ == OPT_IPADDR and ln >= 6:
            out[i + 2:i + 6] = ipb
            return bytes(out)
        i += ln
    return bytes(out)

def socket_inet_aton(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))

def inet_ntoa(b: bytes) -> str:
    return ".".join(str(x) for x in b[:4])


# ---------------- 状态机 ----------------
class PppSession:
    """极简 PPP 协商状态机: LCP → PAP → IPCP → OPEN"""

    def __init__(self, user: str, password: str, local_ip: str = "0.0.0.0",
                 magic: int = 0x12345678):
        self.user, self.password = user, password
        self.magic = magic
        self.ident = 1
        self.local_ip = local_ip
        self.stage = "LCP"          # LCP → AUTH → IPCP → OPEN
        self.log: list[str] = []

    def _next_ident(self) -> int:
        self.ident = (self.ident + 1) & 0xFF
        return self.ident

    def start(self) -> bytes:
        self.stage = "LCP"
        return frame(PROTO_LCP, lcp_config_request(self.ident, magic=self.magic))

    def handle(self, data: bytes) -> list[bytes]:
        """处理一个网关方向帧 → 需要回发的帧列表"""
        parsed = parse(data)
        if parsed is None:
            return []
        proto, payload = parsed
        if proto == PROTO_LCP:
            return self._lcp(payload)
        if proto == PROTO_PAP and self.stage == "AUTH":
            return self._pap(payload)
        if proto == PROTO_IPCP:
            return self._ipcp(payload)
        return []

    def _lcp(self, p: bytes) -> list[bytes]:
        code, ident = p[0], p[1]
        if code == CFG_REQ:
            self.log.append(f"LCP Config-Request#{ident} -> Ack")
            return [frame(PROTO_LCP, lcp_ack(ident, p[4:]))]
        if code == CFG_ACK:
            self.log.append("LCP Acked -> send PAP auth")
            self.stage = "AUTH"
            return [frame(PROTO_PAP, pap_auth_request(self._next_ident(),
                                                      self.user, self.password))]
        if code in (CFG_NAK, CFG_REJ):
            self.log.append(f"LCP Config-{('Nak','Rej')[code == CFG_REJ]}#{ident} -> retry")
            return [frame(PROTO_LCP, lcp_config_request(self._next_ident(),
                                                        magic=self.magic))]
        if code == ECHO_REQ:
            return [frame(PROTO_LCP, lcp_echo_reply(ident, self.magic, p[8:]))]
        return []

    def _pap(self, p: bytes) -> list[bytes]:
        code = p[0]
        if code == PAP_OK:
            self.log.append("PAP OK -> IPCP")
            self.stage = "IPCP"
            return [frame(PROTO_IPCP, ipcp_config_request(self._next_ident(), self.local_ip))]
        if code == PAP_NAK:
            self.log.append("PAP NAK: bad credentials")
            self.stage = "FAILED"
        return []

    def _ipcp(self, p: bytes) -> list[bytes]:
        code, ident = p[0], p[1]
        if code == CFG_REQ:
            return [frame(PROTO_IPCP, lcp_ack(ident, p[4:]))]
        if code == CFG_NAK:
            # Nak 携带网关分配的 IP → 填入重发
            i = 4
            while i < len(p) - 1:
                typ, ln = p[i], p[i + 1]
                if typ == OPT_IPADDR:
                    self.local_ip = inet_ntoa(p[i + 2:i + 6])
                    self.log.append(f"IPCP Nak -> assigned IP {self.local_ip}")
                    break
                i += ln
            return [frame(PROTO_IPCP,
                          _cp(CFG_REQ, self._next_ident(),
                              _opt(OPT_IPADDR, socket_inet_aton(self.local_ip))))]
        if code == CFG_ACK:
            self.log.append(f"IPCP Acked, IP={self.local_ip} -> OPEN")
            self.stage = "OPEN"
        return []
