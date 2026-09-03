# -*- coding: utf-8 -*-
"""
MotionPro (Array AG) VPN 开源客户端 — 全链路复现（控制面 + L3 数据面）

流程: HTTP login → vpnd 指纹 TLS1.2 握手 → vpntunnel → P/Q/T/U 配置协商
      → mptoken → 裸 IP 数据面 (DNS/ICMP/TCP 均验证可达) → logout

凭据与设备标识在 config.py（从 config.example.py 复制后填写）。
协议细节见 PROTOCOL_NOTES.md。
"""
import socket, os, struct, hashlib, hmac, uuid, sys, time, base64
from cryptography.hazmat.primitives.asymmetric import padding as apad, x25519, ec, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_cfgp = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.py')
if not os.path.exists(_cfgp):
    sys.exit('缺少 config.py：请先复制 config.example.py 为 config.py 并填写。')
import importlib.util as _iu
_sp = _iu.spec_from_file_location('mp_config', _cfgp)
_mpmod = _iu.module_from_spec(_sp)
_sp.loader.exec_module(_mpmod)
CFG = _mpmod.CFG

def build_devid(seed: str) -> str:
    """devid = to_upper( base64( SHA256( seed[:255] ) ) )  (devid.c array_vpn_get_devid)
    官方客户端以 255B 机器指纹为输入；服务端仅做设备绑定比对，任意稳定 seed 语义等价。"""
    buf = (seed.encode('utf-8') + b'\x00' * 255)[:255]
    return base64.b64encode(hashlib.sha256(buf).digest()).decode().upper()


def build_ext1() -> str:
    """ext1（hardwareid 哈希）—— 官方算法，RE vpnhwidtool_x64.exe GetMacAuthInfo +
    frida 动态取证 CryptHashData 确认：

        ext1 = md5( "CPU=<cpuid>;OS=<winuuid>;HD=<hdd>;" )

    采集源（官方经 WMI）：cpuid   = Win32_Processor.ProcessorId
                        winuuid = '<major>-<minor>-<build>-' + Win32_ComputerSystemProduct.UUID
                        hdd     = ',' + <硬盘序列号(字节对交换)> + '.'
    本机已装官方客户端时直接读其注册表缓存（HKCU\\Software\\MotionPro\\L3VPN）；
    否则返回 ''（实测服务端不校验 ext1，留空亦可登录）。
    """
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\MotionPro\L3VPN')
        try:
            _, cpuid = winreg.QueryValueEx(k, 'cpuid')
            _, winuuid = winreg.QueryValueEx(k, 'winuuid')
            _, hdd = winreg.QueryValueEx(k, 'hdd')
            return hashlib.md5(('CPU=%s;OS=%s;HD=%s;' % (cpuid, winuuid, hdd))
                               .encode()).hexdigest()
        finally:
            winreg.CloseKey(k)
    except OSError:
        return ''


if CFG.get('devid'):
    DEVICE_ID = CFG['devid']                    # 显式 devid（旧格式，保持原设备身份）
elif CFG.get('devid_seed'):
    DEVICE_ID = build_devid(CFG['devid_seed'])  # seed → 程序生成
else:
    sys.exit('config.py 缺少 devid_seed / devid ')

if CFG.get('ext1') == 'auto':
    EXT1 = build_ext1()
else:
    EXT1 = CFG.get('ext1', '')                  # '' 留空 / 手工指定 32hex

HOST, PORT = CFG['server'], 443

# vpnd 真实 ClientHello（315B，record 头 160301 0136 + handshake 01 000132）。
# random(32B) 会在握手时替换为 os.urandom；其余字节与 vpnd 完全一致。
HELLO_BYTES = bytes.fromhex(
    '16030101360100013203032092e8977a1b814fcebbad439e5826e28f6bafb5b7f3a600276de4760879b6fb0000aec030c02cc028c024c014c00a00a500a300a1009f006b006a0069006800390038003700360088008700860085c032c02ec02ac026c00fc005009d003d00350084c02fc02bc027c023c013c00900a400a200a0009e00670040003f003e0033003200310030e013009a0099009800970045004400430042c031c02dc029c025c00ec004009c003c002f009600410007c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff0100005b000b000403000102000a001e001c001d00170019001c001b0018001a0016000e000d000b000c0009000a00230000000d0024002207010703060106020603050105020503040104020403030103020303020102020203000f000101')

# cipher: (kex, mode, prf_hash, keylen, maclen, macalg)  mode: cbc|gcm|rc4
CINFO = {
    0x0004: ('rsa', 'rc4', 'sha256', 16, 16, 'md5'),
    0x0005: ('rsa', 'rc4', 'sha256', 16, 20, 'sha1'),
    0x002f: ('rsa', 'cbc', 'sha256', 16, 20, 'sha1'), 0x0035: ('rsa', 'cbc', 'sha256', 32, 20, 'sha1'),
    0x003c: ('rsa', 'cbc', 'sha256', 16, 20, 'sha1'), 0x003d: ('rsa', 'cbc', 'sha256', 32, 20, 'sha1'),
    0x009c: ('rsa', 'gcm', 'sha256', 16, 0, ''), 0x009d: ('rsa', 'gcm', 'sha256', 32, 0, ''),
    0xc013: ('ecdhe', 'cbc', 'sha256', 16, 20, 'sha1'), 0xc014: ('ecdhe', 'cbc', 'sha256', 32, 20, 'sha1'),
    0xc02f: ('ecdhe', 'gcm', 'sha256', 16, 0, ''), 0xc030: ('ecdhe', 'gcm', 'sha384', 32, 0, ''),
    0xc027: ('ecdhe', 'cbc', 'sha256', 16, 20, 'sha1'), 0xc028: ('ecdhe', 'cbc', 'sha256', 32, 20, 'sha1'),
}

class RC4:
    def __init__(self, key):
        S = list(range(256)); j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) & 255
            S[i], S[j] = S[j], S[i]
        self.S = S; self.i = 0; self.j = 0
    def crypt(self, data):
        S, i, j = self.S, self.i, self.j
        out = bytearray()
        for b in data:
            i = (i + 1) & 255
            j = (j + S[i]) & 255
            S[i], S[j] = S[j], S[i]
            out.append(b ^ S[(S[i] + S[j]) & 255])
        self.i, self.j = i, j
        return bytes(out)

def _mac_calc(seq, ctype, frag, mkey, alg):
    H = hashlib.md5 if alg == 'md5' else hashlib.sha1
    ln = 16 if alg == 'md5' else 20
    return hmac.new(mkey, struct.pack('>Q', seq) + bytes([ctype, 3, 3]) +
                    struct.pack('>H', len(frag)) + frag, H).digest()[:ln]

def prf(secret, label, seed, nbytes, h='sha256'):
    H = hashlib.sha256 if h == 'sha256' else hashlib.sha384
    hlen = 32 if h == 'sha256' else 48
    out = b''
    a = label + seed
    while len(out) < nbytes:
        a = hmac.new(secret, a, H).digest()
        out += hmac.new(secret, a + label + seed, H).digest()
    return out[:nbytes]

class ExactTLS:
    def __init__(self, host=None, port=None):
        # 默认沿用 config.py 的网关；vpn_service 可注入其他 host 便于测试
        hs = HELLO_BYTES[5:]               # 剥掉外层 record 头，只留 handshake 消息
        self.hello = hs[:6] + os.urandom(32) + hs[38:]   # 换新 random（hs头4B+版本2B后）
        self.hs_sent = self.hello
        self.hs_recv = b''
        self.cr = self.hello[6:38]
        self.sr = b''
        self.sock = socket.create_connection((host or HOST, port or PORT), timeout=15)
        self.cipher = None
        self.ckey = self.skey = self.cmac = self.smac = None
        self.csalt = self.ssalt = None
        self.cseq = self.sseq = 0

    def send_rec(self, ctype, data):
        if os.environ.get('TLS_DUMP'):
            print('SEND rec type=%d len=%d: %s' % (ctype, len(data), data[:64].hex()))
        self.sock.sendall(bytes([ctype, 3, 3]) + struct.pack('>H', len(data)) + data)

    def send_plain_hs(self, htype, body):
        msg = bytes([htype]) + struct.pack('>I', len(body))[1:] + body
        self.hs_sent += msg
        self.send_rec(22, msg)

    def recv_rec(self):
        head = b''
        while len(head) < 5:
            c = self.sock.recv(5 - len(head))
            if not c:
                raise EOFError('closed in header')
            head += c
        ln = int.from_bytes(head[3:5], 'big')
        data = b''
        while len(data) < ln:
            c = self.sock.recv(ln - len(data))
            if not c:
                raise EOFError('closed in body')
            data += c
        return head[0], data

    # ---------- 加密记录 (TLS1.2) ----------
    def send_app(self, data, ctype=23):
        if self.cipher is None:
            self.send_rec(ctype, data)
            return
        kex, mode, h, klen, maclen, macalg = CINFO[self.cipher]
        if mode == 'gcm':
            explicit = os.urandom(8)
            nonce = self.csalt + explicit
            aad = struct.pack('>Q', self.cseq)[:8] + bytes([ctype, 3, 3]) + struct.pack('>H', len(data))
            self.cseq += 1
            c = Cipher(algorithms.AES(self.ckey), modes.GCM(nonce)).encryptor()
            c.authenticate_additional_data(aad)
            ct = c.update(data) + c.finalize()
            self.send_rec(ctype, explicit + ct + c.tag)
        elif mode == 'rc4':
            macv = _mac_calc(self.cseq, ctype, data, self.cmac, macalg)
            self.cseq += 1
            self.send_rec(ctype, self.crc4.crypt(data + macv))
        else:
            iv = os.urandom(16)
            macv = _mac_calc(self.cseq, ctype, data, self.cmac, macalg)
            self.cseq += 1
            plain = data + macv
            c = Cipher(algorithms.AES(self.ckey), modes.CBC(iv)).encryptor()
            pad = 16 - (len(plain) % 16)
            ct = c.update(plain + bytes([pad]) * pad) + c.finalize()
            self.send_rec(ctype, iv + ct)

    def _decrypt_rec(self, ctype, data):
        kex, mode, h, klen, maclen, macalg = CINFO[self.cipher]
        if mode == 'gcm':
            explicit, ct, tag = data[:8], data[8:-16], data[-16:]
            aad = struct.pack('>Q', self.sseq)[:8] + bytes([ctype, 3, 3]) + struct.pack('>H', len(ct))
            d = Cipher(algorithms.AES(self.skey), modes.GCM(self.ssalt + explicit, tag)).decryptor()
            d.authenticate_additional_data(aad)
            self.sseq += 1
            return d.update(ct) + d.finalize()
        if mode == 'rc4':
            raw = self.src4.crypt(data)
            frag, macv = raw[:-maclen], raw[-maclen:]
            expect = _mac_calc(self.sseq, ctype, frag, self.smac, macalg)
            self.sseq += 1
            if macv != expect:
                raise ValueError('bad MAC')
            return frag
        iv, ct = data[:16], data[16:]
        d = Cipher(algorithms.AES(self.skey), modes.CBC(iv)).decryptor()
        raw = d.update(ct) + d.finalize()
        pad = raw[-1]
        if pad < 1 or pad > 16:
            raise ValueError('bad pad %d' % pad)
        raw = raw[:-pad]
        frag, macv = raw[:-maclen], raw[-maclen:]
        expect = _mac_calc(self.sseq, ctype, frag, self.smac, macalg)
        self.sseq += 1
        if macv != expect:
            raise ValueError('bad MAC')
        return frag

    def recv_app(self):
        ctype, data = self.recv_rec()
        if ctype == 21:
            raise EOFError('alert %d' % (data[1] if len(data) > 1 else -1))
        if ctype in (22, 23) and self.cipher is not None:
            return self._decrypt_rec(ctype, data)
        return data

    def _pend(self):
        if not hasattr(self, 'pendbuf'):
            self.pendbuf = b''
        return self.pendbuf

    def read_exact(self, n, to=8):
        self.sock.settimeout(to)
        while len(self._pend()) < n:
            self.pendbuf += self.recv_app()
        out, self.pendbuf = self.pendbuf[:n], self.pendbuf[n:]
        return out

    def read_until(self, delim, to=8):
        self.sock.settimeout(to)
        while delim not in self._pend():
            self.pendbuf += self.recv_app()
        i = self.pendbuf.index(delim) + len(delim)
        out, self.pendbuf = self.pendbuf[:i], self.pendbuf[i:]
        return out

    # ---------- 握手 ----------
    def probe_ffff(self):
        # FUN_10048210 'send specific client hello': FF session_id 探测 CH (82B, raw_234833_s49673_n0.bin)
        import time as _t
        rnd = struct.pack('>I', int(_t.time())) + bytes(range(1, 29))
        body = (b'\x01\x00\x00\x49' + b'\x03\x01' + rnd + b'\x20' + b'\xff' * 32 +
                b'\x00\x02\x00\x04' + b'\x01\x00')
        rec = b'\x16\x03\x01' + struct.pack('>H', len(body)) + body
        self.sock.sendall(rec)
        # 实测服务器对探测 CH 不回包, 无需读取; 直接跟真 CH
        return None

    def handshake(self):
        self.probe_ffff()
        self.send_rec(22, self.hello)
        server_kex = None
        done = False
        while not done:
            ctype, data = self.recv_rec()
            if ctype != 22:
                if ctype == 21:
                    raise EOFError('hs alert %d' % (data[1] if len(data) > 1 else -1))
                continue
            self.hs_recv += data
            p = 0
            while p + 4 <= len(data):
                ht = data[p]
                hl = int.from_bytes(data[p+1:p+4], 'big')
                body = data[p+4:p+4+hl]
                if ht == 2:
                    off = 2 + 32
                    sl = body[off]; off += 1 + sl
                    self.cipher = struct.unpack('>H', body[off:off+2])[0]
                    self.sr = body[2:34]
                    print('ServerHello cipher=%04x' % self.cipher)
                    if self.cipher not in CINFO:
                        raise ValueError('unhandled cipher %04x' % self.cipher)
                elif ht == 11:
                    clen = int.from_bytes(body[:3], 'big')
                    der = body[6:6+int.from_bytes(body[3:6], 'big')]
                    self.server_cert = x509.load_der_x509_certificate(der)
                    print('cert:', self.server_cert.subject.rfc4514_string())
                elif ht == 12:
                    server_kex = body
                elif ht == 14:
                    done = True
                    break
                p += 4 + hl
        kex, mode, h, klen, maclen, macalg = CINFO[self.cipher]
        pubkey = self.server_cert.public_key()
        assert isinstance(pubkey, rsa.RSAPublicKey)
        if kex == 'rsa':
            pm = b'\x03\x03' + os.urandom(46)
            self._pm = pm  # debug: 保存 premaster
            ct = pubkey.encrypt(pm, apad.PKCS1v15())
            self.send_plain_hs(16, struct.pack('>H', len(ct)) + ct)
            print('CKE static RSA')
            pre = pm
        else:
            assert server_kex[0] == 3
            gid = struct.unpack('>H', server_kex[1:3])[0]
            plen = server_kex[3]
            spub = server_kex[4:4+plen]
            if gid == 0x001d:
                sk = x25519.X25519PrivateKey.generate()
                shared = sk.exchange(x25519.X25519PublicKey.from_public_bytes(spub))
                mypub = sk.public_key().public_bytes_raw()
            else:
                curve = {0x0017: ec.SECP256R1, 0x0018: ec.SECP384R1, 0x0019: ec.SECP521R1}[gid]
                sk = ec.generate_private_key(curve())
                shared = sk.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(curve(), spub))
                mypub = sk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            self.send_plain_hs(16, struct.pack('>H', len(mypub)) + mypub)
            print('CKE ECDHE gid=%04x' % gid)
            pre = shared
        ms = prf(pre, b'master secret', self.cr + self.sr, 48, h)
        if mode == 'gcm':
            kb = prf(ms, b'key expansion', self.sr + self.cr, 2*klen + 8, h)
            o = 0
            self.ckey = kb[o:o+klen]; o += klen
            self.skey = kb[o:o+klen]; o += klen
            self.csalt = kb[o:o+4]; o += 4
            self.ssalt = kb[o:o+4]
        else:
            kb = prf(ms, b'key expansion', self.sr + self.cr, 2*maclen + 2*klen + (32 if mode == 'cbc' else 0), h)
            o = 0
            self.cmac = kb[o:o+maclen]; o += maclen
            self.smac = kb[o:o+maclen]; o += maclen
            self.ckey = kb[o:o+klen]; o += klen
            self.skey = kb[o:o+klen]; o += klen
            if mode == 'rc4':
                self.crc4 = RC4(self.ckey)
                self.src4 = RC4(self.skey)
        # CCS
        self.send_rec(20, b'\x01')
        # Finished — transcript = hello + 全部服务端握手消息 + CKE
        H = hashlib.sha256 if h == 'sha256' else hashlib.sha384
        transcript = self.hs_sent[:len(self.hello)] + self.hs_recv + self.hs_sent[len(self.hello):]
        fin = prf(ms, b'client finished', H(transcript).digest(), 12, h)
        # Finished 握手消息必须带 4 字节头 [20][00 00 0c]
        self.send_app(bytes([20, 0, 0, 12]) + fin, ctype=22)
        print('Finished sent')
        # server CCS + Finished
        while True:
            ctype, data = self.recv_rec()
            if ctype == 20:
                continue
            if ctype == 22:
                self.sseq = 0
                plain = self._decrypt_rec(22, data)
                print('server Finished OK (%d B)' % len(plain))
                break
            if ctype == 21:
                raise EOFError('post alert %d' % (data[1] if len(data) > 1 else -1))
        print('=== HANDSHAKE COMPLETE ===')

# ---------------- 隧道流程 ----------------
def ip4(n): return bytes([n&255,(n>>8)&255,(n>>16)&255,(n>>24)&255])

def cksum(d):
    if len(d) % 2: d += b'\x00'
    s = 0
    for i in range(0, len(d), 2): s += (d[i] << 8) + d[i+1]
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def ctrl(cls, payload=b'', f1620=0):
    total = 20 + len(payload)
    return (bytes([0x45, 0x00]) + struct.pack('>H', total) + b'\x00'*4 +
            bytes([0x00, 0xff, 0x00, 0x00]) + struct.pack('>H', cls) +
            b'\x00\x00' + struct.pack('>I', f1620) + payload)

def dns_pkt(src, dst, txid, sport):
    q = b''
    for part in 'www.tongji.edu.cn'.split('.'):
        q += bytes([len(part)]) + part.encode()
    q += b'\x00' + struct.pack('>HH', 1, 1)
    dns = struct.pack('>HHHHHH', txid, 0x0100, 1, 0, 0, 0) + q
    uh = struct.pack('>HHHH', sport, 53, 8 + len(dns), 0)
    ih = struct.pack('>BBHHHBBH', 0x45, 0, 20 + 8 + len(dns), txid, 0x4000, 128, 17, 0)
    ih = ih[:10] + struct.pack('>H', cksum(ih)) + ih[12:]
    return ih + src + dst + uh + dns

def recv_frame(t, timeout=3):
    t.sock.settimeout(timeout)
    try:
        d = t.recv_app()
        return d
    except socket.timeout:
        return None

def do_login(welcome=True):
    from proto_client import AgConnection
    conn = AgConnection(HOST)
    conn.request('GET', '/prx/000/http/localhost/an_login.js')
    devid_enc = DEVICE_ID.replace('+', '%2B').replace('/', '%2F').replace('=', '%3D')
    body = ('method=default_method_localdb&valid=validcode%3D&uname=' + CFG['user'] +
            '&pwd=' + CFG['password'] +
            '&pwd1=&pwd2=&deviceid=' + devid_enc +
            '&device_name=' + CFG['device_name'] +
            '&hardwareid=&ext1=' + EXT1 + '&ext2=')
    conn.request('POST', '/prx/000/http/localhost/login', body.encode())
    if welcome:
        conn.request('GET', '/prx/000/http/localhost/an_welcome.js')
    sess = conn.cookies['ANsession5301755367574550']
    return conn, sess

def main():
    # 隧道建立流程已固化到 VpnService（vpn_service.py）；本 main() 保留原探测演示
    import logging
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    from vpn_service import VpnService
    svc = VpnService()
    st = svc.connect()
    t = st.tls
    vip = st.vip
    vipb = bytes(int(x) for x in vip.split('.'))
    vipi = int.from_bytes(vipb, 'big')
    print('vip LE:', '.'.join(str(b) for b in vipb), ' BE:', '.'.join(str(b) for b in vipb[::-1]))
    print('token:', st.mptoken)

    def udp_cksum(src, dst, uh):
        full = src + dst + b'\x00\x11' + struct.pack('>H', len(uh)) + uh + b'\x00\x00'
        if len(full) % 2: full += b'\x00'
        s = 0
        for i in range(0, len(full), 2): s += (full[i] << 8) + full[i+1]
        while s >> 16: s = (s & 0xFFFF) + (s >> 16)
        return (~s) & 0xFFFF

    def icmp_pkt(src, dst, ident, seq):
        body = struct.pack('>BBHHH', 8, 0, 0, ident, seq) + b'mpvpn-probe-payload!!'
        c = cksum(body)
        body = body[:2] + struct.pack('>H', c) + body[4:]
        ih = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(body), ident, 0x4000, 128, 1, 0)
        ih = ih[:10] + struct.pack('>H', cksum(ih + src + dst)) + ih[12:]
        return ih + src + dst + body

    def dns2(src, dst, txid, sport):
        q = b''
        for part in 'www.tongji.edu.cn'.split('.'):
            q += bytes([len(part)]) + part.encode()
        q += b'\x00' + struct.pack('>HH', 1, 1)
        dns = struct.pack('>HHHHHH', txid, 0x0100, 1, 0, 0, 0) + q
        uh = struct.pack('>HHHH', sport, 53, 8 + len(dns), 0)
        uh = uh[:6] + struct.pack('>H', udp_cksum(src, dst, uh + dns))
        ih = struct.pack('>BBHHHBBH', 0x45, 0, 20 + 8 + len(dns), txid, 0x4000, 128, 17, 0)
        ih = ih[:10] + struct.pack('>H', cksum(ih + src + dst)) + ih[12:]
        return ih + src + dst + uh + dns

    def tcp_syn(src, dst, sport, dport, seq=1):
        tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, 0, 0x50, 0x02, 8192, 0, 0)
        pseudo = src + dst + b'\x00\x06' + struct.pack('>H', len(tcp))
        s = 0
        full = pseudo + tcp
        if len(full) % 2: full += b'\x00'
        for i in range(0, len(full), 2): s += (full[i] << 8) + full[i+1]
        while s >> 16: s = (s & 0xFFFF) + (s >> 16)
        ck = (~s) & 0xFFFF
        tcp = tcp[:16] + struct.pack('>H', ck) + tcp[18:]
        ih = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(tcp), 0x1234, 0x4000, 128, 6, 0)
        ih = ih[:10] + struct.pack('>H', cksum(ih + src + dst)) + ih[12:]
        return ih + src + dst + tcp

    dst = bytes([202, 120, 190, 208])
    # 注: L3/201 隧道上网关不做 PPP (实测 LCP 无响应); PPP 只存在于 vpnd 本地 RAS/SSTP 侧。
    # 数据面 = 裸 IP 包逐条 SSL_write (vpn_tunnel_write, vl3vpn.c:973), 校验和必须正确!
    d1 = dns2(vipb, dst, 0xa011, 49011)
    i1 = icmp_pkt(vipb, dst, 0xa012, 1)
    # 纯裸包矩阵 (不发 class-5, 不发 0x0f)
    t.send_app(d1);                                            print('A bare DNS sent')
    t.send_app(i1);                                            print('C bare ICMP dns-srv sent')
    t.send_app(icmp_pkt(vipb, bytes([1, 1, 1, 1]), 0xa013, 1)); print('E bare ICMP 1.1.1.1 sent')
    t.send_app(tcp_syn(vipb, dst, 50000, 80));                 print('F bare TCP SYN:80 sent')
    t.send_app(ctrl(1));                                       print('keepalive sent')
    print('listening 30s...')
    t.sock.settimeout(30)
    total = 0
    try:
        while True:
            d = t.recv_app()
            total += len(d)
            print('IN %3d B: %s' % (len(d), d[:100].hex()))
    except socket.timeout:
        pass
    except EOFError as e:
        print('EOF:', e)
    # 第二轮重发 (排除 ARP/首包丢弃)
    t.send_app(d1);                            print('A2 bare DNS sent')
    t.send_app(i1);                            print('C2 bare ICMP sent')
    t.send_app(tcp_syn(vipb, dst, 50001, 53)); print('F2 bare TCP SYN:53 sent')
    t.sock.settimeout(20)
    try:
        while True:
            d = t.recv_app()
            total += len(d)
            print('IN2 %3d B: %s' % (len(d), d[:100].hex()))
    except socket.timeout:
        pass
    except EOFError as e:
        print('EOF2:', e)
    print('TOTAL IN:', total, 'B', '=> DATA PLANE ' + ('ALIVE!' if total else 'silent'))
    t.sock.close()
    # 正常登出, 释放 VIP 租约
    svc.shutdown()

if __name__ == '__main__':
    main()
