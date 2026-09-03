# Array MotionPro (AG VPN) 协议分析笔记

> 目标：复现协议，编写开源替代客户端。基于 Windows 客户端 9.0.1.x（OEM 1.2.26）
> 静态字符串 + 本机运行日志（`%LOCALAPPDATA%\MotionPro\Log`、`%ProgramData%\VPN\Log`）实证。
> 网关实例：`vpn.tongji.cn` (202.120.189.34:443)，站点类型 AG_VPN_DEVICE。

## 总体架构

**控制面 = HTTPS(443) 上的普通 HTTP；数据面 = 同一 TLS 连接上隧道化，客户端侧用标准 MS-SSTP + PPP。**

组件分工：
- `MotionPro.exe` — UI，负责登录 HTTP 交互（`aaa.c`）
- `vpnd.exe` — L3VPN 守护，建立 TLS 隧道 + 本地 SSTP 中继（`get_config.c`/`sstp.c`/`common.c`）
- `vl3vpn.dll` / `ArrayVPNApi.dll` — 导出 API（ArrayGetWireGuardList 等）
- 本地 IPC：vpnd 监听 127.0.0.1:65432，`GET/POST /channel/vpn?sender=%s`
- MotionProHttpd.exe（Go 编写）— 127.0.0.1:60012，WebPortal/本地服务

## 控制面流程（全部在一条 TLS1.2 连接上，Host: vpn.tongji.cn:443）

1. **TLS 连接**：`TLSv1_2_client_method`，日志显示 "send specific client hello"（自定义 ClientHello，需 Ghidra 确认指纹/扩展）
2. **获取认证方式**：`GET /prx/000/http/localhost/an_login.js`
   - 响应含 JS 全局变量 `_AN_str_method_list`（JSON：method 列表，default_method_localdb、LDAP 变体、authtype、multiauth 等字段）
3. **登录**：`POST /prx/000/http/localhost/login`
   - Content-Type: application/x-www-form-urlencoded（日志 `POST /prx/000/http/localhost/login HTTP/1.1`，User-Agent: `Mozilla/motionpro 1.x (Windows)MSIE`）
   - Body 形如：`method=default_method_localdb&valid=validcode%3D&uname=<user>&mima=<pw>&mima1=<pw>&mima2=<pw>&deviceid=<base64 blob>`
   - ⚠️ mima 是否明文/哈希待确认（日志中被打码 `*`）
4. **响应**：`302 Location: /prx/000/http/localhost/welcome` + `Set-Cookie: AN_ses<...>=<value>;path=/prx/000/http/;expires=...;secure;`（Cookie 长 74 字节）+ `_AN_msgStr`/`_AN_msgID` 清除 cookie
5. **欢迎页/资源**：`GET /prx/000/http/localhost/an_welcome.js`
6. **用户应用列表**：`GET /prx/000/http/localhost:65200/motionpro/postlogin/apps?_uname=<uid>&_role=default_role&_pid=***&_instid=default`
7. **登出**：`GET /prx/000/http/localhost/logout`

## 隧道建立（vpnd，同一条 TLS 连接）

8. **开隧道**：`GET /prx/000/http/localhost/vpntunnel`（带 AN_ses Cookie）
   - 响应：**`HTTP/1.1 201 OK`** + JSON（"response is json protocol"）
9. **公共配置 JSON**（datalen 220）：
   ```json
   "keepalive_interval": 30,
   "allow_speed_tunnel": 0,
   "speed_tunnel_encryption": 1
   ```
   另有 netpool flags 0x118900、access mode、redirect_url 等
10. **网络配置 JSON**（datalen 698）：虚拟 IP `111.187.82.4/255.255.224.0`、include 列表（本站为 full tunnel 0.0.0.0/0.0.0.0）、exclude 列表、DNS `202.120.190.208/108`、search domains
    - 请求时携带本机网卡 MAC（选中活动适配器）与本地 IP 列表
11. **Keepalive**：间隔 30s（`SOFTWARE\VPN\Keepalive\L3TCPTunnel`）

## 数据面（关键发现：就是 MS-SSTP）

本站 speed tunnel（UDP 加速）被网关禁用（allow_speed_tunnel=0），纯 TCP 路径：

- vpnd 在 **127.0.0.1:65443**（OEM.ini `SSTPAdapterPort`）起本地 SSTP 服务器
  - 本地 TLS 用 schannel + **`server.p12`**（安装目录自带，供 Windows SSTP 客户端校验；rootca-add.bat 把 rootca.crt 装进本机根存储）
- 然后 RAS 拨号：`WAN Miniport (SSTP)` → `127.0.0.1:65443`，电话簿条目名 "Array Networks SSL VPN"
- vpnd `ussl_accept` 接受 Windows 的 SSTP 连接，**把 SSTP/PPP 帧桥接（ussl_send/recv relay）到通往网关的 TLS 隧道连接**
- ⇒ 网关侧就是一个标准 SSTP-over-HTTPS 服务端；vpnd 只是个桥（因为 Windows 原生 SSTP 没法带 AN_ses cookie 认证）
- IP 配置由 PPP IPCP 协商（虚拟 IP 111.187.82.4），DNS 通过 DNS Proxy（DNSProxyType=4）

## Speed Tunnel（UDP 加速，本站未启用）

- `SOFTWARE\VPN\Keepalive\L3UDPTunnel`；`Disable_UDP_Tunnel.reg` 设 `tunnelRule=0`
- InsideProxy.exe 字符串："Speed Tunnel send coreid:%d, len:%d"、"Keep alive packet from Speed Tunnel"
- l3vpn.c: "speed tunnel in client: 10(0:TCP, 1:UDP, 10:Default)"
- 待逆向：UDP 握手与加密（speed_tunnel_encryption=1）

## WireGuard 模式（新版特性，本机 win10 inst=1 不支持）

- ui_strings: "this pc inst win10, can't support WireGuard"、GetWireGuardInfo、array_wg_tunnel、wg.conf
- ArrayWGClient.exe 是 WireGuard 客户端封装；vpnd "config wiregurad faild, switch with sstp"

## 复现路线（开源客户端）

最小可行实现（Python/Go/C 均可）：
1. TLS1.2 连网关 443（SNI+Host 网关域名；关注自定义 ClientHello 是否必需）
2. GET an_login.js 解析 method 列表 → POST login（表单字段 + cookie Jar）
3. 跟随 302 到 welcome，GET an_welcome.js 确认会话
4. 同一连接 GET /prx/000/http/localhost/vpntunnel → 201 + 解析两段 JSON 配置
5. 在同一条 TLS 连接上跑 **MS-SSTP 服务端语义**（或直接扮演 SSTP 客户端向网关发 SSTP_DUPLEX_POST —— 待确认网关期望的方向），PPP 协商 IPCP 拿 IP/DNS
6. 本地 TUN（Linux）写路由/DNS
   - 可复用现成库：sstpc/sstp-client 的 SSTP+PPP 栈思路，或 scapy/tins 自组
7. Keepalive 每 30s（具体帧格式待抓包/Ghidra 确认）

## Round 2 逆向实证（Ghidra @ vl3vpn.dll 1.0.0.36）

### 登录 POST（FUN_1003e7c0 @ 0x1003e7c0，aaa.c）

```
POST /prx/000/http/localhost/login HTTP/1.1        (param_3=1 时为 /register)
Host: <host>[:port]
Cookie: <预置cookie>ANStandalone=true;<session>[NSCOOKIE%3Blocalhost%3B%2F%3BAN_CLIENTSEC=<cs>]
User-Agent: <ctx+0x2d63>                          （日志实测 "Mozilla/motionpro 1.x (Windows)MSIE"）
Content-Type: application/x-www-form-urlencoded
Content-Length: N

method=<m>&valid=<v>&uname=<u>&pwd=<p>&pwd1=<p1>&pwd2=<p2>&deviceid=<d>&device_name=<n>&hardwareid=<h><ext1><ext2>
```

- **pwd 为明文**（直接来自输入缓冲区，无哈希/加密；安全性完全依赖 TLS）——线上字段名是 `pwd`，日志里 `mima` 只是调试打码（中文"密码"拼音）
- `&ext1=<MD5串>`：ctx+0x2e80 标志置位时追加（实测 `deadbeefdeadbeefdeadbeefdeadbeef`，来源待查）
- `&ext2=mpversion=1.1.6@ostype=1@osversion=<ver>@msmodel=`：client flag bit1 置位时追加
- `valid` 即 validcode（Web 启动时 `validcode=@#motionProweb=0` → 拆出 `validcode=` 后的空值，URL 编码为 `validcode%3D`）
- 魔术串 `@@-xyz-!this!-@is@-#for#-$mpdeviceid$-%testing%-^&*()_+array` 是"占位符探测"哨兵（dummy 检测，选中 mima/mima2/mima3 之一）

### deviceid 生成（array_vpn_get_devid @ 0x10059f20，devid.c）

```
devid = to_upper( base64( SHA256( fingerprint_buffer[0..255] ) ) )   # 44 字符
```
- fingerprint_buffer 由 FUN_10059940 收集（机器指纹，255 字节缓冲，具体字段待查但可任意稳定值替代——服务器只做设备绑定比对）
- 实测样例：`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==`

### TCP 隧道 keepalive（FUN_10063d70，l3vpn.c）

20 字节帧，直接 `SSL_write` 到隧道 socket：
```
偏移  内容
0x00  0x45 'E'          magic
0x01  00 00 14          大端长度=20
0x04  00 00 00 00       （保留）
0x08  00 ff 00 00       （flags）
0x0c  00 01             htons(1)（type=keepalive）
0x0e  xx xx             （param_2，缺省 0）
0x10  xxxxxxxx          GetLocalTime 当天毫秒数（LE dword）
```
- 3 次无响应即重连（"keepalive send time more than 3 times, reconnect VPN"）
- interval 来自网关配置 JSON `keepalive_interval`（实测 30s），注册表 `HKCU\SOFTWARE\VPN\Keepalive\L3TCPTunnel` 可覆盖

### vpntunnel 请求模板（l3vpn/l4vpn 两个变体）

L3（tcs）:
```
GET /prx/000/http/localhost/vpntunnel HTTP/1.1
Host: <host>[:port]
Cookie: <cookie>
appid: SSVPVN
clientid: <ctx+0x261c>
Appid:DesktopDirect
```
L4（端口转发版）额外带 `x-devtype: 1`；期望响应 `HTTP/1.1 201 OK`（302 Redirect = 会话失效）。
L4 在 200 OK 后还有 16 字节二进制启动握手：`SSL_write` 16 字节（首字节 0x0f）→ 期望 16 字节应答首字节 0x0f。

### TLS 层（FUN_100492e0，common.c）

- 标准 OpenSSL：`SSL_CTX_new(TLSv1_2_client_method)` → `SSL_connect`，超时 `SSL_ctrl(0x21,4)`=4s
- 可选客户端证书（RSA/ECC/SM2 国密；SM2 走 GMTLS 曲线 0x3d1）
- **FFFF 探测**：`send_specific_id` 时先调 FUN_10048210 发"specific client hello"（AG 私有探测包，用于探测 AG 服务端和选择握手方式；"client will do FFFFFF"）→ 失败则计数 +1 重试标准路径
- `is_sslhandshake_need_FFFF`：先 GET an_welcome.js 测试是否需要特殊握手

### Ghidra 工作流（已验证可复用）

1. `search_byte_patterns`（ASCII hex）定位字符串拷贝地址（注意多份拷贝，死拷贝无引用）
2. 对字符串**起始地址**做小端 4 字节指针搜索（`xx xx 0e 10`），命中处即代码引用
3. `get_function_by_address` → `create_function`（导出表地址需手动建函数）→ `decompile_function`
4. 脚本执行被禁（需 Ghidra 端 `GHIDRA_MCP_ALLOW_SCRIPTS=1`），但字节搜索法可完全替代

## Round 3 逆向实证

### FFFF 探测包（FUN_10048210 @ 0x10048210，common.c）——完全还原

82 字节手工 ClientHello，在 TLS 握手前发到裸 TCP socket：

```
16                record type = handshake
03 01             record version TLS1.0
00 4d             record length = 77
01                ClientHello
00 00 49          body length = 73
03 03             client version TLS1.2
<time32 BE><01 02 .. 1c>   random 32B（时间 + 递增序列）
20                session_id_len = 32
FF×32             session id = 全 0xFF（"FFFF" 得名于此）
00 02             cipher_suites_len = 2
E0 13             cipher 0xE013 —— AG 私有套件（param_2!=1 时为 00 04 = RC4-MD5）
01 00             compression_methods_len = 1
00                null compression
```

- 实际流量路径：探测包 → 标准 OpenSSL TLS1.2 握手 → HTTP。探测是让 AG 网关进入预期状态/识别客户端
- 复现客户端应原样模拟：先发这 82 字节，再跑标准 TLS

### 数据面封帧（FUN_1007a470 @ 0x1007a470，sstp.c IPCP 处理器）

- **SSTP 只存在于本地**（vpnd↔Windows RAS，`Server: vsstpd`）；vpnd 完整解析本地 LCP/PAP/IPCP
- **网关侧收到的是裸 PPP HDLC 帧**：`ff 03 + protocol(2B)`，经 SSL_write 直写隧道 socket
  - 协议号：IPv4=0x0021，IPCP=0x8021，IPCPv6=0x8057
  - IPCP Configure-Request 中的 IP 选项被改写为网关配置 JSON 下发的虚拟 IP 后转发
- keepalive 'E' 帧是控制帧例外（20 字节）；数据帧是否额外加 AG 头待最终确认（当前证据倾向无额外头）
- PAP 凭据由 vpnd 从 RAS 收到后写隧道（"PPP-PAP: ssl write error" 在 PAP 处理器中）→ 认证链：**网关验证 PPP PAP 里的用户名/密码**

### 其它

- registry setter FUN_10063af0：`HKCU\SOFTWARE\VPN\Keepalive\{L3TCPTunnel,L3WGTunnel,L3UDPTunnel}`
- IPCP 处理同时支持 IPv6（CPv6，虚拟 IP 为空时走 0x8057 路径）
- SSTP 状态机回退链：WireGuard 失败 → SSTP；SSTP 拨号失败 → VNIC 直驱模式



## Round 4 实证（PPP 栈 + 网关实测）

### ⚠️ TLS 关键发现（实测 vpn.tongji.cn）

- **网关只接受旧式静态 RSA 密码套件**（实测协商出 `TLS_RSA_WITH_AES_128_CBC_SHA`）
- Python/OpenSSL 默认的现代 ECDHE 套件 → `sslv3 alert handshake failure`
- **复现配方**：TLS1.2 + `ALL:@SECLEVEL=0`（或显式 `AES256-SHA:AES128-SHA:DES-CBC3-SHA`）
- FFFF 探测**可选**（带不带都能连）——它的真实作用是重试路径，不是连接必需
- 原版用老 OpenSSL(TLSv1_2_client_method) 天然带旧套件，所以"看起来"需要探测

### 实测结果（live_check.py，无凭据）

```
TLS established in 0.23s cipher=('AES128-SHA','SSLv3',128) TLSv1.2
GET /prx/000/http/localhost/an_login.js → 200 OK, 3413 bytes
auth methods: ['default_method_localdb', 'LDAP', 'LDAP2', 'LDAP3']
cookie: _AN_msgID
```

### PPP 数据面（ppp.py + test_ppp.py，全部单测通过）

- 客户端直连网关的 PPP 状态机：LCP → PAP → IPCP → OPEN
- 帧 `ff 03 <proto> <payload>`；CP 包 `code(1)+ident(1)+len(2)+options`
- 网关 Config-Request → 原样 Ack；Echo-Request → Reply；IPCP Nak 携带分配 IP
- 修复：`struct.pack(">BBH", ...)`（曾误写 `>BH H` 导致 ident 2 字节）

## Round 5 实证（完整客户端组装 + 端点实测）

- **wintun 0.14.1 已下载到工作目录** `vendor/wintun/`（未装系统组件，运行时由 ctypes 加载）
- `tun_windows.py`：WintunAdapter（ctypes 创建适配器/netsh 配 IP/读写 IP 包，需管理员）
- `full_client.py`：完整链路整合 —— login → vpntunnel → PPP(LCP→PAP→IPCP) → keepalive 线程 → TUN 双向转发
  - TLS 流解复用：'E' keepalive(20B) / PPP 帧(ff03…) / 裸 IPv4 包三分支
- **端点实测**：无会话 GET vpntunnel → `HTTP/1.1 302 Redirect` → `cookietest`，与 vl3vpn.dll 中 "302=session invalid" 逻辑完全吻合 ✅
- 待用户授权：带凭据完整链路实测（login → 201 JSON → PPP OPEN → TUN）

## Round 5 ★ 真实网关全链路打通（带凭据实测，用户授权）

### 根因修复：多行 Set-Cookie 被字典覆盖
- 登录成功但"看不到"会话 —— `ANsession5301755367574550=tongji+REDACTED_<41hex>` 等 7 条 Set-Cookie 只剩最后一条
- A/B 验证：错密码→200（登录页），对密码→302 welcome（登录成功）

### ★ L3 vpntunnel 真身模板（FUN_1005cc10 get_config.c，与旧模板差异巨大）

```
GET /prx/000/http/localhost/vpntunnel HTTP/1.1
Host: <host>
Cookie: ANStandalone=true;ANsession<digits>=<value>
x-devtype: 1
appid: SSPVPN            ← 实际是 SSPVPN（日志里也是它；DLL 另一模板 SSVPVN 是别处用的）
clientid: <devid>
cpuid: 178BFBFF00A60F12  ← HKLM\SOFTWARE\VPN\VPN2\VPNMachineCPUID（16 hex，缺省回退=clientid）
hostname: EXAMPLE-LAPTOP
PAYLOAD-IP-VERSION: 6    ← 字面量
```
- **实测返回 `HTTP/1.1 201 OK`（L3 隧道授予成功！）**（appid 只写 SSVPVN/无 cpuid 时 → 200/0 = L4 分支或拒绝）
- clientid 缺失 → 503；apps 接口 `:65200/motionpro/postlogin/apps` 已通（200 + XML portal）

### 隧道二进制消息协议（实测）

- 201 后：16 字节握手 `0f 00×15` → 回 `0f 00×15` = ACK（L3/L4 通用）
- 消息格式（推断）：`[type:1B][固定头~14B][len16 + data]`
  - `0x45 'E'` = keepalive（20B，无回包）
  - `0x0f` = tcs-start 握手
  - **`0x12` 实测回包**：`12 00…00 2f68 0000 0000 0008 "<username>\0"` — 含 len16=8 + 用户名！
- 待解：common config（220B JSON）与 network config 的请求类型字节

### 登录实测要点
- ext1/deviceid 用原版值（日志复用）非必需项测试未做隔离，但当前组合已成功
- 登录后原始客户端并不 GET welcome（302 即成功），apps 调用激活门户

## Round 6 ★ 隧道二进制消息层测绘（含频率限制警告）

### 隧道消息帧格式（实证确立）
`[type:1B][len:3B BE][payload]`；16 字节定长消息即 len=0x10、payload=15B。
- `0x0f` 握手（16B: 0f 00×15 → 回 0f 00×15）—— L3 201 隧道上同样有效，须先做
- `0x45 'E'` keepalive（20B）
- **0x12 → 回 `[12][00×6][2f68][0000][0000][len16=8]"<username>\0"`（用户名查询）**
- **0x13 → 同格式回密码回显 "<password>"**（会话内密码可查！）
- 0x09/0x0d/0x14/0x17 → 16B 空回显 ACK；0x0a → 触发 36B 错误帧 `[5c][e8ffff=-24][...]` 后服务器断开
- 0x1e 以后全部 ConnectionReset —— **疑似网关侧频率限制**（短时间大量 login/tunnel 会话后触发），须退避

### LCP 裸发被拒
- 201+握手后直接发 `ff03c021...` → 服务器按消息解析（type=0xff, len=0x03c021 荒谬）→ 错误帧 0x5c + 断开
- 用 `[t][len:3][LCP]` 包裹（t=1..8）→ 全部静默（未获 PPP 应答）
- **结论: PPP 帧的封装类型/额外头仍未确定；或数据面实际走裸 IPv4（原版读侧 demux 里 ff03 只是直通透传的可能仍在）**

### 待解：common config（原版 220B JSON）
- 原版流程：201 → "write common config request"(16B, get_config.c:1329) → 回包头含 datalen=220 → JSON(keepalive_interval 等)
- 我方 16B `0f` 请求 → 回包头全 0（datalen=0）→ 无配置数据
- 201 响应体：原版 104B vs 我方 0B —— 差异同源，可能与 postlogin 状态/设备注册态有关
- RE 状态：FUN_1005cc10 中段（201 处理→config 交换）Ghidra 反编译被截断，字符串引用（0x100f0ae3/0x100f0b17/0x100f0b73）无 xref（地址字面量编码搜索失败），需读原始字节手工解码 0x1005cf00-0x1005d1a0 区段

### 客户端整合（proto_client.py）
- login(): 302 即成功；动态会话 Cookie 名 `ANsession<数字>` 按前缀抓取
- open_l3_tunnel(): 原版模板（新连接+仅会话 Cookie+appid: SSPVPN+cpuid+hostname+PAYLOAD-IP-VERSION: 6）→ 201 → 0x0f 握手
- tunnel_send_msg/tunnel_recv_msg/tunnel_query(): 消息层封装
- get_machine_cpuid(): 读 HKLM\SOFTWARE\VPN\VPN2\VPNMachineCPUID，回退硬编码

## Round 7 ★★ 控制面完全破解（字母消息协议 + 双 JSON 配置）

### ★ 隧道消息协议真相（全部实测验证）
格式 A（16B 定长头 + payload）：`[type:1B][11×00][len:4B LE @offset12] + payload`
格式 B（keepalive）：`'E' + len:3B BE(0x14) + 16B body`（20B，服务器会原样回显）

**请求→响应字母配对（type = 响应字母 - 1）：**
| 请求 | 响应 | 内容 |
|---|---|---|
| `'P'`(0x50)+15×00（len=0） | `'Q'`(0x51)+len(4LE) | **common config JSON**（220B：thread_number/netpool_flag 1149184/keepalive_interval 30/allow_speed_tunnel/dns_timeout[1000,1000,1000,5000]/hostmap/callhome_switch） |
| `'T'`(0x54)+48B（len@12=0x20，载荷 32B：[16]=虚拟ip(0)、[20:24]=本机适配器IP、[24]=1、[40:46]=MAC） | `'U'`(0x55) | **net config JSON**（700B：resource_group_flag/client_ipv4(LE int)/client_ipv4_mask(LE)/include_network_resource(ip0,mask0=全流量)/exclude_network_resource(排除段)/dns_servers） |
| 0x12 | 0x12+`2f68 0000 0000 <len16>用户名\0` | 查用户名 |
| 0x13 | 0x13+同格式 | 查密码（会话内密码可回显！注意安全） |

RE 证据：get_config.c FUN_1005cc10 中 `mov byte [ebp-0x11A4],0x50`（'P'）、`mov byte [ebp-0x1194],0x54`+`mov [ebp-0x1188],0x20`（'T'+len）、响应校验 `cmp al,0x51`（'Q'）、`cmp al,0x55`（'U'）。无效响应类型 → "invalid common/network config response, msg type: %d"。

★ 实测（vpn.tongji.cn）：client_ipv4=111.187.82.231，mask /19，DNS=202.120.190.208/108（同济内网 DNS！），include 0/0（全流量），exclude 2 个网段。

### 数据面结论（排除法 + 关键发现）
- 已排除：裸 PPP/裸 IPv4/[letter][3Blen][PPP 或 IP]（字母 A-X 全扫静默）/SSTP [0x10][len:2]
- **发现 WireGuard 模式**（vl3vpn.dll 内置）：
  - `GET /prx/000/http/localhost:54323/wg/v1/available_wg_list?vsite_name=&session_id=`（UA: motionpro-wg）→ JSON "wireguards":[{pub_key,name,desc}]
  - `POST /prx/000/http/localhost:54323/wg/v1/connect`（UA: motionpro-wg，body 含客户端公钥）→ 客户端起标准 WireGuard UDP 隧道
  - `SOFTWARE\VPN\AWG` / `SOFTWARE\VPN\Keepalive\L3WGTunnel`(running) 注册表
  - "connect wg failed, switch to sstp." → **本部署（同济）WG 探测无响应 → 回退 SSTP** 模式
- appid `SSPVPN` = SSP(SSTP) VPN 模式；数据通道帧格式待破（tun 线程写路径经 ctx+0x2648 函数指针，模板 ctx SSE 整体拷贝初始化，需继续 RE）
- tun 线程 @0x10065350；keepalive 发送 FUN_10063d70；"Received keep alive packet from L3 %s Tunnel, send:%d recv:%d interval:%d"

### 客户端整合（proto_client.py）
- login(): 302 即成功；动态会话 Cookie 名 `ANsession<数字>` 按前缀抓取
- open_l3_tunnel(): 原版模板（新连接+仅会话 Cookie+appid: SSPVPN+cpuid+hostname+PAYLOAD-IP-VERSION: 6）→ 201
- get_common_config() / get_net_config(): P→Q / T→U 实现于 full 客户端（本轮脚本实测，下轮固化进 proto_client）
- get_machine_cpuid(): 读 HKLM\SOFTWARE\VPN\VPN2\VPNMachineCPUID

## Round 8 ★★ 数据面帧格式破解（class-5 通道实测打通到"反射"层）

### ★ 隧道数据帧格式（20 字节头，RE 自接收解复用器 @0x10062190）
```
[0]  = 0x45 'E'（服务器不校验，回显保留）
[1]  = 0x00（实测 01-04 也接受）
[2:4] = 总帧长(含头) :2B BE   ← ntohs
[4:9] = 00 00 00 00 00
[9]  = 0xff（硬校验！cmp byte[esi+9],0xff）
[12:14] = 消息类 :2B BE        ← ntohs 后 -1 ∈ {0..5} switch 分派
[14:16] = 子类/标志 :2B BE
[16:20] = 辅助 dword :4B BE（keepalive=ms_of_day；数据帧填 0/token 均被接受）
[20:] = 载荷
```
解复用（客户端接收侧，字节序列实证）：`cmp byte[esi+9],0xff` → `movzx ecx,word[esi+0xc]`→ntohs→`lea edx,[ecx-1]; cmp edx,5; jmp table[0x1006299c]`。

### ★ 消息类分派表（实测响应）
| class | 请求→响应 | 含义 |
|---|---|---|
| 1 | E 保活 → 原样回显 | keepalive（20B 无载荷） |
| 2/3 | → 静默 | 未明（可能是状态通知，载荷待猜） |
| 4 | → `DLS SPEED TUNNEL` 文本 | speed tunnel 控制（allow_speed_tunnel=0 时仅报身份） |
| 5 | IP 包 → **原包回显** | ★ 数据通道！载荷=裸 IP 包（IPv4/IPv6/PPP 都被接受并反射） |
| 6 | → `{"mptoken": N}` JSON | get_mp_token（对应原日志 l3vpn.c:694/Get_MP_Token） |

### 数据转发门控（本轮唯一未解）
网关完整解析 class-5 帧并**逐字节反射**载荷（IP 头校验和正确与否、b1 变体、[16:20]=token/vip、[14:16]=1、IPv6、PPP-LCP 全部同样反射；class2/3 静默；16B 头格式在配置期后失效）。原日志揭示完整架构：
- 配置期后 vpnd 起本地 SSTP 服务器 `127.0.0.1:65443`（sstp_server_str），Windows RAS "WAN Miniport (SSTP)" 用 server.p12 拨号连它
- 本地 PPP（LCP/PAP/IPCP，sstp.c:857-828）在 RAS↔vpnd 之间完成，全程本地
- 之后 get_mp_token(class 6) → VPN_CB_CONNECTED
- **转发门控候选**：① class-2/3 是状态通知（载荷未知）；② 服务端需本地 PPP 完成后的就绪信号；③ MotionPro 额外 HTTPS API
- 下一轮：RE class-2/3 的载荷期望（解复用 case 2/3 处理器 0x100621eb/0x100621fb → call 0x1006FF1D 区）；或抓真实客户端的隧道流量对照

### 网络配置全字段（Round 8 完整解码）
- include: 0.0.0.0/0 protocol=4 port_type=2 ports=[0,65535,...]（全流量）
- exclude: 10.111.192.23/32、202.94.188.6/32
- dns: 202.120.190.208、202.120.190.108；vip 111.187.82.231/19
- 原始日志 vip 例：111.187.82.4；app agent 2.7.0；appid: SSPVPN = SSTP 模式

## 待确认清单

- [x] login 的 pwd 字段编码方式 → 明文（Round 2）
- [x] deviceid 格式 → upper(base64(SHA256(fp)))（Round 2）
- [x] 自定义 TLS ClientHello → FF×32 session + 0xE013（Round 3）
- [x] vpntunnel 请求完整 header → appid/clientid/Appid:DesktopDirect/x-devtype（Round 2）
- [x] 网关侧帧格式 → 裸 PPP HDLC 帧（Round 3）
- [x] keepalive 帧格式 → 20 字节 'E' 帧（Round 2）
- [ ] speed tunnel UDP 协议（低优先级，本站禁用）
- [ ] 数据帧是否带 AG 额外头（倾向无，可在原型实测确认）
- [ ] ext1 MD5 串的输入来源
- [ ] an_login.js 解析细节（method 列表 JSON 字段）

## 工件

- 字符串转储：`temp/motionpro_re/{api,ui,vpnd,proxy,httpd}_strings.txt`
- 协议行提取：`temp/motionpro_re/protocol_lines.txt`（1474 行）
- Ghidra 项目 `/MotionPro/`：ArrayVPNApi.dll、vpnd.exe（已自动分析）

---

# 最终确认（2026-09-03，全链路复现成功）

## ✅ 端到端验证结果（tls_exact.py，纯 Python 从零实现，无任何官方组件）

login(HTTP) → logout → sleep 2 → login → ExactTLS(FF探测CH + 315B 指纹CH, RC4-MD5) → an_welcome.js → vpntunnel(201) → P(0x50) → Q(JSON) → T(0x54, 48B) → U(JSON 网络配置) → class-6 mptoken → **裸 IP 数据面（DNS/ICMP/TCP 全部往返成功）** → logout。
DNS 实测：www.tongji.edu.cn → 202.120.190.208 应答 A 192.168.80.100（内网解析成功）；ICMP echo 到 202.120.190.208 与 1.1.1.1 均有 reply；TCP SYN:80 收到 SYN-ACK。

## 🔑 数据面静默丢包的根因（卡了最久的坑）

网关**逐包校验 IP/UDP/TCP 校验和，错误即静默丢弃**（无任何报错/回包）。此前 bare 包被忽略并非封装问题：
1. **IP 头校验和必须包含源+目的地址**：`cksum(ih)` 只算 12 字节头是错的，必须 `cksum(ih + src + dst)`。
2. **UDP 校验和必须覆盖整个载荷**：`udp_cksum(src,dst,uh)` 漏了 DNS 载荷。
修复后与 scapy 生成结果逐字节一致，数据面立即打通。

## 🔑 TLS 握手前的 FF 探测 ClientHello（FUN_10048210 "send specific client hello"）

vpnd 在真正 SSL_connect 之前、**同一 TCP 连接上**先发一条 82B 探测记录：
`160301004d 01000049 0301 <时间戳4B> 0102...1c(28B) 20 <32×ff> 0002 0004 0100`
- 即 version=TLS1.0、session_id=32 字节 0xFF（"FFFF" 的由来，国密/SKF 探测，见 is_sslhandshake_need_FFFF）、单 cipher 0x0004。
- **实测网关对该探测不回包**；客户端随后直接发真 ClientHello（315B 指纹）。是否为数据面必需尚未单测（加上无害，与真实客户端一致）。

## 线上帧语义最终版

- 记录封装：IP 头风格 20B 包裹 `45 00 <len:2BE> 00000000 00 ff 0000 <class:2BE> <ip[14:16]> <aux:4BE>`；byte[9]==0xff 为控制帧，否则裸 IP 数据包。
- class-1 keepalive（20B，含 ms_of_day aux）→ 网关原样回显；class-4 = DTLS 加速隧道注册（服务端 allow_speed_tunnel=0 时不发，实测会收到 "DTLS SPEED TUNNEL" 回复）；class-5 = "切回 SSL 隧道"通知；class-6 = mptoken 请求（返回 JSON 数字，如 543365147）。
- **L3 隧道上没有 PPP**：实测向网关发 LCP Config-Request 无任何响应。PPP（LCP→PAP→IPCP）只存在于 vpnd 本地 127.0.0.1:65443 SSTP/RAS 侧（sstp.c 本地终结），不进隧道。
- 真实客户端数据面：pcap 证实只有 TCP 443 单流；每包一个 TLS record（DHCP 96B×3、IGMP 40B、mDNS、DNS 68B 等），与我方实现完全同形。开包调试日志（见下）逐包证实 `vpn_tunnel_write`/`read ... from ssl tunnel` 的裸 IP 双向转发。

## 每包调试日志开关（RE 结论，实测有效）

vl3vpn.dll 的 per-packet 日志由双条件控制：`DAT_1011ecc4 != 0 && loglevel < 2`。
`DAT_1011ecc4 = (SHGetValueA(HKLM, "SOFTWARE\\VPN\\Install Manager", "EnablePrintRequest") == 0x2704)`，**每次连接时读取**。
注意 vpnd.exe 是 32 位，读 Wow6432Node 重定向视图。管理员执行：
`reg add "HKLM\SOFTWARE\WOW6432Node\VPN\Install Manager" /v EnablePrintRequest /t REG_DWORD /d 9988 /f`
（9988 = 0x2704）之后重连客户端，`%LOCALAPPDATA%\MotionPro\Log` 即出现
`vpn_tunnel_write: %d bytes, src --> dst` / `read %d bytes from ssl tunnel, src --> dst` 逐包记录。

## 其他实证要点

- T 消息字节精确值：[20:24]=192.0.2.100（get_local_address 第一适配器），[24:28]=0（非重连标志），[40:46]=02:00:00:00:00:01（get_local_mac_address_forwin32）。
- clientid 用 GUID：`VPNMachineGuid` = 00000000-1111-2222-3333-444444444444；devid=deviceid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==。
- U JSON 的整数是**小端字节序 IP 编码**：ip4(n)=[n&255,(n>>8)&255,...]（72530799 → 111.187.82.4 已验证）。
- 会话租约：不 logout 会粘住同一 VIP；login→logout→login 后每次新 VIP（111.187.64.0/19 池）。
- SSL_write(ssl, buf, 48) 的 Finished 需要 4 字节握手头 [20][00 00 0c]——自定义栈不做记录层组装。
- write_to_vpn（sstp.c IP 分支）→ 管道 → 写线程 → vpn_tunnel_write（FUN_10063650）裸 SSL_write；vpn_tunnel_write 唯一调用链是 lwip/TUN 路径 FUN_10068d50 与 SSTP 中继路径。
