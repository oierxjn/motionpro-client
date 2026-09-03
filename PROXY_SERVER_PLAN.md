# MotionPro 代理服务端 — 实现方案（任务书）

> 本文档是给后续持续开发的 agent 的完整任务书，自包含，不依赖任何会话上下文。
> 目标仓库：`E:\Program\Tools\motionpro-client`（Python ≥3.12，uv 管理，依赖仅 `cryptography`）。
> 状态：方案定稿（平台双轨：Windows / Linux）。

---

## 1. 背景与目标

本仓库是一个纯 Python 的 Array Networks MotionPro（AG SSL VPN）开源客户端，
已在同济网关 `vpn.tongji.cn`（202.120.189.34:443，ArrayOS94）上全链路跑通：
HTTP 登录 → 自研 TLS1.2 指纹握手（RC4-MD5）→ `vpntunnel` 201 → P/Q/T/U 配置协商
→ mptoken → 裸 IP 数据面（DNS/ICMP/TCP 均验证可达）→ logout。

**目标**：在保留现有客户端能力的基础上，把它升级为一个**代理服务端**：

- 对外提供 SOCKS5 与 HTTP 代理（监听 `0.0.0.0`，可选认证）
- 任何客户端设备（浏览器/App 等）设置该代理后，流量经本代理转发进同济 VPN 隧道，
  到达同济内网与授权资源（效果等价于"该设备在校园网内"，源 IP 为网关分配的虚拟 IP）
- 客户端设备**无需安装任何 VPN 组件**，只认 socks/http 代理

**架构决策（已定）**：TCP 层**托管给系统内核**（经 TUN 设备），不在 Python 里自研 TCP 栈。
代理协议层用**现成组件**（pproxy / sing-box），自研部分只做：
TUN 设备封装、TUN↔隧道双线程 IP 包搬运（不解析 TCP，只搬运）、控制面服务化。

---

## 2. 现状盘点（代码地图）

| 文件 | 内容 | 复用点 |
|---|---|---|
| `mp_client.py` (583 行) | 主客户端：`ExactTLS` 自研 TLS1.2、`build_devid`(seed)、`build_ext1`(auto)、`do_login`、`main()` 演示流程 | 全部控制面 + TLS 原样复用；`main()` 需重构为服务类 |
| `proto_client.py` | 早期控制面原型（标准 ssl 库），`AgConnection`/`build_deviceid` 等 | 参考，不是主线 |
| `ppp.py` | PPP 状态机——**已证实 L3 隧道上无 PPP**，无需使用 | 忽略 |
| `config.py` / `config.example.py` | 凭据 + 设备标识（`devid_seed` 生成 devid；`ext1: 'auto'`） | 需扩展代理相关配置项 |
| `PROTOCOL_NOTES.md` | 完整逆向笔记（帧格式/流程/坑） | `# 线上帧语义最终版`、`# Round 8` 是数据面关键参考 |
| `uv.lock` / `pyproject.toml` | uv 管理，Python ≥3.12，`cryptography` | 新增依赖走 `uv add` |

**关键能力核实（实测）**：
- `ExactTLS.send_app(data)`：把一个 IP 包/帧作为一个 TLS record 发出（每包一个 record）
- `ExactTLS.recv_app()`：读回一个 record 的解密 payload（**1 record ≈ 1 帧/1 裸包**）
- `ctrl(cls, payload)`：构造 20B 控制帧；`cksum()`：IP 校验和
- keepalive：class-1 帧（20B），网关原样回显；间隔 = Q JSON `keepalive_interval`（实测 30s）
- mptoken：class-6 请求 → `{"mptoken": N}` JSON 回复；每个会话开始时取一次
- VIP/路由/DNS：U JSON `client_ipv4`（**LE int**，用 `ip4()` 转字节）、`include` 为
  `0.0.0.0/0`（全隧道）、`dns_servers` 含同济内网 DNS 202.120.190.208/108

---

## 3. 架构总览

```
[客户端设备: 浏览器/App，设置 socks5/http 代理]
   │
   ▼  (TCP 连接，标准 socks/http 协议)
[代理服务 pproxy/sing-box]   ── 现成组件，监听 0.0.0.0:1080(socks5) / :8080(http)
   │  出口 = 普通 socket → 查本机路由表
   ▼
[TUN 设备]  (wintun @ Windows / /dev/net/tun @ Linux，MTU 1400)
   ▲                │
   │   自研转发循环（forwarder.py，双线程，纯 IP 包搬运，不碰 TCP）
   │                ▼
[自研 TLS 隧道]  ExactTLS + 控制面（login/201/P·Q·T·U/mptoken/keepalive/重连）
   │
   ▼
同济网关 → 内网资源（源 IP = VPN 虚拟 IP 111.187.x.x/19）
```

关键数据流（双向）：
- **下行**：隧道 `recv_app()` → 帧解析（见 §5.1）→ 裸 IP 包写入 TUN → 内核 TCP/UDP 栈处理 → 代理 socket → 客户端
- **上行**：代理 socket → 内核栈 → TUN `read()` → `send_app()` 直接上隧道

TCP 状态机、重传、窗口、MSS 协商全部由内核完成；自研代码看到的是「IP 包」，不是「TCP」。

---

## 4. 模块划分（新增/改造）

建议新文件放仓库根，与 `mp_client.py` 平级：

```
tun_dev.py        TUN 设备封装（Windows wintun ctypes / Linux /dev/net/tun 双实现）
forwarder.py      双线程转发循环 + 帧解析 + keepalive 线程 + 断线检测
vpn_service.py    隧道服务类：把 mp_client.main() 的演示流程固化成
                  VpnService(login → TLS → 201 → PQTU → mptoken → 长期运行 → logout)
proxy_serve.py    入口：装配（启动隧道 + TUN + 代理子进程/内建 socks）+ 信号处理
routes.py         路由配置（Windows netsh / Linux ip 命令封装）
```

约定：
- `mp_client.py` 改造原则：**只做小步重构**（把 `main()` 里的流程提为
  `class VpnService` 或 `def tunnel_setup() -> (tls, vip, netjson)`），
  保留 `ExactTLS`/`build_devid`/`build_ext1`/`do_login`/`ctrl`/`cksum` 原样。
  原有 `uv run mp_client.py` 演示行为尽量保留（可加 `--demo` 旗标）。
- 新增代码**不要**触碰 `ppp.py`（隧道上无 PPP）。

### 4.1 tun_dev.py

接口（两平台同签名，便于 mock 测试）：

```python
class TunDevice:
    def open(self, name: str = "mptun", mtu: int = 1400) -> bytes  # 返回分配的 6B MAC(windows) 或 None
    def read(self, n: int = 65536) -> bytes                        # 阻塞读一个 IP 包
    def write(self, pkt: bytes) -> int                             # 写一个 IP 包
    def set_ip(self, ip: str, mask: str) -> None                   # 设置接口 IP（管理员/root）
    def close(self) -> None
```

- **Linux**：`os.open("/dev/net/tun", O_RDWR)` + `fcntl.ioctl(TUNSETIFF, struct.pack("16sH", b"mptun0", IFF_TUN|IFF_NO_PI))`；需 root/CAP_NET_ADMIN。
- **Windows**：wintun.dll（0.14.1，官网 https://www.wintun.net/ 下载；仓库旧 artifact
  `vendor/wintun` 不在本仓库，需重新获取）。ctypes 加载：`WintunCreateAdapter` →
  `WintunStartSession` → `WintunReceivePackets`/`WintunSendPacket`（轮询 + 事件/延时重试，
  参考天然适用于 wintun 的轮询模式）。创建适配器**需管理员权限**。
- MTU 1400，`set_ip` 填入 U JSON 下发的 VIP 与掩码（VIP 是 LE int，`ip4()` 转换）。

### 4.2 forwarder.py

```python
class Forwarder:
    def __init__(self, tls: ExactTLS, tun: TunDevice, keepalive_interval: int = 30)
    def start(self)          # 起 3 个线程：tunnel→tun、tun→tunnel、keepalive
    def stop(self)
```

- **tunnel→tun 线程**：循环 `recv_app()` → §5.1 帧解析：
  - 控制帧（`byte[9]==0xff`）：丢弃（keepalive 回显等，日志计数即可）
  - 裸 IP 包：`tun.write(pkt)`
- **tun→tunnel 线程**：循环 `tun.read()` → `tls.send_app(pkt)`（校验和由内核已算好，**不要重算**）
- **keepalive 线程**：每 `keepalive_interval` 秒发 `ctrl(1)`；连续 3 次读不到回显即触发重连回调
- 断线检测：`recv_app` 抛 EOFError / socket 超时阈值 → 触发 `vpn_service.reconnect()`

### 4.3 vpn_service.py（核心改造）

把 `main()` 流程固化为可重复调用的服务类，重点：

```python
class VpnService:
    def connect(self) -> dict    # do_login(清 stale) → ExactTLS.handshake → welcome/vpntunnel(PQTU) → mptoken → 返回 {vip, mask, dns, keepalive, tls}
    def reconnect(self)          # tls.close → 重试 connect（指数退避，最多 N 次）
    def shutdown(self)           # 停 forwarder → conn.request(logout)（释放 VIP 租约）
```

注意点：
- 建立顺序沿用 `main()`：login→logout 清 stale → sleep 2 → 重新 login（无 welcome）→
  TLS 握手 → `an_welcome.js` → `vpntunnel`(201) → P(0x50)→Q、T(0x54,48B)→U → `ctrl(6)` mptoken。
- T 消息 48B 构造照抄 `mp_client.py` 现成代码（`ras_ip`/`mac` 从 config 读）。
- `connect()` 成功后把 `{vip, mask, dns, keepalive_interval}` 返回给装配层配 TUN 与路由。

### 4.4 proxy_serve.py（入口）

```python
main():
    加载 CFG → VpnService.connect() → 建 TunDevice → set_ip → 配路由(routes.py)
    → 起动 Forwarder → 启动代理服务（默认：uvx 起 pproxy；可选内建 asyncio socks5）
    → signal(SIGINT/SIGTERM) → 优雅停：Forwarder.stop → VpnService.shutdown → 清理路由
```

- 代理服务**推荐现成组件 `pproxy`**（纯 Python，与 uv 生态一致）：
  `uvx pproxy -l socks5://user:pass@0.0.0.0:1080 -l http://user:pass@0.0.0.0:8080`
  （`--with pproxy` 或正式 `uv add pproxy` 均可；认证项强烈建议开启，因监听 0.0.0.0）
  - 备选：sing-box（Go 单二进制，socks5+http 入站 + direct 出站）
  - 若不想背外部依赖：按 RFC 1928 手写 asyncio SOCKS5（约 150 行）+ HTTP CONNECT（约 80 行）
- 进程管理：`proxy_serve.py` 用 `subprocess` 托管 pproxy 并转发 stdout 到日志文件；
  或文档记录让运维用 systemd（Linux）/ NSSM（Windows）托管整个 `proxy_serve.py`。

### 4.5 routes.py

路由装配核心，**顺序敏感**（先加排除再加默认）：

- **防环（必做，不做必死）**：网关 IP 必须走物理网卡，绝不能进 TUN。
  `gw_ip = socket.getaddrinfo(CFG['server'], 443)[0][4][0]`（动态解析，勿硬编码）
  - Windows：`route add <gw_ip> mask 255.255.255.255 <物理网关> metric 1`
  - Linux：`ip route add <gw_ip>/32 via <物理网关> dev <物理网卡>`
  - 同时排除本机局域网网段（如 192.168.x.0/24）与代理监听地址自身
- **隧道默认路由**（全隧道，与网关 include 0/0 对应）：
  - Windows：`route add 0.0.0.0 mask 0.0.0.0 <VIP> metric 5 if <tun接口idx>`
  - Linux：`ip route add default dev tun0 table 100` + `ip rule add ...`，或简单
    `ip route replace default dev tun0 metric 100`（**建议用 table 避免污染服务器默认路由**）
- **保守模式（可选）**：不加默认路由，只加同济网段/授权资源段，
  需要弄清资源 IP 范围（如 202.120.190.0/24 等），供运维决定。
- 退出时清理（记录添加的路由，按序删除）。

---

## 5. 关键实现细节与已知坑（务必逐条落实）

### 5.1 帧解析（tunnel→tun 侧）

从 `recv_app()` 拿到的 payload 有两种形态，**都以 `0x45 0x00` 开头**，不能按头两个字节判断：

| 形态 | 判定 | 长度字段 | 处理 |
|---|---|---|---|
| 控制帧（20B+） | `payload[9] == 0xff` | `[2:4]` BE = 总长（20+载荷） | 只有 class-1 keepalive 有意义（回显，无需响应）；class-6 是 mptoken 回复（连接期已处理）|
| 裸 IP 包 | `payload[9] == protocol(6/17/1…)` | `[2:4]` BE = IP 总长 | `tun.write(payload)` |

实现提示：读满 20B 先判 `byte[9]`；裸 IP 包按 IP 总长确认完整（1 record ≈ 1 包，通常已对齐，
保险起见按长度字段切分，多余字节进缓冲队列）。**不要把控制帧写进 TUN。**

### 5.2 MTU / MSS

- TUN 接口 MTU 设 **1400**（保守可选 1380）。内核按接口 MTU 自动通告 TCP MSS，
  内层 IP 包不会超过隧道可承载长度。
- 外层 TLS 是独立 TCP 连接（到网关 443），其 MTU 与内层无关，不用管。
- 不要手工改 MSS（clamp 由内核根据 MTU 完成）；若发现大包被网关静默丢（现象：大文件下载卡死、
  小包正常），再降 MTU 至 1320 并排查。

### 5.3 校验和

- **tun→tunnel**：wintun 读出的包是内核协议栈生成的，校验和已正确，**严禁重算**。
- **tunnel→tun**：网关按包校验后发出的包，校验和正确，直接转发。
- 自研构造的包（keepalive 等控制帧）校验和不适用（控制帧无 IP 校验和语义），照抄 `ctrl()`。

### 5.4 keepalive 与重连

- class-1 每 30s（读 Q JSON `keepalive_interval`），3 次无回显 → 判定隧道死 → `reconnect()`。
- `reconnect()`：close 旧 TLS → 重新 `connect()`（自动重取新 VIP）→ 更新 TUN IP/路由 → 恢复 Forwarder。
- 重连期间代理端口保持监听（客户端看到的是短暂 TCP 中断，可接受；文档不承诺无损热迁移）。

### 5.5 优雅退出与凭据安全（重要）

- SIGTERM/SIGINT → `VpnService.shutdown()` → `GET /prx/000/http/localhost/logout` 释放 VIP 租约
  （不登出会粘租约；下次会话会自动重分配新 VIP，但保持好习惯）。
- `config.py` 含明文凭据：**已被 .gitignore 排除，任何提交不得包含**；
  新增配置项只改 `config.example.py` 并留占位。

### 5.6 DNS

- 隧道内解析：同济内网 DNS 202.120.190.208/108。全隧道模式下，代理服务器本机的 DNS
  查询默认走 UDP 53 → 路由进 TUN → 隧道 → 网关转发（实测 DNS over tunnel 可用）。
- 需要"内网只有专属域名"的场景（可选）：把系统 DNS 指向 202.120.190.208（Windows
  `netsh interface ipv4 set dns` / Linux resolv.conf），或用 dnsmasq 分流。
- SOCKS5 客户端自身解析域名时注意：若域名解析不出公网 IP，客户端侧需开"远端解析"
  （SOCKS5 的 domain 模式，pproxy 支持）；文档建议代理开放域名字段转发而非强制 IP 直连。

### 5.7 权限

- Windows：wintun 创建适配器 + netsh 路由 → **管理员权限运行**；用 `RunAsAdmin` 提示或直接交代运维。
- Linux：root 或 `CAP_NET_ADMIN`（systemd unit 写 `AmbientCapabilities`）；文档给 systemd 示例。

---

## 6. 配置扩展（config.example.py / config.py）

```python
# ---- 代理服务端 ----
'server_mode':    True,          # False 时行为等同原 mp_client.py 演示
'proxy_socks':    '0.0.0.0:1080',
'proxy_http':     '0.0.0.0:8080',
'proxy_user':     'CHANGE_ME',   # 留空 = 不认证（不建议对外开放）
'proxy_pass':     'CHANGE_ME',
'tun_name':       'mptun0',      # Windows 用 wintun 适配器名
'tun_mtu':        1400,
'gw_exclude':     True,          # 防环路由开关（默认开，勿关）
'route_mode':     'full',        # 'full' 全隧道 | 'split' 仅指定网段（需 route_include 列表）
'route_include':  [],            # split 模式下要进隧道的网段，如 ['202.120.190.0/24']
'log_file':       'proxy.log',
```

---

## 7. 验证与验收标准（端到端）

按序执行，全部通过才算完成：

1. **隧道服务化冒烟**：`uv run mp_client.py --demo` 仍能复现原演示输出（回归）。
2. **TUN+隧道转发（本机直连）**：`VpnService.connect()` + TunDevice 就绪后，从代理服务器本机：
   - `ping -I <VIP> 202.120.190.208`（Windows `ping -S`）应通；`ping 1.1.1.1` 应通（全隧道）
   - `curl --noproxy '*' http://202.120.190.208/` 经隧道应返回页面
   - **防环验证**：隧道本身不卡死、`vc` 连接持续 2 分钟以上，即证明网关流量未误入 TUN
3. **代理链路（本机）**：
   - SOCKS5：`curl --socks5-hostname user:pass@127.0.0.1:1080 https://www.tongji.edu.cn` 返回页面
   - HTTP：`curl -x http://user:pass@127.0.0.1:8080 -v http://www.tongji.edu.cn` 返回页面
   - 源 IP 验证：访问仅校园网授权的资源（如知网），或在可回显源 IP 的服务上确认源 IP ∈ 111.187.0.0/19
4. **局域网设备**：另一台设备设代理 `http://<服务器IP>:8080`，浏览器正常访问同济资源。
5. **稳定性**：空闲 2 分钟不断（keepalive）；`tls.close()` 模拟断线 → 自动重连成功且新 VIP 生效；
   Ctrl+C/SIGTERM → 日志出现 `logged out`，路由清理完毕。
6. **回归**：`uv run python -m py_compile *.py` 无错；测试账号（如有）登录不受影响。

---

## 8. 里程碑

- **M1（核心打通）**：`tun_dev.py` + `forwarder.py` + `vpn_service.py` 装配完成，
  本机经隧道直连内网 IP 成功（§7.2）。
- **M2（代理接入）**：pproxy/sing-box 或内建 socks5，§7.3 / §7.4 通过。
- **M3（稳定化）**：keepalive/重连/优雅退出/路由清理/日志，§7.5 通过；
  Windows 管理员提示与 Linux systemd 示例落地。
- **M4（可选增强）**：split 路由、多客户端认证、双平台 CI 冒烟脚本。

每完成一个里程碑：`uv run python -m py_compile` + 当轮验收项实测通过后才算 done。

---

## 9. 风险与约束

- **防环路由是唯一"不做必死"项**（§5.1 → §4.5），实现时最先做、单独验证。
- Windows wintun 需重新下载 DLL（仓库无 vendor）；`tun_windows.py`（旧 round 工件）不在仓库，
  需重写 ctypes 封装，可参考 https://github.com/boundlessgeo/wintun-python 等实现思路。
- 代理监听 0.0.0.0 时必须开认证（config 默认占位），否则局域网内任何人可借用流量。
- 保持 `config.py` 不被提交（.gitignore 已覆盖）；提交任何改动前 `git status` 自查。
- 不实现 PPP（隧道上无 PPP，实测无响应）；不实现 speed tunnel UDP 加速（网关已禁用）。

## 10. 参考资料（仓库内）

- `PROTOCOL_NOTES.md`：`# 线上帧语义最终版`（帧结构/class 表）、`# Round 8`（帧格式 RE）、
  `# 最终确认`（数据面校验和坑）、`# 隧道二进制消息层`（P/Q/T/U）
- `mp_client.py`：`ExactTLS`（send_app/recv_app/handshake）、`ctrl`/`cksum`/`ip4`、
  `do_login`、`main()`（流程即 VpnService 蓝本，注意 T 消息 48B 与 PQTU 顺序）
- `README.md`：运行方式（`uv sync` / `uv run mp_client.py`）