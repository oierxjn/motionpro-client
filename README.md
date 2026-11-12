# motionpro-client

Array Networks **MotionPro VPN（AG 网关）** 的开源协议复现客户端（纯 Python，无任何官方组件）。
在 ArrayOS94 网关（如 `vpn.tongji.cn`）上完成全链路实测验证。

> ⚠️ 仅供学习协议研究 / 自用接入自己的账号。

## 文件

| 文件 | 说明 |
|---|---|
| `mp_client.py` | 主客户端：自研 TLS1.2（vpnd 指纹）+ 控制面 + L3 裸 IP 数据面 |
| `vpn_service.py` | `VpnService`：隧道会话服务类（connect/reconnect/shutdown） |
| `proxy_serve.py` | **代理服务端入口**：SOCKS5/HTTP 代理 → TUN → VPN 隧道 |
| `local_proxy.py` | 内建 asyncio 代理组件（SOCKS5 RFC1928 + HTTP/CONNECT，可独立运行/替换） |
| `forwarder.py` | 隧道 ↔ TUN 双线程 IP 包搬运 + keepalive + 帧解复用（`FrameDemuxer`） |
| `tun_dev.py` | TUN 设备封装（Windows wintun / Linux /dev/net/tun 双实现） |
| `routes.py` | 路由装配：防环（网关 IP 固定走物理网卡）+ 0/0 或分段路由 + 回滚 |
| `proto_client.py` | 登录 HTTP 连接封装（AgConnection） |
| `ppp.py` | PPP 状态机（本地 SSTP/RAS 模式用，L3 直连不需要） |
| `config.example.py` | 配置模板 → 复制为 `config.py` 填写（**含凭据，勿提交**） |
| `PROTOCOL_NOTES.md` | 完整协议分析笔记 |

## 依赖

```
uv sync       
```

## 使用：客户端演示

```powershell
Copy-Item config.example.py config.py   # 然后编辑 config.py：填入账号与相关数据

uv run mp_client.py
```

运行后依次输出：stale session cleared → welcome/tunnel 201 → Q/U 配置 JSON → mptoken →
发出 DNS/ICMP/TCP 探测并打印收到的回包（DNS 查询 `www.tongji.edu.cn` 应收到网关内网解析应答），
最后 logout。

## 使用：代理服务端（局域网设备免装 VPN 客户端）

把本机变成 SOCKS5/HTTP 代理：其他设备设置代理后，流量经 VPN 隧道进入校园网
（源 IP = 网关分配的虚拟 IP 111.187.x.x）。

```powershell
# 1) 获取 wintun.dll（管理员 PowerShell，仅 Windows 首次需要）
uv run scripts/fetch_wintun.py

# 2) config.py 填好凭据与代理段（proxy_socks/proxy_http/proxy_user/proxy_pass）

# 3) 管理员运行
uv run proxy_serve.py
```

- **防环**：启动时先把网关 IP 加 /32 路由固定走物理网卡，再把 0/0 指向 TUN
  （这是"不做必死"项，RouteManager 已内置顺序与回滚）。
- 验证：
  ```powershell
  curl.exe --socks5-hostname mp:mp123456@127.0.0.1:1080 https://www.tongji.edu.cn -I
  curl.exe -x http://mp:mp123456@127.0.0.1:8080 http://www.tongji.edu.cn -I
  ```
- 断线自动重连（keepalive 3 周期无回显/EOF 触发，指数退避最多 5 次）；
  Ctrl+C 优雅退出（回滚路由 → 关 TUN → logout 释放 VIP 租约）。
- 仅验证隧道控制面：`uv run proxy_serve.py --check-only`；路由调试：`--route-dry-run`。

### 已知问题与排障（Windows 实测沉淀）

- **wintun 单播黑洞**：0/0 下一跳写 VIP 自身、或假网关没有静态 ARP 邻居，
  都会让单播被内核 ARP 卡死（wintun 无法应答 ARP）。已内置「假网关 +
  静态邻居 + dadtransmits=0」组合，勿改回。
- **广播放大回路**：网关会把段内广播按客户端复制灌下（子网定向广播），
  宿主 NetBIOS/mDNS 逐包应答又灌回隧道，招致网关限流。Forwarder 已双向
  过滤（含子网定向广播）。
- **系统 DNS 瘫痪**：全隧道后 LAN 私有 DNS 不可达。已内置 DNS /32 排除路由。
- **内网域名解析**：校园边界对 VPN 池做单向 NAT，公网解析地址回包源不匹配。
  已默认走隧道 DNS over TCP（`vpn_dns_resolve`），切勿关闭；高峰期单 RTT
  可达 1-3.5s，`vpn_dns_timeout` 默认 8s。
- **网关限流**：数据面质量随时段/会话频率剧烈波动（凌晨秒通，白天/高频
  建会话后高丢包），控制面始终正常，冷却数小时自愈。压测务必控制频率。
- **公网出口与端口策略**：该部署对 VPN 池放行校园资源（如内网 web
  192.168.80.100:80）；部分端口（内网 :443、公网出口）能否使用取决于网关
  与目标策略，与本客户端无关。

### 容器部署（多服务主机推荐）

在跑着其他服务的主机上用容器隔离部署——TUN/路由/0/0 全部作用于容器 netns，
**宿主路由表零改动**（对外服务/其他容器/Tailscale 均无感知）：

```bash
mkdir -p ~/motionpro-deploy && cd ~/motionpro-deploy
# 放入 config.py（从 config.example.py 复制, 设 'deploy_mode': 'container'）
#   与 docker-compose.yml（端口按需改绑, 默认只发布到 Tailscale IP）
curl -LO https://raw.githubusercontent.com/oierxjn/motionpro-client/main/Dockerfile
docker compose build --build-arg PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
docker compose up -d && docker logs -f motionpro-proxy
```

原理：容器内 `default metric 1 dev mptun0` 只作用于容器 netns；「DNAT 进入的
代理客户端回包」（源=容器 eth0 IP）由源地址策略路由（`ip rule from <eth0_ip>
lookup 100`）钉在 docker 网关上，与绑定 VIP 为源的上游流量天然分流。
注意：宿主 resolv.conf 若指向 Tailscale MagicDNS（100.100.100.100），其对部分
域名可能返回空答案，compose 已给容器显式配公共 DNS。

### 模块解耦约定

每个组件只依赖显式接口，可标准化替换/打桩调试：

| 组件 | 接口 | 替换方式 |
|---|---|---|
| 隧道传输 | `send_app(bytes)` / `recv_app()` | `TunnelState.tls` 传任意同形实现 |
| TUN | `TunDevice.open/read/write/set_ip/close` | `create_tun(kind)` / 自定义类 |
| 路由 | `RouteManager.apply_full/rollback` | runner/resolver 可注入, `dry_run` 可调试 |
| 搬运 | `Forwarder(transport, tun, on_dead)` | 帧解析 `FrameDemuxer` 纯函数可单测 |
| 代理 | `ProxyServer.start/stop` | 可换 pproxy/sing-box（出口走本机路由即可） |

## 协议要点（详见 PROTOCOL_NOTES.md）

- **控制面**：HTTPS 443 上普通 HTTP（`/prx/000/http/localhost/login` 等）。
- **隧道**：login 后在**同一台服务器的 443** 上用 vpnd 的 TLS 指纹开第二条 TLS1.2 连接
  （cipher `0x0004` RC4-MD5、无 EtM/EMS；握手前先发一条 session_id=32×0xFF 的探测 ClientHello，
  网关不回复，随后再发真 ClientHello）。自定义栈下 Finished 需自带 4 字节握手头。
- **协商**：`GET /prx/000/http/localhost/vpntunnel`（201）→ P(0x50+15×00) → Q(JSON) →
  T(0x54, 48B, 含本机适配器 IP/MAC) → U(JSON: VIP/掩码/DNS/路由) → class-6 取 mptoken。
- **数据面**：与控制帧同一条 TLS 流复用。20B `45 00 <len> … 00 ff … <class>` 包裹为控制帧
  （1=keepalive 回显、6=mptoken），**裸 IP 包逐条 SSL_write 即为数据**；网关逐包校验
  IP/UDP/TCP 校验和，错误静默丢弃（实现时务必用标准校验和算法，含伪首部）。
- **PPP 与隧道无关**：官方客户端的 PPP(LCP/PAP/IPCP) 全部终结在 vpnd 本地 SSTP/RAS 侧，
  不经过网关，开源直连无需实现。
