# motionpro-client

Array Networks **MotionPro VPN（AG 网关）** 的开源协议复现客户端（纯 Python，无任何官方组件）。
在 ArrayOS94 网关（如 `vpn.tongji.cn`）上完成全链路实测验证。

> ⚠️ 仅供学习协议研究 / 自用接入自己的账号。

## 文件

| 文件 | 说明 |
|---|---|
| `mp_client.py` | 主客户端：自研 TLS1.2（vpnd 指纹）+ 控制面 + L3 裸 IP 数据面 |
| `proto_client.py` | 登录 HTTP 连接封装（AgConnection） |
| `ppp.py` | PPP 状态机（本地 SSTP/RAS 模式用，L3 直连不需要） |
| `config.example.py` | 配置模板 → 复制为 `config.py` 填写（**含凭据，勿提交**） |
| `PROTOCOL_NOTES.md` | 完整协议分析笔记 |

## 依赖

```
uv run mp_client.py        # 或
pip install cryptography
```

仅依赖 `cryptography`。

## 使用

```powershell
Copy-Item config.example.py config.py   # 然后编辑 config.py 填入账号与设备信息
uv run mp_client.py
```

运行后依次输出：stale session cleared → welcome/tunnel 201 → Q/U 配置 JSON → mptoken →
发出 DNS/ICMP/TCP 探测并打印收到的回包（DNS 查询 `www.tongji.edu.cn` 应收到网关内网解析应答），
最后 logout。

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
