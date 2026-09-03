# -*- coding: utf-8 -*-
"""
mp_client 私有配置 —— 含凭据，勿提交到任何公开仓库！

从 config.example.py 复制本文件后按实际情况填写。
"""

CFG = {
    # 网关地址（域名或 IP）
    'server': 'vpn.tongji.cn',

    # 登录凭据
    'user':     'CHANGE_ME',
    'password': 'CHANGE_ME',

    # devid_seed: 任意稳定字符串即可。
    # 如需保持官方客户端时期的设备身份：填入 'devid'（44 字符 base64）并删除 devid_seed。
    'devid_seed':  'CHANGE_ME_任意稳定字符串',
    # 'devid':     '********…44 字符 base64…********',
    'device_name': 'DESKTOP-XXXXXXX',
    'ext1':        'auto',

    # vpntunnel 请求头设备信息
    'clientid': 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX',   # 官方客户端用 VPNMachineGuid (GUID 格式)
    'cpuid':    '178BFBFF00A60F12',                        # CPUID 特征串，可保留此默认值
    'hostname': 'DESKTOP-XXXXXXX',

    # T 消息（0x54）本机信息：首个网络适配器 IPv4 与其 MAC（无冒号 hex）
    'ras_ip': '192.168.1.100',
    'mac':    'aabbccddeeff',

    # ============ 代理服务端（proxy_serve.py）============
    # 监听地址: 'host:port'，置空字符串/None 可停用该监听
    'proxy_socks':    '0.0.0.0:1080',
    'proxy_http':     '0.0.0.0:8080',
    # 开放监听（非 127.0.0.1）必须配置认证，否则拒绝启动
    'proxy_user':     'CHANGE_ME',
    'proxy_pass':     'CHANGE_ME',

    # TUN 设备（Windows wintun / Linux /dev/net/tun）
    'tun_name':       'mptun0',
    'tun_mtu':        1400,
    'tun_kind':       '',            # ''=按平台自动; 'wintun'|'linux'
    'wintun_dll':     '',            # wintun.dll 路径（空=自动搜索 vendor/，先跑 scripts/fetch_wintun.py）

    # 路由: 'full'=全隧道(0/0) | 'split'=仅 route_include 网段进隧道
    'route_mode':     'full',
    'route_include':  [],            # split 模式示例: ['202.120.190.0/24']
    'route_dry_run':  False,         # True=路由命令只打印不执行（调试）

    # 上游连接绑定源 IP（如 VIP）；空=跟随系统路由表
    'proxy_bind_ip':  '',

    # 日志文件（空=仅控制台输出）
    'log_file':       '',
}
