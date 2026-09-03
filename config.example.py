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

    # 设备标识（登录表单与 vpntunnel 请求头）。
    # devid: URL 编码前的 base64 形如 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='
    # ext1:  官方客户端的 hardwareid（32 位 hex，实测可直接复用客户端生成的值）
    'devid':       'CHANGE_ME',
    'device_name': 'DESKTOP-XXXXXXX',
    'ext1':        'CHANGE_ME',

    # vpntunnel 请求头设备信息
    'clientid': 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX',   # 官方客户端用 VPNMachineGuid (GUID 格式)
    'cpuid':    '178BFBFF00A60F12',                        # CPUID 特征串，可保留此默认值
    'hostname': 'DESKTOP-XXXXXXX',

    # T 消息（0x54）本机信息：首个网络适配器 IPv4 与其 MAC（无冒号 hex）
    'ras_ip': '192.168.1.100',
    'mac':    'aabbccddeeff',
}
