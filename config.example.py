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
}
