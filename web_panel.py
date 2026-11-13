# -*- coding: utf-8 -*-
"""
web_panel — 内嵌 Web 控制面板（FastAPI，零构建单页 UI）。

API（全部 JSON）:
    GET  /api/status      Supervisor.snapshot()
    GET  /api/logs?n=200  最近 n 行日志（环形缓冲）
    POST /api/connect     隧道建立（仅 phase=idle）
    POST /api/disconnect  隧道拆除（仅 phase=up; 代理/面板保持运行）
    POST /api/reconnect   up→触发自动重连; idle→等同 connect
    GET  /                单页控制台（内嵌 HTML, 无静态文件依赖）

认证: 非 127.0.0.1 监听必须 Basic 认证（panel_user/panel_pass,
缺省复用 proxy_user/proxy_pass）；回环监听免认证。
"""
import base64
import hmac
import logging
from collections import deque
from threading import Lock

LOG = 'panel'

PANEL_HTML = """<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MotionPro 代理控制台</title>
<style>
:root{--bg:#0f1420;--card:#171e2e;--line:#24304a;--fg:#dbe4f5;--dim:#7f8db0;
--ok:#3fb96f;--warn:#e0a63a;--err:#e05b5b;--acc:#4f8cff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 system-ui,"Segoe UI",sans-serif}
header{display:flex;align-items:center;gap:14px;padding:14px 22px;
border-bottom:1px solid var(--line)}
h1{font-size:17px;margin:0;font-weight:600}
.badge{padding:3px 12px;border-radius:99px;font-size:12px;font-weight:600}
.b-up{background:#123526;color:var(--ok)}.b-idle{background:#232a3a;color:var(--dim)}
.b-busy{background:#3a2f12;color:var(--warn);animation:pulse 1.2s infinite}
.b-stop{background:#3a1212;color:var(--err)}@keyframes pulse{50%{opacity:.5}}
main{max-width:1060px;margin:18px auto;padding:0 16px}
.bar{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap}
button{background:var(--card);border:1px solid var(--line);color:var(--fg);
padding:9px 22px;border-radius:8px;font-size:13px;cursor:pointer}
button:hover:not(:disabled){border-color:var(--acc);color:var(--acc)}
button:disabled{opacity:.35;cursor:not-allowed}
#btn-connect:not(:disabled){border-color:var(--ok);color:var(--ok)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
gap:10px;margin-bottom:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:10px 14px;min-height:58px}
.k{font-size:11px;color:var(--dim);margin-bottom:3px}
.v{font-size:14px;font-weight:600;word-break:break-all;white-space:pre-wrap}
.v.ok{color:var(--ok)}.v.err{color:var(--err)}
h2{font-size:13px;color:var(--dim);margin:18px 0 8px;font-weight:500}
pre{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:12px;font:12px/1.55 Consolas,monospace;height:320px;overflow:auto;
white-space:pre-wrap;margin:0}
</style></head><body>
<header><h1>MotionPro 代理控制台</h1><span id=phase class="badge b-idle">-</span>
<span id=uptime style="color:var(--dim);font-size:12px"></span></header>
<main>
<div class="bar">
<button id=btn-connect onclick="act('/api/connect')">连接</button>
<button id=btn-disconnect onclick="act('/api/disconnect')">断开</button>
<button id=btn-reconnect onclick="act('/api/reconnect')">立即重连</button>
<label style="color:var(--dim);font-size:12px;align-self:center">
<input type=checkbox id=autoscroll checked> 日志自动滚动</label>
</div>
<h2>隧道状态</h2><div class=grid id=tunnel></div>
<h2>转发统计</h2><div class=grid id=stats></div>
<h2>日志</h2><pre id=log></pre>
</main>
<script>
const $=id=>document.getElementById(id);
const esc=s=>{const d=document.createElement('div');d.textContent=s==null?'':s;return d.innerHTML};
function card(k,v,cls){return `<div class=card><div class=k>${k}</div>
<div class="v ${cls||''}">${v}</div></div>`}
async function j(u,o){const r=await fetch(u,o);
if(r.status===401){document.body.innerHTML='<p style="padding:40px">401 请刷新登录</p>';throw 0}
return r.json()}
async function act(p){await j(p,{method:'POST'});refresh()}
function render(s){
const B={up:['up','运行中'],idle:['idle','未连接'],connecting:['busy','连接中'],
reconnecting:['busy','重连中'],stopping:['stop','停止中']};
const [cls,txt]=B[s.phase]||['idle',s.phase];
$('phase').className='badge b-'+cls;$('phase').textContent=txt;
$('btn-connect').disabled=s.phase!=='idle';
$('btn-disconnect').disabled=s.phase!=='up';
$('btn-reconnect').disabled=!['up','idle'].includes(s.phase);
$('uptime').textContent=s.uptime_sec?('已连接 '+Math.floor(s.uptime_sec/60)+'分'+(s.uptime_sec%60)+'秒'):'';
let t=card('虚拟 IP (VIP)',esc(s.vip)||'-',s.vip?'ok':'')+
card('掩码',esc(s.mask)||'-')+card('DNS 服务器',esc((s.dns||[]).join('  '))||'-')+
card('keepalive',s.keepalive_interval?s.keepalive_interval+'s':'-')+
card('mptoken',esc(s.mptoken)||'-')+
card('代理监听',esc((s.proxy_endpoints||[]).join('\\n'))||'-')+
card('模式',esc(s.deploy_mode)+' / '+esc(s.route_mode))+
card('面板地址',esc(s.panel)||'-');
if(s.last_error)t+=card('最近错误',esc(s.last_error),'err');
$('tunnel').innerHTML=t;
const f=s.forwarder;
let st=f?card('上行包数',f.tx_pkts)+card('下行包数',f.rx_pkts)+
card('keepalive 收/发',f.ka_echo+' / '+f.ka_sent)+
card('控制帧',f.rx_ctrl)+card('已过滤',f.dropped)
:card('转发','未运行');
$('stats').innerHTML=st;
}
async function refresh(){
try{const s=await j('/api/status');render(s);
const l=await j('/api/logs?n=400');const el=$('log');
const stick=el.scrollTop+el.clientHeight>=el.scrollHeight-30||$('autoscroll').checked;
el.textContent=(l.lines||[]).join('\\n')||'(暂无日志)';
if(stick)el.scrollTop=el.scrollHeight;
}catch(e){}}
setInterval(refresh,2000);refresh();
</script></body></html>
"""


class LogRing(logging.Handler):
    """线程安全日志环形缓冲（面板 /api/logs 数据源）。"""

    def __init__(self, maxlen: int = 800):
        super().__init__(level=logging.INFO)
        self._buf: deque = deque(maxlen=maxlen)
        self._lock = Lock()
        self.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s %(name)s: %(message)s'))

    def emit(self, record):
        try:
            line = self.format(record)
        except Exception:
            return
        with self._lock:
            self._buf.append(line)

    def tail(self, n: int) -> list:
        with self._lock:
            return list(self._buf)[-n:]


def attach_ring(maxlen: int = 800) -> LogRing:
    """把环形缓冲挂到 root logger（幂等）。"""
    root = logging.getLogger()
    for h in root.handlers:
        if isinstance(h, LogRing):
            return h
    ring = LogRing(maxlen)
    root.addHandler(ring)
    return ring


def panel_auth(cfg: dict, host: str) -> tuple:
    """非回环监听强制认证；回环免认证。优先 panel_user/panel_pass。"""
    if host in ('127.0.0.1', '::1', 'localhost'):
        return ('', '')
    user = str(cfg.get('panel_user') or cfg.get('proxy_user') or '')
    pwd = str(cfg.get('panel_pass') or cfg.get('proxy_pass') or '')
    if not (user and pwd):
        raise SystemExit(
            '面板绑定非回环 %s 需认证: 配置 panel_user/panel_pass '
            '(或 proxy_user/proxy_pass)' % host)
    return (user, pwd)


def create_app(sup, auth: tuple = ('', '')):
    """app 工厂；返回 (FastAPI, LogRing)。"""
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse, JSONResponse, Response

    ring = attach_ring()
    app = FastAPI(title='MotionPro Proxy Panel',
                  docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware('http')
    async def _auth(request: Request, call_next):
        if auth[0]:
            want = 'Basic ' + base64.b64encode(
                ('%s:%s' % auth).encode()).decode()
            got = request.headers.get('authorization', '')
            if not hmac.compare_digest(got, want):
                return Response(status_code=401, headers={
                    'WWW-Authenticate': 'Basic realm="motionpro-panel"'})
        return await call_next(request)

    @app.get('/api/status')
    async def api_status():
        return sup.snapshot()

    @app.get('/api/logs')
    async def api_logs(n: int = 200):
        return {'lines': ring.tail(max(1, min(n, 800)))}

    @app.post('/api/connect')
    async def api_connect():
        if sup.phase != 'idle':
            return JSONResponse({'ok': False,
                                 'error': 'phase=%s, 无法连接' % sup.phase},
                                status_code=409)
        await sup.bg_connect()
        return {'ok': True, 'phase': 'connecting'}

    @app.post('/api/disconnect')
    async def api_disconnect():
        if sup.phase != 'up':
            return JSONResponse({'ok': False,
                                 'error': 'phase=%s, 无已建立的隧道' % sup.phase},
                                status_code=409)
        sup.phase = 'stopping'
        await sup.tunnel_down()
        sup.phase = 'idle'
        return {'ok': True, 'phase': 'idle'}

    @app.post('/api/reconnect')
    async def api_reconnect():
        if sup.phase == 'up':
            sup._reconnect_evt.set()
            return {'ok': True, 'phase': 'reconnecting'}
        if sup.phase == 'idle':
            await sup.bg_connect()
            return {'ok': True, 'phase': 'connecting'}
        return JSONResponse({'ok': False, 'error': 'phase=%s' % sup.phase},
                            status_code=409)

    @app.get('/', response_class=HTMLResponse)
    async def index():
        return PANEL_HTML

    return app, ring
