# -*- coding: utf-8 -*-
"""Web 管理界面 + REST API。

单页设计：所有信息都在首页，没有多余页面。
  GET  /                    管理面板（添加域名 + 状态 + 节点明细）
  GET  /status              JSON 状态（浏览器访问给页面）
  GET  /api/domains         域名列表
  POST /api/domains         新增域名
  DEL  /api/domains/<id>    删除域名
  PATCH /api/domains/<id>   修改配置
  POST /api/domains/<id>/scan  立即扫描
  GET  /api/health          健康检查
"""
import html
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import __version__

TEMPLATE_DIR = os.path.dirname(os.path.abspath(__file__))


def _norm_colos(value):
    """把各种写法的机房列表规范化，顺便挡住非法字符。

    机房代码固定是 3 个字母（HKG/NRT/SIN...），只允许这一种形态，
    既避免脏数据进配置，也避免被拼进 HTML / JS 当注入载荷。
    """
    if isinstance(value, str):
        items = value.replace("，", ",").split(",")
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        raise ApiError("机房格式错误")
    out = []
    for item in items:
        c = str(item).strip().upper()
        if not c:
            continue
        if not re.fullmatch(r"[A-Z]{3}", c):
            raise ApiError(f"机房代码不合法：{c}（应为 3 个字母，如 HKG）")
        if c not in out:
            out.append(c)
    if not out:
        raise ApiError("机房不能为空")
    return out


def _fmt_age(ts):
    if not ts:
        return "从未"
    delta = int(time.time() - ts)
    if delta < 60:
        return f"{delta} 秒前"
    if delta < 3600:
        return f"{delta // 60} 分钟前"
    if delta < 86400:
        return f"{delta // 3600} 小时前"
    return f"{delta // 86400} 天前"


class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


_local_ip_cache = None


def _local_ip():
    """本机对局域网可见的 IP，用来拼 cloudflared 的解析器地址。

    不会真的发包：UDP connect 只是让内核选出默认路由的源地址。
    拿不到就返回空，界面提示用户手动填 NAS IP。
    """
    global _local_ip_cache
    if _local_ip_cache:
        return _local_ip_cache
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("223.5.5.5", 53))
        _local_ip_cache = s.getsockname()[0]
    except Exception:
        _local_ip_cache = ""
    finally:
        s.close()
    return _local_ip_cache


class Handler(BaseHTTPRequestHandler):
    store = None
    scanner = None
    cfg = None
    tunnel_dns = None
    server_version = "cfopt/" + __version__

    def log_message(self, fmt, *args):
        pass

    # ------------------------------------------------------------ 分发
    def do_GET(self):
        path = urlparse(self.path).path
        try:
            if path in ("/", "/index.html"):
                self._page_overview()
            elif path == "/status":
                self._page_status()
            elif path in ("/api/health", "/health"):
                # 两个路径都支持：/api/health 是正式接口，
                # /health 给 docker healthcheck 和监控脚本用
                self._json({"ok": True, "version": __version__})
            elif path == "/api/domains":
                self._json({"domains": [d.snapshot() for d in self.store.list()]})
            elif path == "/api/tunnel":
                self._json(self._tunnel_json())
            elif path.startswith("/api/domains/"):
                self._api_get_domain(path)
            else:
                self._error_page(404, "页面不存在")
        except ApiError as e:
            self._json({"error": e.message}, e.status)
        except Exception as e:
            self._json({"error": f"服务端异常: {e}"}, 500)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/api/domains":
                self._api_add_domain()
            elif path == "/api/tunnel/scan":
                self._api_tunnel_scan()
            elif path.endswith("/scan") and path.startswith("/api/domains/"):
                self._api_scan(path, parsed.query)
            else:
                raise ApiError("未知接口", 404)
        except ApiError as e:
            self._json({"error": e.message}, e.status)
        except Exception as e:
            self._json({"error": f"服务端异常: {e}"}, 500)

    def do_PATCH(self):
        path = urlparse(self.path).path
        try:
            if path == "/api/tunnel":
                self._api_tunnel_patch()
            elif path.startswith("/api/domains/"):
                self._api_patch_domain(path)
            else:
                raise ApiError("未知接口", 404)
        except ApiError as e:
            self._json({"error": e.message}, e.status)
        except Exception as e:
            self._json({"error": f"服务端异常: {e}"}, 500)

    def do_DELETE(self):
        path = urlparse(self.path).path
        try:
            if path.startswith("/api/domains/"):
                self._api_delete_domain(path)
            else:
                raise ApiError("未知接口", 404)
        except ApiError as e:
            self._json({"error": e.message}, e.status)
        except Exception as e:
            self._json({"error": f"服务端异常: {e}"}, 500)

    # ------------------------------------------------------------ API
    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ApiError("Content-Length 非法")
        if length <= 0:
            return {}
        if length > 64 * 1024:
            raise ApiError("请求体过大", 413)
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            raise ApiError("JSON 格式错误")

    @staticmethod
    def _domain_id(path):
        parts = [p for p in path.split("/") if p]
        if len(parts) >= 3 and parts[0] == "api" and parts[1] == "domains":
            return parts[2]
        raise ApiError("缺少域名 ID", 404)

    def _api_get_domain(self, path):
        d = self.store.get(self._domain_id(path))
        if not d:
            raise ApiError("域名不存在", 404)
        self._json(d.snapshot())

    def _api_add_domain(self):
        body = self._read_json()
        host = (body.get("host") or "").strip()
        colos = _norm_colos(body.get("colos") or ["HKG"])
        try:
            top_n = int(body.get("top_n") or 2)
            per_net = int(body.get("per_net") or 2)
            interval = int(body.get("interval") or 21600)
            raw_max = body.get("max_ms", 200)
            max_ms = int(200 if raw_max is None else raw_max)
        except (TypeError, ValueError):
            raise ApiError("数字参数格式错误")
        if not 1 <= top_n <= 10:
            raise ApiError("top_n 应在 1-10 之间")
        if not 1 <= per_net <= 10:
            raise ApiError("per_net 应在 1-10 之间")
        if interval < 600:
            raise ApiError("扫描周期不能小于 600 秒（避免被判定为扫描）")
        if max_ms != 0 and not 50 <= max_ms <= 3000:
            raise ApiError("延迟上限应在 50-3000ms 之间，或 0 表示不限")

        # 先做格式校验，省掉一次无意义的 DNS 查询
        from .store import _valid_host
        if not host:
            raise ApiError("域名不能为空")
        if "*" in host:
            raise ApiError("不支持通配符域名，请填写具体主机名，"
                           "如 wxp6.de5.net")
        if not _valid_host(host):
            raise ApiError(f"域名格式不合法：{host}")

        # 确认域名真的接入了 Cloudflare，避免白扫 13 分钟
        from .probe import check_domain_on_cloudflare
        cf_ok, detail = check_domain_on_cloudflare(host)
        if cf_ok is False:
            raise ApiError(
                f"{host} 似乎没有接入 Cloudflare：它解析到 "
                f"{', '.join(detail[:3])}，不属于 Cloudflare 网段。"
                f"请确认域名已托管到 Cloudflare，且 DNS 记录开启了小黄云（已代理）。")

        try:
            d = self.store.add(host, colos=colos, top_n=top_n,
                               per_net=per_net, interval=interval,
                               max_ms=max_ms)
        except ValueError as e:
            raise ApiError(str(e))

        self.scanner.trigger(d)
        resp = {"ok": True, "domain": d.snapshot()}
        if cf_ok is None:
            # 解析不了不阻止，但告知用户
            resp["warning"] = f"未能确认 Cloudflare 归属：{detail}"
        self._json(resp, 201)

    def _api_delete_domain(self, path):
        did = self._domain_id(path)
        if not self.store.remove(did):
            raise ApiError("域名不存在", 404)
        self._json({"ok": True})

    def _api_patch_domain(self, path):
        did = self._domain_id(path)
        d = self.store.get(did)
        if not d:
            raise ApiError("域名不存在", 404)
        body = self._read_json()
        fields = {}
        if "colos" in body:
            fields["colos"] = _norm_colos(body["colos"])
        for key, lo, hi in (("top_n", 1, 10), ("per_net", 1, 10),
                            ("interval", 600, 604800)):
            if key in body and body[key] is not None:
                try:
                    v = int(body[key])
                except (TypeError, ValueError):
                    raise ApiError(f"{key} 必须是数字")
                if not lo <= v <= hi:
                    raise ApiError(f"{key} 应在 {lo}-{hi} 之间")
                fields[key] = v
        if "enabled" in body:
            fields["enabled"] = bool(body["enabled"])
        if "max_ms" in body and body["max_ms"] is not None:
            try:
                v = int(body["max_ms"])
            except (TypeError, ValueError):
                raise ApiError("max_ms 必须是数字")
            if v != 0 and not 50 <= v <= 3000:
                raise ApiError("延迟上限应在 50-3000ms 之间，或 0 表示不限")
            fields["max_ms"] = v

        d = self.store.update(did, **fields)
        if "max_ms" in fields:
            # 先把当前下发的超限节点立即剔掉，再后台按新上限重扫
            d.trim_by_latency()
        # 换了机房或延迟上限就立刻按新条件重扫，不用等下一个周期
        if ("colos" in fields or "max_ms" in fields
                or (fields.get("enabled") is True and not d.last_scan_ok)):
            self.scanner.trigger(d)
        self._json({"ok": True, "domain": d.snapshot()})

    def _api_scan(self, path, query=""):
        did = self._domain_id(path)
        d = self.store.get(did)
        if not d:
            raise ApiError("域名不存在", 404)
        if self.scanner.is_running(d.id):
            self._json({"ok": True, "msg": "扫描已在进行中"})
            return
        full = "full=1" in query
        if full:
            # 清掉网段缓存，强制扫描全部 Cloudflare 段。
            # 快速扫描只抽样缓存网段，可能漏掉目标机房更快的节点。
            d.nets = []
            d.nets_colos = []
            self.store.save()
        self.scanner.trigger(d)
        self._json({"ok": True,
                    "msg": "已触发全量扫描" if full else "已触发扫描"})

    # ------------------------------------------------------------ 响应
    # ------------------------------------------------------------ Tunnel 加速
    def _tunnel_json(self):
        t = self.store.tunnel
        snap = t.snapshot()
        snap["dns_port"] = getattr(self.cfg, "tunnel_dns_port", 0)
        snap["dns_ready"] = bool(self.tunnel_dns and self.tunnel_dns.ok)
        snap["local_ip"] = _local_ip()
        snap["running"] = self.scanner.is_running(self.scanner.TUNNEL_KEY)
        snap["pins"] = {k: list(v) for k, v in t.pins().items()}
        return {"ok": True, "tunnel": snap}

    def _api_tunnel_patch(self):
        t = self.store.tunnel
        body = self._read_json()
        fields = {}
        if "enabled" in body:
            fields["enabled"] = bool(body["enabled"])
        for key, lo, hi in (("top_n", 1, 5), ("interval", 600, 604800)):
            if key in body and body[key] is not None:
                try:
                    v = int(body[key])
                except (TypeError, ValueError):
                    raise ApiError(f"{key} 必须是数字")
                if not lo <= v <= hi:
                    raise ApiError(f"{key} 应在 {lo}-{hi} 之间")
                fields[key] = v
        t.update(**fields)
        self.store.save()
        # 刚开启又还没有结果时立刻扫一次，不用让用户等下一个周期
        if (fields.get("enabled") and not t.edges
                and not self.scanner.is_running(self.scanner.TUNNEL_KEY)):
            self.scanner.trigger_tunnel()
        self._json({"ok": True, "tunnel": t.snapshot()})

    def _api_tunnel_scan(self):
        if self.scanner.is_running(self.scanner.TUNNEL_KEY):
            self._json({"ok": True, "msg": "扫描已在进行中"})
            return
        self.scanner.trigger_tunnel()
        self._json({"ok": True, "msg": "已开始扫描隧道边缘"})

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html, status=200):
        body = html.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error_page(self, status, msg):
        self._send_html(
            f"<!doctype html><meta charset=utf-8><title>{status}</title>"
            "<style>body{font:14px/1.7 system-ui;max-width:600px;margin:80px auto;"
            "padding:0 20px;color:#333}a{color:#0a58ca}</style>"
            f"<h2>{status}</h2><p>{msg}</p><p><a href='/'>返回首页</a></p>",
            status)

    # ------------------------------------------------------------ 主页面
    def _page_overview(self):
        domains = [d.snapshot() for d in self.store.list()]
        cards = "".join(self._domain_card(d) for d in domains)
        if not cards:
            cards = ('<div class="empty">'
                     '<div class="empty-icon">◎</div>'
                     '<p>还没有添加域名</p>'
                     '<p class="hint">在上方输入一个接入 Cloudflare 的域名，'
                     '比如 <code>ai2.kdns.fr</code></p></div>')

        total = len(domains)
        ok_count = sum(1 for d in domains if d["last_scan_ok"])
        pending = sum(1 for d in domains if not d["last_scan_at"])
        # 有任何一个域名正在扫描（有进度）或还没出结果，就开启自动刷新
        scanning_now = any(
            d.get("progress") or not d["last_scan_at"] for d in domains)
        # 页面渲染时的排队/扫描状态，供前端检测“排队 → 扫描中”的切换
        ui_state = "|".join(
            d["id"] + (":scan" if d.get("progress")
                       else (":done" if d["last_scan_at"] else ":queued"))
            for d in domains)
        # 隧道扫描同样要自动刷新：它只有 20 秒左右，但用户盯着看
        tt = self.store.tunnel
        tunnel_scanning = bool(tt.progress)
        tunnel_state = (("on" if tt.enabled else "off") + ":"
                        + ("scan" if tt.progress else "idle") + ":"
                        + str(len(tt.edges)))

        html = f"""<!doctype html><html lang=zh><head><meta charset=utf-8>
<title>Cloudflare 优选管理</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
*{{box-sizing:border-box}}
body{{font:14px/1.65 -apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",
sans-serif;max-width:960px;margin:0 auto;padding:26px 20px 80px;color:#1a1a1a;
background:#f6f7f9}}
h1{{font-size:21px;font-weight:660;margin:0 0 3px;letter-spacing:-.01em}}
.sub{{color:#6b7480;font-size:13px;margin:0 0 22px}}
.top{{display:flex;justify-content:space-between;align-items:flex-start;
gap:16px;flex-wrap:wrap;margin-bottom:22px}}
.summary{{display:flex;gap:8px;flex-wrap:wrap}}
.pill{{font-size:12.5px;padding:5px 12px;border-radius:20px;background:#fff;
border:1px solid #e2e5e9;color:#5a6472}}
.pill b{{color:#111}}
.pill.good{{background:#eaf7ec;border-color:#c9e8cf;color:#1a7f37}}
.pill.warn{{background:#fff6e8;border-color:#f2ddb8;color:#a15c07}}
.addbox{{background:#fff;border:1px solid #e2e5e9;border-radius:11px;
padding:18px 20px;margin-bottom:20px}}
.addbox h3{{font-size:13.5px;margin:0 0 13px;font-weight:620;color:#374151}}
.row{{display:flex;gap:9px;flex-wrap:wrap;align-items:flex-end}}
.hint{{font-size:11.5px;color:#8b929c;margin-top:9px;line-height:1.6}}
.field{{display:flex;flex-direction:column;gap:5px}}
.field label{{font-size:11.5px;color:#6b7480}}
input,select{{font:13.5px inherit;padding:8px 11px;border:1px solid #d3d8de;
border-radius:7px;background:#fff;color:#111;outline:none}}
input:focus,select:focus{{border-color:#0a58ca;box-shadow:0 0 0 3px rgba(10,88,202,.1)}}
input#host{{min-width:230px}}
button{{font:13.5px inherit;padding:9px 18px;border:none;border-radius:7px;
background:#0a58ca;color:#fff;cursor:pointer;font-weight:550}}
button:hover{{background:#0950b8}}
button:disabled{{background:#b9c0c8;cursor:not-allowed}}
button.ghost{{background:#eceef1;color:#374151}}
button.ghost:hover{{background:#e0e3e8}}
button.danger{{background:#fbe9e9;color:#b42318}}
button.danger:hover{{background:#f7d9d9}}
button.sm{{padding:5px 11px;font-size:12.5px}}
#msg{{display:none;padding:10px 14px;border-radius:7px;margin-bottom:14px;
font-size:13px}}
#msg.ok{{display:block;background:#e6f4e6;color:#1a7f37}}
#msg.bad{{display:block;background:#fbe9e9;color:#b42318}}
.card{{background:#fff;border:1px solid #e2e5e9;border-radius:11px;
padding:18px 20px;margin-bottom:14px}}
.card.off{{opacity:.62}}
.card.scanning{{border-color:#9dc0f0;box-shadow:0 0 0 3px rgba(10,88,202,.07)}}
.chead{{display:flex;justify-content:space-between;align-items:flex-start;
gap:14px;flex-wrap:wrap}}
.host{{font-size:16px;font-weight:650;letter-spacing:-.01em;
font-family:ui-monospace,"SF Mono",Consolas,monospace;display:flex;
align-items:center;gap:9px;flex-wrap:wrap}}
.badge{{font-size:11.5px;font-weight:600;padding:3px 9px;border-radius:20px;
display:inline-flex;align-items:center;gap:5px}}
.badge.ok{{background:#eaf7ec;color:#1a7f37}}
.badge.warn{{background:#fff6e8;color:#a15c07}}
.badge.bad{{background:#fbe9e9;color:#b42318}}
.badge.run{{background:#e8f0fd;color:#0a58ca}}
.badge.idle{{background:#eceef1;color:#4b5563}}
pre.cfg{{background:#1b1f24;color:#d6dde4;padding:12px 14px;border-radius:8px;
overflow-x:auto;font-size:12px;line-height:1.55;margin:0 0 8px;
font-family:ui-monospace,"SF Mono",Consolas,monospace}}
.dot{{width:7px;height:7px;border-radius:50%;background:currentColor;
display:inline-block}}
.badge.run .dot{{animation:pulse 1s ease-in-out infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.25}}}}
.meta{{font-size:12px;color:#7a828e;margin-top:5px;line-height:1.7}}
.acts{{display:flex;gap:6px;flex-wrap:wrap}}

.sect{{margin-top:16px;border-top:1px solid #eef0f3;padding-top:13px}}
.sect-t{{font-size:11.5px;color:#8b929c;letter-spacing:.05em;
text-transform:uppercase;font-weight:600;margin-bottom:9px;
display:flex;align-items:center;gap:8px}}
.sect-t span{{text-transform:none;letter-spacing:0;font-weight:400;
color:#a3aab3}}
.now{{display:flex;gap:8px;flex-wrap:wrap}}
.now .ipwrap{{background:#eef7ef;border:1px solid #cfe8cf;border-radius:8px;
padding:8px 12px;display:flex;flex-direction:column;gap:2px;min-width:150px}}
.now .ipwrap .ip{{font-family:ui-monospace,Consolas,monospace;font-size:13.5px;
font-weight:600;color:#14682c}}
.now .ipwrap .lat{{font-size:11.5px;color:#4a7a55}}
.now .none{{background:#fdf3e7;border:1px solid #f5dfc0;border-radius:8px;
padding:9px 13px;color:#b54708;font-size:13px}}

table.nodes{{width:100%;border-collapse:collapse;font-size:12.5px;
margin-top:2px}}
table.nodes th{{text-align:left;font-weight:600;color:#8b929c;font-size:11px;
letter-spacing:.04em;text-transform:uppercase;padding:5px 8px;
border-bottom:1px solid #eef0f3}}
table.nodes td{{padding:6px 8px;border-bottom:1px solid #f4f5f7;
font-family:ui-monospace,Consolas,monospace;color:#374151}}
table.nodes tr:last-child td{{border-bottom:none}}
table.nodes tr.pick td{{background:#f6fbf7}}
table.nodes tr.pick td:first-child{{border-left:2px solid #3fb950;
padding-left:6px}}
table.nodes .colo{{font-family:inherit;color:#5a6472}}
table.nodes .colo.hit{{color:#1a7f37;font-weight:600}}
.bar{{height:5px;background:#eef0f3;border-radius:3px;overflow:hidden;
min-width:50px}}
.bar i{{display:block;height:100%;background:#8fb8f5;border-radius:3px}}
.tag{{font-size:10.5px;padding:2px 7px;border-radius:20px;background:#eaf7ec;
color:#1a7f37;font-weight:600;font-family:inherit}}
.chips{{display:flex;gap:5px;flex-wrap:wrap;margin-top:8px}}
.chip{{font-size:11.5px;background:#eceef1;color:#4b5563;padding:2px 9px;
border-radius:20px;font-family:ui-monospace,Consolas,monospace}}
.chip .cms{{font-weight:400;opacity:.7}}
.chip.hit{{background:#e6f4e6;color:#1a7f37;font-weight:600}}
.err{{font-size:12.5px;color:#b42318;background:#fbe9e9;padding:9px 12px;
border-radius:7px;margin-top:11px}}
.warnbox{{display:flex;align-items:center;justify-content:space-between;
gap:12px;flex-wrap:wrap;background:#fff6e8;border:1px solid #f2ddb8;
color:#a15c07;font-size:12.5px;padding:9px 12px;border-radius:7px;
margin-top:11px}}
.editrow{{display:flex;gap:9px;flex-wrap:wrap;align-items:flex-end;
background:#f8fafc;border:1px dashed #d6dbe2;border-radius:8px;
padding:12px 14px;margin-top:12px}}
.editrow input{{min-width:180px}}
.empty{{background:#fff;border:1px dashed #d3d8de;border-radius:11px;
padding:50px 20px;text-align:center;color:#6b7480}}
.empty-icon{{font-size:30px;color:#c8ccd2;margin-bottom:10px}}
.empty p{{margin:4px 0}}
.hint{{font-size:12.5px;color:#8b929c}}
code{{background:#eceef1;padding:2px 6px;border-radius:4px;font-size:12.5px;
font-family:ui-monospace,Consolas,monospace}}
.spin{{display:inline-block;width:12px;height:12px;border:2px solid #c9d8f0;
border-top-color:#0a58ca;border-radius:50%;animation:sp .7s linear infinite;
vertical-align:-2px}}
@keyframes sp{{to{{transform:rotate(360deg)}}}}
.progwrap{{flex:1;min-width:240px;background:#f4f7fc;border:1px solid #d6e4f7;
border-radius:8px;padding:10px 14px}}
.progtop{{font-size:12.5px;color:#3a5a8c;display:flex;align-items:center;
gap:7px;margin-bottom:8px}}
.progbar{{height:6px;background:#dfe9f7;border-radius:3px;overflow:hidden}}
.progbar i{{display:block;height:100%;background:#0a58ca;border-radius:3px;
transition:width .4s ease}}
@media(max-width:640px){{
  .row{{flex-direction:column;align-items:stretch}}
  input#host{{min-width:0}}
  .chead{{flex-direction:column}}
  .top{{flex-direction:column}}
}}
</style></head><body>

<div class="top">
  <div>
    <h1>Cloudflare 优选管理</h1>
    <p class="sub">添加域名后自动优选并下发最优节点</p>
  </div>
  <div class="summary">
    <span class="pill">v{__version__}</span>
    <span class="pill">域名 <b>{total}</b></span>
    <span class="pill {'good' if ok_count == total and total else ''}">
      已接入 <b>{ok_count}</b></span>
    {f'<span class="pill warn">扫描中 <b>{pending}</b></span>' if pending else ''}
  </div>
</div>

<div class="addbox">
  <h3>添加域名</h3>
  <div id="msg"></div>
  <div class="row">
    <div class="field">
      <label>域名（须已接入 Cloudflare）</label>
      <input id="host" placeholder="ai2.kdns.fr" autocomplete="off" spellcheck="false">
    </div>
    <div class="field">
      <label>偏好机房（更快的其他机房自动采用）</label>
      <select id="colos">
        <option value="HKG">HKG 香港</option>
        <option value="NRT">NRT 东京</option>
        <option value="SIN">SIN 新加坡</option>
        <option value="HKG,NRT">HKG + NRT</option>
        <option value="HKG,SIN,NRT">HKG + SIN + NRT</option>
        <option value="SIN,NRT">SIN + NRT</option>
        <option value="LAX">LAX 洛杉矶</option>
        <option value="LAX,SJC">LAX + SJC</option>
        <option value="SJC">SJC 圣何塞</option>
        <option value="SEA">SEA 西雅图</option>
        <option value="AMS">AMS 阿姆斯特丹</option>
      </select>
    </div>
    <div class="field">
      <label>下发节点数</label>
      <select id="topn">
        <option value="2">2 个</option>
        <option value="3">3 个</option>
        <option value="1">1 个</option>
      </select>
    </div>
    <div class="field">
      <label>延迟上限</label>
      <select id="maxms">
        <option value="200">≤200 ms</option>
        <option value="100">≤100 ms</option>
        <option value="150">≤150 ms</option>
        <option value="250">≤250 ms</option>
        <option value="300">≤300 ms</option>
        <option value="0">不限</option>
      </select>
    </div>
    <div class="field">
      <label>扫描周期</label>
      <select id="interval">
        <option value="21600">6 小时</option>
        <option value="3600">1 小时</option>
        <option value="43200">12 小时</option>
      </select>
    </div>
    <button id="addbtn" onclick="addDomain()">添加并扫描</button>
  </div>
  <div class="hint">每次扫描会自动合并
    <a href="https://ip.v2too.top/" target="_blank" rel="noopener">ip.v2too.top</a>
    的三网优选 IP（约 30 个）一起测速。站点的延迟标签不参与判断，
    最终仍按本机实测择优。机房只是偏好：其他机房快 20ms 以上时会自动采用，
    避免出口线路把 HKG 绕远后仍被迫使用高延迟节点。</div>
</div>

<div id="tunnel">{self._tunnel_card()}</div>

<div id="list">{cards}</div>

<script>
function showMsg(text, ok) {{
  var m = document.getElementById("msg");
  m.textContent = text;
  m.className = ok ? "ok" : "bad";
  if (ok) setTimeout(function () {{ m.className = ""; }}, 4000);
}}

function addDomain() {{
  var host = document.getElementById("host").value.trim();
  if (!host) {{ showMsg("请填写域名", false); return; }}
  var btn = document.getElementById("addbtn");
  btn.disabled = true; btn.textContent = "添加中...";
  fetch("/api/domains", {{
    method: "POST",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{
      host: host,
      colos: document.getElementById("colos").value.split(","),
      top_n: parseInt(document.getElementById("topn").value, 10),
      interval: parseInt(document.getElementById("interval").value, 10),
      max_ms: parseInt(document.getElementById("maxms").value, 10)
    }})
  }}).then(function (r) {{
    return r.json().then(function (j) {{ return {{s: r.status, j: j}}; }});
  }}).then(function (res) {{
    if (res.s >= 400) {{ showMsg(res.j.error || "添加失败", false); }}
    else {{
      var w = res.j.warning ? "（" + res.j.warning + "）" : "";
      showMsg("已添加 " + host + "，正在后台扫描..." + w, true);
      setTimeout(function(){{location.reload();}}, 900);
    }}
  }}).catch(function (e) {{ showMsg("请求失败: " + e, false); }})
    .finally(function () {{ btn.disabled = false; btn.textContent = "添加并扫描"; }});
}}

function rescan(id, full) {{
  if (full && !confirm("全量扫描会检查全部 Cloudflare 网段，通常需要几分钟。确定开始？")) return;
  fetch("/api/domains/" + id + "/scan" + (full ? "?full=1" : ""), {{method: "POST"}})
    .then(function (r) {{ return r.json(); }})
    .then(function (j) {{
      if (j.error) alert(j.error); else location.reload();
    }})
    .catch(function (e) {{ alert("请求失败: " + e); }});
}}

function del(id, host) {{
  if (!confirm("确定删除 " + host + " ？")) return;
  fetch("/api/domains/" + id, {{method: "DELETE"}})
    .then(function (r) {{ return r.json(); }})
    .then(function (j) {{ if (j.ok) location.reload(); else alert(j.error || "删除失败"); }});
}}

function toggle(id, enabled) {{
  fetch("/api/domains/" + id, {{
    method: "PATCH",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{enabled: enabled}})
  }}).then(function () {{ location.reload(); }});
}}

function toggleEdit(id) {{
  var el = document.getElementById("edit-" + id);
  el.style.display = el.style.display === "none" ? "flex" : "none";
}}

function saveEdit(id) {{
  var colos = document.getElementById("ecolos-" + id).value
    .split(/[,，]/).map(function (s) {{ return s.trim(); }})
    .filter(function (s) {{ return s; }});
  fetch("/api/domains/" + id, {{
    method: "PATCH",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{
      colos: colos,
      top_n: parseInt(document.getElementById("etop-" + id).value, 10),
      interval: parseInt(document.getElementById("eint-" + id).value, 10),
      max_ms: parseInt(document.getElementById("emax-" + id).value, 10)
    }})
  }}).then(function (r) {{
    return r.json().then(function (j) {{ return {{s: r.status, j: j}}; }});
  }}).then(function (res) {{
    if (res.s >= 400) {{ alert(res.j.error || "保存失败"); return; }}
    location.reload();
  }}).catch(function (e) {{ alert("请求失败: " + e); }});
}}

function setColos(id, colos) {{
  fetch("/api/domains/" + id, {{
    method: "PATCH",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{colos: colos.split(",")}})
  }}).then(function (r) {{ return r.json(); }})
    .then(function (j) {{
      if (j.error) alert(j.error); else location.reload();
    }});
}}

document.getElementById("host").addEventListener("keydown", function (e) {{
  if (e.key === "Enter") addDomain();
}});

function saveTunnel() {{
  fetch("/api/tunnel", {{
    method: "PATCH",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{
      top_n: parseInt(document.getElementById("ttop").value, 10),
      interval: parseInt(document.getElementById("tiv").value, 10)
    }})
  }}).then(function (r) {{
    return r.json().then(function (j) {{ return {{s: r.status, j: j}}; }});
  }}).then(function (res) {{
    if (res.s >= 400) alert(res.j.error || "保存失败"); else location.reload();
  }}).catch(function (e) {{ alert("请求失败: " + e); }});
}}

function toggleTunnel(on) {{
  fetch("/api/tunnel", {{
    method: "PATCH",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{enabled: on}})
  }}).then(function (r) {{
    return r.json().then(function (j) {{ return {{s: r.status, j: j}}; }});
  }}).then(function (res) {{
    if (res.s >= 400) alert(res.j.error || "操作失败"); else location.reload();
  }});
}}

function tunnelScan() {{
  fetch("/api/tunnel/scan", {{method: "POST"}})
    .then(function (r) {{ return r.json(); }})
    .then(function () {{ location.reload(); }})
    .catch(function (e) {{ alert("请求失败: " + e); }});
}}

function copyText(id) {{
  var el = document.getElementById(id);
  if (!el) return;
  var ta = document.createElement("textarea");
  ta.value = el.textContent;
  document.body.appendChild(ta);
  ta.select();
  try {{ document.execCommand("copy"); }} catch (e) {{}}
  document.body.removeChild(ta);
}}

// 隧道边缘扫描约 20 秒，扫完自动刷新一次，把结果和「已生效」显示出来
(function () {{
  if ({"true" if tunnel_scanning else "false"} !== true) return;
  var last = {json.dumps(tunnel_state)};
  function stateOf(j) {{
    var t = j.tunnel;
    return (t.enabled ? "on" : "off") + ":" + (t.progress ? "scan" : "idle")
      + ":" + t.edges.length;
  }}
  function tick() {{
    fetch("/api/tunnel").then(function (r) {{ return r.json(); }})
      .then(function (j) {{
        if (stateOf(j) !== last) location.reload();
        else setTimeout(tick, 2000);
      }})
      .catch(function () {{ setTimeout(tick, 5000); }});
  }}
  setTimeout(tick, 2000);
}})();

// 扫描中自动刷新，让用户看到进度条和节点出现。
// 用 fetch 局部刷新而不是整页 reload，避免闪烁和滚动位置丢失。
(function () {{
  var scanning = {"true" if scanning_now else "false"};
  if (!scanning) return;
  var lastState = {json.dumps(ui_state)};

  function stateOf(j) {{
    var parts = [];
    for (var i = 0; i < j.domains.length; i++) {{
      var d = j.domains[i];
      parts.push(d.id + (d.progress ? ":scan"
                        : (d.last_scan_at ? ":done" : ":queued")));
    }}
    return parts.join("|");
  }}

  function tick() {{
    fetch("/api/domains").then(function (r) {{ return r.json(); }})
      .then(function (j) {{
        var still = false;
        for (var i = 0; i < j.domains.length; i++) {{
          if (j.domains[i].progress) {{ still = true; break; }}
          if (!j.domains[i].last_scan_at) {{ still = true; break; }}
        }}
        // 状态从“排队”变成“扫描中”时整页刷新，进度才不会一直停住
        var state = stateOf(j);
        if (!still || state !== lastState) {{ location.reload(); return; }}
        setTimeout(tick, 2000);
      }})
      .catch(function () {{ setTimeout(tick, 5000); }});
  }}
  setTimeout(tick, 2000);
}})();
</script>
</body></html>"""
        self._send_html(html)

    # ------------------------------------------------------------ Tunnel 卡片
    def _tunnel_card(self):
        esc = html.escape
        t = self.store.tunnel
        snap = t.snapshot()
        port = getattr(self.cfg, "tunnel_dns_port", 15353)
        lip = _local_ip()
        resolver = f"{lip or '<NAS_IP>'}:{port}"
        pins = t.pins()
        prog = snap.get("progress")
        pinned_ips = {ip for ips in pins.values() for ip in ips}

        if not t.enabled:
            badge = '<span class="badge idle"><i class="dot"></i>未开启</span>'
        elif prog:
            badge = (f'<span class="badge run"><i class="dot"></i>'
                     f'扫描中 {prog["pct"]}%</span>')
        elif snap.get("stale"):
            badge = '<span class="badge warn"><i class="dot"></i>已退回上游</span>'
        elif pinned_ips:
            badge = '<span class="badge ok"><i class="dot"></i>已生效</span>'
        else:
            badge = '<span class="badge warn"><i class="dot"></i>还没有结果</span>'

        state = ""
        if not t.enabled:
            state = ("开启后，本应用会在 <b>:%d</b> 上单独给 cloudflared 做解析，"
                     "不改动 NAS 的系统 DNS，也不影响域名优选的 hosts 下发。" % port)
        elif snap.get("stale"):
            state = (f"上次扫描已过 {int(t.MAX_AGE / 86400)} 天，为避免连接器一直用"
                     "失效边缘，解析已交回上游 DNS。点“立即扫描”可恢复加速。")
        elif pinned_ips:
            r1 = ", ".join(pins.get("region1.v2.argotunnel.com", []))
            r2 = ", ".join(pins.get("region2.v2.argotunnel.com", []))
            state = (f"region1 → <code>{esc(r1)}</code>　"
                     f"region2 → <code>{esc(r2)}</code><br>"
                     "连接器只会连这些实测最快的隧道边缘；扫描失败时自动退回上游解析，"
                     "不会让隧道连不上。")
        else:
            state = "正在等待首次扫描，通常 20 秒内完成。"

        rows = []
        for i, e in enumerate(t.edges[:10]):
            pick = " class=pick" if e["ip"] in pinned_ips else ""
            tag = ('<span class="tag">已下发</span>'
                   if e["ip"] in pinned_ips else "")
            rows.append(
                f'<tr{pick}><td>{i + 1}</td><td>{esc(e["ip"])}</td>'
                f'<td class="colo">{esc(e.get("colo") or "???")}</td>'
                f'<td>{e["connect_ms"]:.0f} ms</td><td>{tag}</td></tr>')
        table = ""
        if rows:
            table = f"""<div class="sect">
  <div class="sect-t">隧道边缘实测
    <span>端口 7844 · 存活 {t.total_alive} 个</span></div>
  <table class="nodes">
    <thead><tr><th>#</th><th>边缘 IP</th><th>机房</th><th>握手</th><th></th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</div>"""

        docker_cfg = (
            "services:\n"
            "  cloudflared:\n"
            "    image: cloudflare/cloudflared:latest\n"
            "    restart: unless-stopped\n"
            "    command: tunnel --no-autoupdate run\n"
            "    environment:\n"
            f"      - TUNNEL_DNS_RESOLVER_ADDRS={resolver}")
        native_cfg = (f"cloudflared tunnel run "
                      f"--dns-resolver-addrs {resolver} <TUNNEL_NAME>")

        err = (f'<div class="err">{esc(t.last_error)}</div>'
               if t.last_error and not t.edges else "")
        dns_warn = ""
        if self.tunnel_dns is not None and not self.tunnel_dns.ok:
            dns_warn = (f'<div class="err">:{port} 绑定失败：'
                        f'{esc(self.tunnel_dns.udp_error or "未知原因")}，'
                        '可用环境变量 TUNNEL_DNS_LISTEN 换个端口。</div>')

        top_sel = "".join(
            f'<option value="{n}"{" selected" if t.top_n == n else ""}>'
            f'{n} 个</option>' for n in (1, 2, 3))
        iv_sel = "".join(
            f'<option value="{v}"{" selected" if t.interval == v else ""}>'
            f'{lbl}</option>'
            for v, lbl in ((3600, "1 小时"), (21600, "6 小时"),
                           (86400, "1 天"), (259200, "3 天")))

        return f"""<div class="addbox" id="tunnelcard">
  <h3>Cloudflare Tunnel 加速
    <span style="float:right">{badge}</span></h3>
  <div class="hint" style="margin-top:0;margin-bottom:12px">{state}</div>
  {dns_warn}
  <div class="row">
    <div class="field">
      <label>每个 region 下发边缘数</label>
      <select id="ttop">{top_sel}</select>
    </div>
    <div class="field">
      <label>重新扫描周期</label>
      <select id="tiv">{iv_sel}</select>
    </div>
    <button onclick="saveTunnel()">保存</button>
    <button class="ghost" onclick="tunnelScan()">立即扫描</button>
    <button class="{'danger' if t.enabled else ''}"
          onclick="toggleTunnel({'false' if t.enabled else 'true'})">
      {'关闭加速' if t.enabled else '开启加速'}</button>
  </div>
  <div class="sect">
    <div class="sect-t">接入方法 <span>给 cloudflared 指定解析器即可，无需改系统 DNS</span></div>
    <div class="hint" style="margin:0 0 8px">
      Docker / 飞牛容器：在 cloudflared 容器加下面这个环境变量
      （原生服务用命令参数）。</div>
    <pre class="cfg" id="cfgdocker">{esc(docker_cfg)}</pre>
    <pre class="cfg">{esc(native_cfg)}</pre>
    <button class="ghost sm" onclick="copyText('cfgdocker')">复制 Compose 片段</button>
  </div>
  {table}
  <div class="hint">
    隧道有两跳：<b>访问者 → Cloudflare 边缘</b> 和 <b>边缘 → 本机 cloudflared</b>。
    这里优化的是后者（占隧道带宽瓶颈的大头，直接决定上传/下载速度）；
    前者由访问者自己的 DNS 决定，本机改不了。
    段内 IP 不共享 anycast，同一段也会落到不同机房，所以逐 IP 全量实测 7844 端口。</div>
  {err}
</div>"""

    # ------------------------------------------------------------ 域名卡片
    def _domain_card(self, d):
        esc = html.escape
        prog = d.get("progress")
        scanning = bool(prog) or not d["last_scan_at"]
        if prog:
            badge = (f'<span class="badge run"><i class="dot"></i>'
                     f'扫描中 {prog["pct"]}%</span>')
        elif not d["last_scan_at"]:
            badge = '<span class="badge run"><i class="dot"></i>排队中</span>'
        elif d["last_scan_ok"]:
            badge = '<span class="badge ok"><i class="dot"></i>已接入</span>'
        else:
            badge = '<span class="badge bad"><i class="dot"></i>未接入</span>'

        # ---- 当前下发节点
        if d["ips"]:
            nodes_now = []
            lat = {n["ip"]: n for n in d["nodes"]}
            for ip in d["ips"]:
                n = lat.get(ip, {})
                ms = n.get("connect_ms")
                colo = n.get("colo", "")
                sub = f"{colo} · {ms:.0f} ms" if ms else colo or "已下发"
                nodes_now.append(
                    f'<div class="ipwrap"><span class="ip">{esc(ip)}</span>'
                    f'<span class="lat">{esc(sub)}</span></div>')
            now_html = "".join(nodes_now)
        elif prog:
            # 有进度就显示进度条，而不是干巴巴一句"稍候"
            now_html = (
                f'<div class="progwrap">'
                f'<div class="progtop"><span class="spin"></span>'
                f' 正在扫描 {prog["done"]} / {prog["total"]}'
                f' · 已存活 {prog["alive"]}'
                f' · {prog["elapsed"]}s</div>'
                f'<div class="progbar"><i style="width:{prog["pct"]}%"></i></div>'
                f'</div>')
        elif scanning:
            now_html = ('<div class="none"><span class="spin"></span> '
                        '正在等待扫描（前面的域名完成后自动开始）…</div>')
        else:
            now_html = '<div class="none">没有可用节点，请检查域名或换机房</div>'

        # ---- 降级提示：目标机房没节点时，告诉用户实际用了哪些，并支持一键采用
        warn_html = ""
        warning = d.get("last_warning") or ""
        if warning:
            buttons = []
            fb = ",".join(d.get("fallback_colos") or [])
            if fb:
                buttons.append(
                    '<button class="ghost sm" onclick="setColos(\''
                    + d["id"] + "', '" + esc(fb) + "')\">改用 "
                    + esc(fb) + "</button>")
            buttons.append(
                '<button class="ghost sm" onclick="rescan(\''
                + d["id"] + "', true)\">全量扫描</button>")
            fix = ('<div style="display:flex;gap:6px;flex-wrap:wrap">'
                   + "".join(buttons) + "</div>")
            warn_html = ('<div class="warnbox"><span>' + esc(warning)
                         + "</span>" + fix + "</div>")

        # ---- 候选节点表（按延迟排序）
        nodes = d["nodes"]
        active_colos = d.get("fallback_colos") or d["colos"]
        if nodes:
            shown = nodes[:20]
            mx = max(n["connect_ms"] for n in shown) or 1
            rows = []
            for n in shown:
                picked = n["ip"] in d["ips"]
                pct = max(4, n["connect_ms"] / mx * 100)
                rows.append(
                    f'<tr class="{"pick" if picked else ""}">'
                    f'<td>{esc(n["ip"])}</td>'
                    f'<td class="colo {"hit" if n["colo"] in active_colos else ""}">'
                    f'{esc(n["colo"])}</td>'
                    f'<td>{n["connect_ms"]:.0f} ms</td>'
                    f'<td><div class="bar"><i style="width:{pct:.0f}%"></i></div></td>'
                    f'<td>{"<span class=\'tag\'>使用中</span>" if picked else ""}</td>'
                    f'</tr>')
            hit_colos = ",".join(sorted({n["colo"] for n in nodes}))
            table = f"""<div class="sect">
  <div class="sect-t">候选节点 <span>按延迟排序，前 {min(len(nodes), 20)} 个
    （共 {len(nodes)} 个可用，{esc(hit_colos)}）</span></div>
  <table class="nodes">
    <tr><th>IP</th><th>机房</th><th>握手</th><th>对比</th><th></th></tr>
    {''.join(rows)}
  </table>
</div>"""
        else:
            table = ""

        # ---- 机房分布
        dist = sorted(d["colos_found"].items(), key=lambda kv: -kv[1])[:8]
        cb = d.get("colo_best") or {}
        chips = "".join(
            f'<span class="chip{" hit" if c in active_colos else ""}">'
            f'{esc(c)} {n}'
            + (f'<span class="cms"> · {cb[c]:.0f}ms</span>' if c in cb else "")
            + '</span>'
            for c, n in dist)
        dist_html = (f'<div class="chips">{chips}</div>' if chips else "")

        err = (f'<div class="err">{esc(d["last_error"])}</div>'
               if d["last_error"] else "")
        off = "" if d["enabled"] else " off"
        sc = " scanning" if scanning else ""
        toggle_label = "停用" if d["enabled"] else "启用"
        toggle_val = "false" if d["enabled"] else "true"
        best = f' · 最快 {d["best_ms"]:.0f} ms' if d["best_ms"] else ""
        alive = f' · 存活 {d["total_alive"]}' if d["total_alive"] else ""
        limit_label = (f"延迟 ≤{d['max_ms']}ms" if d["max_ms"] else "延迟不限")
        cache_label = (f' · 缓存 {d["net_count"]} 段'
                       if d["net_count"] else " · 下轮全量")

        # ---- 行内编辑表单（改机房/节点数/周期）
        top_choices = sorted({1, 2, 3, 5, d["top_n"]})
        top_opts = "".join(
            f'<option value="{v}"{" selected" if v == d["top_n"] else ""}>'
            f'{v} 个</option>' for v in top_choices)

        def _fmt_iv(s):
            return f"{s // 3600} 小时" if s % 3600 == 0 else f"{s} 秒"

        int_choices = sorted({3600, 21600, 43200, 86400, d["interval"]})
        int_opts = "".join(
            f'<option value="{v}"{" selected" if v == d["interval"] else ""}>'
            f'{_fmt_iv(v)}</option>' for v in int_choices)

        max_choices = sorted({100, 150, 200, 250, 300, d["max_ms"]})
        max_opts = "".join(
            f'<option value="{v}"{" selected" if v == d["max_ms"] else ""}>'
            f'{"不限" if v == 0 else f"≤{v} ms"}</option>'
            for v in max_choices)
        edit_html = f"""<div class="editrow" id="edit-{d['id']}" style="display:none">
  <div class="field"><label>偏好机房（3 字母代码，逗号分隔；更快的其他机房自动采用）</label>
    <input id="ecolos-{d['id']}" value="{esc(','.join(d['colos']))}"
           placeholder="HKG,SIN,NRT"></div>
  <div class="field"><label>下发节点数</label>
    <select id="etop-{d['id']}">{top_opts}</select></div>
  <div class="field"><label>扫描周期</label>
    <select id="eint-{d['id']}">{int_opts}</select></div>
  <div class="field"><label>延迟上限</label>
    <select id="emax-{d['id']}">{max_opts}</select></div>
  <button class="sm" onclick="saveEdit('{d['id']}')">保存</button>
  <button class="ghost sm" onclick="toggleEdit('{d['id']}')">取消</button>
</div>"""

        return f"""<div class="card{off}{sc}">
  <div class="chead">
    <div>
      <div class="host">{esc(d["host"])} {badge}</div>
      <div class="meta">偏好 {esc(",".join(d["colos"]))} · {limit_label}{cache_label}
        · 周期 {_fmt_iv(d["interval"])}
        · 上次 {_fmt_age(d["last_scan_at"])}{best}{alive}</div>
    </div>
    <div class="acts">
      <button class="ghost sm" onclick="rescan('{d["id"]}')"
              title="增量扫描：只扫上次发现的网段，速度快">扫描</button>
      <button class="ghost sm" onclick="rescan('{d["id"]}', true)"
              title="全量扫描：重扫全部 Cloudflare 网段，可发现缓存漏掉的节点">全量</button>
      <button class="ghost sm" onclick="toggleEdit('{d["id"]}')">设置</button>
      <button class="ghost sm" onclick="toggle('{d["id"]}', {toggle_val})">{toggle_label}</button>
      <button class="danger sm" onclick="del('{d["id"]}', '{esc(d["host"])}')">删除</button>
    </div>
  </div>
  {edit_html}
  <div class="sect">
    <div class="sect-t">当前下发 <span>{len(d["ips"])} 个节点</span></div>
    <div class="now">{now_html}</div>
    {dist_html}
    {warn_html}
  </div>
  {table}
  {err}
</div>"""

    # ------------------------------------------------------------ 状态页
    def _page_status(self):
        domains = [d.snapshot() for d in self.store.list()]
        payload = {"version": __version__, "mode": self.cfg.mode,
                   "domains": domains,
                   "tunnel": self._tunnel_json()["tunnel"]}
        if "application/json" in (self.headers.get("Accept") or ""):
            self._json(payload)
            return
        pretty = json.dumps(payload, ensure_ascii=False, indent=2)
        html = f"""<!doctype html><html lang=zh><head><meta charset=utf-8>
<title>状态 · cfopt</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
body{{font:14px/1.7 -apple-system,"Segoe UI","PingFang SC",sans-serif;
max-width:820px;margin:0 auto;padding:28px 20px 80px;color:#1a1a1a;
background:#f6f7f9}}
h1{{font-size:20px;font-weight:650;margin:0 0 6px}}
a{{color:#0a58ca;font-size:13px}}
pre{{background:#1b1f24;color:#d6dde4;padding:16px;border-radius:8px;
overflow-x:auto;font-size:12.5px;line-height:1.6;margin-top:16px}}
</style></head><body>
<h1>运行状态</h1><a href="/">← 返回管理面板</a>
<pre>{pretty}</pre>
</body></html>"""
        self._send_html(html)


def serve(cfg, store, scanner, tunnel_dns=None):
    Handler.cfg = cfg
    Handler.store = store
    Handler.scanner = scanner
    Handler.tunnel_dns = tunnel_dns
    return ThreadingHTTPServer(("0.0.0.0", cfg.http_port), Handler)
