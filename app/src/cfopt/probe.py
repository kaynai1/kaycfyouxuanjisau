# -*- coding: utf-8 -*-
"""Cloudflare 边缘探测：按机房识别 + 延迟测量。

核心思路：直连 TLS 并读取响应头里的 CF-RAY（形如 a4ca4e02af43ec2b-HKG），
末段就是机房代码。即使服务返回 403/404/522，该头依然存在，所以能测私有服务。
"""
import ipaddress
import json
import socket
import ssl
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# Cloudflare 官方 IPv4 段（https://www.cloudflare.com/ips-v4/）
CF_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

UA = "Mozilla/5.0 (X11; Linux x86_64) cfopt/2.0"

# 复用一个 SSLContext。每次探测都 create_default_context() 会重新加载
# 系统 CA，在 NAS 上单次可达上百毫秒；120 个线程同时加载更会互相拖慢。
_SSL_CTX = None
_SSL_CTX_LOCK = threading.Lock()


def _ssl_context():
    global _SSL_CTX
    if _SSL_CTX is None:
        with _SSL_CTX_LOCK:
            if _SSL_CTX is None:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                _SSL_CTX = ctx
    return _SSL_CTX

# v2too 的三网优选列表，每个运营商单独返回一个数组
V2TOO_API = "https://ip.v2too.top/api/nodes?carrier={}"
_v2too_cache = {"at": 0.0, "ips": []}
_v2too_lock = threading.Lock()

# ---------------------------------------------------------------- Cloudflare Tunnel
# cloudflared（隧道连接器）不走普通边缘段，而是连隧道专用段。
# 这两段是隧道协议（7844）唯一开放的地方，普通优选 IP 连不上 7844。
TUNNEL_V4 = ["198.41.192.0/24", "198.41.200.0/24"]
TUNNEL_PORT = 7844
# 连接器按 SRV _v2-origintunneld._tcp.argotunnel.com 拿到这两个域名，
# 再解析 A 记录。只要接管这两条 A 记录，就能把连接器钉到实测最快的边缘。
TUNNEL_REGIONS = ["region1.v2.argotunnel.com", "region2.v2.argotunnel.com"]


def is_cloudflare_ip(ip):
    """判断 IP 是否属于 Cloudflare 网段。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in CF_V4:
        if addr in ipaddress.ip_network(cidr):
            return True
    return False


def check_domain_on_cloudflare(host, resolver=None, timeout=5.0):
    """检查域名是否真的接入了 Cloudflare。

    原理：接入 CF 的域名（小黄云开启）解析到的是 CF 的 Anycast IP，
    没接入的解析到自己的源站 IP。所以查一次 A 记录就能判断。

    返回 (ok, detail)：
      ok=True  → detail 是解析到的 CF IP 列表
      ok=False → detail 说明原因
      ok=None  → 无法判断（解析失败等），此时不应阻止用户添加
    """
    import socket as _socket
    host = host.lstrip("*.").rstrip(".")
    try:
        infos = _socket.getaddrinfo(host, None, _socket.AF_INET)
    except Exception as e:
        return None, f"DNS 解析失败：{e}"

    ips = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        return None, "DNS 没有返回 A 记录"

    cf_ips = [ip for ip in ips if is_cloudflare_ip(ip)]
    if cf_ips:
        return True, cf_ips
    return False, ips


def probe_once(ip, host, port=443, timeout=4.0):
    """单次探测。返回 dict 或 None。"""
    ctx = _ssl_context()
    t0 = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            connect_ms = (time.perf_counter() - t0) * 1000.0
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                tls_ms = (time.perf_counter() - t0) * 1000.0
                req = (
                    f"HEAD / HTTP/1.1\r\nHost: {host}\r\n"
                    f"User-Agent: {UA}\r\nAccept: */*\r\n"
                    "Connection: close\r\n\r\n"
                )
                ss.sendall(req.encode())
                buf = b""
                while b"\r\n\r\n" not in buf and len(buf) < 16384:
                    chunk = ss.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                ttfb_ms = (time.perf_counter() - t0) * 1000.0
    except Exception:
        return None

    colo, status = None, None
    for line in buf.decode("latin-1").split("\r\n"):
        low = line.lower()
        if low.startswith("cf-ray:"):
            colo = line.split("-")[-1].strip().upper()
        elif low.startswith("http/"):
            parts = line.split()
            if len(parts) > 1 and parts[1].isdigit():
                status = int(parts[1])

    return {
        "ip": ip,
        "colo": colo or "???",
        "connect_ms": round(connect_ms, 1),
        "tls_ms": round(tls_ms, 1),
        "ttfb_ms": round(ttfb_ms, 1),
        "status": status,
    }


def probe(ip, host, port=443, timeout=4.0, retries=2):
    """带重试的探测。CF 边缘偶发丢首包，单次失败不代表不可用。"""
    for attempt in range(retries + 1):
        r = probe_once(ip, host, port, timeout)
        if r:
            return r
        if attempt < retries:
            time.sleep(0.2)
    return None


def _fetch_v2too_carrier(carrier, timeout):
    req = urllib.request.Request(
        V2TOO_API.format(carrier),
        headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read(1 << 20).decode("utf-8"))
    return data if isinstance(data, list) else []


def fetch_v2too_ips(timeout=5.0, ttl=900):
    """抓 v2too 三网优选 IP，15 分钟内复用结果。

    站点的延迟/速度是它自己网络的测值，和本机不一定一致，
    所以这里只取 IP，最终仍由本机探测决定排序和机房。
    抓取失败时返回上次成功的结果；全部失败则返回空，不影响正常扫描。
    """
    with _v2too_lock:
        if time.time() - _v2too_cache["at"] < ttl:
            return list(_v2too_cache["ips"])

        data_by = {}
        with ThreadPoolExecutor(max_workers=3) as pool:
            futs = {pool.submit(_fetch_v2too_carrier, c, timeout): c
                    for c in ("ct", "cm", "cu")}
            for fut in as_completed(futs):
                try:
                    data_by[futs[fut]] = fut.result()
                except Exception:
                    continue

        ips, seen = [], set()
        for carrier in ("ct", "cm", "cu"):
            for item in data_by.get(carrier) or []:
                if not isinstance(item, dict):
                    continue
                ip = str(item.get("ip") or "").strip()
                if ip and ip not in seen and is_cloudflare_ip(ip):
                    seen.add(ip)
                    ips.append(ip)
        _v2too_cache["at"] = time.time()
        if ips:
            _v2too_cache["ips"] = ips
        return list(_v2too_cache["ips"])


def tcp_connect_ms(ip, port=443, timeout=4.0):
    """只测 TCP 握手耗时，供顺序复测使用。

    并发扫描时线程在 connect 返回和读时间戳之间会被调度走，
    读数可能被放大好几倍；顺序调用没有这个问题。
    """
    t0 = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return round((time.perf_counter() - t0) * 1000.0, 1)
    except Exception:
        return None


def _median(values):
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def expand_ranges(cidrs, per_net):
    """每个 /24 抽 per_net 个 IP。CF 的 Anycast 路由按段下发，同段落地通常一致。"""
    out = []
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.prefixlen >= 24:
            out.extend(str(h) for h in list(net.hosts())[:per_net])
            continue
        for sub in net.subnets(new_prefix=24):
            hosts = list(sub.hosts())
            if hosts:
                out.extend(str(h) for h in hosts[:per_net])
    return out


def scan(ips, host, workers=120, timeout=3.0, progress=None,
         retries=0, refine_top=0):
    """并发扫描，返回存活结果列表。

    性能要点（这是实测得出的，不是猜的）：
      - 死 IP 的单次探测要等满 timeout；带重试的话耗时 = timeout × (retries+1)。
        之前默认 timeout=4 + retries=2 → 单个死 IP 耗 12.5 秒，
        11912 个候选要跑 13 分钟。
      - 存活 IP 单次约 1.1 秒，重试对它们几乎没用。
      所以默认 retries=0、timeout=3：死 IP 只等 3 秒，整体快 4 倍以上。

    refine_top > 0 时，对延迟最好的前 N 个（外加每个机房最快 10 个）
    改为顺序做 3 次纯 TCP 握手，取中位数覆盖并发扫描的读数。
    并发扫描（上百线程）测出的 connect_ms 会被线程调度放大——实测同一个
    HKG 节点并发报 594ms、顺序只有 111ms，所以不能保留原始值，
    也不能用 max() 复测。

    progress(done, total, alive) 可选回调。
    """
    results, done, total = [], 0, len(ips)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(probe, ip, host, 443, timeout, retries): ip
                for ip in ips}
        for fut in as_completed(futs):
            done += 1
            r = fut.result()
            if r:
                results.append(r)
            if progress and (done % 200 == 0 or done == total):
                progress(done, total, len(results))

    # 并发读数不可信：对靠前的候选顺序做 3 次 TCP 握手，用中位数作为延迟。
    # 除了总排名前 N，每个机房再单独取前 10，避免目标/降级机房的节点
    # 因并发读数被排到总榜后面而漏掉复测。
    if refine_top and results:
        results.sort(key=lambda r: r["connect_ms"])
        head, seen = [], set()
        for r in results[:refine_top]:
            head.append(r)
            seen.add(id(r))
        by_colo = {}
        for r in results:
            if r["colo"] != "???":
                by_colo.setdefault(r["colo"], []).append(r)
        for group in by_colo.values():
            for r in group[:10]:
                if id(r) not in seen:
                    head.append(r)
                    seen.add(id(r))

        for r in head:
            samples = []
            for _ in range(3):
                ms = tcp_connect_ms(r["ip"], 443, max(timeout, 2.0))
                if ms is not None:
                    samples.append(ms)
            if samples:
                r["connect_ms"] = round(_median(samples), 1)
        results.sort(key=lambda r: (r["connect_ms"], r["ttfb_ms"]))

    return results


def nets_from_results(results, colo, limit=0):
    """从扫描结果提取指定机房的 /24 网段，按最快延迟排序。"""
    buckets = {}
    for r in results:
        if r["colo"] != colo:
            continue
        n = str(ipaddress.ip_network(r["ip"] + "/24", strict=False))
        buckets.setdefault(n, []).append(r["connect_ms"])
    ordered = sorted(buckets.items(), key=lambda kv: min(kv[1]))
    nets = [n for n, _ in ordered]
    return nets[:limit] if limit else nets


def tunnel_candidates():
    """隧道边缘全部候选 IP（两段各 254 个，逐 IP 而不是抽样）。

    普通扫描按 /24 抽样是因为同段 anycast 落地一致；隧道段不是 anycast，
    同段不同 IP 分到不同机房（实测 LAX 与 SJC 混在同一 /24 里），
    必须全量测。
    """
    out = []
    for cidr in TUNNEL_V4:
        out.extend(str(h) for h in ipaddress.ip_network(cidr, strict=False).hosts())
    return out


def _probe_tunnel_ip(ip, timeout):
    """连接器实际用的端口是 7844，普通 443 的延迟不代表这条路径。"""
    return tcp_connect_ms(ip, TUNNEL_PORT, timeout)


def scan_tunnel_edges(workers=64, timeout=2.5, progress=None,
                      refine_head=15, colo_count=12):
    """扫描隧道边缘，返回 (最优列表, 存活总数)。

    步骤：并发粗测 7844 → 前 N 个顺序复测取中位数（并发读数会被线程调度
    放大）→ 对最靠前的若干个再测 443 以识别机房（CF-RAY）。机房只是给
    界面解释用，排序始终以 7844 实测延迟为准。
    """
    ips = tunnel_candidates()
    total = len(ips)
    alive = []
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_probe_tunnel_ip, ip, timeout): ip for ip in ips}
        for fut in as_completed(futs):
            done += 1
            ms = fut.result()
            if ms is not None:
                alive.append({"ip": futs[fut], "connect_ms": ms, "colo": "???"})
            if progress and (done % 50 == 0 or done == total):
                progress(done, total, len(alive))

    if not alive:
        return [], 0

    alive.sort(key=lambda r: r["connect_ms"])
    head = alive[:refine_head]
    for r in head:
        samples = [ms for ms in
                   (_probe_tunnel_ip(r["ip"], max(timeout, 2.0))
                    for _ in range(3)) if ms is not None]
        if not samples:
            # 复测三连失败说明刚才的读数是抖动，直接剔除，
            # 否则会把一个连不上的边缘下发给连接器。
            r["connect_ms"] = None
            continue
        r["connect_ms"] = round(_median(samples), 1)
    head = [r for r in head if r["connect_ms"] is not None]
    head.sort(key=lambda r: r["connect_ms"])

    def fill_colo(r):
        p = probe_once(r["ip"], "www.cloudflare.com", 443, max(timeout, 3.0))
        r["colo"] = (p or {}).get("colo") or "???"
        return r

    for grp in (head[:colo_count],):
        with ThreadPoolExecutor(max_workers=min(8, len(grp) or 1)) as pool:
            list(pool.map(fill_colo, grp))

    return head, len(alive)


def download_speed(ip, host, path, timeout=10.0, max_bytes=8 * 1024 * 1024):
    """真实下载测速，返回 (秒, 字节) 或 None。"""
    ctx = _ssl_context()
    t0 = time.perf_counter()
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                req = (
                    f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                    f"User-Agent: {UA}\r\nAccept: */*\r\n"
                    "Accept-Encoding: identity\r\n"
                    "Connection: close\r\n\r\n"
                )
                ss.sendall(req.encode())
                buf = b""
                while b"\r\n\r\n" not in buf:
                    ch = ss.recv(65536)
                    if not ch:
                        break
                    buf += ch
                if b"\r\n\r\n" not in buf:
                    return None
                _, body = buf.split(b"\r\n\r\n", 1)
                n = len(body)
                while n < max_bytes:
                    ch = ss.recv(65536)
                    if not ch:
                        break
                    n += len(ch)
                return time.perf_counter() - t0, n
    except Exception:
        return None
