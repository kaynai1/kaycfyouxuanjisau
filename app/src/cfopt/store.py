# -*- coding: utf-8 -*-
"""多域名配置的持久化存储。

设计要点：
- 单文件 JSON，原子写入（os.replace），避免写一半断电导致配置全丢
- 每个域名独立的扫描状态与网段缓存，互不影响
- 首次启动时把环境变量里的单域名迁移成一条记录，保证向后兼容
"""
import json
import os
import threading
import time
import uuid

SCHEMA_VERSION = 3


def _new_id():
    return uuid.uuid4().hex[:12]


class Domain:
    """单个域名的配置 + 运行状态。"""

    FIELDS = ("id", "host", "colos", "top_n", "per_net", "interval",
              "max_ms", "enabled", "created_at", "ips", "nodes",
              "colos_found", "total_alive", "best_ms", "last_scan_at",
              "last_scan_ok", "last_error", "last_warning",
              "fallback_colos", "colo_best", "nets", "nets_colos")

    def __init__(self, host, colos=None, top_n=2, per_net=2,
                 interval=21600, max_ms=200, enabled=True, **kw):
        self.id = kw.get("id") or _new_id()
        self.host = host.strip().lower().rstrip(".")
        self.colos = colos or ["HKG"]
        self.top_n = int(top_n)
        self.per_net = int(per_net)
        self.interval = int(interval)
        # 下发节点的延迟上限（毫秒），0 表示不限制
        self.max_ms = int(max_ms)
        self.enabled = bool(enabled)
        self.created_at = kw.get("created_at") or int(time.time())

        # 运行状态
        self.ips = kw.get("ips") or []
        # 候选节点明细：[{ip, colo, connect_ms, ttfb_ms}, ...]
        # 让界面能显示"扫描到了哪些节点、各自延迟多少"，而不只是最终选中的几个
        self.nodes = kw.get("nodes") or []
        self.colos_found = kw.get("colos_found") or {}
        self.total_alive = kw.get("total_alive") or 0
        self.best_ms = kw.get("best_ms") or 0.0
        self.last_scan_at = kw.get("last_scan_at") or 0
        self.last_scan_ok = kw.get("last_scan_ok", False)
        self.last_error = kw.get("last_error", "")
        self.last_warning = kw.get("last_warning", "")
        self.fallback_colos = kw.get("fallback_colos") or []
        # 各机房本轮最快延迟 {colo: ms}，界面用它解释机房切换
        self.colo_best = kw.get("colo_best") or {}
        self.nets = kw.get("nets") or []      # 已发现的网段，用于快速复扫
        # 这批网段是为哪个机房筛出来的。机房一改，缓存就必须作废，
        # 否则会一直只扫旧机房的段，永远扫不到新机房。
        self.nets_colos = kw.get("nets_colos") or []
        # 扫描进度（只在内存里，不落盘）：{done, total, alive, started}
        self.progress = None
        self._lock = threading.Lock()

    # ---------------------------------------------------------- 进度
    def set_progress(self, done, total, alive):
        with self._lock:
            if self.progress is None:
                self.progress = {"started": int(time.time())}
            self.progress.update(done=done, total=total, alive=alive)

    def clear_progress(self):
        with self._lock:
            self.progress = None

    def progress_snapshot(self):
        with self._lock:
            if not self.progress:
                return None
            p = dict(self.progress)
            total = p.get("total") or 0
            p["pct"] = int(p.get("done", 0) / total * 100) if total else 0
            p["elapsed"] = int(time.time() - p.get("started", time.time()))
            return p

    # ---------------------------------------------------------- 序列化
    def to_dict(self):
        return {k: getattr(self, k) for k in self.FIELDS}

    @classmethod
    def from_dict(cls, d):
        return cls(
            host=d.get("host", ""),
            colos=d.get("colos") or ["HKG"],
            top_n=d.get("top_n", 2),
            per_net=d.get("per_net", 2),
            interval=d.get("interval", 21600),
            max_ms=d.get("max_ms", 200),
            enabled=d.get("enabled", True),
            **{k: d[k] for k in ("id", "created_at", "ips", "nodes",
                                 "colos_found", "total_alive", "best_ms",
                                 "last_scan_at", "last_scan_ok",
                                 "last_error", "last_warning",
                                 "fallback_colos", "colo_best", "nets",
                                 "nets_colos") if k in d}
        )

    # ---------------------------------------------------------- 状态更新
    def apply_scan(self, ips, colos_found, nets=None, nodes=None,
                   total_alive=0, warning="", fallback_colos=None,
                   colo_best=None):
        with self._lock:
            self.ips = ips
            self.colos_found = colos_found
            self.colo_best = dict(colo_best or {})
            # 只保留前 50 个节点明细，避免配置文件膨胀
            self.nodes = (nodes or [])[:50]
            self.total_alive = total_alive
            self.best_ms = min((n["connect_ms"] for n in self.nodes),
                               default=0.0)
            self.last_scan_at = int(time.time())
            self.last_scan_ok = bool(ips)
            self.last_error = "" if ips else "扫描无结果"
            self.last_warning = warning or ""
            self.fallback_colos = list(fallback_colos or [])
            if nets:
                self.nets = nets
        self._persist()

    def mark_failed(self, err, clear_ips=False):
        with self._lock:
            self.last_scan_ok = False
            self.last_error = str(err)[:300]
            self.last_warning = ""
            self.fallback_colos = []
            self.last_scan_at = int(time.time())
            if clear_ips:
                # 延迟上限收紧后旧节点已不合规，宁可不下发也不能继续用高延迟 IP
                self.ips = []
                self.nodes = []
                self.colo_best = {}
                self.best_ms = 0.0
        self._persist()

    def trim_by_latency(self):
        """按 max_ms 立即裁掉已下发的高延迟节点。

        改小上限后马上生效，不用等重扫跑完（全量扫描可能要十几分钟）。
        """
        limit = self.max_ms or 0
        if not limit:
            return
        with self._lock:
            ms = {n["ip"]: n["connect_ms"] for n in self.nodes}
            kept = [ip for ip in self.ips if ms.get(ip, 0) <= limit]
            if kept != self.ips:
                self.ips = kept
                self.nodes = [n for n in self.nodes
                              if n["connect_ms"] <= limit]
                self.best_ms = min((n["connect_ms"] for n in self.nodes),
                                   default=0.0)
                self.last_scan_ok = bool(kept)
                if not kept:
                    self.last_error = f"现有节点延迟均超过 {limit}ms，已停止下发"
        self._persist()

    def _persist(self):
        """扫描结果变化后立即落盘，避免重启丢结果。"""
        store = getattr(self, "_store", None)
        if store is not None:
            try:
                store.save()
            except Exception:
                pass

    def get_ips(self):
        with self._lock:
            return list(self.ips)

    def snapshot(self):
        with self._lock:
            prog = None
            if self.progress:
                p = dict(self.progress)
                total = p.get("total") or 0
                p["pct"] = int(p.get("done", 0) / total * 100) if total else 0
                p["elapsed"] = int(time.time() - p.get("started", time.time()))
                prog = p
            return {
                "id": self.id,
                "host": self.host,
                "colos": list(self.colos),
                "top_n": self.top_n,
                "per_net": self.per_net,
                "interval": self.interval,
                "max_ms": self.max_ms,
                "enabled": self.enabled,
                "created_at": self.created_at,
                "ips": list(self.ips),
                "nodes": [dict(n) for n in self.nodes],
                "colos_found": dict(self.colos_found),
                "total_alive": self.total_alive,
                "best_ms": self.best_ms,
                "last_scan_at": self.last_scan_at,
                "last_scan_ok": self.last_scan_ok,
                "last_error": self.last_error,
                "last_warning": self.last_warning,
                "fallback_colos": list(self.fallback_colos),
                "colo_best": dict(self.colo_best),
                "net_count": len(self.nets),
                "progress": prog,
            }


class TunnelState:
    """Cloudflare Tunnel 连接器边缘优选的全局状态。

    隧道连接器不按域名走，它只连 Cloudflare 自己的边缘段
    （region1/region2.v2.argotunnel.com:7844）。所以这里是一份全局配置，
    所有隧道共用。
    """

    # 结果放太久就不再接管解析，交回上游 DNS：
    # 宁可隧道没有优化，也不能让连接器一直用一批 Cloudflare 已经撤掉的边缘 IP，
    # 那会直接把隧道连不上。
    MAX_AGE = 3 * 86400

    def __init__(self, enabled=False, interval=21600, top_n=2, **kw):
        self.enabled = bool(enabled)
        self.interval = int(interval)
        self.top_n = max(1, int(top_n))
        # 优选边缘明细：[{ip, colo, connect_ms}, ...]，已按延迟排序
        self.edges = kw.get("edges") or []
        self.total_alive = kw.get("total_alive") or 0
        self.last_scan_at = kw.get("last_scan_at") or 0
        self.last_scan_ok = kw.get("last_scan_ok", False)
        self.last_error = kw.get("last_error", "")
        self.progress = None
        # 可重入：snapshot() 持锁时还要读 progress_snapshot()
        self._lock = threading.RLock()
        self._store = None

    @classmethod
    def from_dict(cls, d):
        d = d or {}
        return cls(
            enabled=d.get("enabled", False),
            interval=d.get("interval", 21600),
            top_n=d.get("top_n", 2),
            **{k: d[k] for k in ("edges", "total_alive", "last_scan_at",
                                 "last_scan_ok", "last_error") if k in d}
        )

    def to_dict(self):
        with self._lock:
            return {k: getattr(self, k) for k in
                    ("enabled", "interval", "top_n", "edges", "total_alive",
                     "last_scan_at", "last_scan_ok", "last_error")}

    # ---------------------------------------------------------- 进度
    def set_progress(self, done, total, alive):
        with self._lock:
            if self.progress is None:
                self.progress = {"started": int(time.time())}
            self.progress.update(done=done, total=total, alive=alive)

    def clear_progress(self):
        with self._lock:
            self.progress = None

    def progress_snapshot(self):
        with self._lock:
            if not self.progress:
                return None
            p = dict(self.progress)
            total = p.get("total") or 0
            p["pct"] = int(p.get("done", 0) / total * 100) if total else 0
            p["elapsed"] = int(time.time() - p.get("started", time.time()))
            return p

    # ---------------------------------------------------------- 扫描结果
    def apply_scan(self, edges, total_alive):
        with self._lock:
            self.edges = edges[:40]
            self.total_alive = total_alive
            self.last_scan_at = int(time.time())
            self.last_scan_ok = bool(edges)
            self.last_error = "" if edges else "隧道边缘段全部不可达"
        self._persist()

    def mark_failed(self, err):
        # 故意保留上一次的 edges：扫描偶发失败不该让隧道退回慢边缘
        with self._lock:
            self.last_scan_ok = False
            self.last_error = err
            self.last_scan_at = int(time.time())
        self._persist()

    def _persist(self):
        store = self._store
        if store is not None:
            try:
                store.save()
            except Exception:
                pass

    def update(self, **fields):
        if "top_n" in fields and fields["top_n"] is not None:
            self.top_n = max(1, int(fields["top_n"]))
        if "interval" in fields and fields["interval"] is not None:
            self.interval = int(fields["interval"])
        if "enabled" in fields and fields["enabled"] is not None:
            self.enabled = bool(fields["enabled"])

    def pins(self):
        """返回 {域名: [ip, ...]}，交给 DNS 层钉住连接器。

        region1 拿最快的一批，region2 拿次快的一批：两个都返回同一组 IP
        等于没有备份，主边缘出问题时候连接器无处可退。
        结果过期或没扫出来时返回空 —— DNS 层会自动转发上游，隧道照常工作。
        """
        with self._lock:
            if not self.enabled or not self.edges:
                return {}
            if time.time() - self.last_scan_at > self.MAX_AGE:
                return {}
            n = self.top_n
            ordered = [e["ip"] for e in self.edges if e.get("ip")]
            if not ordered:
                return {}
            primary = ordered[:n]
            backup = ordered[n:2 * n] or ordered[-n:]
            return {"region1.v2.argotunnel.com": primary,
                    "region2.v2.argotunnel.com": backup}

    def snapshot(self):
        with self._lock:
            prog = self.progress_snapshot()
            return {
                "enabled": self.enabled,
                "interval": self.interval,
                "top_n": self.top_n,
                "edges": [dict(e) for e in self.edges],
                "total_alive": self.total_alive,
                "last_scan_at": self.last_scan_at,
                "last_scan_ok": self.last_scan_ok,
                "last_error": self.last_error,
                "stale": bool(self.enabled and self.edges and
                              time.time() - self.last_scan_at > self.MAX_AGE),
                "progress": prog,
            }


class DomainStore:
    """域名的增删改查 + 落盘。线程安全。"""

    def __init__(self, path, log=print):
        self.path = path
        self.log = log
        self._lock = threading.RLock()
        self._domains = []
        self.tunnel = TunnelState()
        self.tunnel._store = self
        self._load()

    def _attach(self, domains):
        """给每个域名挂上 store 引用，让扫描结果能自动落盘。

        不这么做的话，apply_scan 只改内存，容器重启后扫描结果全丢，
        用户会看到"明明扫过又变成空的"。
        """
        for d in domains:
            d._store = self
        return domains

    # ---------------------------------------------------------- 读写
    def _load(self):
        if not os.path.exists(self.path):
            self._domains = []
            return
        try:
            with open(self.path, encoding="utf-8-sig") as f:
                data = json.load(f)
        except Exception as e:
            self.log(f"域名配置读取失败，将以空配置启动：{e}")
            self._domains = []
            return

        items = data.get("domains", []) if isinstance(data, dict) else data
        self._domains = self._attach([Domain.from_dict(d) for d in items
                                      if d.get("host")])
        if isinstance(data, dict):
            self.tunnel = TunnelState.from_dict(data.get("tunnel"))
            self.tunnel._store = self
        self.log(f"载入 {len(self._domains)} 个域名配置")
        if self.tunnel.enabled:
            self.log(f"Tunnel 加速已启用（上次扫描 {len(self.tunnel.edges)} 个边缘）")

    def save(self):
        with self._lock:
            payload = {
                "version": SCHEMA_VERSION,
                "updated_at": int(time.time()),
                "domains": [d.to_dict() for d in self._domains],
                "tunnel": self.tunnel.to_dict(),
            }
            try:
                os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
                tmp = self.path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(payload, f, ensure_ascii=False, indent=2)
                os.replace(tmp, self.path)
            except OSError as e:
                # Docker 单文件挂载时 rename 会 EBUSY，退回原地写
                self.log(f"配置原子写入失败（{e.strerror or e}），改为原地写入")
                with open(self.path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, ensure_ascii=False, indent=2)
                try:
                    os.unlink(self.path + ".tmp")
                except OSError:
                    pass

    # ---------------------------------------------------------- 查询
    def list(self):
        with self._lock:
            return list(self._domains)

    def enabled(self):
        with self._lock:
            return [d for d in self._domains if d.enabled]

    def get(self, domain_id):
        with self._lock:
            for d in self._domains:
                if d.id == domain_id:
                    return d
        return None

    def by_host(self, host):
        host = host.strip().lower().rstrip(".")
        with self._lock:
            for d in self._domains:
                if d.host == host:
                    return d
        return None

    # ---------------------------------------------------------- 写入
    def add(self, host, colos=None, top_n=2, per_net=2,
            interval=21600, max_ms=200, enabled=True):
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            raise ValueError("域名不能为空")
        if not _valid_host(host):
            raise ValueError(f"域名格式不合法：{host}")

        with self._lock:
            if self.by_host(host):
                raise ValueError(f"域名 {host} 已存在")
            d = Domain(host, colos=colos, top_n=top_n, per_net=per_net,
                       interval=interval, max_ms=max_ms, enabled=enabled)
            self._attach([d])
            self._domains.append(d)
            self.save()
            return d

    def remove(self, domain_id):
        with self._lock:
            before = len(self._domains)
            self._domains = [d for d in self._domains if d.id != domain_id]
            if len(self._domains) == before:
                return False
            self.save()
            return True

    def update(self, domain_id, **fields):
        with self._lock:
            d = self.get(domain_id)
            if not d:
                return None
            for key in ("colos", "top_n", "per_net", "interval", "max_ms",
                        "enabled"):
                if key in fields and fields[key] is not None:
                    setattr(d, key, fields[key])
            if fields.get("colos") is not None:
                # 用户手动改了偏好机房，清掉上一轮的切换提示
                d.fallback_colos = []
                d.last_warning = ""
            self.save()
            return d

    # ---------------------------------------------------------- 迁移
    def ensure_from_env(self, host, colos, top_n, per_net, interval):
        """首次启动时用环境变量里的单域名建一条记录，避免升级后配置丢失。"""
        if not host:
            return None
        with self._lock:
            existing = self.by_host(host)
            if existing:
                return existing
            if self._domains:
                return None  # 已有其他域名，不强行加
            self.log(f"从环境变量迁移域名 {host} 到管理配置")
            return self.add(host, colos=colos, top_n=top_n,
                            per_net=per_net, interval=interval)


def _valid_host(host):
    """简单但够用的域名校验：至少两段、不含空格、不允许通配符。

    通配符不能让探测器当 SNI 用（`*.example.com` 会被 Cloudflare
    直接拒成 400），加了也只会永远扫不到节点，所以入口直接拒绝。
    """
    if len(host) > 253 or " " in host or ".." in host or "*" in host:
        return False
    if host.startswith(".") or host.endswith("."):
        return False
    parts = host.split(".")
    if len(parts) < 2:
        return False
    for p in parts:
        if not p or len(p) > 63:
            return False
        if not all(c.isalnum() or c in "-_" for c in p):
            return False
        if p.startswith("-") or p.endswith("-"):
            return False
    return True

