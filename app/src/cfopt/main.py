# -*- coding: utf-8 -*-
"""cfopt 守护进程：多域名优选 + Web 管理面板。

启动流程：
  1. 读 data/domains.json，恢复各域名的配置与上次扫描结果
  2. 起 Web 管理界面（用户可以随时添加/删除域名）
  3. 后台为每个域名独立扫描，结果写入 hosts / 供 DNS 应答

设计原则：**任何情况下都不能让域名解析挂掉**。
  - 扫描失败 → 保留上一次结果
  - 从未扫出结果 → DNS 转发上游，站点照常可访问（只是没优化）
"""
import json
import os
import sys
import threading
import time
import traceback

from . import __version__, web
from .dnssrv import DnsServer
from .probe import (CF_V4, TUNNEL_REGIONS, expand_ranges, nets_from_results,
                    scan)
from .scanner import Scanner
from .store import DomainStore

LOG_PREFIX = "[cfopt]"


def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{ts} {LOG_PREFIX} {msg}", flush=True)


# ---------------------------------------------------------------- 配置
class Config:
    def __init__(self):
        self.target_host = os.environ.get("TARGET_HOST", "").strip()
        self.colos = [c.strip().upper() for c in
                      os.environ.get("COLOS", "HKG").split(",") if c.strip()]
        self.per_net = int(os.environ.get("PER_NET", "2"))
        self.workers = int(os.environ.get("WORKERS", "200"))
        self.interval = int(os.environ.get("INTERVAL", "21600"))
        self.top_n = int(os.environ.get("TOP_N", "3"))
        self.timeout = float(os.environ.get("TIMEOUT", "3"))
        self.dns_listen = os.environ.get("DNS_LISTEN", "0.0.0.0:53")
        # 隧道加速专用 DNS：只服务 cloudflared，单独占一个非特权端口，
        # 不碰 NAS 系统 DNS，关掉开关也不会影响本机其它解析。
        self.tunnel_dns_listen = os.environ.get("TUNNEL_DNS_LISTEN",
                                                "0.0.0.0:15353")
        self.upstreams = self._parse_upstreams(
            os.environ.get("UPSTREAMS", "223.5.5.5:53,119.29.29.29:53"))
        self.data_dir = os.environ.get("DATA_DIR", "/data")
        self.http_port = int(os.environ.get("HTTP_PORT", "8080"))
        # 多域名配置与 mosdns 兼容的 hosts 输出
        self.domains_file = os.path.join(self.data_dir, "domains.json")
        self.hosts_file = os.path.join(self.data_dir, "hosts.txt")
        # 跳过启动自动扫描，只用于 CI 冒烟测试，避免给 CF 发无谓请求
        self.skip_scan = os.environ.get("SKIP_SCAN", "").lower() in ("1", "true", "yes")
        # DNS 绑定失败时是否直接退出。默认 True：宁可起不来，
        # 也不要"看起来在跑但完全不生效"。
        self.fail_fast = os.environ.get("FAIL_FAST", "1").lower() not in ("0", "false", "no")
        # 模式：dns = 起 DNS 服务；hosts = 只写 hosts 文件不起 DNS
        # 只给单机用时选 hosts：少一个可能挂掉的组件，整机解析不依赖容器存活
        self.mode = os.environ.get("MODE", "dns").strip().lower()
        # MODE=hosts 时写入的系统 hosts 文件路径（容器内需挂载宿主机文件）
        self.system_hosts = os.environ.get("SYSTEM_HOSTS", "")
        self.hosts_marker = "cfopt-managed"

    @staticmethod
    def _parse_upstreams(raw):
        out = []
        for item in raw.split(","):
            item = item.strip()
            if not item:
                continue
            if ":" in item and item.count(":") == 1:
                host, port = item.rsplit(":", 1)
                out.append((host, int(port)))
            else:
                out.append((item, 53))
        return out or [("223.5.5.5", 53)]

    def validate(self):
        # 多域名模式下 TARGET_HOST 是可选的：不填就用空配置启动，
        # 用户在 Web 面板里添加域名。填了则作为首次迁移的初始域名。
        if self.target_host and self.interval < 600:
            log(f"警告：INTERVAL={self.interval}s 过短，已提升到 600s")
            self.interval = 600


# ---------------------------------------------------------------- 状态

def write_hosts_all(cfg, domains):
    """把所有已启用的、已扫描成功的域名写进 hosts 文件。

    data/hosts.txt 用 mosdns 格式（域名在前）；系统 /etc/hosts 用
    标准格式（IP 在前），两者都由这里统一产出。
    即使一个可写域名都没有也要写：这样才能把已删除/已停用域名的
    旧记录清掉，而不是永久残留在 /etc/hosts 里。
    """
    rows = [(d.host, d.get_ips()) for d in domains
            if d.enabled and d.get_ips()]

    # 1) data/hosts.txt —— mosdns 兼容格式
    try:
        os.makedirs(cfg.data_dir, exist_ok=True)
        tmp = cfg.hosts_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(f"# cfopt {__version__}  "
                    f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            for host, ips in rows:
                f.write(f"{host} {' '.join(ips)}\n")
        os.replace(tmp, cfg.hosts_file)
        log(f"已写入 {cfg.hosts_file}（{len(rows)} 个域名）")
    except Exception as e:
        log(f"hosts 写入失败：{e}")

    # 2) 系统 hosts —— 仅 hosts 模式
    if cfg.mode == "hosts" and cfg.system_hosts:
        write_system_hosts(cfg, rows)


def write_system_hosts(cfg, rows):
    """把多个域名的优选 IP 写进系统 /etc/hosts，只改自己标记的区块。

    rows 是 [(host, [ip, ...]), ...]。
    单机使用时这比起一个 DNS 服务更稳：容器挂了，hosts 里已有的解析
    依然有效，不会导致整机断网。
    """
    path = cfg.system_hosts
    begin = f"# >>> {cfg.hosts_marker} >>>"
    end = f"# <<< {cfg.hosts_marker} <<<"
    try:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except FileNotFoundError:
            lines = []

        # 剔除上一次写入的区块，避免重复累积
        kept, skipping = [], False
        for line in lines:
            if line.strip() == begin:
                skipping = True
                continue
            if line.strip() == end:
                skipping = False
                continue
            if not skipping:
                kept.append(line)

        block = [begin]
        count = 0
        for host, ips in rows:
            for ip in ips:
                block.append(f"{ip}\t{host}")
                count += 1
        block.append(end)

        content = "\n".join(kept + block) + "\n"
        tmp = path + ".cfopt.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(content)
        try:
            os.replace(tmp, path)
        except OSError as e:
            # Docker 单文件挂载（- /etc/hosts:/hosts/etc-hosts）时，
            # 挂载点是独立挂载点，跨挂载点 rename 会 EBUSY。
            # 此时退回原地写入：非原子，但这是唯一可行的方式。
            log(f"原子替换失败（{e.strerror or e}），改为原地写入")
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            try:
                os.unlink(tmp)
            except OSError:
                pass
        log(f"已更新系统 hosts：{path}（{count} 条）")
    except PermissionError:
        log(f"系统 hosts 写入失败：权限不足（{path} 需要 root 或可写挂载）")
    except Exception as e:
        log(f"系统 hosts 写入失败：{e}")


def main():
    cfg = Config()
    cfg.validate()
    log(f"cfopt v{__version__} 启动")
    log(f"数据目录 {cfg.data_dir} · 运行模式 {cfg.mode}")

    # ---------------------------------------------------------- 多域名存储
    os.makedirs(cfg.data_dir, exist_ok=True)
    store = DomainStore(cfg.domains_file, log=log)

    # 向后兼容：老版本用环境变量配置单域名，升级后自动迁移成一条记录
    if cfg.target_host:
        store.ensure_from_env(cfg.target_host, cfg.colos, cfg.top_n,
                              cfg.per_net, cfg.interval)
    if not store.list():
        log(f"还没有任何域名。打开面板添加：http://<本机IP>:{cfg.http_port}/")

    # ---------------------------------------------------------- 扫描器
    scanner = Scanner(store, workers=cfg.workers, timeout=cfg.timeout, log=log)

    # ---------------------------------------------------------- DNS 服务
    dns = None
    if cfg.mode == "dns":
        host, port = cfg.dns_listen.rsplit(":", 1)
        dns = DnsServer(
            listen_host=host,
            listen_port=int(port),
            upstreams=cfg.upstreams,
            match_domains=[d.host for d in store.list()],
            get_ips=_make_resolver(store),
            log=log,
        )
        dns.start()
        log(f"上游 DNS：{', '.join(f'{h}:{p}' for h, p in cfg.upstreams)}")
        if not dns.ok:
            log("=" * 60)
            log("致命错误：DNS 服务未能启动")
            log(f"  {dns.udp_error or 'UDP 绑定超时'}")
            log("  排查：53 端口是否被占用（ss -lunp | grep :53）")
            log("=" * 60)
            if cfg.fail_fast:
                return 1

    # ---------------------------------------------------------- 隧道加速 DNS
    # 与主 DNS 独立：MODE=hosts 时也要能用，因为 cloudflared 是自己指定
    # 解析器（TUNNEL_DNS_RESOLVER_ADDRS），不依赖系统 DNS。
    # 端口被占只告警不退出：隧道加速属于增强功能，不该拖累域名优选。
    thost, tport = cfg.tunnel_dns_listen.rsplit(":", 1)
    cfg.tunnel_dns_port = int(tport)
    tunnel_dns = DnsServer(
        listen_host=thost,
        listen_port=int(tport),
        upstreams=cfg.upstreams,
        match_domains=list(TUNNEL_REGIONS),
        get_ips=_make_tunnel_resolver(store),
        log=log,
    )
    tunnel_dns.start()
    if tunnel_dns.ok:
        log(f"Tunnel 加速 DNS：{thost}:{tport}"
            f"（{'已开启' if store.tunnel.enabled else '未开启'}）")
    else:
        log(f"Tunnel 加速 DNS 启动失败：{tunnel_dns.udp_error or '绑定超时'}，"
            f"可用 TUNNEL_DNS_LISTEN=0.0.0.0:<其他端口> 更换")

    # ---------------------------------------------------------- 扫描循环
    def hosts_sig():
        """当前应写进 hosts 的内容签名，增删改启停都会让它变化。"""
        return tuple((d.id, tuple(d.get_ips()))
                     for d in store.enabled() if d.get_ips())

    def needs_scan(d):
        if not d.last_scan_at or not d.ips:
            return True
        if d.max_ms:
            # 旧结果里可能还有超过延迟上限的节点，重启后立即重扫
            ms = {n["ip"]: n["connect_ms"] for n in d.nodes}
            if any(ms.get(ip, 0) > d.max_ms for ip in d.ips):
                return True
        return False

    def scan_loop():
        write_hosts_all(cfg, store.list())
        last_sig = hosts_sig()

        # 交给调度器立即按域名并行派发；不要在这里同步 scan_one，
        # 否则第一个域名全量扫描期间，后面的域名会一直显示“排队中”。
        scanner.start()
        for d in store.enabled():
            if needs_scan(d):
                scanner.trigger(d)
        # 轮询签名而不是只看扫描时间：删除域名、停用域名、改配置
        # 都能在一轮内反映到 hosts，不会留下悬空记录
        while True:
            time.sleep(20)
            sig = hosts_sig()
            if sig != last_sig:
                last_sig = sig
                write_hosts_all(cfg, store.list())

    if not cfg.skip_scan:
        threading.Thread(target=scan_loop, daemon=True).start()
    else:
        log("SKIP_SCAN 已启用，不自动扫描")
        write_hosts_all(cfg, store.list())

    # ---------------------------------------------------------- Web 服务
    httpd = web.serve(cfg, store, scanner, tunnel_dns=tunnel_dns)
    log(f"管理界面 http://0.0.0.0:{cfg.http_port}/")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("收到中断，退出")
    finally:
        scanner.stop()
        if dns:
            dns.stop()
        tunnel_dns.stop()
    return 0


def _make_resolver(store):
    """给 DnsServer 的多域名解析回调。

    按查询名查 store，返回该域名的优选 IP；查不到返回空列表，
    DnsServer 会自动回退上游，保证域名不会解析失败。
    """
    def resolve(qname=None):
        if qname is None:
            out = []
            for d in store.list():
                out.extend(d.get_ips())
            return out
        d = store.by_host(qname)
        if d:
            return d.get_ips()
        # 子域名继承父域名结果：CF 边缘对所有子域是同一套 anycast IP
        for d in store.list():
            if qname.endswith("." + d.host):
                return d.get_ips()
        return []

    return resolve


def _make_tunnel_resolver(store):
    """隧道加速的解析回调：只回答 region1/region2.v2.argotunnel.com。

    没有优选结果（未开启、还没扫、结果过期）时返回空列表，
    DnsServer 自动转发上游，连接器拿到 Cloudflare 的原始答案 ——
    最坏情况只是没提速，不会让隧道连不上。
    """
    def resolve(qname=None):
        pins = store.tunnel.pins()
        if qname is None:
            out = []
            for ips in pins.values():
                out.extend(ips)
            return out
        return list(pins.get(qname.rstrip(".").lower(), []))

    return resolve


if __name__ == "__main__":
    sys.exit(main())
