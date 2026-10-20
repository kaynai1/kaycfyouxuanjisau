# -*- coding: utf-8 -*-
"""cfopt 命令行入口：兼容原有子命令用法。"""
import argparse
import json
import os
import sys
import time

from . import __version__
from .probe import CF_V4, download_speed, expand_ranges, nets_from_results, probe, scan


def _load_nets(path):
    with open(path, encoding="utf-8") as f:
        return [s.strip() for s in
                f.read().replace("\n", ",").split(",") if s.strip()]


def cmd_scan(args):
    if args.nets_file and os.path.exists(args.nets_file):
        cidrs = _load_nets(args.nets_file)
        print(f"从 {args.nets_file} 载入 {len(cidrs)} 个网段")
    elif args.ranges:
        cidrs = [c.strip() for c in args.ranges.split(",") if c.strip()]
    else:
        cidrs = CF_V4

    want = set() if args.colo.upper() == "ALL" else {
        c.strip().upper() for c in args.colo.split(",") if c.strip()}
    ips = expand_ranges(cidrs, args.per_net)
    print(f"目标域名: {args.host}")
    print(f"目标机房: {'不过滤' if not want else ','.join(sorted(want))}")
    print(f"候选 IP: {len(ips)} 个（{len(cidrs)} 个网段）")
    print("开始扫描 ...")

    t0 = time.time()

    def progress(done, total, alive):
        print(f"\r  进度 {done}/{total}  存活 {alive}", end="", flush=True)

    results = scan(ips, args.host, workers=args.workers,
                   timeout=args.timeout, progress=progress)
    print(f"\n完成，存活 {len(results)} 个，耗时 {time.time() - t0:.1f}s")
    if not results:
        print("没有任何 IP 存活。", file=sys.stderr)
        return 1

    dist = {}
    for r in results:
        dist[r["colo"]] = dist.get(r["colo"], 0) + 1
    print("\n机房分布:")
    for colo, cnt in sorted(dist.items(), key=lambda kv: -kv[1]):
        print(f"  {colo:<6} {cnt:>5} 个{'  <-- 目标' if colo in want else ''}")

    picked = [r for r in results if r["colo"] in want] if want else results
    if not picked:
        print(f"\n没有落到 {','.join(sorted(want))} 的 IP。", file=sys.stderr)
        return 1

    picked.sort(key=lambda r: (r["connect_ms"], r["ttfb_ms"]))
    top = picked[: args.top]
    print(f"\n{'=' * 60}\n最优 {len(top)} 个\n{'=' * 60}")
    print(f"{'IP':<17}{'机房':<6}{'握手ms':>8}{'TTFB ms':>9}")
    print("-" * 60)
    for r in top:
        print(f"{r['ip']:<17}{r['colo']:<6}{r['connect_ms']:>8.0f}{r['ttfb_ms']:>9.0f}")

    if args.write_json:
        with open(args.write_json, "w", encoding="utf-8") as f:
            json.dump({
                "host": args.host,
                "colo_filter": sorted(want),
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "colo_distribution": dist,
                "top": top,
                "all": sorted(results, key=lambda r: r["connect_ms"]),
            }, f, ensure_ascii=False, indent=2)
        print(f"\n已写入 {args.write_json}")

    if args.write_hosts:
        tmp = args.write_hosts + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(f"# cfopt {__version__} "
                    f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{args.host} {' '.join(r['ip'] for r in top)}\n")
        os.replace(tmp, args.write_hosts)
        print(f"已写入 {args.write_hosts}")

    print(f"\n总耗时 {time.time() - t0:.1f}s")
    return 0


def cmd_nets(args):
    d = json.load(open(args.from_json, encoding="utf-8"))
    colo = args.colo.upper()
    rows = [r for r in d["all"] if r["colo"] == colo]
    if not rows:
        print(f"{args.from_json} 里没有 {colo} 的 IP", file=sys.stderr)
        return 1
    nets = nets_from_results(d["all"], colo)
    print(f"{colo} IP 共 {len(rows)} 个，分布在 {len(nets)} 个 /24 网段")
    for n in nets[:20]:
        print(f"  {n}")
    if args.write:
        with open(args.write, "w", encoding="utf-8") as f:
            f.write(",".join(nets))
        print(f"\n已写入 {args.write}（{len(nets)} 个网段）")
    return 0


def cmd_check(args):
    ips = [s.strip() for s in args.ips.split(",") if s.strip()]
    print(f"目标域名: {args.host}\n检测 {len(ips)} 个 IP ...\n")
    print(f"{'IP':<17}{'机房':<6}{'握手ms':>8}{'TLS ms':>8}{'TTFB ms':>9}  状态")
    print("-" * 62)
    for ip in ips:
        r = probe(ip, args.host, timeout=args.timeout)
        if not r:
            print(f"{ip:<17}{'FAIL':<6}")
            continue
        print(f"{r['ip']:<17}{r['colo']:<6}{r['connect_ms']:>8.0f}"
              f"{r['tls_ms']:>8.0f}{r['ttfb_ms']:>9.0f}  {r['status']}")
    return 0


def cmd_bench(args):
    ips = [s.strip() for s in args.ips.split(",") if s.strip()]
    print(f"目标域名: {args.host}\n测速路径: {args.path}\n")
    print(f"{'IP':<17}{'握手ms':>8}{'耗时s':>8}{'字节':>10}{'速度MB/s':>10}")
    print("-" * 56)
    rows = []
    for ip in ips:
        pr = probe(ip, args.host, timeout=args.timeout)
        if not pr:
            print(f"{ip:<17}{'FAIL':>8}")
            continue
        runs = []
        for _ in range(args.rounds):
            r = download_speed(ip, args.host, args.path,
                               args.timeout, args.max_bytes)
            if r:
                runs.append(r)
        if not runs:
            print(f"{ip:<17}{pr['connect_ms']:>8.0f}{'下载失败':>8}")
            continue
        warm = runs[1:] if len(runs) > 1 else runs
        dt = sum(x[0] for x in warm) / len(warm)
        n = warm[-1][1]
        speed = (n / dt / 1024 / 1024) if dt > 0 else 0
        rows.append((ip, speed))
        print(f"{ip:<17}{pr['connect_ms']:>8.0f}{dt:>8.2f}{n:>10}{speed:>10.2f}")
    if rows:
        rows.sort(key=lambda x: -x[1])
        print(f"\n最快: {rows[0][0]}  {rows[0][1]:.2f} MB/s")
    return 0


def cmd_verify(args):
    """验证本机 DNS 是否真的在返回优选 IP。

    这是排查"部署了但没生效"的关键一步：直接向指定 DNS 发查询，
    对比它返回的 IP 和 hosts.txt 里记录的优选 IP。
    """
    import socket as _socket
    import struct as _struct

    def query(name, server, port, timeout=5.0):
        q = b"".join(bytes([len(p)]) + p.encode()
                     for p in name.split(".")) + b"\x00"
        pkt = (b"\x5a\x5a\x01\x00" + _struct.pack("!HHHH", 1, 0, 0, 0)
               + q + _struct.pack("!HH", 1, 1))
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(pkt, (server, port))
            data, _ = s.recvfrom(4096)
        finally:
            s.close()

        _, flags, qd, an, _, _ = _struct.unpack("!HHHHHH", data[:12])

        def skip_name(buf, pos):
            """跳过域名。压缩指针占 2 字节，普通标签占 1+len。"""
            while pos < len(buf):
                length = buf[pos]
                if length == 0:
                    return pos + 1
                if length & 0xC0:      # 压缩指针
                    return pos + 2
                pos += length + 1
            return pos

        off = 12
        for _ in range(qd):
            off = skip_name(data, off) + 4   # 跳过 QTYPE + QCLASS

        ips = []
        for _ in range(an):
            off = skip_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _, _, rdlen = _struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            if rtype == 1 and rdlen == 4:
                ips.append(".".join(str(b) for b in data[off:off + 4]))
            off += rdlen
        return flags & 0xF, ips

    print(f"DNS 服务器: {args.server}:{args.port}")
    print(f"目标域名:   {args.host}\n")

    rcode, ips = query(args.host, args.server, args.port)
    print(f"查询 {args.host}")
    if rcode != 0:
        print(f"  ❌ 返回 rcode={rcode}，DNS 异常")
        return 1
    if not ips:
        print("  ❌ 返回 0 条记录（域名无法解析）")
        return 1
    print(f"  ✅ 返回 {len(ips)} 条: {', '.join(ips)}")

    # 与 hosts 文件对照
    if args.hosts and os.path.exists(args.hosts):
        with open(args.hosts, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) > 1 and parts[0].rstrip(".") == args.host.rstrip("."):
                    expected = parts[1:]
                    if expected == ips:
                        print("  ✅ 与 hosts 文件一致")
                    else:
                        print(f"  ⚠️  hosts 文件记录的是: {', '.join(expected)}")
                    break

    # 判断是否落到了优选机房
    if args.check_colo:
        from .probe import probe
        for ip in ips:
            r = probe(ip, args.host, timeout=args.timeout, retries=1)
            if not r:
                print(f"  {ip:<17} 探测失败")
                continue
            mark = "✅" if r["colo"] in args.check_colo else "❌"
            print(f"  {mark} {ip:<17} 落地 {r['colo']}  "
                  f"握手 {r['connect_ms']:.0f}ms")

    # 普通域名必须能正常解析，否则说明转发坏了
    rcode2, ips2 = query("www.baidu.com", args.server, args.port)
    print(f"\n查询 www.baidu.com（验证转发）")
    if rcode2 == 0 and ips2:
        print(f"  ✅ 正常转发，返回 {len(ips2)} 条")
    else:
        print(f"  ❌ 转发异常 rcode={rcode2}")

    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="cfopt",
        description="Cloudflare 边缘 IP 优选（按机房筛选 + 延迟 + 吞吐）")
    ap.add_argument("-v", "--version", action="version",
                    version=f"cfopt {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("-H", "--host", required=True, help="目标域名")
        p.add_argument("-t", "--timeout", type=float, default=4.0)

    p = sub.add_parser("scan", help="扫描网段")
    common(p)
    p.add_argument("-c", "--colo", default="HKG", help="目标机房，默认 HKG")
    p.add_argument("-n", "--top", type=int, default=8)
    p.add_argument("-w", "--workers", type=int, default=120)
    p.add_argument("--per-net", type=int, default=1)
    p.add_argument("--ranges", default="")
    p.add_argument("--nets-file", default="")
    p.add_argument("--write-json", default="")
    p.add_argument("--write-hosts", default="")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("nets", help="从结果提取网段")
    p.add_argument("--from-json", required=True)
    p.add_argument("-c", "--colo", default="HKG")
    p.add_argument("--write", default="")
    p.set_defaults(func=cmd_nets)

    p = sub.add_parser("check", help="检测 IP 机房")
    common(p)
    p.add_argument("--ips", required=True)
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("bench", help="真实下载测速")
    common(p)
    p.add_argument("--ips", required=True)
    p.add_argument("--path", default="/")
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--max-bytes", type=int, default=8 * 1024 * 1024)
    p.set_defaults(func=cmd_bench)

    p = sub.add_parser("serve", help="启动守护进程（DNS + 定时优选）")
    p.set_defaults(func=lambda a: __import__("cfopt.main", fromlist=["main"]).main())

    p = sub.add_parser("verify", help="验证 DNS 是否真的返回优选 IP")
    p.add_argument("-H", "--host", required=True, help="目标域名")
    p.add_argument("-s", "--server", default="127.0.0.1", help="DNS 服务器")
    p.add_argument("-p", "--port", type=int, default=53, help="DNS 端口")
    p.add_argument("--hosts", default="", help="对照 hosts.txt 路径")
    p.add_argument("--check-colo", default="",
                   help="同时探测返回的 IP 落地机房，如 HKG")
    p.add_argument("-t", "--timeout", type=float, default=4.0)
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n已中断", file=sys.stderr)
        return 130
