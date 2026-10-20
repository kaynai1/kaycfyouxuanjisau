# -*- coding: utf-8 -*-
"""多域名扫描调度。

每个域名独立线程、独立周期、独立网段缓存。
用"到期检查"而不是"每域名一个 sleep"，这样增删域名不需要重启。
"""
import threading
import time
import traceback

from .probe import (CF_V4, expand_ranges, fetch_v2too_ips,
                    nets_from_results, scan)


class Scanner:
    # 一次只跑一个域名的扫描。每个扫描自己就开 120–200 个探测线程，
    # 两个域名同时跑会互相抢 CPU/连接，实测连快速扫描都会整段超时，
    # 然后误回退到上万 IP 的全量扫描，反而更慢。
    MAX_CONCURRENT = 1

    def __init__(self, store, workers=200, timeout=3.0, log=print):
        self.store = store
        self.workers = workers
        self.timeout = timeout
        self.log = log
        self._stop = threading.Event()
        self._running = {}          # domain_id -> bool，防止同一域名并发扫
        self._slots = threading.Semaphore(self.MAX_CONCURRENT)
        self._lock = threading.Lock()

    # ---------------------------------------------------------- 单域名扫描
    def scan_one(self, domain):
        """扫描一个域名。失败不影响其他域名。"""
        with self._lock:
            if self._running.get(domain.id):
                self.log(f"[{domain.host}] 已有扫描在进行，跳过")
                return
            self._running[domain.id] = True
        try:
            if not self._slots.acquire(blocking=False):
                self.log(f"[{domain.host}] 等待其他域名扫描完成")
                self._slots.acquire()
            try:
                self._do_scan(domain)
            finally:
                self._slots.release()
        except Exception:
            err = traceback.format_exc(limit=2)
            domain.mark_failed(err)
            self.log(f"[{domain.host}] 扫描异常：{err}")
        finally:
            with self._lock:
                self._running.pop(domain.id, None)
            self.store.save()

    def _with_v2too(self, ips, host):
        """把 v2too 的三网优选 IP 并入候选，仍由本机实测决定排序和机房。"""
        extra = fetch_v2too_ips()
        if not extra:
            self.log(f"[{host}] v2too 优选源暂不可用，继续使用内置网段")
            return ips
        seen = set(ips)
        added = [ip for ip in extra if ip not in seen]
        if added:
            self.log(f"[{host}] 加入 v2too 优选源 {len(added)} 个候选 IP")
        return ips + added

    def _do_scan(self, domain):
        host = domain.host
        self.log(f"[{host}] 开始扫描，目标机房 {','.join(domain.colos)}")

        # 网段缓存必须和目标机房绑定。
        # 之前的 bug：缓存只按"当时命中的机房"生成，且一旦存在就永远只用它。
        # 结果是把机房从 NRT 改成 HKG 后，缓存里全是 NRT 的段，
        # 再怎么扫都只会看到 NRT/SIN/LAX，永远出不来 HKG。
        cache_colos = getattr(domain, "nets_colos", None) or []
        # 自动切换机房后，缓存对应的是实际采用的机房而不是偏好机房，
        # 两种都算有效，否则下一轮又会掉进全量扫描。
        cache_valid = bool(domain.nets) and (
            cache_colos == list(domain.colos)
            or cache_colos == list(domain.fallback_colos or []))
        if domain.nets and not cache_valid:
            self.log(f"[{host}] 机房已变更（缓存来自 {','.join(cache_colos) or '未知'}），"
                     f"丢弃网段缓存，改为全量扫描")
            domain.nets = []

        cidrs = domain.nets if cache_valid else CF_V4
        fast = cache_valid
        ips = self._with_v2too(expand_ranges(cidrs, domain.per_net), host)
        self.log(f"[{host}] {'快速' if fast else '全量'}扫描，"
                 f"{len(ips)} 个候选 IP")

        t0 = time.time()
        # 实时进度写进 domain，前端轮询就能看到百分比，
        # 不用干等十几分钟不知道卡在哪
        domain.set_progress(0, len(ips), 0)

        def on_progress(done, total, alive):
            domain.set_progress(done, total, alive)

        # 小批量（快速扫描）不需要上百个线程，线程太多反而容易整批超时
        if len(ips) <= 200:
            scan_workers = min(self.workers, 32)
        elif len(ips) <= 1000:
            scan_workers = min(self.workers, 64)
        else:
            scan_workers = self.workers
        results = scan(ips, host, workers=scan_workers,
                       timeout=self.timeout, progress=on_progress,
                       refine_top=20)
        if not results and fast:
            # 瞬时抖动/连接拥塞会让整批探测都失败。先用低并发重试一次，
            # 不要直接掉进上万 IP 的全量扫描（那会把后面的域名堵很久）。
            self.log(f"[{host}] 快速扫描无存活，低并发重试一次")
            domain.set_progress(0, len(ips), 0)
            results = scan(ips, host, workers=min(16, max(4, len(ips))),
                           timeout=self.timeout, progress=on_progress,
                           refine_top=20)
        # 快速模式只扫缓存网段；整段不可达时回退全量，避免永远空结果
        if not results and fast:
            fast = False
            domain.nets = []
            ips = self._with_v2too(expand_ranges(CF_V4, domain.per_net), host)
            self.log(f"[{host}] 快速扫描无存活，回退全量（{len(ips)} 个候选）")
            domain.set_progress(0, len(ips), 0)
            results = scan(ips, host, workers=self.workers,
                           timeout=self.timeout, progress=on_progress,
                           refine_top=20)
        domain.clear_progress()
        self.log(f"[{host}] 存活 {len(results)} 个，耗时 {time.time() - t0:.0f}s")

        if not results:
            domain.mark_failed("所有 IP 均不可达")
            return

        dist = {}
        for r in results:
            dist[r["colo"]] = dist.get(r["colo"], 0) + 1

        # 延迟上限：超过 max_ms 的节点不进入下发列表（0 = 不限）
        limit = domain.max_ms or 0
        eligible = results
        if limit:
            eligible = [r for r in results if r["connect_ms"] <= limit]
            if not eligible:
                fastest = min(r["connect_ms"] for r in results)
                domain.mark_failed(
                    f"没有延迟 ≤{limit}ms 的节点（最快 {fastest:.0f}ms），"
                    f"已停止下发", clear_ips=True)
                return

        # 每轮都记下各机房的最快延迟，界面用它解释为什么换机房。
        colo_best = {}
        for r in eligible:
            if r["colo"] == "???":
                continue
            if r["connect_ms"] < colo_best.get(r["colo"], float("inf")):
                colo_best[r["colo"]] = r["connect_ms"]
        colo_best = {c: round(ms, 1) for c, ms in colo_best.items()}

        picked = [r for r in eligible if r["colo"] in domain.colos]
        warning = ""
        fallback_colos = []
        auto_switched = False
        if picked:
            # 目标机房只是偏好，不是硬限制：NAS 的出口线路经常让 HKG
            # 变成 150ms+，而同一时刻 SJC/LAX 只有几十毫秒。别的机房
            # 快 20ms 以上就直接采用，否则等于逼用户用慢节点。
            known = [r for r in eligible if r["colo"] != "???"]
            target_best = min(r["connect_ms"] for r in picked)
            if known:
                auto_best = min(known, key=lambda r: (r["connect_ms"], r["ttfb_ms"]))
                if (auto_best["colo"] not in domain.colos
                        and auto_best["connect_ms"] + 20 <= target_best):
                    auto_switched = True
                    picked = known
                    warning = (
                        f"偏好机房 {','.join(domain.colos)} 最快 {target_best:.0f}ms，"
                        f"已自动采用快 {target_best - auto_best['connect_ms']:.0f}ms 的 "
                        f"{auto_best['colo']}（{auto_best['connect_ms']:.0f}ms）节点")
                    self.log(f"[{host}] {warning}")
        if not picked:
            # 目标机房没有节点时自动降级，别让整个域名变成"未接入"。
            # ??? 是拿不到 CF-RAY 的异常响应，不参与选择。
            known = [r for r in eligible if r["colo"] != "???"]
            if not known:
                domain.mark_failed("只探测到无法识别机房的响应")
                return
            counts = {}
            for r in known:
                counts[r["colo"]] = counts.get(r["colo"], 0) + 1
            fallback_colos = [c for c, _ in
                              sorted(counts.items(), key=lambda kv: -kv[1])][:3]
            picked = known
            suffix = f"（≤{limit}ms）" if limit else ""
            warning = (f"未发现 {','.join(domain.colos)} 节点{suffix}，"
                       f"已自动采用 {','.join(fallback_colos)} 的可用节点")
            self.log(f"[{host}] {warning}")

        picked.sort(key=lambda r: (r["connect_ms"], r["ttfb_ms"]))
        top = picked[: domain.top_n]
        new_ips = [r["ip"] for r in top]
        if auto_switched and top:
            # 实际下发的机房，供界面高亮和「改用」按钮使用
            fallback_colos = sorted({r["colo"] for r in top})

        # 完整候选明细：命中机房的全部，按延迟排序。
        # 界面要靠它显示"扫到了哪些节点、各自延迟多少"，
        # 而不是只看到最终选中的两三个。
        nodes = [{"ip": r["ip"], "colo": r["colo"],
                  "connect_ms": round(r["connect_ms"], 1),
                  "ttfb_ms": round(r["ttfb_ms"], 1)}
                 for r in picked]

        # 生成/更新网段缓存，并记下它对应的机房。
        # 每轮全量扫描后都刷新，避免缓存长期停留在过期网段上。
        effective_colos = fallback_colos or domain.colos
        nets = domain.nets
        if fast and fallback_colos and not auto_switched:
            # 缓存网段里已经没有目标机房：作废缓存，下一轮全量重新找
            domain.nets_colos = []
        if not fast or auto_switched:
            # 自动切换机房时，快速扫描的命中同样可以重建缓存：
            # 这批网段刚被验证过，下一轮不用再全量。
            nets = []
            for colo in effective_colos:
                part = nets_from_results(eligible, colo, limit=100)
                if part:
                    nets.extend(part)
            if not nets:
                # 一个都没命中，退而记录命中数最多的机房
                top_colo = max(dist.items(), key=lambda kv: kv[1])[0]
                nets = nets_from_results(eligible, top_colo, limit=200)
            if nets:
                domain.nets_colos = list(effective_colos)
                self.log(f"[{host}] 记录 {len(nets)} 个网段（对应机房 "
                         f"{','.join(effective_colos)}）")
            elif auto_switched:
                domain.nets_colos = []

        domain.apply_scan(new_ips, dist, nets, nodes=nodes,
                          total_alive=len(results), warning=warning,
                          fallback_colos=fallback_colos, colo_best=colo_best)
        self.log(f"[{host}] 可用 {len(picked)} 个节点，采用 "
                 f"{','.join(effective_colos)}，选中 " + ", ".join(
                     f"{r['ip']}({r['connect_ms']:.0f}ms)" for r in top))

    # ---------------------------------------------------------- 调度循环
    def start(self):
        threading.Thread(target=self._loop, daemon=True).start()
        self.log("扫描调度器已启动")

    def _loop(self):
        while not self._stop.is_set():
            now = int(time.time())
            for d in self.store.enabled():
                if now - d.last_scan_at >= d.interval:
                    # 每个域名独立线程，互不阻塞
                    threading.Thread(target=self.scan_one, args=(d,),
                                     daemon=True).start()
                    # 错开一点，避免瞬间打出几百个并发
                    time.sleep(0.5)
            self._stop.wait(30)

    def trigger(self, domain):
        """手动触发，立即返回。"""
        threading.Thread(target=self.scan_one, args=(domain,),
                         daemon=True).start()

    def stop(self):
        self._stop.set()

    def is_running(self, domain_id):
        with self._lock:
            return bool(self._running.get(domain_id))
