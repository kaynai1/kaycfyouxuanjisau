# -*- coding: utf-8 -*-
"""极简 DNS 服务：命中目标域名返回优选 IP，其余原样转发。

不依赖 mosdns / smartdns。实现要点：
- 只处理 A / AAAA，其余类型一律转发
- 目标域名 A 记录由优选结果生成，AAAA 返回空应答（促使客户端回退到 IPv4）
- 其他域名把原始报文转发给上游，原样回传，不解析内容
"""
import socket
import struct
import threading
import time

# 不支持的查询类型直接转发
QTYPE_A = 1
QTYPE_AAAA = 28


def parse_qname(data, offset=12):
    """解析查询名，返回 (域名小写, 结束偏移)。"""
    labels = []
    while True:
        if offset >= len(data):
            raise ValueError("truncated")
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:  # 查询报文里出现压缩指针，说明格式异常
            raise ValueError("compression in question")
        label = data[offset:offset + length]
        if len(label) < length:
            raise ValueError("truncated label")
        labels.append(label.decode("latin-1"))
        offset += length
    return ".".join(labels).lower(), offset


def parse_question(data):
    """返回 (qname, qtype, question_end_offset)。"""
    qname, off = parse_qname(data, 12)
    if off + 4 > len(data):
        raise ValueError("truncated question")
    qtype = struct.unpack("!H", data[off:off + 2])[0]
    return qname, qtype, off + 4


def build_answer(query, qname_end, qtype, ips, ttl=300):
    """构造应答：复制头部与问题段，追加 A 记录。"""
    tid = query[0:2]
    # 原始 flags 的低 4 位是 RCODE；取 opcode + RD，置 QR/RA
    qflags = struct.unpack("!H", query[2:4])[0]
    flags = 0x8000 | (qflags & 0x7800) | 0x0080 | (qflags & 0x0100)
    flags |= 0x0000  # NOERROR

    question = query[12:qname_end]
    ancount = len(ips) if qtype == QTYPE_A else 0

    header = tid + struct.pack("!HHHHH", flags, 1, ancount, 0, 0)
    body = bytearray(header + question)

    if qtype == QTYPE_A:
        for ip in ips:
            body += b"\xc0\x0c"                     # 指向问题段域名
            body += struct.pack("!HHIH", QTYPE_A, 1, ttl, 4)
            body += socket.inet_aton(ip)
    return bytes(body)


class DnsServer:
    def __init__(self, listen_host, listen_port, upstreams, match_domains,
                 get_ips, log=print):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstreams = upstreams
        self.match_domains = [d.lower().rstrip(".") for d in match_domains]
        self.get_ips = get_ips          # 回调，返回当前优选 IP 列表
        self.log = log
        self._stop = threading.Event()
        self._udp = None
        self._tcp = None
        self.queries = 0
        self.hits = 0
        # 绑定状态：供 main.py 在启动后校验，避免"看起来起来了其实没生效"
        self.udp_ready = False
        self.tcp_ready = False
        self.udp_error = ""
        self.tcp_error = ""

    # -------------------------------------------------- 匹配
    def _matches(self, qname):
        for d in self.match_domains:
            if qname == d or qname.endswith("." + d):
                return True
        return False

    def _ips_for(self, qname):
        """取该查询名对应的优选 IP。

        get_ips 优先按查询名解析（多域名模式）；老接口不接受参数时
        回退到无参调用，保持向后兼容。
        """
        try:
            return self.get_ips(qname) or []
        except TypeError:
            return self.get_ips() or []

    # -------------------------------------------------- 转发
    def _forward(self, packet):
        for up in self.upstreams:
            try:
                host, port = up
                fam = socket.AF_INET6 if ":" in host else socket.AF_INET
                with socket.socket(fam, socket.SOCK_DGRAM) as s:
                    s.settimeout(2.5)
                    s.sendto(packet, (host, port))
                    data, _ = s.recvfrom(4096)
                    return data
            except Exception:
                continue
        return None

    # -------------------------------------------------- 处理单个查询
    def handle(self, data):
        if len(data) < 12:
            return None
        try:
            qname, qtype, qend = parse_question(data)
        except Exception:
            return self._forward(data)

        self.queries += 1

        if qtype in (QTYPE_A, QTYPE_AAAA):
            # 多域名模式下按查询名精确取 IP；子域名继承父域名的结果
            ips = self._ips_for(qname)
            if not ips and not self._matches(qname):
                return self._forward(data)

            if qtype == QTYPE_AAAA:
                # 主动返回空 AAAA，促使客户端走 IPv4，
                # 避免 IPv6 被调度到远端机房
                self.hits += 1
                return build_answer(data, qend, qtype, [])

            if not ips:
                # 没有优选结果时绝不能返回空应答，否则域名直接解析失败。
                # 回退到上游，站点照常可访问（只是没优化）。
                return self._forward(data)
            self.hits += 1
            return build_answer(data, qend, qtype, ips)
        return self._forward(data)

    # -------------------------------------------------- UDP
    def _serve_udp(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.listen_host, self.listen_port))
        except OSError as e:
            # 必须显式上报：端口被占用时若静默崩溃，容器看起来"正常运行"，
            # 实际 DNS 完全无效，是极难排查的故障。
            self.udp_error = f"UDP {self.listen_host}:{self.listen_port} 绑定失败: {e}"
            self.log(f"[dns] 错误：{self.udp_error}")
            self.log("[dns] 常见原因：53 端口已被占用（飞牛OS 自带 DNS、"
                     "dnsmasq、AdGuardHome 等），或未授予 NET_BIND_SERVICE")
            s.close()
            return
        s.settimeout(1.0)
        self._udp = s
        self.udp_ready = True
        self.log(f"[dns] UDP 监听 {self.listen_host}:{self.listen_port}")
        while not self._stop.is_set():
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                resp = self.handle(data)
                if resp:
                    s.sendto(resp, addr)
            except Exception as e:
                self.log(f"[dns] UDP 处理异常: {e}")
        s.close()

    # -------------------------------------------------- TCP
    def _serve_tcp(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.listen_host, self.listen_port))
            s.listen(64)
        except OSError as e:
            self.tcp_error = f"TCP {self.listen_host}:{self.listen_port} 绑定失败: {e}"
            self.log(f"[dns] 错误：{self.tcp_error}")
            s.close()
            return
        s.settimeout(1.0)
        self._tcp = s
        self.tcp_ready = True
        self.log(f"[dns] TCP 监听 {self.listen_host}:{self.listen_port}")
        while not self._stop.is_set():
            try:
                conn, _ = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_tcp_conn, args=(conn,),
                             daemon=True).start()
        s.close()

    def _handle_tcp_conn(self, conn):
        try:
            conn.settimeout(5)
            head = self._recv_exact(conn, 2)
            if not head:
                return
            length = struct.unpack("!H", head)[0]
            data = self._recv_exact(conn, length)
            if not data:
                return
            resp = self.handle(data)
            if resp:
                conn.sendall(struct.pack("!H", len(resp)) + resp)
        except Exception:
            pass
        finally:
            conn.close()

    @staticmethod
    def _recv_exact(conn, n):
        buf = b""
        while len(buf) < n:
            ch = conn.recv(n - len(buf))
            if not ch:
                return None
            buf += ch
        return buf

    # -------------------------------------------------- 生命周期
    def start(self, wait=1.5):
        """启动 UDP/TCP 监听，并等待绑定结果。

        wait 秒内若 UDP 仍未就绪，说明端口冲突或权限不足——调用方应当
        据此决定是告警退出还是降级继续，而不是假装启动成功。
        """
        threading.Thread(target=self._serve_udp, daemon=True).start()
        threading.Thread(target=self._serve_tcp, daemon=True).start()
        deadline = time.time() + wait
        while time.time() < deadline:
            if self.udp_ready or self.udp_error:
                break
            time.sleep(0.05)

    @property
    def ok(self):
        """UDP 是否可用。DNS 主要走 UDP，UDP 挂了等于服务无效。"""
        return self.udp_ready

    def stop(self):
        self._stop.set()
        for s in (self._udp, self._tcp):
            try:
                if s:
                    s.close()
            except Exception:
                pass
