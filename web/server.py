#!/usr/bin/env python3
"""GunGK Web 管理台（重写版，Python 标准库 only，无第三方依赖）.

设计原则（沿用并保留旧版已验证的安全基线，不降级）：
- 只监听内网地址（默认由 WEB_BIND 环境变量指定，绝不默认 0.0.0.0）。
- 口令只存 scrypt 哈希文件（600），登录防爆破：同 IP 5 次失败锁定 300 秒。
- 会话 token 12 小时 TTL，Cookie HttpOnly + SameSite=Strict；写操作必须带会话级 CSRF token
  和 X-Requested-With: XMLHttpRequest 头。
- 所有写操作（注销/挂断/重载/改配置/启停服务）都要二次确认（前端）+ 操作审计日志。
- 网闸数据唯一来源：GnuGk 状态口 TCP 7000（rv/cv/s 等），不绕开网闸、不直接改内存状态。
- 配置编辑只改白名单字段，保存前先做时间戳备份，改后 reload（只影响新呼叫）。

运行：
    python3 server.py --set-password   # 首次设置口令（交互输入两次）
    python3 server.py                  # 启动，默认监听 $WEB_BIND:$WEB_PORT

环境变量：
    WEB_BIND (默认 127.0.0.1，部署时填内网 IP)、WEB_PORT (默认 8090)
    GK_HOST (默认 127.0.0.1)、GK_PORT (默认 7000)
    GK_CONFIG (默认 /etc/gnugk/gatekeeper.ini)
    PASS_FILE (默认 /etc/gnugk-web/admin.pass)
    ACTIONS_LOG (默认 /opt/gnugk-web/actions.log)
    GK_LOG (默认 /var/log/gnugk.log)
    STATIC_DIR (默认本文件同目录下的 static/)
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

WEB_BIND = os.environ.get("WEB_BIND", "127.0.0.1")
WEB_PORT = int(os.environ.get("WEB_PORT", "8090"))
GK_HOST = os.environ.get("GK_HOST", "127.0.0.1")
GK_PORT = int(os.environ.get("GK_PORT", "7000"))
GK_CONFIG = os.environ.get("GK_CONFIG", "/etc/gnugk/gatekeeper.ini")
PASS_FILE = os.environ.get("PASS_FILE", "/etc/gnugk-web/admin.pass")
ACTIONS_LOG = os.environ.get("ACTIONS_LOG", "/opt/gnugk-web/actions.log")
GK_LOG = os.environ.get("GK_LOG", "/var/log/gnugk.log")
STATIC_DIR = os.environ.get("STATIC_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"))

SESSION_TTL = 12 * 3600
LOCK_AFTER = 5
LOCK_SECONDS = 300

sessions = {}          # token -> {"csrf": str, "expires": float}
failed = {}            # ip -> {"count": int, "until": float}
sessions_lock = threading.Lock()

# ---------------------------------------------------------------- 状态口
def decode_status(raw: bytes) -> str:
    """状态口文本解码；中文别名可能出现 latin1->utf8 双编码，做有保护的修复."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")


def repair_double_encoded(text: str) -> str:
    try:
        fixed = text.encode("latin-1").decode("utf-8")
        # 只有修复后不再含替换符、且确实变了，才采纳，避免误伤正常 ASCII
        if fixed != text and "\ufffd" not in fixed:
            return fixed
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass
    return text


def gk_command(cmd: str, timeout: float = 5.0) -> str:
    """向状态口发一条命令，读到以 ';' 结束的回复为止。返回解码后的文本。"""
    with socket.create_connection((GK_HOST, GK_PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        # 状态口连入可能先发 banner，读到第一个 ';' 后丢弃（若无 banner 也无害：见下）
        buf = b""
        try:
            while b";" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        # 若 banner 读完后连接仍可写命令，继续；否则重连一次再发命令
        try:
            sock.sendall((cmd.strip() + "\n").encode())
            out = b""
            while b";" not in out:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                out += chunk
            return decode_status(out)
        except (OSError, socket.timeout):
            # 回退：新连接直接发命令（适用于无 banner 的实现）
            with socket.create_connection((GK_HOST, GK_PORT), timeout=timeout) as sock2:
                sock2.settimeout(timeout)
                sock2.sendall((cmd.strip() + "\n").encode())
                out = b""
                while b";" not in out:
                    chunk = sock2.recv(4096)
                    if not chunk:
                        break
                    out += chunk
                return decode_status(out)


def gk_online() -> bool:
    try:
        gk_command("s", timeout=3.0)
        return True
    except Exception:
        return False


def parse_endpoints(raw: str):
    """解析 rv/par 输出：行以 RCF| 开头；格式随版本而异，做容错解析，原始行始终保留。"""
    endpoints = []
    count = None
    for line in raw.splitlines():
        line = line.strip()
        m = re.search(r"Number of Endpoints:\s*(\d+)", line)
        if m:
            count = int(m.group(1))
        if line.startswith("RCF|"):
            body = line[4:]
            ep = {"raw": repair_double_encoded(body)}
            # 尽力提取 IP:端口（形如 <IP>:<端口>）和第一个别名 token
            ipm = re.search(r"(\d+\.\d+\.\d+\.\d+:\d+)", body)
            if ipm:
                ep["address"] = ipm.group(1)
            parts = [p.strip() for p in body.split("|") if p.strip()]
            if parts:
                ep["alias"] = repair_double_encoded(parts[0])
            endpoints.append(ep)
    return endpoints, count


def parse_calls(raw: str):
    """解析 cv/pcc 输出：容错解析，原始行始终保留；呼叫号形如 'Call number N' 时提取。"""
    calls = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith(("All", "Number of", "CallTable", "--")):
            continue
        if line == ";" or line.startswith("CurrentCalls"):
            continue
        call = {"raw": repair_double_encoded(line)}
        m = re.search(r"Call number\s+(\d+)", line, re.I)
        if m:
            call["number"] = m.group(1)
        ipm = re.findall(r"(\d+\.\d+\.\d+\.\d+:\d+)", line)
        if ipm:
            call["addresses"] = ipm
        calls.append(call)
    return calls


def parse_stats(raw: str):
    stats = {"raw": raw}
    for key, pat in [
        ("total_endpoints", r"Total Endpoints:\s*(\d+)"),
        ("terminals", r"Terminals:\s*(\d+)"),
        ("gateways", r"Gateways:\s*(\d+)"),
    ]:
        m = re.search(pat, raw)
        if m:
            stats[key] = int(m.group(1))
    return stats


# ---------------------------------------------------------------- conntrack 速率（采样法）
_rate_state = {"ts": 0.0, "bytes_by_ip": {}, "rates": {}}
_rate_lock = threading.Lock()


def _conntrack_bytes():
    """读 /proc/net/nf_conntrack，汇总 RTP 段（30000-30999）UDP 流的字节数（按目的 IP）。"""
    totals = {}
    try:
        with open("/proc/net/nf_conntrack", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if "udp" not in line or "dport=3" not in line:
                    continue
                mport = re.search(r"dport=(\d+)", line)
                if not mport or not (30000 <= int(mport.group(1)) <= 30999):
                    continue
                mdst = re.search(r"dst=(\d+\.\d+\.\d+\.\d+)", line)
                mbytes = re.search(r"bytes=(\d+)", line)
                if mdst and mbytes:
                    totals[mdst.group(1)] = totals.get(mdst.group(1), 0) + int(mbytes.group(1))
    except OSError:
        return None
    return totals


def sample_rates():
    """每 5 秒采样一次（由后台线程调用），用字节增量算 kbps；无 conntrack 时返回 None。"""
    now = time.time()
    totals = _conntrack_bytes()
    if totals is None:
        return None
    with _rate_lock:
        prev_ts, prev = _rate_state["ts"], _rate_state["bytes_by_ip"]
        rates = {}
        if prev_ts and now > prev_ts:
            for ip, total in totals.items():
                delta = total - prev.get(ip, 0)
                if delta > 0:
                    rates[ip] = round(delta * 8 / (now - prev_ts) / 1000, 1)
        _rate_state.update({"ts": now, "bytes_by_ip": totals, "rates": rates})
        return rates


def _rate_sampler():
    while True:
        try:
            sample_rates()
        except Exception:
            pass
        time.sleep(5)


# ---------------------------------------------------------------- 口令与会话
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return "scrypt$16384$8$1$" + salt.hex() + "$" + dk.hex()


def verify_password(password: str) -> bool:
    try:
        with open(PASS_FILE, encoding="utf-8") as fh:
            stored = fh.read().strip()
        _, n, r, p, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                            n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def password_configured() -> bool:
    try:
        with open(PASS_FILE, encoding="utf-8") as fh:
            return fh.read().strip().startswith("scrypt$")
    except OSError:
        return False


def is_locked(ip: str) -> bool:
    ent = failed.get(ip)
    return bool(ent and ent.get("until", 0) > time.time())


def record_failure(ip: str):
    ent = failed.setdefault(ip, {"count": 0, "until": 0})
    ent["count"] += 1
    if ent["count"] >= LOCK_AFTER:
        ent["until"] = time.time() + LOCK_SECONDS
        ent["count"] = 0


def new_session():
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    with sessions_lock:
        sessions[token] = {"csrf": csrf, "expires": time.time() + SESSION_TTL}
    return token, csrf


def get_session(handler):
    cookie = handler.headers.get("Cookie", "")
    m = re.search(r"session=([^;]+)", cookie)
    if not m:
        return None
    with sessions_lock:
        sess = sessions.get(m.group(1))
        if sess and sess["expires"] > time.time():
            return sess
        sessions.pop(m.group(1), None)
    return None


def log_action(ip: str, action: str, result: str):
    line = f"{datetime.now().isoformat(timespec='seconds')} {ip} {action} {result}\n"
    try:
        os.makedirs(os.path.dirname(ACTIONS_LOG) or ".", exist_ok=True)
        with open(ACTIONS_LOG, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass


# ---------------------------------------------------------------- 配置编辑（白名单字段）
EDITABLE = {
    # section -> {field: (label, hint)}
    "Gatekeeper::Main": {"Home": ("监听地址（内网,公网）", "逗号分隔两个 IP，状态口 7000 随 Home 监听")},
    "RoutedMode": {
        "AcceptUnregisteredCalls": ("接受未注册呼叫", "1=接受，0=拒绝"),
        "H245PortRange": ("H.245 端口段", "例如 21000-21999"),
    },
    "Proxy": {
        "RTPPortRange": ("RTP/RTCP 端口段", "例如 30000-30999"),
        "InternalNetwork": ("内网网段", "填本环境内网网段，例如 <INTERNAL_CIDR>"),
        "IgnoreSignaledIPs": ("忽略信令 IP", "1=开启（配合白名单）"),
        "AllowSignaledIPsFrom": ("信令 IP 白名单来源网段", "逗号分隔的管理网段"),
        "AllowSignaledIPs": ("信令 IP 白名单（固定 IP）", "只列真正可达的固定 IP，不要填全部私网段"),
    },
    "RasSrv::RRQFeatures": {
        "SupportDynamicIP": ("动态 IP 注册", "换网后同别名换 IP 不被拒绝"),
        "OverwriteEPOnSameAddress": ("同地址覆盖注册", "1=开启"),
    },
    "GkStatus::Auth": {
        "rule": ("状态口鉴权规则", "建议 regex"),
        "regex": ("状态口放行正则", "只放行回环与管理网段"),
        "default": ("状态口默认动作", "建议 forbid"),
        "Shutdown": ("状态口关机命令", "必须 forbid"),
    },
}


def read_config_fields():
    """读 gatekeeper.ini，返回白名单字段的当前值（缺失则为空），以及文件是否存在。"""
    fields = {}
    section = None
    try:
        with open(GK_CONFIG, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return fields, False
    for line in lines:
        s = line.strip()
        m = re.match(r"\[(.+)\]", s)
        if m:
            section = m.group(1)
            continue
        if section in EDITABLE and "=" in s and not s.startswith(("#", ";")):
            k, v = s.split("=", 1)
            if k.strip() in EDITABLE[section]:
                fields[f"{section}.{k.strip()}"] = v.strip()
    return fields, True


def write_config_fields(updates: dict):
    """只改白名单字段，其余行原样保留；保存前做时间戳备份。返回备份路径。"""
    with open(GK_CONFIG, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    backup = f"{GK_CONFIG}.bak-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    with open(backup, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    section = None
    done = set()
    out = []
    for line in lines:
        s = line.strip()
        m = re.match(r"\[(.+)\]", s)
        if m:
            section = m.group(1)
            out.append(line)
            continue
        if section in EDITABLE and "=" in s and not s.startswith(("#", ";")):
            k = s.split("=", 1)[0].strip()
            key = f"{section}.{k}"
            if key in updates:
                out.append(f"{k}={updates[key]}\n")
                done.add(key)
                continue
        out.append(line)
    # 白名单字段在原文件不存在时，追加到对应段末尾（段不存在则新建段）
    for key, value in updates.items():
        if key in done:
            continue
        sec, field = key.split(".", 1)
        out.append(f"\n[{sec}]\n{field}={value}\n")
    with open(GK_CONFIG, "w", encoding="utf-8") as fh:
        fh.writelines(out)
    return backup


# ---------------------------------------------------------------- HTTP 层
READ_COMMANDS = {"rv": "rv", "par": "par", "cv": "cv", "pcc": "pcc", "s": "s"}
ACTIONS = {
    "unregister_alias": lambda t: f"ua {t}",
    "unregister_ip": lambda t: f"uip {t}",
    "unregister_all": lambda t: "uae",
    "disconnect_call": lambda t: f"dc {t}",
    "disconnect_ip": lambda t: f"dip {t}",
    "disconnect_alias": lambda t: f"dca {t}",
    "disconnect_all": lambda t: "cc",
    "reload": lambda t: "reload",
}
SERVICES = {"gnugk", "gnugk-web", "gnugk-routes", "nftables"}
SERVICE_OPS = {"start", "stop", "restart"}


def run_cmd(args, timeout=5):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return f"error: {e}"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # 不向 stdout 刷访问日志，保持日志干净
        pass

    def _headers(self, status=200, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'")

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self._headers(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(n) if n else b""
            return json.loads(raw.decode() or "{}")
        except Exception:
            return {}

    def _require_auth(self):
        sess = get_session(self)
        if not sess:
            self._json({"error": "unauthorized"}, 401)
            return None
        return sess

    def _require_csrf(self, sess):
        if self.headers.get("X-Requested-With") != "XMLHttpRequest":
            return False
        return hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), sess["csrf"])

    def _serve_static(self, path):
        name = "index.html" if path in ("/", "") else path.lstrip("/")
        if ".." in name or "/" in name:
            self._json({"error": "not found"}, 404)
            return
        full = os.path.join(STATIC_DIR, name)
        if not os.path.isfile(full):
            self._json({"error": "not found"}, 404)
            return
        ctype = "text/html" if name.endswith(".html") else "text/css" if name.endswith(".css") \
            else "application/javascript" if name.endswith(".js") else "text/plain"
        with open(full, "rb") as fh:
            body = fh.read()
        self._headers(200, ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/", "/index.html", "/app.js", "/style.css"):
            self._serve_static(path)
            return
        sess = self._require_auth()
        if not sess:
            return
        ip = self.client_address[0]
        if path == "/api/me":
            self._json({"authenticated": True, "csrf": sess["csrf"]})
        elif path == "/api/state":
            try:
                rv = gk_command("rv")
                cv = gk_command("cv")
                st = gk_command("s")
                endpoints, count = parse_endpoints(rv)
                calls = parse_calls(cv)
                with _rate_lock:
                    rates = dict(_rate_state["rates"])
                self._json({
                    "gk_online": True, "sampled_at": datetime.now().isoformat(timespec="seconds"),
                    "endpoints": endpoints, "endpoint_count": count if count is not None else len(endpoints),
                    "calls": calls, "call_count": len(calls),
                    "stats": parse_stats(st), "rates": rates,
                    "rates_note": "速率来自 conntrack 采样（需 nf_conntrack_acct=1）；历史通话不回补计数，新建通话才有速率。" if rates is not None else "未读到 conntrack 数据：请确认已开启 nf_conntrack_acct，或在容器场景下改在宿主统计。",
                })
            except Exception as e:
                self._json({"gk_online": False, "error": str(e), "endpoints": [], "calls": []})
        elif path == "/api/config":
            fields, exists = read_config_fields()
            self._json({"exists": exists, "path": GK_CONFIG, "editable": EDITABLE, "values": fields})
        elif path == "/api/network":
            self._json({"ip_addr": run_cmd(["ip", "-brief", "addr"]),
                        "ip_route": run_cmd(["ip", "route"]),
                        "note": "只读展示；改路由请走部署变量文件重新渲染后应用，见 DEPLOY.md。"})
        elif path == "/api/firewall":
            self._json({"ruleset": run_cmd(["nft", "list", "ruleset"]),
                        "ports": [
                            {"port": "22", "proto": "TCP", "use": "SSH", "scope": "仅管理网段"},
                            {"port": "7000", "proto": "TCP", "use": "GnuGk 状态口", "scope": "仅管理网段"},
                            {"port": "8090", "proto": "TCP", "use": "Web 管理台", "scope": "仅管理网段"},
                            {"port": "1719", "proto": "UDP", "use": "H.225 RAS", "scope": "内外网"},
                            {"port": "1720", "proto": "TCP", "use": "Q.931", "scope": "内外网"},
                            {"port": "21000-21999", "proto": "TCP", "use": "H.245", "scope": "内外网"},
                            {"port": "30000-30999", "proto": "UDP", "use": "RTP/RTCP 媒体代理", "scope": "内外网"},
                        ]})
        elif path == "/api/services":
            out = {}
            for svc in sorted(SERVICES):
                out[svc] = run_cmd(["systemctl", "is-active", svc])
            out["gnugk_instances"] = run_cmd(["pgrep", "-c", "-x", "gnugk"])
            out["single_instance_ok"] = out["gnugk_instances"] == "1"
            self._json(out)
        elif path == "/api/logs":
            def tail(p, n=200):
                try:
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        return "".join(fh.readlines()[-n:])
                except OSError as e:
                    return f"无法读取 {p}: {e}"
            self._json({"actions_log": tail(ACTIONS_LOG), "gk_log": tail(GK_LOG)})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        ip = self.client_address[0]
        data = self._read_json()
        if path == "/api/login":
            if is_locked(ip):
                self._json({"error": "该 IP 已锁定 300 秒，请稍后再试"}, 429)
                return
            if not password_configured():
                self._json({"error": "口令未配置：请先在服务器上运行 python3 server.py --set-password"}, 500)
                return
            if verify_password(data.get("password", "")):
                failed.pop(ip, None)
                token, csrf = new_session()
                body = json.dumps({"ok": True, "csrf": csrf}).encode()
                self._headers(200)
                self.send_header("Set-Cookie", f"session={token}; HttpOnly; SameSite=Strict; Path=/")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                log_action(ip, "login", "ok")
            else:
                record_failure(ip)
                log_action(ip, "login", "failed")
                self._json({"error": "口令错误"}, 401)
            return
        sess = self._require_auth()
        if not sess:
            return
        if not self._require_csrf(sess):
            self._json({"error": "CSRF 校验失败"}, 403)
            return
        if path == "/api/logout":
            with sessions_lock:
                sessions.clear()
            self._json({"ok": True})
        elif path == "/api/action":
            action = data.get("action", "")
            target = str(data.get("target", "")).strip()
            if action not in ACTIONS or (action not in ("unregister_all", "disconnect_all", "reload") and not target):
                self._json({"error": "非法操作或缺少目标"}, 400)
                return
            try:
                result = gk_command(ACTIONS[action](target))
                log_action(ip, f"{action} {target}", "ok")
                self._json({"ok": True, "result": result})
            except Exception as e:
                log_action(ip, f"{action} {target}", f"error {e}")
                self._json({"error": str(e)}, 500)
        elif path == "/api/config":
            updates = {k: str(v) for k, v in data.get("values", {}).items()}
            bad = [k for k in updates if not any(k == f"{sec}.{f}" for sec in EDITABLE for f in EDITABLE[sec])]
            if bad:
                self._json({"error": f"不允许编辑的字段：{bad}"}, 400)
                return
            try:
                backup = write_config_fields(updates)
                try:
                    reload_result = gk_command("reload")
                except Exception as e:
                    reload_result = f"reload 未执行（网闸可能离线）：{e}"
                log_action(ip, "config_save", f"ok backup={backup}")
                self._json({"ok": True, "backup": backup, "reload": reload_result,
                            "note": "reload 只对新呼叫生效，不影响进行中通话；回滚请用备份文件覆盖后 reload。"})
            except Exception as e:
                self._json({"error": str(e)}, 500)
        elif path == "/api/service":
            svc, op = data.get("service", ""), data.get("op", "")
            if svc not in SERVICES or op not in SERVICE_OPS:
                self._json({"error": "非法服务或操作"}, 400)
                return
            result = run_cmd(["systemctl", op, svc])
            log_action(ip, f"service {op} {svc}", "ok")
            self._json({"ok": True, "result": result,
                        "note": "重启 gnugk-web 本身会导致当前页面断开，刷新后即可恢复。" if svc == "gnugk-web" else ""})
        elif path == "/api/change-password":
            if not verify_password(data.get("current", "")):
                self._json({"error": "当前口令错误"}, 401)
                return
            new = data.get("new", "")
            if len(new) < 8 or new != data.get("confirm", ""):
                self._json({"error": "新口令至少 8 位且两次输入需一致"}, 400)
                return
            os.makedirs(os.path.dirname(PASS_FILE) or ".", exist_ok=True)
            with open(PASS_FILE, "w", encoding="utf-8") as fh:
                fh.write(hash_password(new))
            os.chmod(PASS_FILE, 0o600)
            with sessions_lock:
                sessions.clear()
            log_action(ip, "change_password", "ok")
            self._json({"ok": True, "note": "口令已更换，所有会话已失效，请重新登录。"})
        else:
            self._json({"error": "not found"}, 404)


def set_password_interactive():
    import getpass
    p1 = getpass.getpass("新口令：")
    p2 = getpass.getpass("再次输入新口令：")
    if p1 != p2 or len(p1) < 8:
        print("两次输入不一致或口令不足 8 位，未修改。")
        return 1
    os.makedirs(os.path.dirname(PASS_FILE) or ".", exist_ok=True)
    with open(PASS_FILE, "w", encoding="utf-8") as fh:
        fh.write(hash_password(p1))
    os.chmod(PASS_FILE, 0o600)
    print(f"口令已写入 {PASS_FILE}（scrypt 哈希，600 权限）。")
    return 0


def main():
    if "--set-password" in sys.argv:
        return set_password_interactive()
    if not password_configured():
        print(f"警告：口令未配置（{PASS_FILE} 不存在或格式不对），登录将被拒绝。")
        print("请先运行：python3 server.py --set-password")
    threading.Thread(target=_rate_sampler, daemon=True).start()
    server = ThreadingHTTPServer((WEB_BIND, WEB_PORT), Handler)
    print(f"GunGK Web 管理台监听 {WEB_BIND}:{WEB_PORT}（仅内网），网闸状态口 {GK_HOST}:{GK_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
