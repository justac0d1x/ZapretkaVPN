#!/usr/bin/env python3
"""Check proxy URIs with Xray Core and sing-box.

Supported: vless, vmess, trojan, ss/shadowsocks, hysteria2/hy2
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

XRAY_BIN = os.environ.get("XRAY_BIN", "xray")
SINGBOX_BIN = os.environ.get("SINGBOX_BIN", "sing-box")
SUPPORTED_XRAY = {"vless", "vmess", "trojan", "ss", "shadowsocks"}
SUPPORTED_HY2 = {"hysteria2", "hy2"}
ALL_KNOWN = SUPPORTED_XRAY | SUPPORTED_HY2 | {"hysteria", "tuic", "wireguard"}
PROXY_LINK_RE = re.compile(r"(?i)\b(?:%s)://[^\s'\"<>]+" % "|".join(map(re.escape, sorted(ALL_KNOWN))))
EMOJI_FLAG_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")

@dataclass
class NodeResult:
    index: int
    name: str
    uri: str
    scheme: str
    ok: bool
    latency_ms: int | None = None
    status_code: int | None = None
    error: str | None = None


# ---------- utils ----------
def b64decode_padded(data: str) -> bytes:
    data = data.strip().replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data)

def qs_one(qs: dict[str, list[str]], *names: str, default: str | None = None) -> str | None:
    for n in names:
        v = qs.get(n)
        if v and v[0] != "":
            return v[0]
    return default

def as_bool(v: str | None) -> bool:
    return bool(v and v.lower() in {"1", "true", "yes", "y"})

def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def node_name(uri: str, fallback: str) -> str:
    display_name = os.environ.get("NODE_NAME", "Zapretka").strip() or "Zapretka"
    frag = urlsplit(uri).fragment
    if frag:
        name = unquote(frag)
        m = EMOJI_FLAG_RE.search(name)
        flag = m.group(0) if m else "🌐"
        return f"{flag} {display_name}"
    return fallback


# ---------- stream settings ----------
def build_stream_settings(qs: dict[str, list[str]], fallback_host: str) -> dict[str, Any]:
    network = qs_one(qs, "type", "net", default="tcp") or "tcp"
    security = qs_one(qs, "security", "tls", default="none") or "none"

    network_map = {"raw": "tcp", "xhttp": "splithttp", "h2": "http", "http": "http"}
    network = network_map.get(network, network)
    if security == "false": security = "none"
    if security == "true": security = "tls"

    ss: dict[str, Any] = {"network": network, "security": security}
    server_name = qs_one(qs, "sni", "serverName", "peer", default=fallback_host)

    if security == "tls":
        tls = {"serverName": server_name, "allowInsecure": as_bool(qs_one(qs, "allowInsecure", "insecure"))}
        if alpn := qs_one(qs, "alpn"):
            tls["alpn"] = [x.strip() for x in alpn.split(",")]
        if fp := qs_one(qs, "fp", "fingerprint"):
            tls["fingerprint"] = fp
        ss["tlsSettings"] = tls
    elif security == "reality":
        ss["realitySettings"] = {
            "serverName": server_name,
            "publicKey": qs_one(qs, "pbk", "publicKey", default="") or "",
            "shortId": qs_one(qs, "sid", "shortId", default="") or "",
            "fingerprint": qs_one(qs, "fp", "fingerprint") or "chrome",
            "spiderX": qs_one(qs, "spx", "spiderX", default="/") or "/",
        }

    path = qs_one(qs, "path", default="/") or "/"
    host = qs_one(qs, "host") or ""

    transport = {
        "ws": {"wsSettings": {"path": path, "headers": {"Host": host} if host else {}}},
        "grpc": {"grpcSettings": {"serviceName": qs_one(qs, "serviceName", "service", default="") or "", "multiMode": qs_one(qs, "mode") == "multi"}},
        "httpupgrade": {"httpupgradeSettings": {"path": path, "host": host}},
        "splithttp": {"splithttpSettings": {"path": path, "host": host, "mode": qs_one(qs, "mode", default="auto")}},
        "http": {"httpSettings": {"path": [path], "host": [host or fallback_host]}},
    }
    if network in transport:
        ss.update(transport[network])
    return ss


# ---------- outbounds: xray ----------
def outbound_vless(uri: str) -> dict[str, Any]:
    p = urlsplit(uri); qs = parse_qs(p.query)
    user = {"id": unquote(p.username), "encryption": qs_one(qs, "encryption", default="none") or "none"}
    if flow := qs_one(qs, "flow"): user["flow"] = flow
    return {"protocol": "vless", "settings": {"vnext": [{"address": p.hostname, "port": int(p.port), "users": [user]}]}, "streamSettings": build_stream_settings(qs, p.hostname)}

def outbound_trojan(uri: str) -> dict[str, Any]:
    p = urlsplit(uri); qs = parse_qs(p.query)
    return {"protocol": "trojan", "settings": {"servers": [{"address": p.hostname, "port": int(p.port), "password": unquote(p.username)}]}, "streamSettings": build_stream_settings(qs, p.hostname)}

def outbound_vmess(uri: str) -> dict[str, Any]:
    data = json.loads(b64decode_padded(uri[8:].split("#", 1)[0]).decode())
    host, port, uuid = data["add"], int(data["port"]), data["id"]
    qs = {k: [str(data.get(v, ""))] for k, v in {"type":"net","security":"tls","sni":"sni","host":"host","path":"path","fp":"fp","alpn":"alpn"}.items() if data.get(v)}
    qs.setdefault("type", ["tcp"]); qs.setdefault("security", ["none"])
    return {"protocol": "vmess", "settings": {"vnext": [{"address": host, "port": port, "users": [{"id": uuid, "alterId": int(data.get("aid", 0) or 0), "security": data.get("scy", "auto")}]}]}, "streamSettings": build_stream_settings(qs, host)}

def outbound_ss(uri: str) -> dict[str, Any]:
    scheme = "shadowsocks://" if uri.startswith("shadowsocks://") else "ss://"
    rest = uri[len(scheme):].split("#", 1)[0].split("?", 1)[0]
    if "@" not in rest:
        rest = b64decode_padded(rest).decode()
    userinfo, server = rest.rsplit("@", 1)
    if ":" not in userinfo:
        userinfo = b64decode_padded(unquote(userinfo)).decode()
    method, password = userinfo.split(":", 1)
    host, port_str = server.rsplit(":", 1)
    host = host.strip("[]")
    return {"protocol": "shadowsocks", "settings": {"servers": [{"address": host, "port": int(port_str), "method": method, "password": password}]}}

def xray_outbound(uri: str) -> tuple[str, dict[str, Any]]:
    scheme = urlsplit(uri).scheme.lower()
    builders = {"vless": outbound_vless, "vmess": outbound_vmess, "trojan": outbound_trojan, "ss": outbound_ss, "shadowsocks": outbound_ss}
    if scheme in builders: return scheme, builders[scheme](uri)
    raise ValueError(f"unsupported scheme: {scheme}")


# ---------- outbounds: sing-box / hysteria2 ----------
def hysteria2_outbound(uri: str) -> dict[str, Any]:
    p = urlsplit(uri); qs = parse_qs(p.query)
    ob = {
        "type": "hysteria2",
        "server": p.hostname,
        "server_port": p.port or 443,
        "password": unquote(p.username or ""),
        "tls": {"enabled": True, "server_name": qs_one(qs, "sni", "peer") or p.hostname, "insecure": as_bool(qs_one(qs, "allowInsecure", "insecure"))},
    }
    if obfs := qs_one(qs, "obfs", "obfsType"):
        ob["obfs"] = {"type": obfs, **({"password": pw} if (pw := qs_one(qs, "obfs-password", "obfsPassword")) else {})}
    return ob


# ---------- runner ----------
class ProxyRunner:
    def __init__(self, backend: str, outbound: dict):
        self.backend = backend  # "xray" or "singbox"
        self.outbound = outbound
        self.proc = None
        self.cfg_path = ""

    def __enter__(self):
        port = free_port()
        if self.backend == "xray":
            cfg = {
                "log": {"loglevel": "warning"},
                "inbounds": [{"protocol": "socks", "listen": "127.0.0.1", "port": port, "settings": {"udp": False}}],
                "outbounds": [{**self.outbound, "tag": "proxy"}, {"tag": "direct", "protocol": "freedom"}],
            }
            bin_path = XRAY_BIN
        else:
            cfg = {
                "log": {"level": "warn"},
                "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
                "outbounds": [self.outbound],
            }
            bin_path = SINGBOX_BIN

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(cfg, f); self.cfg_path = f.name

        self.proc = subprocess.Popen([bin_path, "run", "-c", self.cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.port = port
        
        # wait for socks port
        deadline = time.time() + 6
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3): break
            except OSError:
                if self.proc.poll() is not None: raise RuntimeError(f"{bin_path} exited early")
                time.sleep(0.1)
        else:
            raise TimeoutError("proxy did not start")
        return self.port

    def __exit__(self, *exc):
        if self.proc:
            self.proc.terminate()
            try: self.proc.wait(timeout=2)
            except: self.proc.kill()
        with contextlib.suppress(Exception): os.unlink(self.cfg_path)


def test_via_socks(port: int, test_url: str, timeout: float) -> tuple[int, int]:
    proxies = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
    start = time.time()
    try:
        r = requests.get(test_url, proxies=proxies, timeout=timeout)
        return r.status_code, int((time.time() - start) * 1000)
    except Exception:
        return 0, 0


def check_node(index: int, uri: str, test_url: str, timeout: float) -> NodeResult:
    name = node_name(uri, f"node-{index}")
    scheme = urlsplit(uri).scheme.lower()
    try:
        if scheme in SUPPORTED_HY2:
            backend, outbound = "singbox", hysteria2_outbound(uri)
        else:
            scheme, outbound = xray_outbound(uri)
            backend = "xray"
        
        with ProxyRunner(backend, outbound) as port:
            status, latency = test_via_socks(port, test_url, timeout)
        
        ok = 200 <= status < 400 or status == 204
        return NodeResult(index, name, uri, scheme, ok, latency, status, None if ok else f"bad HTTP {status}")
    except Exception as exc:
        return NodeResult(index, name, uri, scheme, False, error=str(exc))


# ---------- loading ----------
def extract_proxy_links(text: str) -> list[str]:
    def normalize(v: str) -> str | None:
        v = v.strip().strip("'\"[]{}")
        return v if urlsplit(v).scheme.lower() in ALL_KNOWN else None

    candidates = []
    for line in text.splitlines():
        if n := normalize(line): candidates.append(n)
    candidates += [n for m in PROXY_LINK_RE.findall(text) if (n := normalize(m))]
    
    # try base64 subscription decode
    compact = "".join(text.split())
    with contextlib.suppress(Exception):
        decoded = b64decode_padded(compact).decode("utf-8", errors="ignore")
        if decoded != text:
            candidates += extract_proxy_links(decoded)
    
    # dedupe preserve order
    seen, out = set(), []
    for c in candidates:
        if c not in seen: seen.add(c); out.append(c)
    return out

def env_lines(name: str) -> list[str]:
    value = os.environ.get(name, "").strip()
    if not value: return []
    return [l.strip() for l in value.splitlines() if l.strip() and not l.strip().startswith("#")]

def fetch_subscription(url: str, user_agent: str, timeout: float, proxies: dict[str, str] | None = None) -> str:
    headers = {
        "User-Agent": user_agent,
        "Accept": os.environ.get("SUBSCRIPTION_ACCEPT", "*/*"),
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    retries = int(os.environ.get("FETCH_RETRIES", "4"))
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, headers=headers, timeout=max(timeout, 20), allow_redirects=True, proxies=proxies)
            body = r.text or ""
            via = " via subscription proxy" if proxies else ""
            looks_html = body.lstrip().lower().startswith(("<!doctype", "<html"))
            print(f"  ↳ status={r.status_code} content-type={r.headers.get('content-type','unknown')} bytes={len(body)}{via}" + (" ⚠️ looks like HTML" if looks_html else ""), flush=True)
            r.raise_for_status()
            return body
        except Exception as exc:
            last_exc = exc
            if attempt < retries:
                delay = 1.5 * (attempt + 1)
                print(f"  ↳ attempt {attempt+1}/{retries+1} failed ({type(exc).__name__}), retrying in {delay:.1f}s...", flush=True)
                time.sleep(delay)
                continue
            print(f"  ↳ all {retries+1} attempts failed: {type(exc).__name__}", flush=True)
            raise last_exc  # type: ignore

@contextlib.contextmanager
def subscription_proxy(uri: str):
    """Запускает xray прокси для скачивания подписок, возвращает dict proxies для requests"""
    scheme, outbound = xray_outbound(uri)
    with ProxyRunner("xray", outbound) as port:
        proxy_url = f"socks5h://127.0.0.1:{port}"
        print(f"Subscription fetch proxy started through {scheme} on 127.0.0.1:{port}", flush=True)
        yield {"http": proxy_url, "https": proxy_url}

def load_all_nodes(path: Path, timeout: float) -> list[str]:
    nodes = []
    if path.exists():
        nodes += extract_proxy_links(path.read_text(encoding="utf-8"))
    
    nodes += extract_proxy_links("\n".join(env_lines("NODE_URIS")))

    # subscription fetch, optionally via PROXY_URI
    proxy_uri = os.environ.get("PROXY_URI", "").strip()
    fetch_proxies: dict[str, str] | None = None
    proxy_ctx = subscription_proxy(proxy_uri) if proxy_uri else contextlib.nullcontext(None)

    try:
        with proxy_ctx as proxies:
            fetch_proxies = proxies
            subscription_urls = env_lines("NODE_URLS")
            user_agent = os.environ.get("USER_AGENT", "HiddifyNext/2.0.5").strip() or "HiddifyNext/2.0.5"
            for sub_url in subscription_urls:
                try:
                    host = urlsplit(sub_url).hostname or "subscription"
                    print(f"Fetching subscription from {host} with User-Agent: {user_agent}", flush=True)
                    content = fetch_subscription(sub_url, user_agent, timeout, fetch_proxies)
                    extracted = extract_proxy_links(content)
                    print(f"  extracted {len(extracted)} link(s)", flush=True)
                    nodes += extracted
                except Exception as exc:
                    host = urlsplit(sub_url).hostname or "subscription"
                    print(f"  failed to fetch subscription from {host}: {exc}", file=sys.stderr, flush=True)
    except Exception as exc:
        print(f"Failed to start subscription proxy: {exc}", file=sys.stderr, flush=True)

    seen, out = set(), []
    for n in nodes:
        if n not in seen: seen.add(n); out.append(n)
    return out


# ---------- main ----------
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="nodes.txt")
    ap.add_argument("--output", default="output/sub.txt")
    ap.add_argument("--report", default="output/report.md")
    ap.add_argument("--test-url", default="https://www.gstatic.com/generate_204")
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--concurrency", type=int, default=10)
    args = ap.parse_args(argv)

    nodes = load_all_nodes(Path(args.input), args.timeout)
    print(f"Loaded {len(nodes)} node(s), concurrency={args.concurrency}")

    results: list[NodeResult | None] = [None] * len(nodes)

    def worker(idx: int, uri: str):
        res = check_node(idx + 1, uri, args.test_url, args.timeout)
        print(f"[{idx+1}/{len(nodes)}] {res.name} → {'OK %dms' % res.latency_ms if res.ok else 'FAIL ' + (res.error or '')}", flush=True)
        return idx, res

    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = [ex.submit(worker, i, u) for i, u in enumerate(nodes)]
        for f in as_completed(futs):
            i, r = f.result(); results[i] = r

    results = [r for r in results if r]  # type: ignore
    working = [r.uri for r in results if r.ok]
    
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text("\n".join(working) + ("\n" if working else ""), encoding="utf-8")
    
    report = ["# Node check report", "", f"Total: {len(results)}", f"Working: {len(working)}", "",
        "| # | Status | Scheme | Name | Latency | HTTP | Error |",
        "|---:|:---:|---|---|---:|---:|:---|"]
    for r in results:
        report.append(f"| {r.index} | {'✅' if r.ok else '❌'} | `{r.scheme}` | {r.name} | {r.latency_ms or ''} | {r.status_code or ''} | {(r.error or '').replace('|','\\/')} |")
    Path(args.report).write_text("\n".join(report) + "\n", encoding="utf-8")
    
    print(f"Working: {len(working)}/{len(results)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
