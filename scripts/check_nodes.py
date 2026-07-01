#!/usr/bin/env python3
"""Check proxy URIs with Xray Core and write working links.

Supported by this script through Xray Core:
- vless://
- vmess://
- trojan://
- ss:// / shadowsocks://

Hysteria2/HY2 is intentionally reported as unsupported because Xray Core does not
run Hysteria2 outbounds. Add sing-box or hysteria client for those links.
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


XRAY_BIN = os.environ.get("XRAY_BIN", "xray")
SUPPORTED_SCHEMES = {"vless", "vmess", "trojan", "ss", "shadowsocks"}
UNSUPPORTED_SCHEMES = {"hysteria2", "hy2", "hysteria", "tuic", "wireguard"}
ALL_KNOWN_SCHEMES = SUPPORTED_SCHEMES | UNSUPPORTED_SCHEMES | {"hy2"}
PROXY_LINK_RE = re.compile(
    r"(?i)\\b(?:" + "|".join(re.escape(s) for s in sorted(ALL_KNOWN_SCHEMES)) + r")://[^\\s'\"<>]+"
)


@dataclass
class NodeResult:
    index: int
    name: str
    uri: str
    scheme: str
    ok: bool
    latency_ms: int | None = None
    status_code: int | None = None
    country: str | None = None
    error: str | None = None


def b64decode_padded(data: str) -> bytes:
    data = data.strip().replace("-", "+").replace("_", "/")
    data += "=" * ((4 - len(data) % 4) % 4)
    return base64.b64decode(data)


def one(qs: dict[str, list[str]], *names: str, default: str | None = None) -> str | None:
    for name in names:
        values = qs.get(name)
        if values and values[0] != "":
            return values[0]
    return default


def as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "y"}


def split_csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [x.strip() for x in value.split(",") if x.strip()]


def node_name(uri: str, fallback: str) -> str:
    try:
        frag = urlsplit(uri).fragment
        return unquote(frag) if frag else fallback
    except Exception:
        return fallback


def host_port(server: str) -> tuple[str, int]:
    parsed = urlsplit("//" + server)
    if not parsed.hostname or not parsed.port:
        raise ValueError(f"cannot parse server host/port: {server}")
    return parsed.hostname, int(parsed.port)


def stream_settings(parsed, qs: dict[str, list[str]], fallback_host: str) -> dict[str, Any]:
    network = one(qs, "type", "net", default="tcp") or "tcp"
    security = one(qs, "security", "tls", default="none") or "none"

    # Some clients/panels use `type=raw` for what Xray Core calls plain TCP transport.
    if network == "raw":
        network = "tcp"
    if network in {"h2", "http"}:
        network = "http"
    if security == "false":
        security = "none"
    if security == "true":
        security = "tls"

    if network not in {"tcp", "ws", "grpc", "httpupgrade", "splithttp", "http"}:
        raise ValueError(f"network transport '{network}' is not implemented in this MVP")

    ss: dict[str, Any] = {"network": network, "security": security}

    server_name = one(qs, "sni", "serverName", "peer", default=fallback_host)
    alpn = split_csv(one(qs, "alpn"))
    fp = one(qs, "fp", "fingerprint")

    if security == "tls":
        tls: dict[str, Any] = {
            "serverName": server_name,
            "allowInsecure": as_bool(one(qs, "allowInsecure", "insecure"), False),
        }
        if alpn:
            tls["alpn"] = alpn
        if fp:
            tls["fingerprint"] = fp
        ss["tlsSettings"] = tls
    elif security == "reality":
        reality: dict[str, Any] = {
            "serverName": server_name,
            "publicKey": one(qs, "pbk", "publicKey", default=""),
            "shortId": one(qs, "sid", "shortId", default=""),
            "fingerprint": fp or "chrome",
            "spiderX": one(qs, "spx", "spiderX", default="/"),
        }
        ss["realitySettings"] = reality
    elif security in {"none", ""}:
        ss["security"] = "none"
    else:
        raise ValueError(f"security '{security}' is not implemented")

    if network == "ws":
        headers: dict[str, str] = {}
        ws_host = one(qs, "host")
        if ws_host:
            headers["Host"] = ws_host
        ss["wsSettings"] = {
            "path": one(qs, "path", default="/") or "/",
            "headers": headers,
        }
    elif network == "grpc":
        ss["grpcSettings"] = {
            "serviceName": one(qs, "serviceName", "service", default="") or "",
            "multiMode": one(qs, "mode") == "multi",
        }
    elif network == "httpupgrade":
        ss["httpupgradeSettings"] = {
            "path": one(qs, "path", default="/") or "/",
            "host": one(qs, "host", default="") or "",
        }
    elif network == "splithttp":
        ss["splithttpSettings"] = {
            "path": one(qs, "path", default="/") or "/",
            "host": one(qs, "host", default="") or "",
        }
    elif network == "http":
        ss["httpSettings"] = {
            "path": [one(qs, "path", default="/") or "/"],
            "host": [one(qs, "host", default=fallback_host) or fallback_host],
        }

    return ss


def outbound_vless(uri: str) -> dict[str, Any]:
    p = urlsplit(uri)
    qs = parse_qs(p.query)
    if not p.hostname or not p.port or not p.username:
        raise ValueError("bad vless URI: expected vless://uuid@host:port")
    user: dict[str, Any] = {
        "id": unquote(p.username),
        "encryption": one(qs, "encryption", default="none") or "none",
    }
    flow = one(qs, "flow")
    if flow:
        user["flow"] = flow
    return {
        "protocol": "vless",
        "settings": {
            "vnext": [{"address": p.hostname, "port": int(p.port), "users": [user]}]
        },
        "streamSettings": stream_settings(p, qs, p.hostname),
    }


def outbound_trojan(uri: str) -> dict[str, Any]:
    p = urlsplit(uri)
    qs = parse_qs(p.query)
    if not p.hostname or not p.port or not p.username:
        raise ValueError("bad trojan URI: expected trojan://password@host:port")
    return {
        "protocol": "trojan",
        "settings": {
            "servers": [
                {"address": p.hostname, "port": int(p.port), "password": unquote(p.username)}
            ]
        },
        "streamSettings": stream_settings(p, qs, p.hostname),
    }


def outbound_vmess(uri: str) -> dict[str, Any]:
    raw = uri[len("vmess://") :].split("#", 1)[0].strip()
    data = json.loads(b64decode_padded(raw).decode("utf-8"))
    host = data.get("add")
    port = int(data.get("port"))
    uuid = data.get("id")
    if not host or not port or not uuid:
        raise ValueError("bad vmess URI: missing add/port/id")

    qs = {
        "type": [data.get("net", "tcp")],
        "security": [data.get("tls", "none") or "none"],
    }
    if data.get("sni"):
        qs["sni"] = [data["sni"]]
    if data.get("host"):
        qs["host"] = [data["host"]]
    if data.get("path"):
        qs["path"] = [data["path"]]
    if data.get("fp"):
        qs["fp"] = [data["fp"]]
    if data.get("alpn"):
        qs["alpn"] = [data["alpn"]]

    return {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": host,
                    "port": port,
                    "users": [
                        {
                            "id": uuid,
                            "alterId": int(data.get("aid", 0) or 0),
                            "security": data.get("scy", "auto") or "auto",
                        }
                    ],
                }
            ]
        },
        "streamSettings": stream_settings(None, qs, host),
    }


def parse_ss_userinfo(userinfo: str) -> tuple[str, str]:
    decoded = unquote(userinfo)
    if ":" not in decoded:
        decoded = b64decode_padded(decoded).decode("utf-8")
    method, password = decoded.split(":", 1)
    return method, password


def outbound_ss(uri: str) -> dict[str, Any]:
    scheme = "shadowsocks://" if uri.startswith("shadowsocks://") else "ss://"
    rest = uri[len(scheme) :]
    rest = rest.split("#", 1)[0].split("?", 1)[0]

    if "@" in rest:
        userinfo, server = rest.rsplit("@", 1)
        method, password = parse_ss_userinfo(userinfo)
        host, port = host_port(server)
    else:
        decoded = b64decode_padded(rest).decode("utf-8")
        userinfo, server = decoded.rsplit("@", 1)
        method, password = parse_ss_userinfo(userinfo)
        host, port = host_port(server)

    return {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [
                {"address": host, "port": port, "method": method, "password": password}
            ]
        },
    }


def outbound_from_uri(uri: str) -> tuple[str, dict[str, Any]]:
    scheme = urlsplit(uri).scheme.lower()
    if scheme == "vless":
        return scheme, outbound_vless(uri)
    if scheme == "vmess":
        return scheme, outbound_vmess(uri)
    if scheme == "trojan":
        return scheme, outbound_trojan(uri)
    if scheme in {"ss", "shadowsocks"}:
        return scheme, outbound_ss(uri)
    if scheme in UNSUPPORTED_SCHEMES:
        raise NotImplementedError(f"{scheme} is not supported by Xray Core in this project")
    raise ValueError(f"unsupported URI scheme: {scheme or '<empty>'}")


def free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def xray_config(outbound: dict[str, Any], socks_port: int) -> dict[str, Any]:
    outbound = dict(outbound)
    outbound.setdefault("tag", "proxy")
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": True},
            }
        ],
        "outbounds": [outbound],
    }


def start_xray(config: dict[str, Any]) -> tuple[subprocess.Popen, str]:
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(config, tmp, ensure_ascii=False, indent=2)
    tmp.close()
    proc = subprocess.Popen(
        [XRAY_BIN, "run", "-config", tmp.name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc, tmp.name


def wait_port(port: int, proc: subprocess.Popen, seconds: float = 4.0) -> None:
    deadline = time.time() + seconds
    last_err: Exception | None = None
    while time.time() < deadline:
        if proc.poll() is not None:
            stderr = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(f"xray exited early: {stderr.strip()[:600]}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except Exception as exc:
            last_err = exc
            time.sleep(0.1)
    raise TimeoutError(f"xray SOCKS port did not open: {last_err}")


def stop_xray(proc: subprocess.Popen, config_path: str) -> None:
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(config_path)


def test_via_socks(port: int, url: str, timeout: float) -> tuple[int, int]:
    proxies = {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }
    started = time.perf_counter()
    r = requests.get(url, proxies=proxies, timeout=timeout, allow_redirects=False)
    latency_ms = int((time.perf_counter() - started) * 1000)
    return r.status_code, latency_ms


def country_via_socks(port: int, timeout: float) -> str | None:
    proxies = {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }
    urls = ["https://ipinfo.io/country", "https://ifconfig.co/country-iso"]
    for url in urls:
        try:
            r = requests.get(url, proxies=proxies, timeout=timeout, allow_redirects=False)
            if r.ok:
                value = r.text.strip().upper()
                if len(value) == 2:
                    return value
        except Exception:
            pass
    return None


def check_node(index: int, uri: str, test_url: str, timeout: float, require_country: str | None) -> NodeResult:
    name = node_name(uri, f"node-{index}")
    scheme = urlsplit(uri).scheme.lower()
    try:
        scheme, outbound = outbound_from_uri(uri)
        port = free_port()
        proc, cfg = start_xray(xray_config(outbound, port))
        try:
            wait_port(port, proc)
            status, latency = test_via_socks(port, test_url, timeout)
            ok = 200 <= status < 400 or status == 204
            country = None
            if ok and require_country:
                country = country_via_socks(port, timeout)
                if country != require_country.upper():
                    return NodeResult(index, name, uri, scheme, False, latency, status, country, f"country {country or 'unknown'} != {require_country.upper()}")
            if not ok:
                return NodeResult(index, name, uri, scheme, False, latency, status, country, f"bad HTTP status {status}")
            return NodeResult(index, name, uri, scheme, True, latency, status, country)
        finally:
            stop_xray(proc, cfg)
    except NotImplementedError as exc:
        return NodeResult(index, name, uri, scheme, False, error=str(exc))
    except Exception as exc:
        return NodeResult(index, name, uri, scheme, False, error=str(exc))


def normalize_candidate_link(value: str) -> str | None:
    value = value.strip().strip("'\",[]{}")
    if not value or value.startswith("#"):
        return None
    scheme = urlsplit(value).scheme.lower()
    if scheme in ALL_KNOWN_SCHEMES:
        return value
    return None


def extract_proxy_links(text: str) -> list[str]:
    """Extract proxy links from plain text, base64 subscription text, or YAML-ish text."""
    candidates: list[str] = []

    def add_from(raw: str) -> None:
        for line in raw.splitlines():
            link = normalize_candidate_link(line)
            if link:
                candidates.append(link)
        for match in PROXY_LINK_RE.findall(raw):
            link = normalize_candidate_link(match)
            if link:
                candidates.append(link)

    add_from(text)

    compact = "".join(text.split())
    if compact:
        with contextlib.suppress(Exception):
            decoded = b64decode_padded(compact).decode("utf-8", errors="ignore")
            if decoded and decoded != text:
                add_from(decoded)

    return dedupe(candidates)


def dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def load_nodes(path: Path) -> list[str]:
    if not path.exists():
        return []
    return extract_proxy_links(path.read_text(encoding="utf-8"))


def env_lines(name: str) -> list[str]:
    value = os.environ.get(name, "").strip()
    if not value:
        return []
    return [line.strip() for line in value.splitlines() if line.strip() and not line.strip().startswith("#")]


def fetch_subscription(
    url: str,
    user_agent: str,
    timeout: float,
    proxies: dict[str, str] | None = None,
) -> str:
    # Keep these headers close to real subscription clients and to the old
    # Render/axios implementation. Some panels return HTML or 403 when Accept
    # looks like a browser/plain-text preference, but return subscription data
    # for Accept: */* plus a supported User-Agent.
    headers = {
        "User-Agent": user_agent,
        "Accept": os.environ.get("SUBSCRIPTION_ACCEPT", "*/*"),
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    last_exc: Exception | None = None
    retries = int(os.environ.get("SUBSCRIPTION_FETCH_RETRIES", "2"))
    for attempt in range(retries + 1):
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=max(timeout, 18),
                allow_redirects=True,
                proxies=proxies,
            )
            body = response.text or ""
            content_type = response.headers.get("content-type", "unknown")
            looks_html = body.lstrip().lower().startswith(("<!doctype", "<html"))
            via = " via subscription proxy" if proxies else ""
            print(
                f"  ↳ status={response.status_code} content-type={content_type} bytes={len(body)}{via}"
                + (" ⚠️ looks like HTML" if looks_html else ""),
                flush=True,
            )
            response.raise_for_status()
            return body
        except Exception as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(1.2)
                continue
            raise last_exc


def start_subscription_proxy(uri: str) -> tuple[subprocess.Popen, str, dict[str, str]]:
    """Start Xray as a local SOCKS proxy using a proxy URI as outbound."""
    scheme, outbound = outbound_from_uri(uri)
    port = free_port()
    proc, cfg = start_xray(xray_config(outbound, port))
    wait_port(port, proc)
    print(f"Subscription fetch proxy started through {scheme} on 127.0.0.1:{port}", flush=True)
    proxy_url = f"socks5h://127.0.0.1:{port}"
    return proc, cfg, {"http": proxy_url, "https": proxy_url}


def load_all_nodes(path: Path, timeout: float) -> list[str]:
    nodes: list[str] = []

    # Public/non-secret file in repo.
    nodes.extend(load_nodes(path))

    # Secrets can contain one or many full proxy URIs, one per line.
    nodes.extend(extract_proxy_links("\n".join(env_lines("SERVER_VLESS_URI"))))
    nodes.extend(extract_proxy_links("\n".join(env_lines("NODE_URIS"))))

    # Optional full proxy URI used only for downloading subscriptions.
    # Example: SUBSCRIPTION_PROXY_URI=vless://uuid@host:443?...#fetch-proxy
    proxy_uri = os.environ.get("SUBSCRIPTION_PROXY_URI", "").strip()
    proxy_proc: subprocess.Popen | None = None
    proxy_cfg = ""
    fetch_proxies: dict[str, str] | None = None
    if proxy_uri:
        try:
            proxy_proc, proxy_cfg, fetch_proxies = start_subscription_proxy(proxy_uri)
        except Exception as exc:
            print(f"Failed to start subscription proxy: {exc}", file=sys.stderr, flush=True)

    try:
        # Secret with subscription URLs only, one URL per line.
        subscription_urls = env_lines("SUBSCRIPTION_URLS")
        user_agent = os.environ.get("SUBSCRIPTION_USER_AGENT", "HiddifyNext/2.0.5").strip() or "HiddifyNext/2.0.5"
        for sub_url in subscription_urls:
            try:
                host = urlsplit(sub_url).hostname or "subscription"
                print(f"Fetching subscription from {host} with User-Agent: {user_agent}", flush=True)
                content = fetch_subscription(sub_url, user_agent, timeout, fetch_proxies)
                extracted = extract_proxy_links(content)
                print(f"  extracted {len(extracted)} link(s)", flush=True)
                nodes.extend(extracted)
            except Exception as exc:
                host = urlsplit(sub_url).hostname or "subscription"
                print(f"  failed to fetch subscription from {host}: {exc}", file=sys.stderr, flush=True)
    finally:
        if proxy_proc is not None:
            stop_xray(proxy_proc, proxy_cfg)

    return dedupe(nodes)


def write_outputs(results: list[NodeResult], output: Path, report: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    working = [r.uri for r in results if r.ok]
    output.write_text("\n".join(working) + ("\n" if working else ""), encoding="utf-8")

    lines = [
        "# Node check report",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"Total: {len(results)}",
        f"Working: {len(working)}",
        "",
        "| # | Status | Scheme | Name | Latency | HTTP | Country | Error |",
        "|---:|:---:|---|---|---:|---:|:---:|---|",
    ]
    for r in results:
        status = "✅" if r.ok else "❌"
        latency = str(r.latency_ms) + " ms" if r.latency_ms is not None else ""
        http = str(r.status_code) if r.status_code is not None else ""
        country = r.country or ""
        err = (r.error or "").replace("|", "\\|").replace("\n", " ")
        name = r.name.replace("|", "\\|")
        lines.append(f"| {r.index} | {status} | `{r.scheme}` | {name} | {latency} | {http} | {country} | {err} |")
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="nodes.txt")
    parser.add_argument("--output", default="output/working_nodes.txt")
    parser.add_argument("--report", default="output/report.md")
    parser.add_argument("--test-url", default="https://www.gstatic.com/generate_204")
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--require-country", default=os.environ.get("REQUIRE_COUNTRY", "").strip() or None)
    args = parser.parse_args(argv)

    nodes = load_all_nodes(Path(args.input), args.timeout)
    print(f"Loaded {len(nodes)} unique node(s) from file, secrets, and subscriptions")
    results: list[NodeResult] = []
    for idx, uri in enumerate(nodes, 1):
        print(f"[{idx}/{len(nodes)}] checking {node_name(uri, f'node-{idx}')} ...", flush=True)
        res = check_node(idx, uri, args.test_url, args.timeout, args.require_country)
        results.append(res)
        if res.ok:
            print(f"  OK {res.latency_ms} ms status={res.status_code} country={res.country or '-'}")
        else:
            print(f"  FAIL {res.error}")

    write_outputs(results, Path(args.output), Path(args.report))
    print(f"Working: {sum(1 for r in results if r.ok)}/{len(results)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
