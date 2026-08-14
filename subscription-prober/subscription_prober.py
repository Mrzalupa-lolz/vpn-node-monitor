#!/usr/bin/env python3
"""
subscription_prober.py — берёт ссылку(и) подписки в одном из трёх форматов:
  - base64/plain-список share-линков (vless://, vmess://, trojan://, ss://);
  - sing-box JSON ({"outbounds":[{"type": "vless", "server": ...}, ...]});
  - нативный Xray-core client-config JSON ({"outbounds":[{"protocol": "vless",
    "settings": {...}, "streamSettings": {...}}, ...]} — именно так выглядят
    подписки-балансировщики с routing.balancers/routing.rules и любые
    xhttp/hysteria2-outbound'ы с полным набором полей: такие outbound'ы
    передаются в итоговый конфиг as-is, без потери padding/xmux/finalmask).
Поднимает каждый прокси через локальный Xray-core (по одному SOCKS5-инбаунду
на прокси в общем процессе) и проверяет доступность списка целевых сайтов
через каждый прокси.
Результат — матрица proxy x site — уходит на central-server (/ingest-probes)
и отображается на веб-дашборде.

Требует установленный бинарник Xray-core (тот же, что используется на нодах).
Работать может как на самой ноде, так и на отдельном "watcher"-хосте с
доступом в интернет — это фактически имитация реального клиента.

Только stdlib + вызов внешнего xray/curl — без pip-зависимостей.
"""

import base64
import concurrent.futures
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse, parse_qs, unquote

# --------------------------------------------------------------------------
# Конфигурация через переменные окружения (см. subscription-prober.env.example)
# --------------------------------------------------------------------------

SUBSCRIPTION_URLS = [u for u in os.environ.get("SUB_PROBER_SUBSCRIPTIONS", "").split(",") if u.strip()]
TARGET_SITES = [u for u in os.environ.get(
    "SUB_PROBER_TARGETS",
    "https://www.google.com,https://www.youtube.com,https://www.netflix.com,"
    "https://web.telegram.org,https://discord.com,https://chat.openai.com"
).split(",") if u.strip()]

XRAY_BIN = os.environ.get("SUB_PROBER_XRAY_BIN", "/usr/local/bin/xray")
SOCKS_BASE_PORT = int(os.environ.get("SUB_PROBER_SOCKS_BASE_PORT", "11000"))
PROBE_TIMEOUT = int(os.environ.get("SUB_PROBER_PROBE_TIMEOUT", "8"))
MAX_WORKERS = int(os.environ.get("SUB_PROBER_MAX_WORKERS", "16"))
XRAY_STARTUP_WAIT = float(os.environ.get("SUB_PROBER_XRAY_STARTUP_WAIT", "1.5"))
MAX_PROXIES = int(os.environ.get("SUB_PROBER_MAX_PROXIES", "200"))
PROBE_NODE_TAG = os.environ.get("SUB_PROBER_TAG", os.uname().nodename if hasattr(os, "uname") else "prober")

CENTRAL_POST_URL = os.environ.get("SUB_PROBER_CENTRAL_URL", "")   # напр. https://monitor.example.com/ingest-probes
CENTRAL_POST_TOKEN = os.environ.get("SUB_PROBER_CENTRAL_TOKEN", "")

STATE_DIR = os.environ.get("SUB_PROBER_STATE_DIR", "/var/lib/subscription-prober")
LOG_FILE = os.environ.get("SUB_PROBER_LOG_FILE", "/var/log/subscription-prober/prober.log")


def log(msg):
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {msg}"
    print(line, file=sys.stderr)
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------
# 1. Получение и разбор подписки
# --------------------------------------------------------------------------

def fetch_url(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "subscription-prober/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def b64_decode_loose(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def parse_subscription(raw_text):
    """Возвращает список "сырых" прокси-описаний: либо строка share-линка
    (vless://... vmess://... trojan://... ss://...), либо dict (sing-box outbound)."""
    raw_text = raw_text.strip()
    if not raw_text:
        return []

    # Вариант 1: валидный JSON — список outbounds. Два разных диалекта:
    #  - sing-box: {"type": "vless", "server": ..., "server_port": ...}
    #  - нативный Xray-core client-config (панели/балансировщики отдают именно это):
    #    {"protocol": "vless", "settings": {...}, "streamSettings": {...}}
    # Оба могут прийти как {"outbounds": [...]} (в т.ч. с routing.balancers/routing.rules —
    # эти секции просто игнорируются, нам нужны только сами outbound-объекты) или как голый список.
    try:
        data = json.loads(raw_text)
        outbounds = None
        if isinstance(data, dict) and "outbounds" in data:
            outbounds = data["outbounds"]
        elif isinstance(data, list):
            outbounds = data
        if outbounds is not None:
            singbox_types = ("vless", "vmess", "trojan", "shadowsocks")
            xray_protocols = ("vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2")
            return [o for o in outbounds if isinstance(o, dict)
                     and (o.get("type") in singbox_types or o.get("protocol") in xray_protocols)]
    except json.JSONDecodeError:
        pass

    # Вариант 2: сырой текст уже содержит share-линки построчно
    if re.search(r'^(vless|vmess|trojan|ss)://', raw_text, re.MULTILINE):
        return [ln.strip() for ln in raw_text.splitlines() if "://" in ln]

    # Вариант 3: весь блок — base64 от списка share-линков (классическая подписка)
    try:
        decoded = b64_decode_loose(raw_text).decode("utf-8", errors="replace")
        if re.search(r'^(vless|vmess|trojan|ss)://', decoded, re.MULTILINE):
            return [ln.strip() for ln in decoded.splitlines() if "://" in ln]
    except Exception:
        pass

    log("не удалось распознать формат подписки (ни JSON, ни base64-список ссылок)")
    return []


# --------------------------------------------------------------------------
# 2. Нормализация в общий ProxyDef и генерация Xray outbound
# --------------------------------------------------------------------------

def parse_share_link(uri):
    """vless:// vmess:// trojan:// ss:// -> ProxyDef dict, либо None при ошибке."""
    try:
        scheme = uri.split("://", 1)[0].lower()

        if scheme == "vmess":
            payload = uri[len("vmess://"):]
            obj = json.loads(b64_decode_loose(payload).decode("utf-8", errors="replace"))
            return {
                "remark": obj.get("ps") or obj.get("add", "vmess"),
                "protocol": "vmess", "address": obj["add"], "port": int(obj["port"]),
                "uuid": obj.get("id"), "alterId": int(obj.get("aid", 0) or 0),
                "network": (obj.get("net") or "tcp"), "security": ("tls" if obj.get("tls") else "none"),
                "sni": obj.get("sni") or obj.get("host") or obj.get("add"),
                "fp": obj.get("fp") or "chrome",
                "ws_path": obj.get("path") or "/", "ws_host": obj.get("host") or "",
                "grpc_service": obj.get("path") or "",
                "alpn": obj.get("alpn") or "",
            }

        parsed = urlparse(uri)
        q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        remark = unquote(parsed.fragment) if parsed.fragment else parsed.hostname
        userinfo = parsed.username or ""

        if scheme == "vless":
            return {
                "remark": remark, "protocol": "vless",
                "address": parsed.hostname, "port": parsed.port,
                "uuid": userinfo,
                "network": q.get("type", "tcp"), "security": q.get("security", "none"),
                "sni": q.get("sni") or parsed.hostname, "fp": q.get("fp", "chrome"),
                "pbk": q.get("pbk", ""), "sid": q.get("sid", ""), "spx": q.get("spx", "/"),
                "flow": q.get("flow", ""),
                "ws_path": q.get("path", "/"), "ws_host": q.get("host", ""),
                "grpc_service": q.get("serviceName", ""),
                "xhttp_mode": q.get("mode", "auto"),
                "alpn": q.get("alpn", ""),
            }

        if scheme == "trojan":
            return {
                "remark": remark, "protocol": "trojan",
                "address": parsed.hostname, "port": parsed.port,
                "password": userinfo,
                "network": q.get("type", "tcp"), "security": q.get("security", "tls"),
                "sni": q.get("sni") or parsed.hostname, "fp": q.get("fp", "chrome"),
                "pbk": q.get("pbk", ""), "sid": q.get("sid", ""), "spx": q.get("spx", "/"),
                "flow": q.get("flow", ""),
                "ws_path": q.get("path", "/"), "ws_host": q.get("host", ""),
                "grpc_service": q.get("serviceName", ""),
                "alpn": q.get("alpn", ""),
            }

        if scheme == "ss":
            # ss://base64(method:password)@host:port#remark  ИЛИ  ss://base64(method:password@host:port)
            if "@" in uri.split("://", 1)[1]:
                address, port = parsed.hostname, parsed.port
                try:
                    method, password = b64_decode_loose(userinfo).decode().split(":", 1)
                except Exception:
                    method, password = userinfo.split(":", 1) if ":" in userinfo else ("aes-256-gcm", userinfo)
            else:
                whole = b64_decode_loose(uri.split("://", 1)[1].split("#")[0]).decode()
                creds, hostport = whole.split("@", 1)
                method, password = creds.split(":", 1)
                address, port = hostport.split(":", 1)
                port = int(port)
            return {
                "remark": remark or address, "protocol": "shadowsocks",
                "address": address, "port": int(port),
                "method": method, "password": password,
                "network": "tcp", "security": "none",
            }
    except Exception as e:
        log(f"parse_share_link fail: {e}")
    return None


def parse_singbox_outbound(obj):
    try:
        t = obj["type"]
        tls = obj.get("tls") or {}
        reality = tls.get("reality") or {}
        transport = obj.get("transport") or {}
        pd = {
            "remark": obj.get("tag", t), "protocol": t,
            "address": obj["server"], "port": int(obj["server_port"]),
            "network": transport.get("type", "tcp"),
            "security": "reality" if reality.get("enabled") else ("tls" if tls.get("enabled") else "none"),
            "sni": tls.get("server_name", obj["server"]),
            "fp": (tls.get("utls") or {}).get("fingerprint", "chrome"),
            "pbk": reality.get("public_key", ""), "sid": reality.get("short_id", ""), "spx": "/",
            "flow": obj.get("flow", ""),
            "ws_path": transport.get("path", "/"), "ws_host": (transport.get("headers") or {}).get("Host", ""),
            "grpc_service": transport.get("service_name", ""),
            "alpn": ",".join(tls.get("alpn", [])) if tls.get("alpn") else "",
        }
        if t == "vless":
            pd["uuid"] = obj.get("uuid")
        elif t == "vmess":
            pd["uuid"] = obj.get("uuid"); pd["alterId"] = obj.get("alter_id", 0)
        elif t == "trojan":
            pd["password"] = obj.get("password")
        elif t == "shadowsocks":
            pd["method"] = obj.get("method"); pd["password"] = obj.get("password")
        return pd
    except Exception as e:
        log(f"parse_singbox_outbound fail: {e}")
        return None


def parse_xray_outbound(obj):
    """Нативный Xray-core client outbound — {"protocol": "...", "settings": {...},
    "streamSettings": {...}}. Такое отдают панели, экспортирующие полный конфиг
    (роутеры/балансировщики с routing.balancers, xhttp с полным набором padding/xmux,
    hysteria2 и т.д.) — вместо share-линков или sing-box JSON.

    В отличие от parse_share_link/parse_singbox_outbound мы НЕ разбираем поля обратно
    в общий ProxyDef (это создавало бы риск потерять специфичные для транспорта поля
    вроде xhttpSettings.extra или streamSettings.hysteriaSettings/finalmask) — settings и
    streamSettings передаются в итоговый Xray-конфиг as-is, меняется только tag."""
    try:
        proto = obj.get("protocol")
        if proto not in ("vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2"):
            return None  # freedom/blackhole/dns/api и т.п. — не прокси, пропускаем
        settings = obj.get("settings")
        if not isinstance(settings, dict):
            return None
        remark = obj.get("tag") or proto
        return {"remark": remark, "_raw_outbound": {
            "protocol": proto,
            "settings": settings,
            "streamSettings": obj.get("streamSettings") or {},
        }}
    except Exception as e:
        log(f"parse_xray_outbound fail: {e}")
        return None


def build_xray_outbound(tag, pd):
    if "_raw_outbound" in pd:
        outbound = dict(pd["_raw_outbound"])
        outbound["tag"] = tag
        return outbound
    network = {
        "tcp": "raw", "raw": "raw", "ws": "websocket", "websocket": "websocket",
        "grpc": "grpc", "h2": "http", "http": "http", "httpupgrade": "httpupgrade",
        "xhttp": "xhttp", "kcp": "mkcp", "mkcp": "mkcp",
    }.get(pd.get("network", "tcp"), pd.get("network", "tcp"))
    security = pd.get("security", "none")

    stream = {"network": network, "security": security}
    if security == "reality":
        stream["realitySettings"] = {
            "serverName": pd.get("sni") or pd["address"],
            "fingerprint": pd.get("fp") or "chrome",
            "password": pd.get("pbk", ""),
            "shortId": pd.get("sid", ""),
            "spiderX": pd.get("spx") or "/",
        }
    elif security == "tls":
        tls_settings = {"serverName": pd.get("sni") or pd["address"], "fingerprint": pd.get("fp") or "chrome"}
        if pd.get("alpn"):
            tls_settings["alpn"] = pd["alpn"].split(",")
        stream["tlsSettings"] = tls_settings

    if network == "websocket":
        ws = {"path": pd.get("ws_path") or "/"}
        if pd.get("ws_host"):
            ws["headers"] = {"Host": pd["ws_host"]}
        stream["wsSettings"] = ws
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": pd.get("grpc_service", "")}
    elif network == "xhttp":
        xh = {"mode": pd.get("xhttp_mode") or "auto", "path": pd.get("ws_path") or "/"}
        if pd.get("ws_host"):
            xh["host"] = pd["ws_host"]
        stream["xhttpSettings"] = xh

    proto = pd["protocol"]
    if proto == "vless":
        user = {"id": pd["uuid"], "encryption": "none"}
        if network == "raw" and security in ("reality", "tls") and pd.get("flow"):
            user["flow"] = pd["flow"]
        settings = {"vnext": [{"address": pd["address"], "port": pd["port"], "users": [user]}]}
    elif proto == "vmess":
        settings = {"vnext": [{"address": pd["address"], "port": pd["port"],
                                "users": [{"id": pd["uuid"], "alterId": pd.get("alterId", 0), "security": "auto"}]}]}
    elif proto == "trojan":
        user = {"address": pd["address"], "port": pd["port"], "password": pd["password"]}
        if network == "raw" and security in ("reality", "tls") and pd.get("flow"):
            user["flow"] = pd["flow"]
        settings = {"servers": [user]}
    elif proto in ("shadowsocks", "ss"):
        proto = "shadowsocks"
        settings = {"servers": [{"address": pd["address"], "port": pd["port"],
                                  "method": pd.get("method", "aes-256-gcm"), "password": pd.get("password", "")}]}
        stream = {"network": "raw", "security": "none"}
    else:
        return None

    return {"tag": tag, "protocol": proto, "settings": settings, "streamSettings": stream}


# --------------------------------------------------------------------------
# 3. Сборка и запуск общего Xray-процесса со всеми прокси одновременно
# --------------------------------------------------------------------------

def build_xray_config(proxies):
    inbounds, outbounds, rules = [], [], []
    entries = []  # (tag, remark, local_port)
    for i, pd in enumerate(proxies):
        tag = f"px{i}"
        outbound = build_xray_outbound(tag, pd)
        if not outbound:
            continue
        port = SOCKS_BASE_PORT + i
        inbounds.append({
            "tag": f"in{i}", "listen": "127.0.0.1", "port": port,
            "protocol": "socks", "settings": {"udp": False, "auth": "noauth"},
        })
        outbounds.append(outbound)
        rules.append({"type": "field", "inboundTag": [f"in{i}"], "outboundTag": tag})
        entries.append((tag, pd.get("remark") or f"proxy-{i}", port))

    outbounds.append({"tag": "direct", "protocol": "freedom"})
    outbounds.append({"tag": "block", "protocol": "blackhole"})

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    return config, entries


def curl_probe(local_port, target_url):
    t0 = time.time()
    try:
        out = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--socks5-hostname", f"127.0.0.1:{local_port}",
             "--max-time", str(PROBE_TIMEOUT), target_url],
            capture_output=True, text=True, timeout=PROBE_TIMEOUT + 3,
        )
        latency_ms = int((time.time() - t0) * 1000)
        code = out.stdout.strip()
        ok = code.isdigit() and 200 <= int(code) < 400
        return {"target": target_url, "ok": ok, "http_code": code or "0", "latency_ms": latency_ms}
    except subprocess.TimeoutExpired:
        return {"target": target_url, "ok": False, "http_code": "timeout",
                "latency_ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"target": target_url, "ok": False, "http_code": "error", "latency_ms": 0, "error": str(e)[:120]}


def run_probe_cycle():
    all_proxies = []
    for sub_url in SUBSCRIPTION_URLS:
        try:
            raw = fetch_url(sub_url)
        except (urllib.error.URLError, TimeoutError) as e:
            log(f"не удалось получить подписку {sub_url}: {e}")
            continue
        for entry in parse_subscription(raw):
            if isinstance(entry, dict):
                # "protocol" — нативный Xray-core outbound (панели/балансировщики),
                # "type" — sing-box outbound. Форматы разные, поля не пересекаются.
                pd = parse_xray_outbound(entry) if "protocol" in entry else parse_singbox_outbound(entry)
            else:
                pd = parse_share_link(entry)
            if pd:
                all_proxies.append(pd)

    if not all_proxies:
        log("нет ни одного успешно распарсенного прокси — пропускаем цикл")
        return None

    all_proxies = all_proxies[:MAX_PROXIES]
    config, entries = build_xray_config(all_proxies)
    if not entries:
        log("build_xray_config не дал ни одного валидного outbound")
        return None

    os.makedirs(STATE_DIR, exist_ok=True)
    fd, cfg_path = tempfile.mkstemp(prefix="xray-prober-", suffix=".json", dir=STATE_DIR)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(config, f)

    proc = None
    results = []
    try:
        proc = subprocess.Popen([XRAY_BIN, "run", "-c", cfg_path],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        time.sleep(XRAY_STARTUP_WAIT)
        if proc.poll() is not None:
            out = proc.stdout.read() if proc.stdout else ""
            log(f"xray завершился сразу после старта (код {proc.returncode}) — проверьте конфиг/бинарник. "
                f"Вывод xray: {out[-2000:]}")
            return None

        jobs = [(tag, remark, port, site) for (tag, remark, port) in entries for site in TARGET_SITES]
        by_proxy = {tag: {"remark": remark, "results": []} for (tag, remark, _) in entries}

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(curl_probe, port, site): (tag) for (tag, remark, port, site) in jobs}
            for fut in concurrent.futures.as_completed(futs):
                tag = futs[fut]
                by_proxy[tag]["results"].append(fut.result())

        results = [{"proxy": v["remark"], "results": v["results"]} for v in by_proxy.values()]
    finally:
        if proc and proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            os.remove(cfg_path)
        except OSError:
            pass

    return {"node": PROBE_NODE_TAG, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "targets": TARGET_SITES, "proxies": results}


def post_central(payload):
    if not CENTRAL_POST_URL:
        return
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(CENTRAL_POST_URL, data=body, method="POST",
                                  headers={"Content-Type": "application/json"})
    if CENTRAL_POST_TOKEN:
        req.add_header("Authorization", f"Bearer {CENTRAL_POST_TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except (urllib.error.URLError, TimeoutError) as e:
        log(f"central POST failed: {e}")


def main():
    if not SUBSCRIPTION_URLS:
        log("SUB_PROBER_SUBSCRIPTIONS не задан — нечего проверять")
        sys.exit(1)
    if not os.path.isfile(XRAY_BIN) or not os.access(XRAY_BIN, os.X_OK):
        log(f"xray бинарник не найден/не исполняем: {XRAY_BIN}")
        sys.exit(1)

    payload = run_probe_cycle()
    if payload is None:
        sys.exit(1)

    ok_count = sum(1 for p in payload["proxies"] for r in p["results"] if r["ok"])
    total = sum(len(p["results"]) for p in payload["proxies"])
    log(f"цикл завершён: {len(payload['proxies'])} прокси x {len(TARGET_SITES)} сайтов, доступно {ok_count}/{total}")

    post_central(payload)

    # локальный снапшот на диске — на случай если central-server временно недоступен
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = os.path.join(STATE_DIR, "last_probe.json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, os.path.join(STATE_DIR, "last_probe.json"))
    except OSError:
        pass


if __name__ == "__main__":
    main()
