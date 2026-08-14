#!/usr/bin/env python3
"""
vpn-monitor-server.py — лёгкий центральный приёмник метрик от нод
(vpn-node-monitor.sh) с веб-дашбордом в реальном времени.

Только stdlib — никаких pip-зависимостей, безопасно ставить на любую VPS.

Эндпоинты:
  POST /ingest        — принимает JSON от ноды (см. CENTRAL_POST_URL в .env ноды)
                         требует заголовок: Authorization: Bearer <INGEST_TOKEN>
  GET  /api/nodes      — JSON со снапшотом всех нод (для дашборда)
  GET  /               — HTML-дашборд (авто-обновление раз в 5с)

Хранение: последний снапшот на ноду держится в памяти и персистится
атомарной записью в state.json, чтобы пережить рестарт процесса.
Никакой БД не требуется — это не история/графики, а "текущее состояние
флота", что и нужно для оперативного мониторинга.
"""

import json
import os
import threading
import time
import hmac
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# --- Конфигурация через переменные окружения ---
LISTEN_HOST = os.environ.get("VPN_MON_LISTEN", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("VPN_MON_PORT", "8787"))
INGEST_TOKEN = os.environ.get("VPN_MON_INGEST_TOKEN", "")
PROBES_INGEST_TOKEN = os.environ.get("VPN_MON_PROBES_INGEST_TOKEN", "") or INGEST_TOKEN
DASH_USER = os.environ.get("VPN_MON_DASH_USER", "")
DASH_PASS = os.environ.get("VPN_MON_DASH_PASS", "")
STATE_FILE = os.environ.get("VPN_MON_STATE_FILE", "/var/lib/vpn-monitor-server/state.json")
PROBES_STATE_FILE = os.environ.get("VPN_MON_PROBES_STATE_FILE", "/var/lib/vpn-monitor-server/probes.json")
STALE_AFTER_SEC = int(os.environ.get("VPN_MON_STALE_SEC", "90"))     # нода не слала данные > 90с
DOWN_AFTER_SEC = int(os.environ.get("VPN_MON_DOWN_SEC", "300"))      # нода не слала данные > 5 мин
PROBES_STALE_AFTER_SEC = int(os.environ.get("VPN_MON_PROBES_STALE_SEC", "600"))

_lock = threading.Lock()
_nodes = {}   # host -> payload dict (+ _received_at)
_probes = {}  # prober_node -> payload dict (+ _received_at)


def load_state():
    global _nodes, _probes
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            _nodes = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        _nodes = {}
    try:
        with open(PROBES_STATE_FILE, "r", encoding="utf-8") as f:
            _probes = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        _probes = {}


def save_state():
    d = os.path.dirname(STATE_FILE)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_nodes, f)
    os.replace(tmp, STATE_FILE)


def save_probes_state():
    d = os.path.dirname(PROBES_STATE_FILE)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = PROBES_STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_probes, f)
    os.replace(tmp, PROBES_STATE_FILE)


def node_status(n):
    age = time.time() - n.get("_received_at", 0)
    if n.get("alerts"):
        return "alert"
    if age > DOWN_AFTER_SEC:
        return "down"
    if age > STALE_AFTER_SEC:
        return "stale"
    return "ok"


DASHBOARD_HTML = r"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>VPN Nodes Monitor</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {
    --bg: #0f1115; --panel: #171a21; --border: #262b36; --text: #e6e9ef;
    --muted: #8b93a7; --ok: #35c46b; --warn: #e0a83e; --bad: #e0503e; --down: #5a6274;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text); font-family: ui-monospace, Consolas, monospace; }
  header { padding: 16px 24px; border-bottom: 1px solid var(--border); display:flex; justify-content:space-between; align-items:center; }
  header h1 { font-size: 16px; margin: 0; font-weight: 600; letter-spacing:.02em; }
  #summary { color: var(--muted); font-size: 13px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border); font-size: 13px; white-space: nowrap; }
  th { color: var(--muted); font-weight: 500; text-transform: uppercase; font-size: 11px; letter-spacing: .04em; position: sticky; top: 0; background: var(--bg); }
  tr:hover td { background: var(--panel); }
  .dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:8px; vertical-align:middle; }
  .ok   { background: var(--ok); box-shadow: 0 0 6px var(--ok); }
  .warn { background: var(--warn); box-shadow: 0 0 6px var(--warn); }
  .bad, .alert  { background: var(--bad); box-shadow: 0 0 6px var(--bad); }
  .down { background: var(--down); }
  .bar { display:inline-block; width:60px; height:6px; background:#262b36; border-radius:3px; overflow:hidden; vertical-align:middle; margin-left:6px;}
  .bar > span { display:block; height:100%; background: var(--ok); }
  .bar.warn > span { background: var(--warn); }
  .bar.bad > span { background: var(--bad); }
  .host { font-weight:600; }
  .muted { color: var(--muted); }
  .alerts { color: var(--bad); font-size:12px; }
  #empty { padding:40px; text-align:center; color:var(--muted); }
  main { max-width: 1400px; margin: 0 auto; overflow-x:auto; }
  section { margin-bottom: 36px; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); font-weight: 500; padding: 20px 0 8px; margin: 0; }
  .cell-ok   { color: var(--ok); }
  .cell-bad  { color: var(--bad); }
  .lat { color: var(--muted); font-size: 11px; }
  td.site-cell { text-align:center; }
  #probes-empty { padding:24px 0; color:var(--muted); }
</style>
</head>
<body>
<header>
  <h1>VPN NODES MONITOR</h1>
  <div id="summary">загрузка...</div>
</header>
<main>
<section>
<table id="tbl">
  <thead><tr>
    <th></th><th>Нода</th><th>CPU</th><th>Steal</th><th>RAM</th><th>Диск</th><th>Load1</th>
    <th>Conntrack</th><th>WG online</th><th>OpenVPN</th><th>Xray сессий</th><th>Обновлено</th><th>Алерты</th>
  </tr></thead>
  <tbody></tbody>
</table>
<div id="empty" style="display:none">Пока нет данных ни от одной ноды. Проверьте CENTRAL_POST_URL / токен на нодах.</div>
</section>
<section>
<h2>Доступность сайтов через прокси подписки</h2>
<table id="probes-tbl">
  <thead><tr id="probes-head"></tr></thead>
  <tbody></tbody>
</table>
<div id="probes-empty">Пока нет данных проб. Проверьте subscription-prober / SUB_PROBER_CENTRAL_URL.</div>
</section>
</main>
<script>
function barClass(v) { return v >= 90 ? 'bad' : v >= 75 ? 'warn' : ''; }
function fmtAge(sec) {
  if (sec < 60) return sec + 'с назад';
  if (sec < 3600) return Math.floor(sec/60) + 'м назад';
  return Math.floor(sec/3600) + 'ч назад';
}
async function refresh() {
  let data;
  try {
    const r = await fetch('/api/nodes', {cache: 'no-store'});
    data = await r.json();
  } catch (e) { return; }
  const tbody = document.querySelector('#tbl tbody');
  const rows = Object.values(data).sort((a,b) => a.host.localeCompare(b.host));
  document.getElementById('empty').style.display = rows.length ? 'none' : 'block';
  document.getElementById('summary').textContent =
    rows.length + ' нод · ok: ' + rows.filter(n=>n.status==='ok').length +
    ' · внимание: ' + rows.filter(n=>n.status==='alert'||n.status==='stale').length +
    ' · недоступно: ' + rows.filter(n=>n.status==='down').length;
  tbody.innerHTML = rows.map(n => `
    <tr>
      <td><span class="dot ${n.status}"></span></td>
      <td class="host">${n.host}</td>
      <td>${n.cpu_pct}% <span class="bar ${barClass(n.cpu_pct)}"><span style="width:${Math.min(n.cpu_pct,100)}%"></span></span></td>
      <td class="muted">${n.cpu_steal_pct}%</td>
      <td>${n.mem_used_pct}% <span class="bar ${barClass(n.mem_used_pct)}"><span style="width:${Math.min(n.mem_used_pct,100)}%"></span></span></td>
      <td>${n.disk_max_pct}% <span class="bar ${barClass(n.disk_max_pct)}"><span style="width:${Math.min(n.disk_max_pct,100)}%"></span></span></td>
      <td>${n.load1}</td>
      <td class="muted">${n.conntrack_pct}%</td>
      <td>${n.wg_peers_online}/${n.wg_peers_total}</td>
      <td>${n.openvpn_clients}</td>
      <td>${n.xray_sessions}</td>
      <td class="muted">${fmtAge(n.age_sec)}</td>
      <td class="alerts">${(n.alerts||[]).map(a=>a.message).join('; ')}</td>
    </tr>`).join('');
}
function shortSite(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch (e) { return url; }
}
async function refreshProbes() {
  let data;
  try {
    const r = await fetch('/api/probes', {cache: 'no-store'});
    data = await r.json();
  } catch (e) { return; }
  const nodes = Object.values(data).sort((a,b) => a.node.localeCompare(b.node));
  document.getElementById('probes-empty').style.display = nodes.length ? 'none' : 'block';
  if (!nodes.length) return;

  // Собираем плоский список строк (node + proxy) и общий набор сайтов (из первой пробы каждой ноды)
  const allSites = [...new Set(nodes.flatMap(n => n.targets || []))];
  const head = document.getElementById('probes-head');
  head.innerHTML = '<th>Prober-нода</th><th>Прокси (из подписки)</th>' +
    allSites.map(s => `<th>${shortSite(s)}</th>`).join('') + '<th>Обновлено</th>';

  const rows = [];
  for (const n of nodes) {
    for (const p of (n.proxies || [])) {
      const bySite = {};
      for (const r of p.results) bySite[r.target] = r;
      rows.push({ node: n.node, proxy: p.proxy, bySite, age: n.age_sec });
    }
  }
  const tbody = document.querySelector('#probes-tbl tbody');
  tbody.innerHTML = rows.map(row => `
    <tr>
      <td class="muted">${row.node}</td>
      <td>${row.proxy}</td>
      ${allSites.map(s => {
        const r = row.bySite[s];
        if (!r) return '<td class="site-cell muted">—</td>';
        const cls = r.ok ? 'cell-ok' : 'cell-bad';
        const mark = r.ok ? '●' : '✕';
        return `<td class="site-cell ${cls}" title="${r.http_code}">${mark}<div class="lat">${r.latency_ms}мс</div></td>`;
      }).join('')}
      <td class="muted">${fmtAge(row.age)}</td>
    </tr>`).join('');
}
refresh();
refreshProbes();
setInterval(refresh, 5000);
setInterval(refreshProbes, 10000);
</script>
</body>
</html>
"""


def check_auth_header(header_value, expected_token):
    if not expected_token:
        return False
    if not header_value or not header_value.startswith("Bearer "):
        return False
    provided = header_value[len("Bearer "):]
    return hmac.compare_digest(provided, expected_token)


def probe_status(p):
    age = time.time() - p.get("_received_at", 0)
    if age > PROBES_STALE_AFTER_SEC:
        return "stale"
    return "ok"


class Handler(BaseHTTPRequestHandler):
    server_version = "vpn-monitor-server/1.0"

    def log_message(self, fmt, *args):
        pass  # тихий лог, чтобы не засорять journal; при отладке можно включить

    def _dash_authorized(self):
        if not DASH_USER:
            return True  # аутентификация дашборда не настроена (используйте reverse proxy!)
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8")
            user, _, pw = decoded.partition(":")
        except Exception:
            return False
        return hmac.compare_digest(user, DASH_USER) and hmac.compare_digest(pw, DASH_PASS)

    def _require_dash_auth(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="vpn-monitor"')
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            if not self._dash_authorized():
                return self._require_dash_auth()
            body = DASHBOARD_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/nodes":
            if not self._dash_authorized():
                return self._require_dash_auth()
            now = time.time()
            with _lock:
                out = {}
                for host, n in _nodes.items():
                    d = dict(n)
                    d["age_sec"] = int(now - n.get("_received_at", 0))
                    d["status"] = node_status(n)
                    d.pop("_received_at", None)
                    out[host] = d
            body = json.dumps(out).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/probes":
            if not self._dash_authorized():
                return self._require_dash_auth()
            now = time.time()
            with _lock:
                out = {}
                for node, p in _probes.items():
                    d = dict(p)
                    d["age_sec"] = int(now - p.get("_received_at", 0))
                    d["status"] = probe_status(p)
                    d.pop("_received_at", None)
                    out[node] = d
            body = json.dumps(out).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def _read_json_body(self, max_len=2_000_000):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > max_len:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except Exception:
            return None

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/ingest":
            if not check_auth_header(self.headers.get("Authorization", ""), INGEST_TOKEN):
                self.send_response(401)
                self.end_headers()
                return
            payload = self._read_json_body(1_000_000)
            if payload is None or "host" not in payload:
                self.send_response(400)
                self.end_headers()
                return
            host = str(payload["host"])[:255]
            payload["_received_at"] = time.time()
            with _lock:
                _nodes[host] = payload
                save_state()
            self.send_response(204)
            self.end_headers()
        elif path == "/ingest-probes":
            if not check_auth_header(self.headers.get("Authorization", ""), PROBES_INGEST_TOKEN):
                self.send_response(401)
                self.end_headers()
                return
            payload = self._read_json_body(2_000_000)
            if payload is None or "node" not in payload:
                self.send_response(400)
                self.end_headers()
                return
            node = str(payload["node"])[:255]
            payload["_received_at"] = time.time()
            with _lock:
                _probes[node] = payload
                save_probes_state()
            self.send_response(204)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


def main():
    load_state()
    if not INGEST_TOKEN:
        print("[WARN] VPN_MON_INGEST_TOKEN не задан — /ingest будет отклонять все запросы.")
    if not DASH_USER:
        print("[WARN] VPN_MON_DASH_USER не задан — дашборд БЕЗ пароля. "
              "Ставьте за nginx с TLS + Basic Auth или задайте VPN_MON_DASH_USER/PASS.")
    srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"vpn-monitor-server слушает {LISTEN_HOST}:{LISTEN_PORT}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
