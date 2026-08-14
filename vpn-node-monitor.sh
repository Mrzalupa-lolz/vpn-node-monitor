#!/usr/bin/env bash
#
# vpn-node-monitor.sh — легковесный отказоустойчивый мониторинг VPN-ноды
# (WireGuard / OpenVPN / Xray-VLESS) для systemd-таймера.
#
# Запуск: одноразовый (one-shot). Между запусками счётчики (CPU/сеть/диск)
# хранятся в STATE_DIR, дельта считается без sleep — минимальная нагрузка.
#
# Вывод:
#   - Prometheus textfile-экспорт (node_exporter textfile collector)
#   - локальный JSON-лог (по одной строке на запуск)
#   - Telegram-алерты (только при переходе состояния, с debounce)
#   - опциональный HTTP POST на центральный сервер
#
# Безопасность: приватные ключи WireGuard никогда не читаются и не логируются.
# Публичные ключи и идентификаторы пользователей (email/CN) по умолчанию
# хэшируются (см. LOG_USER_IDENTIFIERS в .env).

set -uo pipefail
umask 077

# ---------------------------------------------------------------------------
# 0. Конфигурация
# ---------------------------------------------------------------------------

SCRIPT_NAME="vpn-node-monitor"
CONFIG_FILE="${VPN_MONITOR_CONFIG:-/etc/vpn-node-monitor/vpn-node-monitor.env}"

# Значения по умолчанию (перекрываются из CONFIG_FILE)
METRICS_DIR="/var/lib/node_exporter/textfile_collector"
METRICS_FILE="${METRICS_DIR}/vpn_node.prom"
LOG_DIR="/var/log/vpn-node-monitor"
LOG_FILE="${LOG_DIR}/monitor.log"
STATE_DIR="/var/lib/vpn-node-monitor"

WG_ENABLE="auto"                 # auto|yes|no
OPENVPN_ENABLE="auto"
OPENVPN_STATUS_FILES="/etc/openvpn/openvpn-status.log /etc/openvpn/server/openvpn-status.log"
XRAY_ENABLE="auto"
XRAY_BIN="/usr/local/bin/xray"
XRAY_API_ADDR="127.0.0.1:10085"
XRAY_INBOUND_PORTS=""            # напр. "443 8443" — для подсчёта ESTABLISHED-сессий через ss

SYSTEMD_UNITS="xray xray.service sing-box wg-quick@wg0 wg-quick@wg1 openvpn@server openvpn remnawave-node"

LOG_USER_IDENTIFIERS="hash"      # hash|plain — как логировать email/CN пользователей

CPU_ALERT_PCT=90
MEM_ALERT_PCT=90
DISK_ALERT_PCT=90
LOAD_ALERT_MULT=2                # алерт если loadavg1 > nproc * LOAD_ALERT_MULT
CONNTRACK_ALERT_PCT=90
ALERT_REPEAT_MIN=30              # не слать повторный алерт по тому же поводу чаще, чем раз в N минут

TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""

CENTRAL_POST_URL=""
CENTRAL_POST_TOKEN=""
CENTRAL_POST_TIMEOUT=10

NODE_TAG="$(hostname -f 2>/dev/null || hostname)"

# shellcheck disable=SC1090
[ -r "$CONFIG_FILE" ] && source "$CONFIG_FILE"

mkdir -p "$METRICS_DIR" "$LOG_DIR" "$STATE_DIR" 2>/dev/null
chmod 700 "$STATE_DIR" 2>/dev/null

NOW_EPOCH=$(date +%s)
NOW_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ---------------------------------------------------------------------------
# 1. Утилиты
# ---------------------------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

# Никогда не даём в лог похожие на ключи строки (base64/hex длиной как WG/Reality ключи)
mask_sensitive() {
    sed -E 's/[A-Za-z0-9+\/]{43}=/[REDACTED_KEY]/g; s/\b[0-9a-fA-F]{64}\b/[REDACTED_KEY]/g'
}

hash_id() {
    # короткий стабильный псевдонимный ID вместо email/CN/pubkey
    printf '%s' "$1" | sha256sum | cut -c1-12
}

log_json() {
    # $1 = произвольная JSON-строка (уже собранная)
    printf '%s\n' "$1" | mask_sensitive >> "$LOG_FILE"
}

# Атомарная запись prom-файла, чтобы node_exporter не читал "половину"
PROM_TMP="$(mktemp "${METRICS_DIR}/.vpn_node.XXXXXX")"
prom() { printf '%s\n' "$1" >> "$PROM_TMP"; }

finalize_prom() {
    mv -f "$PROM_TMP" "$METRICS_FILE"
    chmod 644 "$METRICS_FILE" 2>/dev/null
}
trap 'rm -f "$PROM_TMP" 2>/dev/null' EXIT

state_get() { # $1=key -> stdout значение или пусто
    local f="${STATE_DIR}/$1"
    [ -r "$f" ] && cat "$f" || true
}
state_set() { # $1=key $2=value
    printf '%s' "$2" > "${STATE_DIR}/$1.tmp" && mv -f "${STATE_DIR}/$1.tmp" "${STATE_DIR}/$1"
}

# ---------------------------------------------------------------------------
# 2. Алерты (Telegram + HTTP POST) с debounce по причине
# ---------------------------------------------------------------------------

ALERTS_JSON="[]"          # накопитель алертов для central POST
ALERTS_RAISED=0

should_fire() { # $1 = уникальный ключ причины алерта -> 0 если пора слать
    local key="alert_last_${1}"
    local last
    last=$(state_get "$key")
    if [ -z "$last" ] || [ $(( NOW_EPOCH - last )) -ge $(( ALERT_REPEAT_MIN * 60 )) ]; then
        state_set "$key" "$NOW_EPOCH"
        return 0
    fi
    return 1
}

send_telegram() { # $1 = текст
    [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ] || return 0
    have curl || return 0
    curl -s -m 10 --retry 1 \
        -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
        --data-urlencode "text=$1" \
        --data-urlencode "parse_mode=Markdown" \
        >/dev/null 2>>"${LOG_DIR}/telegram_errors.log" || true
}

raise_alert() { # $1=reason_key $2=severity $3=message
    local reason="$1" sev="$2" msg="$3"
    ALERTS_RAISED=1
    if should_fire "$reason"; then
        send_telegram "*[${sev}]* \`${NODE_TAG}\`: ${msg}"
        log_json "{\"ts\":\"${NOW_ISO}\",\"level\":\"alert\",\"severity\":\"${sev}\",\"reason\":\"${reason}\",\"message\":\"${msg}\"}"
    fi
    ALERTS_JSON=$(printf '%s' "$ALERTS_JSON" | sed "s/\]\$/,{\"reason\":\"${reason}\",\"severity\":\"${sev}\",\"message\":\"$(printf '%s' "$msg" | sed 's/"/\\"/g')\"}]/")
    ALERTS_JSON="${ALERTS_JSON/[,/[}"   # почистить ведущую запятую если массив был пуст
}

# ---------------------------------------------------------------------------
# 3. Системные метрики: CPU, RAM, LA, диск, сеть, температура, PSI, conntrack
# ---------------------------------------------------------------------------

NPROC=$(nproc 2>/dev/null || echo 1)

# --- CPU (включая steal — индикатор оверселлинга хоста гипервизором) ---
read -r _ cpu_user cpu_nice cpu_sys cpu_idle cpu_iowait cpu_irq cpu_softirq cpu_steal _ < <(grep '^cpu ' /proc/stat)
cpu_total_now=$((cpu_user+cpu_nice+cpu_sys+cpu_idle+cpu_iowait+cpu_irq+cpu_softirq+cpu_steal))
cpu_idle_now=$((cpu_idle+cpu_iowait))

prev_cpu_total=$(state_get cpu_total_prev); prev_cpu_idle=$(state_get cpu_idle_prev); prev_cpu_steal=$(state_get cpu_steal_prev)
cpu_pct="0"; steal_pct="0"
if [ -n "$prev_cpu_total" ]; then
    dt=$(( cpu_total_now - prev_cpu_total ))
    if [ "$dt" -gt 0 ]; then
        d_idle=$(( cpu_idle_now - prev_cpu_idle ))
        d_steal=$(( cpu_steal - prev_cpu_steal ))
        cpu_pct=$(awk -v dt="$dt" -v di="$d_idle" 'BEGIN{printf "%.2f", (1-di/dt)*100}')
        steal_pct=$(awk -v dt="$dt" -v ds="$d_steal" 'BEGIN{printf "%.2f", (ds/dt)*100}')
    fi
fi
state_set cpu_total_prev "$cpu_total_now"; state_set cpu_idle_prev "$cpu_idle_now"; state_set cpu_steal_prev "$cpu_steal"

# --- Load average ---
read -r la1 la5 la15 _ < /proc/loadavg

# --- RAM ---
mem_total_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
mem_avail_kb=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
mem_used_pct=$(awk -v t="$mem_total_kb" -v a="$mem_avail_kb" 'BEGIN{ if(t>0) printf "%.2f", (1-a/t)*100; else print "0"}')

# --- Диск (использование по смонтированным реальным ФС) + IO дельта ---
DISK_PROM=""
DISK_MAX_PCT=0
while read -r fs size used avail pct mount; do
    p="${pct%\%}"
    [[ "$p" =~ ^[0-9]+$ ]] || continue
    (( p > DISK_MAX_PCT )) && DISK_MAX_PCT=$p
    mount_esc=$(printf '%s' "$mount" | sed 's/"/\\"/g')
    DISK_PROM+="vpn_node_disk_used_percent{mount=\"${mount_esc}\"} ${p}
"
done < <(df -x tmpfs -x devtmpfs -x overlay -x squashfs -P 2>/dev/null | tail -n +2)

read -r rd_sectors wr_sectors <<<"$(awk '$3 !~ /loop|ram/ {rd+=$6; wr+=$10} END{print rd, wr}' /proc/diskstats)"
disk_rd_now=$(( (rd_sectors) * 512 )); disk_wr_now=$(( (wr_sectors) * 512 ))
prev_rd=$(state_get disk_rd_prev); prev_wr=$(state_get disk_wr_prev); prev_ts=$(state_get sample_ts_prev)
disk_rd_bps=0; disk_wr_bps=0
if [ -n "$prev_ts" ] && [ "$NOW_EPOCH" -gt "$prev_ts" ]; then
    interval=$(( NOW_EPOCH - prev_ts ))
    [ -n "$prev_rd" ] && disk_rd_bps=$(( (disk_rd_now - prev_rd) / interval ))
    [ -n "$prev_wr" ] && disk_wr_bps=$(( (disk_wr_now - prev_wr) / interval ))
fi
state_set disk_rd_prev "$disk_rd_now"; state_set disk_wr_prev "$disk_wr_now"

# --- Сеть: bytes/sec по интерфейсам (кроме lo/докер-мостов/wg — их отдельно) ---
NET_PROM=""
while read -r iface rx_bytes _ _ _ _ _ _ _ tx_bytes _; do
    iface="${iface%:}"
    [[ "$iface" == "lo" ]] && continue
    [[ "$iface" =~ ^(docker|veth|br-|virbr) ]] && continue
    prev_rx=$(state_get "net_rx_${iface}"); prev_tx=$(state_get "net_tx_${iface}")
    rx_bps=0; tx_bps=0
    if [ -n "$prev_rx" ] && [ -n "$prev_ts" ] && [ "$NOW_EPOCH" -gt "$prev_ts" ]; then
        interval=$(( NOW_EPOCH - prev_ts ))
        rx_bps=$(( (rx_bytes - prev_rx) / interval ))
        tx_bps=$(( (tx_bytes - prev_tx) / interval ))
    fi
    state_set "net_rx_${iface}" "$rx_bytes"; state_set "net_tx_${iface}" "$tx_bytes"
    NET_PROM+="vpn_node_net_receive_bytes_per_second{iface=\"${iface}\"} ${rx_bps}
vpn_node_net_transmit_bytes_per_second{iface=\"${iface}\"} ${tx_bps}
"
done < <(tail -n +3 /proc/net/dev)

state_set sample_ts_prev "$NOW_EPOCH"

# --- Температура (best-effort, без внешних зависимостей) ---
TEMP_C=""
if [ -d /sys/class/thermal ]; then
    for z in /sys/class/thermal/thermal_zone*/temp; do
        [ -r "$z" ] || continue
        raw=$(cat "$z" 2>/dev/null) || continue
        [[ "$raw" =~ ^[0-9]+$ ]] || continue
        c=$(awk -v r="$raw" 'BEGIN{printf "%.1f", r/1000}')
        # берём максимум по зонам как приблизительную "температуру CPU"
        if [ -z "$TEMP_C" ] || (( $(awk -v a="$c" -v b="$TEMP_C" 'BEGIN{print (a>b)}') )); then TEMP_C="$c"; fi
    done
fi

# --- PSI (Pressure Stall Information) — раннее обнаружение узких мест ядра ---
PSI_PROM=""
for r in cpu memory io; do
    f="/proc/pressure/${r}"
    [ -r "$f" ] || continue
    some_avg10=$(awk -F'avg10=| ' '/^some/{print $3}' "$f")
    [ -n "$some_avg10" ] && PSI_PROM+="vpn_node_psi_some_avg10{resource=\"${r}\"} ${some_avg10}
"
done

# --- Conntrack (важно для нод с большим числом клиентов) ---
CT_COUNT=""; CT_MAX=""
[ -r /proc/sys/net/netfilter/nf_conntrack_count ] && CT_COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
[ -r /proc/sys/net/netfilter/nf_conntrack_max ] && CT_MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
CT_PCT=0
if [ -n "$CT_COUNT" ] && [ -n "$CT_MAX" ] && [ "$CT_MAX" -gt 0 ]; then
    CT_PCT=$(awk -v c="$CT_COUNT" -v m="$CT_MAX" 'BEGIN{printf "%.2f", c/m*100}')
fi

# ---------------------------------------------------------------------------
# 4. Статус systemd-юнитов VPN-служб (только реально существующие)
# ---------------------------------------------------------------------------

SVC_PROM=""
for unit in $SYSTEMD_UNITS; do
    systemctl list-unit-files "$unit" >/dev/null 2>&1 || continue
    state=$(systemctl is-active "$unit" 2>/dev/null || echo "unknown")
    val=0; [ "$state" = "active" ] && val=1
    SVC_PROM+="vpn_node_service_up{unit=\"${unit}\"} ${val}
"
    if [ "$val" -eq 0 ]; then
        raise_alert "service_down_${unit}" "CRITICAL" "служба ${unit} не активна (состояние: ${state})"
    fi
done

# ---------------------------------------------------------------------------
# 5. WireGuard: пиры, хэндшейки, трафик (без чтения приватных ключей)
# ---------------------------------------------------------------------------

WG_PROM=""
wg_total_peers=0; wg_online_peers=0
if { [ "$WG_ENABLE" = "yes" ] || [ "$WG_ENABLE" = "auto" ]; } && have wg; then
    for iface in $(wg show interfaces 2>/dev/null); do
        while IFS=$'\t' read -r pubkey _psk endpoint allowed_ips latest_hs rx tx _keepalive; do
            [ -z "${pubkey:-}" ] && continue
            wg_total_peers=$((wg_total_peers+1))
            peer_id=$(hash_id "$pubkey")   # публичный ключ тоже не логируем в открытом виде
            online=0
            if [ -n "$latest_hs" ] && [ "$latest_hs" != "0" ] && (( NOW_EPOCH - latest_hs < 180 )); then
                online=1; wg_online_peers=$((wg_online_peers+1))
            fi
            WG_PROM+="vpn_node_wg_peer_online{iface=\"${iface}\",peer=\"${peer_id}\"} ${online}
vpn_node_wg_peer_rx_bytes{iface=\"${iface}\",peer=\"${peer_id}\"} ${rx:-0}
vpn_node_wg_peer_tx_bytes{iface=\"${iface}\",peer=\"${peer_id}\"} ${tx:-0}
"
        done < <(wg show "$iface" dump 2>/dev/null | tail -n +2)
    done
fi
WG_PROM+="vpn_node_wg_peers_total ${wg_total_peers}
vpn_node_wg_peers_online ${wg_online_peers}
"

# ---------------------------------------------------------------------------
# 6. OpenVPN: активные клиенты и трафик из status-log (status-version 2)
# ---------------------------------------------------------------------------

OVPN_PROM=""
ovpn_clients=0
if [ "$OPENVPN_ENABLE" = "yes" ] || [ "$OPENVPN_ENABLE" = "auto" ]; then
    for statusf in $OPENVPN_STATUS_FILES; do
        [ -r "$statusf" ] || continue
        while IFS=',' read -r tag cn real_addr bytes_rx bytes_tx connected_since _; do
            [ "$tag" = "CLIENT_LIST" ] || continue
            [ "$cn" = "Common Name" ] && continue
            ovpn_clients=$((ovpn_clients+1))
            cid=$( [ "$LOG_USER_IDENTIFIERS" = "plain" ] && printf '%s' "$cn" || hash_id "$cn" )
            OVPN_PROM+="vpn_node_openvpn_client_rx_bytes{client=\"${cid}\"} ${bytes_rx:-0}
vpn_node_openvpn_client_tx_bytes{client=\"${cid}\"} ${bytes_tx:-0}
"
        done < "$statusf"
    done
fi
OVPN_PROM+="vpn_node_openvpn_clients_total ${ovpn_clients}
"

# ---------------------------------------------------------------------------
# 7. Xray/VLESS: трафик по пользователям через Stats API + число сессий по ss
# ---------------------------------------------------------------------------

XRAY_PROM=""
xray_active_sessions=0
if { [ "$XRAY_ENABLE" = "yes" ] || [ "$XRAY_ENABLE" = "auto" ]; } && [ -x "$XRAY_BIN" ]; then
    if have "$XRAY_BIN"; then
        stats_json=$("$XRAY_BIN" api statsquery --server="$XRAY_API_ADDR" -pattern "user>>>" 2>/dev/null || true)
        if [ -n "$stats_json" ] && have python3; then
            XRAY_PROM+=$(printf '%s' "$stats_json" | python3 - "$LOG_USER_IDENTIFIERS" <<'PYEOF'
import json, sys, hashlib
mode = sys.argv[1]
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for stat in data.get("stat", []):
    name = stat.get("name", "")
    value = stat.get("value", 0)
    parts = name.split(">>>")
    if len(parts) != 4:
        continue
    _, user, _, direction = parts
    uid = user if mode == "plain" else hashlib.sha256(user.encode()).hexdigest()[:12]
    print(f'vpn_node_xray_user_{direction}_bytes{{user="{uid}"}} {value}')
PYEOF
)
        fi
    fi
    if [ -n "$XRAY_INBOUND_PORTS" ] && have ss; then
        for port in $XRAY_INBOUND_PORTS; do
            cnt=$(ss -Htn state established "( sport = :${port} )" 2>/dev/null | wc -l)
            xray_active_sessions=$((xray_active_sessions+cnt))
            XRAY_PROM+="vpn_node_xray_established_sessions{port=\"${port}\"} ${cnt}
"
        done
    fi
fi

# ---------------------------------------------------------------------------
# 8. Пороговые алерты по системным метрикам
# ---------------------------------------------------------------------------

if (( $(awk -v c="$cpu_pct" -v t="$CPU_ALERT_PCT" 'BEGIN{print (c>t)}') )); then
    raise_alert "cpu_high" "WARNING" "загрузка CPU ${cpu_pct}% (порог ${CPU_ALERT_PCT}%)"
fi
if (( $(awk -v m="$mem_used_pct" -v t="$MEM_ALERT_PCT" 'BEGIN{print (m>t)}') )); then
    raise_alert "mem_high" "WARNING" "использование RAM ${mem_used_pct}% (порог ${MEM_ALERT_PCT}%)"
fi
if (( DISK_MAX_PCT > DISK_ALERT_PCT )); then
    raise_alert "disk_high" "WARNING" "диск заполнен на ${DISK_MAX_PCT}% (порог ${DISK_ALERT_PCT}%)"
fi
load_threshold=$(awk -v n="$NPROC" -v m="$LOAD_ALERT_MULT" 'BEGIN{printf "%.2f", n*m}')
if (( $(awk -v l="$la1" -v t="$load_threshold" 'BEGIN{print (l>t)}') )); then
    raise_alert "load_high" "WARNING" "Load average 1m = ${la1} (порог ${load_threshold}, ядер: ${NPROC})"
fi
if (( $(awk -v c="$CT_PCT" -v t="$CONNTRACK_ALERT_PCT" 'BEGIN{print (c>t)}') )); then
    raise_alert "conntrack_high" "WARNING" "conntrack таблица заполнена на ${CT_PCT}% (${CT_COUNT}/${CT_MAX})"
fi

# ---------------------------------------------------------------------------
# 9. Сборка Prometheus-файла
# ---------------------------------------------------------------------------

prom "# HELP vpn_node_cpu_usage_percent Использование CPU, %"
prom "# TYPE vpn_node_cpu_usage_percent gauge"
prom "vpn_node_cpu_usage_percent ${cpu_pct}"
prom "# HELP vpn_node_cpu_steal_percent CPU steal time (индикатор оверселлинга хоста), %"
prom "# TYPE vpn_node_cpu_steal_percent gauge"
prom "vpn_node_cpu_steal_percent ${steal_pct}"
prom "# HELP vpn_node_load1 Load average за 1 минуту"
prom "# TYPE vpn_node_load1 gauge"
prom "vpn_node_load1 ${la1}"
prom "vpn_node_load5 ${la5}"
prom "vpn_node_load15 ${la15}"
prom "vpn_node_cpu_cores ${NPROC}"
prom "# HELP vpn_node_mem_used_percent Использование RAM, %"
prom "# TYPE vpn_node_mem_used_percent gauge"
prom "vpn_node_mem_used_percent ${mem_used_pct}"
[ -n "$TEMP_C" ] && { prom "# HELP vpn_node_temperature_celsius Температура (макс. по термозонам)"; prom "# TYPE vpn_node_temperature_celsius gauge"; prom "vpn_node_temperature_celsius ${TEMP_C}"; }
prom "# HELP vpn_node_disk_used_percent Использование ФС по точкам монтирования, %"
prom "# TYPE vpn_node_disk_used_percent gauge"
prom "${DISK_PROM}"
prom "vpn_node_disk_read_bytes_per_second ${disk_rd_bps}"
prom "vpn_node_disk_write_bytes_per_second ${disk_wr_bps}"
prom "# HELP vpn_node_net_receive_bytes_per_second Входящий трафик по интерфейсу, байт/с"
prom "# TYPE vpn_node_net_receive_bytes_per_second gauge"
prom "${NET_PROM}"
[ -n "$PSI_PROM" ] && { prom "# HELP vpn_node_psi_some_avg10 PSI some avg10, % (перегрузка ресурса)"; prom "# TYPE vpn_node_psi_some_avg10 gauge"; prom "${PSI_PROM}"; }
prom "# HELP vpn_node_conntrack_used_percent Заполненность conntrack-таблицы, %"
prom "# TYPE vpn_node_conntrack_used_percent gauge"
prom "vpn_node_conntrack_used_percent ${CT_PCT}"
prom "# HELP vpn_node_service_up Статус systemd-юнита (1=active)"
prom "# TYPE vpn_node_service_up gauge"
prom "${SVC_PROM}"
prom "# HELP vpn_node_wg_peer_online WireGuard: пир онлайн (handshake < 180s)"
prom "# TYPE vpn_node_wg_peer_online gauge"
prom "${WG_PROM}"
prom "# HELP vpn_node_openvpn_clients_total Число подключённых клиентов OpenVPN"
prom "# TYPE vpn_node_openvpn_clients_total gauge"
prom "${OVPN_PROM}"
prom "# HELP vpn_node_xray_established_sessions Активные ESTABLISHED-сессии на inbound-порт Xray"
prom "# TYPE vpn_node_xray_established_sessions gauge"
prom "${XRAY_PROM}"
prom "# HELP vpn_node_alerts_active 1 если в этом цикле были подняты алерты"
prom "# TYPE vpn_node_alerts_active gauge"
prom "vpn_node_alerts_active ${ALERTS_RAISED}"
prom "vpn_node_scrape_timestamp_seconds ${NOW_EPOCH}"

finalize_prom

# ---------------------------------------------------------------------------
# 10. Локальный JSON-лог сводки цикла
# ---------------------------------------------------------------------------

log_json "$(cat <<EOF
{"ts":"${NOW_ISO}","host":"${NODE_TAG}","cpu_pct":${cpu_pct},"cpu_steal_pct":${steal_pct},"load1":${la1},"mem_used_pct":${mem_used_pct},"disk_max_pct":${DISK_MAX_PCT},"conntrack_pct":${CT_PCT},"wg_peers_online":${wg_online_peers},"wg_peers_total":${wg_total_peers},"openvpn_clients":${ovpn_clients},"xray_sessions":${xray_active_sessions},"alerts_raised":${ALERTS_RAISED}}
EOF
)"

# ---------------------------------------------------------------------------
# 11. Опциональная отправка на центральный сервер
# ---------------------------------------------------------------------------

if [ -n "$CENTRAL_POST_URL" ] && have curl; then
    payload=$(cat <<EOF
{"host":"${NODE_TAG}","ts":"${NOW_ISO}","cpu_pct":${cpu_pct},"cpu_steal_pct":${steal_pct},"load1":${la1},"mem_used_pct":${mem_used_pct},"disk_max_pct":${DISK_MAX_PCT},"conntrack_pct":${CT_PCT},"wg_peers_online":${wg_online_peers},"wg_peers_total":${wg_total_peers},"openvpn_clients":${ovpn_clients},"xray_sessions":${xray_active_sessions},"alerts":${ALERTS_JSON}}
EOF
)
    curl -s -m "$CENTRAL_POST_TIMEOUT" --retry 2 --retry-delay 2 \
        -X POST "$CENTRAL_POST_URL" \
        -H "Content-Type: application/json" \
        ${CENTRAL_POST_TOKEN:+-H "Authorization: Bearer ${CENTRAL_POST_TOKEN}"} \
        -d "$payload" \
        >/dev/null 2>>"${LOG_DIR}/central_post_errors.log" || \
        log_json "{\"ts\":\"${NOW_ISO}\",\"level\":\"error\",\"message\":\"central POST failed\"}"
fi

exit 0
