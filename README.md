# vpn-node-monitor

Фаул-толерантный мониторинг парка VPN-нод (WireGuard / OpenVPN / Xray-VLESS)
+ проверка доступности сайтов через прокси из подписок ("работает ли обход
блокировок на самом деле") + центральный веб-дашборд.

## Компоненты

| Компонент | Где ставится | Что делает |
|---|---|---|
| `vpn-node-monitor.sh` | **на каждой VPN-ноде** | системные метрики + метрики WG/OpenVPN/Xray, Prometheus textfile, Telegram-алерты, POST на центральный сервер |
| `central-server/vpn-monitor-server.py` | **на одном central-сервере** | принимает данные от нод и от prober'а, отдаёт веб-дашборд |
| `subscription-prober/subscription_prober.py` | **на одном сервере** (central или отдельный "watcher") | берёт вашу subscription-ссылку, поднимает каждый прокси из неё через Xray, проверяет доступность списка сайтов через каждый, шлёт результат на central |

Дашборд: `https://<ваш-домен>/` — таблица нод (CPU/RAM/диск/steal/WG-пиры/...) +
матрица "прокси x сайт" от prober'а.

---

## 0. Общие требования

- Debian/Ubuntu (команды ниже — `apt`; на других дистрибутивах — свои пакетные менеджеры)
- Домен с TLS (Let's Encrypt) перед центральным сервером — дашборд отдаёт логин/пароль и токены, голый HTTP недопустим
- Если домен проксируется через Cloudflare — **обязательно DNS-only (серое облако)**, а не Proxied (оранжевое). Оранжевый прокси Cloudflare перехватывает и блокирует POST-запросы от нод/prober'а (WAF), это даёт `403 Forbidden` вместо реального ответа сервера.
- Все компоненты — только `bash`/`python3` stdlib, никаких pip/npm зависимостей

---

## 1. Центральный сервер

### 1.1 Пакеты

```bash
apt update
apt install -y git python3 nginx certbot python3-certbot-nginx
```

### 1.2 Системные пользователи (least-privilege)

Дашборд и prober работают НЕ от root — если в python-коде когда-нибудь найдут
уязвимость, атакующий получит права мусорного юзера, а не root.

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin vpn-monitor
useradd --system --no-create-home --shell /usr/sbin/nologin subprober
```

### 1.3 Клонировать репозиторий

Сервисы запускаются **прямо из репозитория** (`/opt/vpn-node-monitor`), без
промежуточного копирования в `/usr/local/bin` — так `git pull` сразу
обновляет то, что реально исполняется.

```bash
git clone https://github.com/Mrzalupa-lolz/vpn-node-monitor.git /opt/vpn-node-monitor
chmod 755 /opt /opt/vpn-node-monitor

# central-server и subscription-prober работают от разных непривилегированных
# юзеров — им нужны права на чтение СВОИХ подкаталогов репозитория
chown -R vpn-monitor:vpn-monitor /opt/vpn-node-monitor/central-server
chown -R subprober:subprober     /opt/vpn-node-monitor/subscription-prober
chmod 755 /opt/vpn-node-monitor/central-server/vpn-monitor-server.py
chmod 755 /opt/vpn-node-monitor/subscription-prober/subscription_prober.py
```

### 1.4 Конфиг дашборда

```bash
mkdir -p /etc/vpn-monitor-server /var/lib/vpn-monitor-server
chown vpn-monitor:vpn-monitor /var/lib/vpn-monitor-server

cp /opt/vpn-node-monitor/central-server/vpn-monitor-server.env.example \
   /etc/vpn-monitor-server/vpn-monitor-server.env
nano /etc/vpn-monitor-server/vpn-monitor-server.env
```

Что обязательно поменять:
- `VPN_MON_INGEST_TOKEN` — случайная строка (`openssl rand -hex 32`), её же впишете в `.env` на каждой ноде как `CENTRAL_POST_TOKEN`
- `VPN_MON_PROBES_INGEST_TOKEN` — отдельный токен для prober'а (можно тот же, можно другой)
- `VPN_MON_DASH_USER` / `VPN_MON_DASH_PASS` — логин/пароль от веб-дашборда

> **Важно про формат `.env`:** `systemd EnvironmentFile` **не поддерживает
> инлайн-комментарии** после значения (`KEY=value   # комментарий` —
> комментарий целиком уедет в значение переменной и всё сломает).
> Комментарии — только на отдельной строке, начинающейся с `#`.

```bash
chmod 600 /etc/vpn-monitor-server/vpn-monitor-server.env
```

### 1.5 systemd

```bash
cp /opt/vpn-node-monitor/central-server/vpn-monitor-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vpn-monitor-server

systemctl status vpn-monitor-server --no-pager
curl -s -o /dev/null -w 'direct=%{http_code}\n' http://127.0.0.1:8787/healthz   # ожидаем 200
```

Если порт `8787` уже занят другим процессом (например старым
`remnawave-monitor` или чем-то ещё) — `ss -ltnp | grep 8787` покажет, что
именно его держит, либо смените `VPN_MON_PORT` в `.env`.

### 1.6 nginx + TLS

```bash
cat > /etc/nginx/sites-available/vpn-monitor <<'EOF'
server {
    listen 80;
    server_name monitor.example.com;   # ваш домен, DNS-only если Cloudflare

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 30s;
    }
}
EOF

ln -s /etc/nginx/sites-available/vpn-monitor /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

certbot --nginx -d monitor.example.com
```

Убедитесь, что в `sites-enabled` **нет второго конфига**, проксирующего на
тот же backend с другим `server_name` — дублирующие конфиги на разных
доменах для одного и того же порта плодят путаницу при отладке.

### 1.7 subscription-prober (проверка сайтов через прокси из подписки)

```bash
mkdir -p /etc/subscription-prober /var/lib/subscription-prober /var/log/subscription-prober
chown subprober:subprober /var/lib/subscription-prober /var/log/subscription-prober

cp /opt/vpn-node-monitor/subscription-prober/subscription-prober.env.example \
   /etc/subscription-prober/subscription-prober.env
nano /etc/subscription-prober/subscription-prober.env
```

Обязательно задать:
- `SUB_PROBER_SUBSCRIPTIONS` — ваша(и) ссылка(и) подписки (через запятую, если несколько)
- `SUB_PROBER_CENTRAL_URL` — `https://monitor.example.com/ingest-probes`
- `SUB_PROBER_CENTRAL_TOKEN` — значение `VPN_MON_PROBES_INGEST_TOKEN` из шага 1.4
- `SUB_PROBER_XRAY_BIN` — путь к бинарнику `xray` (тот же, что используется на нодах)

Поддерживаемые форматы подписки — определяются автоматически:
- share-линки (`vless://`, `vmess://`, `trojan://`, `ss://`), plain-список или base64
- sing-box JSON (`{"outbounds":[{"type":"vless", "server": ...}]}`)
- нативный Xray-core client-config JSON (`{"outbounds":[{"protocol":"vless", "settings":{...}, "streamSettings":{...}}]}`) — в т.ч. балансировщики (`routing.balancers`) и xhttp/hysteria2 с полным набором полей (padding, xmux, finalmask и т.п.). Секции `routing.balancers`/`routing.rules` игнорируются — каждый outbound проверяется отдельно, а не через балансировку.

```bash
chmod 600 /etc/subscription-prober/subscription-prober.env
chmod +x /opt/vpn-node-monitor/subscription-prober/subscription_prober.py

cp /opt/vpn-node-monitor/subscription-prober/subscription-prober.service /etc/systemd/system/
cp /opt/vpn-node-monitor/subscription-prober/subscription-prober.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now subscription-prober.timer

# разовый прогон прямо сейчас
systemctl start subscription-prober.service
journalctl -u subscription-prober.service -n 30 --no-pager
```

Ожидаемая строка в логе: `цикл завершён: N прокси x M сайтов, доступно X/Y`.
Если `нет ни одного успешно распарсенного прокси` — проверьте формат
подписки (см. выше) и что ссылка вообще отдаёт данные (`curl <ссылка>`).

---

## 2. Обычная VPN-нода

### 2.1 Пакеты

```bash
apt update
apt install -y git curl jq bc iproute2 wireguard-tools
```
(`wireguard-tools` — только если на ноде используется WireGuard)

Если ещё не стоит `node_exporter` — установите отдельно, флаг
`--collector.textfile.directory=/var/lib/node_exporter/textfile_collector`
обязателен.

### 2.2 Клонировать репозиторий

```bash
git clone https://github.com/Mrzalupa-lolz/vpn-node-monitor.git /opt/vpn-node-monitor
chmod 755 /opt /opt/vpn-node-monitor
chmod +x /opt/vpn-node-monitor/vpn-node-monitor.sh
```

Скрипт работает от `root` (нужны права на `wg show dump`, `systemctl
is-active`, чтение `/proc/net/*`) — отдельного системного юзера заводить не
нужно.

### 2.3 Конфиг

```bash
mkdir -p /etc/vpn-node-monitor
cp /opt/vpn-node-monitor/vpn-node-monitor.env.example \
   /etc/vpn-node-monitor/vpn-node-monitor.env
nano /etc/vpn-node-monitor/vpn-node-monitor.env
```

Что стоит поправить:
- `SYSTEMD_UNITS` — реальные юниты этой ноды (несуществующие сами пропускаются, можно смело перечислить с запасом: `xray xray.service sing-box wg-quick@wg0 openvpn@server remnawave-node`)
- `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` — если нужны алерты в Telegram
- `CENTRAL_POST_URL` — `https://monitor.example.com/ingest`
- `CENTRAL_POST_TOKEN` — значение `VPN_MON_INGEST_TOKEN` с центрального сервера (шаг 1.4)
- `NODE_TAG` — понятное имя ноды для дашборда (пусто = `hostname -f`)

```bash
chmod 600 /etc/vpn-node-monitor/vpn-node-monitor.env
```

### 2.4 Каталоги вывода

> Юнит использует `ProtectSystem=strict` + `ReadWritePaths=` — эти пути
> должны **существовать до первого запуска**, иначе systemd падает с
> `Failed to set up mount namespacing ... status=226/NAMESPACE` ещё до
> того, как скрипт успевает их создать сам.

```bash
mkdir -p /var/lib/vpn-node-monitor /var/log/vpn-node-monitor \
         /var/lib/node_exporter/textfile_collector
```

### 2.5 systemd + logrotate

```bash
cp /opt/vpn-node-monitor/systemd/vpn-node-monitor.service /etc/systemd/system/
cp /opt/vpn-node-monitor/systemd/vpn-node-monitor.timer /etc/systemd/system/
cp /opt/vpn-node-monitor/logrotate/vpn-node-monitor /etc/logrotate.d/vpn-node-monitor

systemctl daemon-reload
systemctl enable --now vpn-node-monitor.timer

# разовый запуск прямо сейчас
systemctl start vpn-node-monitor.service
journalctl -u vpn-node-monitor.service -n 30 --no-pager
```

### 2.6 Проверка

```bash
cat /var/lib/node_exporter/textfile_collector/vpn_node.prom
tail -n 20 /var/log/vpn-node-monitor/monitor.log
```

Если задан `CENTRAL_POST_URL` — нода должна появиться в таблице на
`https://monitor.example.com/` в течение ~30 секунд (интервал таймера).

---

## 3. Обновление

Юнит-файлы — это **копии** в `/etc/systemd/system`, не симлинки на
репозиторий. `git pull` их не трогает — после каждого обновления, если
менялись `.service`/`.timer`, копию нужно перезалить и сделать
`daemon-reload`.

### Центральный сервер

```bash
cd /opt/vpn-node-monitor
git pull
cp central-server/vpn-monitor-server.service /etc/systemd/system/
cp subscription-prober/subscription-prober.service subscription-prober/subscription-prober.timer /etc/systemd/system/
systemctl daemon-reload
systemctl restart vpn-monitor-server
systemctl status vpn-monitor-server --no-pager
systemctl start subscription-prober.service
journalctl -u subscription-prober.service -n 20 --no-pager
```

### Обычная нода

```bash
cd /opt/vpn-node-monitor
git pull
cp systemd/vpn-node-monitor.service systemd/vpn-node-monitor.timer /etc/systemd/system/
chmod +x vpn-node-monitor.sh
systemctl daemon-reload
systemctl start vpn-node-monitor.service
journalctl -u vpn-node-monitor.service -n 20 --no-pager
```

---

## 4. Диагностика частых проблем

| Симптом | Причина | Что проверить |
|---|---|---|
| `TypeError: encoding of hostname failed` в логе `vpn-monitor-server` | Инлайн-комментарий после значения в `.env` (systemd не режет `# ...` после `KEY=value`) | `cat -A /etc/vpn-monitor-server/vpn-monitor-server.env` — комментарий должен быть на отдельной строке |
| `405`/чужой JSON при `curl 127.0.0.1:8787` | На порту сидит другой процесс | `ss -ltnp \| grep 8787` → `cat /proc/<pid>/cmdline` |
| Сайт отдаёт `403` | Домен проксируется через Cloudflare (оранжевое облако) | Переключить DNS-запись в Cloudflare на DNS-only (серое облако) |
| Пароль дашборда "не подходит" | Пароль реально не тот, либо `auth_basic` в nginx перехватывает раньше python | `grep -rn auth_basic /etc/nginx/sites-enabled/`; `curl -u user:pass http://127.0.0.1:8787/` в обход nginx |
| `status=203/EXEC` в journalctl | У скрипта не выставлен бит `+x`, либо файла нет по указанному пути | `ls -l`, `chmod +x` |
| `status=226/NAMESPACE`, `Failed to set up mount namespacing` | `ReadWritePaths=` в юните ссылается на несуществующую директорию | `mkdir -p` нужные пути (см. 2.4) до старта юнита |
| `python3: can't open file '/usr/local/bin/....py'` после переноса в `/opt` | Юнит в `/etc/systemd/system` не перезалит после смены `ExecStart` в репозитории | `cp .../*.service /etc/systemd/system/ && systemctl daemon-reload` |
| `central POST failed: HTTP Error 502` | Backend (`vpn-monitor-server`) временно не отвечает (например, в момент своего рестарта) | `curl 127.0.0.1:8787/healthz` напрямую; если `200` — было разовое совпадение по времени, просто повторить прогон |
| `subscription-prober`: "нет ни одного успешно распарсенного прокси" | Формат подписки не распознан | Проверить `curl <ссылка подписки>` — валидный ли это JSON/share-линки; см. поддерживаемые форматы в 1.7 |
| Высокий `%CPU` у процесса ноды (`rw-core`/`xray`) | Часто — реальная нагрузка трафиком, не баг | `top -b -n1 -o %CPU`; смотреть на `%st` (steal) в шапке — если высокий, это урезание CPU хостером, а не потребление вашим процессом; `nproc` — сколько ядер вообще есть, `ss -tn state established \| wc -l` — сколько сессий |
