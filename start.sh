#!/usr/bin/env bash
# ============================================================================
# ARTEX — Unified Service Runner & Reverse Proxy Manager
# ============================================================================
# Works both as the Docker/Supervisor entrypoint (`./start.sh [-addr :8787]`)
# and as the multi-service runner (`tmux`, `dev`, `domain`, `status`, `stop`, `logs`).
#
# Usage:
#   ./start.sh                         # Run ARTEX supervisor in foreground (or Docker ENTRYPOINT)
#   ./start.sh all                     # Start Backend (:8787) + Frontend (:3000) + Chrome (:9222) in tmux
#   ./start.sh tmux                    # Alias for ./start.sh all
#   ./start.sh dev                     # Run Backend + Frontend in hot-reload dev mode
#   sudo ./start.sh domain <domain> [--ssl] # Configure Nginx reverse proxy on port 80/443 for domain
#   ./start.sh status                  # Check status of all ARTEX services
#   ./start.sh stop                    # Stop all ARTEX processes & tmux session
#   ./start.sh logs                    # Follow live ARTEX logs
# ============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

TMUX_SESSION="artex"
ARTEX_PORT="${ARTEX_PORT:-8787}"
WEB_PORT="${WEB_PORT:-3000}"

validate_port() {
  local name="$1" val="$2"
  case "$val" in
    ''|*[!0-9]*)
      printf "[-] Invalid %s=%q: must be a numeric port between 1 and 65535\n" "$name" "$val" >&2
      exit 1
      ;;
  esac
  if [ "$val" -lt 1 ] || [ "$val" -gt 65535 ]; then
    printf "[-] Invalid %s=%s: must be between 1 and 65535\n" "$name" "$val" >&2
    exit 1
  fi
}

validate_port "ARTEX_PORT" "$ARTEX_PORT"
validate_port "WEB_PORT" "$WEB_PORT"

info() { printf "${BLUE}[*]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\n" "$*" >&2; }
die()  { printf "${RED}[-]${NC} %s\n" "$*" >&2; exit 1; }

start_chrome_headless() {
  if pgrep -f "remote-debugging-port=9222" >/dev/null 2>&1; then
    ok "Headless Chrome already running on 127.0.0.1:9222"
    return 0
  fi
  local chrome_bin=""
  for cand in google-chrome google-chrome-stable chromium-browser chromium "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; do
    if command -v "$cand" >/dev/null 2>&1 || [ -x "$cand" ]; then
      chrome_bin="$cand"
      break
    fi
  done
  if [ -z "$chrome_bin" ]; then
    warn "Chrome/Chromium not found; skipping standalone port 9222 listener"
    return 0
  fi
  nohup "$chrome_bin" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 about:blank >/tmp/artex-chrome.log 2>&1 &
  ok "Started Headless Chrome on 127.0.0.1:9222"
}

start_tmux_all() {
  [ -x ./artex ] || die "./artex binary not found. Run: ./setup.sh build"

  start_chrome_headless
  if command -v tmux >/dev/null 2>&1; then
    tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true
  fi
  if [ -f /tmp/artex-backend.pid ]; then
    kill "$(cat /tmp/artex-backend.pid)" 2>/dev/null || true
    rm -f /tmp/artex-backend.pid
  fi
  if [ -f /tmp/artex-web.pid ]; then
    kill "$(cat /tmp/artex-web.pid)" 2>/dev/null || true
    rm -f /tmp/artex-web.pid
  fi
  pkill -f "./artex -addr" 2>/dev/null || true
  pkill -f "next start -p ${WEB_PORT}" 2>/dev/null || true
  sleep 1

  if command -v tmux >/dev/null 2>&1; then
    tmux new-session -d -s "$TMUX_SESSION" -n "backend" "cd '$SCRIPT_DIR' && ./start.sh -addr :${ARTEX_PORT} 2>&1 | tee -a /tmp/artex-server.log"
    if [ -d "$SCRIPT_DIR/web/.next" ]; then
      tmux new-window -t "$TMUX_SESSION:1" -n "frontend" "cd '$SCRIPT_DIR/web' && while :; do NODE_OPTIONS='--max-http-header-size=65536' npx next start -p ${WEB_PORT} 2>&1 | tee -a /tmp/artex-web.log; sleep 2; done"
    fi
    tmux new-window -t "$TMUX_SESSION:2" -n "logs" "tail -f /tmp/artex-server.log"

    ok "Started all ARTEX services in tmux session '$TMUX_SESSION'"
    info "Attach to tmux session: tmux attach -t $TMUX_SESSION"
  else
    warn "tmux not installed; starting ARTEX services as background daemons"
    nohup "$SCRIPT_DIR/start.sh" -addr ":${ARTEX_PORT}" >>/tmp/artex-server.log 2>&1 &
    echo $! >/tmp/artex-backend.pid
    if [ -d "$SCRIPT_DIR/web/.next" ]; then
      ( cd "$SCRIPT_DIR/web" && NODE_OPTIONS="--max-http-header-size=65536" nohup npx next start -p "${WEB_PORT}" >>/tmp/artex-web.log 2>&1 & echo $! >/tmp/artex-web.pid )
    fi
    sleep 1
    ok "Started ARTEX background services (logs: /tmp/artex-server.log, /tmp/artex-web.log)"
  fi
  show_status
}

configure_nginx_domain() {
  local domain="${1:-_}"
  local ssl="${2:-0}"
  [ "$(id -u)" -eq 0 ] || die "Root required to configure Nginx: sudo ./start.sh domain $domain"
  info "Configuring Nginx reverse proxy for domain '${domain}' -> 127.0.0.1:${ARTEX_PORT}..."

  cat > /etc/nginx/sites-available/artex.conf <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};

    client_max_body_size 100M;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://127.0.0.1:${ARTEX_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
        proxy_intercept_errors on;
        error_page 502 503 504 =503 @maintenance;
    }

    location @maintenance {
        default_type text/html;
        return 503 '<!DOCTYPE html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="3"><title>ARTEX — Updating System</title><style>body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#09090b;color:#fafafa;font-family:system-ui,-apple-system,sans-serif;text-align:center}.card{max-width:440px;padding:36px;border:1px solid #27272a;border-radius:16px;background:#18181b;box-shadow:0 20px 50px rgba(0,0,0,.5)}.spinner{width:36px;height:36px;margin:0 auto 20px;border:3px solid #27272a;border-top-color:#10b981;border-radius:50%;animation:s 1s linear infinite}@keyframes s{to{transform:rotate(360deg)}}h2{margin:0 0 10px;font-size:20px}p{margin:0;color:#a1a1aa;font-size:14px;line-height:1.6}</style></head><body><div class="card"><div class="spinner"></div><h2>ARTEX System Updating</h2><p>Applying the latest repository update and restarting services.<br>This page will automatically reconnect in a few seconds...</p></div></body></html>';
    }
}
EOF
  rm -f /etc/nginx/sites-enabled/default
  ln -sf /etc/nginx/sites-available/artex.conf /etc/nginx/sites-enabled/artex.conf
  nginx -t && systemctl enable --now nginx && systemctl reload nginx
  ok "Nginx routing http://${domain} -> 127.0.0.1:${ARTEX_PORT}"

  if [ "$ssl" = "1" ] && [ "$domain" != "_" ]; then
    info "Provisioning Let's Encrypt TLS certificate for ${domain}..."
    certbot --nginx -d "$domain" --non-interactive --agree-tos --register-unsafely-without-email --redirect || warn "Certbot failed; HTTP on port 80 remains active."
  fi
}

show_status() {
  echo ""
  printf "${CYAN}══════════════════════════════════════════════════════════════════${NC}\n"
  printf "${GREEN}📊 ARTEX Service Status${NC}\n"
  printf "${CYAN}══════════════════════════════════════════════════════════════════${NC}\n"
  if lsof -i ":${ARTEX_PORT}" >/dev/null 2>&1 || pgrep -f "./artex" >/dev/null 2>&1; then
    ok "ARTEX Core Backend (:${ARTEX_PORT} + Proxy :8788) : RUNNING"
  else
    warn "ARTEX Core Backend (:${ARTEX_PORT})              : STOPPED"
  fi
  if lsof -i ":${WEB_PORT}" >/dev/null 2>&1; then
    ok "Next.js Web UI     (:${WEB_PORT})              : RUNNING"
  else
    info "Next.js Web UI     (:${WEB_PORT})              : Embedded in :${ARTEX_PORT}"
  fi
  if pgrep -f "remote-debugging-port=9222" >/dev/null 2>&1; then
    ok "Headless Chrome    (:9222)              : RUNNING"
  fi
  if command -v tmux >/dev/null 2>&1 && tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
    ok "tmux Session       (${TMUX_SESSION})              : ACTIVE (tmux attach -t ${TMUX_SESSION})"
  fi
  printf "${CYAN}══════════════════════════════════════════════════════════════════${NC}\n"
}

run_supervisor() {
  BIN=./artex
  [ -x "$BIN" ] || die "Executable not found: $BIN (run ./setup.sh build first)"

  RESTART_CODE=75
  MAX_DELAY=60
  child=0
  stopping=0

  forward() {
    stopping=1
    if [ "$child" -ne 0 ]; then
      kill -TERM "$child" 2>/dev/null || true
    fi
  }
  trap forward INT TERM

  delay=1
  while :; do
    "$BIN" "$@" &
    child=$!
    wait "$child"
    code=$?
    if [ "$code" -gt 128 ]; then
      wait "$child"
      code=$?
    fi
    child=0

    if [ "$stopping" -eq 1 ]; then
      echo "[artex] stopped"
      exit 0
    fi

    case "$code" in
      0)
        echo "[artex] exited cleanly"
        exit 0
        ;;
      "$RESTART_CODE")
        echo "[artex] restarting to apply update..."
        pkill -f "next-server" 2>/dev/null || true
        delay=1
        ;;
      *)
        echo "[artex] unexpected exit (code=$code), restarting in ${delay}s..." >&2
        sleep "$delay"
        delay=$((delay * 2))
        [ "$delay" -gt "$MAX_DELAY" ] && delay=$MAX_DELAY
        ;;
    esac
  done
}

case "${1:-}" in
  all|tmux)
    shift
    start_tmux_all "$@"
    ;;
  dev)
    shift
    cleanup() { kill 0 2>/dev/null || true; }
    trap cleanup EXIT INT TERM
    go run ./cmd/artex -addr :8787 -proxy 127.0.0.1:8788 &
    ( cd web && npm run dev ) &
    info "Dev mode running: Backend :8787 | Traffic Proxy :8788 | Frontend http://localhost:3000 (Ctrl-C to stop)"
    wait
    ;;
  domain)
    shift
    dom="${1:-}"
    [ -n "$dom" ] || die "Usage: sudo ./start.sh domain <yourdomain.com> [--ssl]"
    ssl_flag=0
    [ "${2:-}" = "--ssl" ] && ssl_flag=1
    configure_nginx_domain "$dom" "$ssl_flag"
    ;;
  status)
    show_status
    ;;
  stop)
    info "Stopping ARTEX services..."
    if command -v tmux >/dev/null 2>&1; then
      tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true
    fi
    if [ -f /tmp/artex-backend.pid ]; then
      kill "$(cat /tmp/artex-backend.pid)" 2>/dev/null || true
      rm -f /tmp/artex-backend.pid
    fi
    if [ -f /tmp/artex-web.pid ]; then
      kill "$(cat /tmp/artex-web.pid)" 2>/dev/null || true
      rm -f /tmp/artex-web.pid
    fi
    pkill -f "./artex" 2>/dev/null || true
    pkill -f "next start -p ${WEB_PORT}" 2>/dev/null || true
    pkill -f "remote-debugging-port=9222" 2>/dev/null || true
    if command -v systemctl >/dev/null 2>&1; then
      systemctl stop artex.service 2>/dev/null || true
    fi
    ok "All ARTEX services stopped"
    ;;
  logs)
    tail -n 100 -f /tmp/artex-server.log /var/log/artex.log 2>/dev/null
    ;;
  help|--help|-h)
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    run_supervisor "$@"
    ;;
esac


