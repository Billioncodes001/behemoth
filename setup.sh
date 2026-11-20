#!/usr/bin/env bash
# ============================================================================
# ARTEX — Unified Setup, Build, Update & Admin Maintenance Script
# ============================================================================
# Consolidates: Ubuntu production setup, Docker setup, Local setup,
# Cross-platform release builder, Updater, and Admin Password Reset.
#
# Usage:
#   sudo ./setup.sh full [--domain example.com] [--ssl]  # Complete Ubuntu production setup
#   ./setup.sh local                                     # Local build & PostgreSQL config
#   ./setup.sh docker                                    # Docker Compose setup
#   ./setup.sh build [--target os/arch] [--release]      # Build frontend + single binary
#   ./setup.sh update                                    # Pull & rebuild/update deployment
#   ./setup.sh reset-password [-p 'NewPass!']            # Reset ARTEX admin password in DB
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { echo -e "${BLUE}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*" >&2; }
die()  { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }
ask()  { local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }
rand_secret() { LC_ALL=C tr -dc 'A-Za-z0-9' < <(head -c 256 /dev/urandom) | cut -c1-24; }

banner() {
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║          ARTEX — Autonomous Penetration Testing Platform         ║${NC}"
  echo -e "${CYAN}║         Unified Setup, Build, Update & Maintenance Utility       ║${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
  echo ""
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Root privileges required. Run with: sudo ./setup.sh $*"
  fi
}

install_system_deps() {
  info "Installing Ubuntu/Debian system packages, browser dependencies, and pentest tools..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y -qq
  apt-get install -y -qq \
    curl wget git jq unzip zip tar tmux ca-certificates gnupg lsb-release \
    build-essential pkg-config openssl ufw nginx certbot python3-certbot-nginx \
    postgresql postgresql-contrib \
    python3 python3-pip python3-venv \
    nmap sqlmap dnsutils whois netcat-openbsd socat ripgrep || true

  apt-get install -y -qq \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2t64 2>/dev/null || \
  apt-get install -y -qq \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 2>/dev/null || true

  if ! command -v google-chrome >/dev/null 2>&1 && ! command -v chromium >/dev/null 2>&1 && ! command -v chromium-browser >/dev/null 2>&1; then
    info "Installing headless Chrome/Chromium for Browser Automation & Report Screenshots..."
    apt-get install -y -qq chromium-browser 2>/dev/null || apt-get install -y -qq chromium 2>/dev/null || {
      wget -q -O /tmp/google-chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb && \
      apt-get install -y -qq /tmp/google-chrome.deb && rm -f /tmp/google-chrome.deb || true
    }
  fi
  install_security_arsenal
  ok "System dependencies and security tools installed"
}

install_gh_release_tool() {
  local repo="$1" bin_name="$2" install_as="${3:-$2}"
  local target_dir="/usr/local/bin"
  if [[ ! -w "$target_dir" ]]; then
    target_dir="$HOME/.local/bin"
    mkdir -p "$target_dir"
  fi
  if command -v "$install_as" >/dev/null 2>&1; then
    return 0
  fi
  local os_tag="linux" arch_tag="amd64"
  case "$(uname -s)" in
    Darwin|darwin) os_tag="macOS" ;;
  esac
  case "$(uname -m)" in
    aarch64|arm64) arch_tag="arm64" ;;
  esac
  local dl_url
  dl_url="$(python3 - "$repo" "$os_tag" "$arch_tag" <<'PY' 2>/dev/null || true
import json, sys, urllib.request
repo, os_tag, arch_tag = sys.argv[1], sys.argv[2].lower(), sys.argv[3].lower()
os_aliases = ["macos", "darwin"] if os_tag == "macos" else ["linux"]
arch_aliases = ["arm64", "aarch64"] if arch_tag == "arm64" else ["amd64", "x86_64", "64-bit"]
req = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest", headers={"User-Agent": "artex-setup"})
with urllib.request.urlopen(req, timeout=15) as r:
    data = json.load(r)
for a in data.get("assets", []):
    n = a.get("name", "").lower()
    if n.endswith((".zip", ".tar.gz", ".tgz")) and "checksum" not in n:
        if any(o in n for o in os_aliases) and any(ar in n for ar in arch_aliases):
            print(a["browser_download_url"])
            break
PY
)"
  [[ -n "$dl_url" ]] || return 0
  local tmpd
  tmpd="$(mktemp -d)"
  if curl -fsSL "$dl_url" -o "$tmpd/pkg" 2>/dev/null; then
    if [[ "$dl_url" == *.zip ]]; then
      unzip -qo "$tmpd/pkg" -d "$tmpd" >/dev/null 2>&1 || true
    else
      tar -xzf "$tmpd/pkg" -C "$tmpd" >/dev/null 2>&1 || true
    fi
    local found_bin
    found_bin="$(find "$tmpd" -type f -name "$bin_name" | head -n 1)"
    if [[ -n "$found_bin" && -f "$found_bin" ]]; then
      install -m 0755 "$found_bin" "${target_dir}/${install_as}"
      ok "Installed ${install_as} -> ${target_dir}/${install_as}"
    fi
  fi
  rm -rf "$tmpd"
}

install_security_arsenal() {
  info "Provisioning offensive & reconnaissance CLI arsenal..."
  if command -v apt-get >/dev/null 2>&1 && [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y -qq 2>/dev/null || true
    for pkg in nmap sqlmap whatweb nikto gobuster ffuf dirb hydra sslscan wafw00f dnsutils whois netcat-openbsd socat ripgrep jq python3-requests python3-bs4 python3-dnspython; do
      apt-get install -y -qq "$pkg" >/dev/null 2>&1 || true
    done
  fi

  install_gh_release_tool "projectdiscovery/nuclei" "nuclei" "nuclei"
  install_gh_release_tool "projectdiscovery/subfinder" "subfinder" "subfinder"
  install_gh_release_tool "projectdiscovery/httpx" "httpx" "httpx-pd"
  if [[ -x /usr/local/bin/httpx-pd ]] && ! command -v httpx >/dev/null 2>&1; then
    ln -sf /usr/local/bin/httpx-pd /usr/local/bin/httpx 2>/dev/null || true
  fi
  install_gh_release_tool "projectdiscovery/dnsx" "dnsx" "dnsx"
  install_gh_release_tool "ffuf/ffuf" "ffuf" "ffuf"
  install_gh_release_tool "OJ/gobuster" "gobuster" "gobuster"

  if command -v nuclei >/dev/null 2>&1; then
    nuclei -update-templates -silent >/dev/null 2>&1 &
  fi
  ok "Security CLI arsenal ready"
}

install_golang() {
  local req_ver="1.26.10"
  export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
  if command -v go >/dev/null 2>&1; then
    local cur_ver
    cur_ver="$(go version | awk '{print $3}' | sed 's/go//')"
    if [[ "$cur_ver" == "${req_ver}"* ]]; then
      ok "Go already installed: $(go version)"
      return
    fi
  fi
  info "Installing Go ${req_ver}..."
  local arch="amd64"
  case "$(uname -m)" in
    aarch64|arm64) arch="arm64" ;;
  esac
  local os_name="linux"
  case "$(uname -s)" in
    Darwin|darwin) os_name="darwin" ;;
  esac
  curl -fsSL "https://go.dev/dl/go${req_ver}.${os_name}-${arch}.tar.gz" -o /tmp/go.tar.gz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tar.gz
  rm -f /tmp/go.tar.gz
  mkdir -p /usr/local/bin
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
  ok "Installed $(go version)"
}

install_nodejs() {
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    local major
    major="$(node -v | sed 's/v//' | cut -d. -f1)"
    if [[ "$major" -ge 18 ]]; then
      ok "Node.js already installed: $(node -v) (npm $(npm -v))"
      return
    fi
  fi
  info "Installing Node.js 20 LTS..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y -qq nodejs
  ok "Installed Node.js $(node -v) (npm $(npm -v))"
}

install_playwright_globals() {
  if command -v npm >/dev/null 2>&1; then
    info "Ensuring Playwright MCP, Reasoning/Memory MCPs & CLI are installed..."
    npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest @modelcontextprotocol/server-sequential-thinking@latest @modelcontextprotocol/server-memory@latest >/dev/null 2>&1 || true
    npx playwright install --with-deps chromium >/dev/null 2>&1 || true
    ok "Playwright MCP, Reasoning/Memory MCPs & Chromium ready"
  fi
}

setup_postgresql() {
  info "Configuring PostgreSQL database..."
  systemctl enable --now postgresql

  if [[ -f config.json ]]; then
    ok "Existing config.json detected — preserving database configuration"
    return
  fi

  local db_pass
  db_pass="$(rand_secret)"
  su - postgres -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname = 'artex'\" | grep -q 1 || psql -c \"CREATE USER artex WITH PASSWORD '${db_pass}';\""
  su - postgres -c "psql -c \"ALTER USER artex WITH PASSWORD '${db_pass}';\""
  su - postgres -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname = 'artex'\" | grep -q 1 || psql -c \"CREATE DATABASE artex OWNER artex;\""
  su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE artex TO artex;\""

  cat > config.json <<EOF
{
  "database": {
    "host": "127.0.0.1",
    "port": 5432,
    "user": "artex",
    "password": "${db_pass}",
    "dbname": "artex",
    "sslmode": "disable"
  }
}
EOF
  chmod 600 config.json
  ok "PostgreSQL database 'artex' initialized and config.json created"
}

build_artex() {
  export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
  if command -v npm >/dev/null 2>&1; then
    info "Building Next.js frontend static bundle (for embedded single-binary)..."
    (
      cd web
      if [[ -f package-lock.json ]]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi
      npm run build:static
    )
    rm -rf server/webui/dist && mkdir -p server/webui && cp -r web/out server/webui/dist
    info "Building Next.js server runtime bundle (with /api/* proxy rewrites)..."
    ( cd web && npm run build )
  fi
  local build_ver="${ARTEX_BUILD_VERSION:-}"
  if [[ -z "$build_ver" ]]; then
    build_ver="$(git describe --tags --abbrev=0 2>/dev/null || echo "2.3.0")"
  fi
  build_ver="${build_ver#v}"
  info "Compiling single-binary ARTEX server (./artex v${build_ver})..."
  CGO_ENABLED=0 go build -tags embedui -trimpath -ldflags "-s -w -X main.version=${build_ver}" -o artex ./cmd/artex
  chmod +x artex start.sh
  ok "Compiled ./artex v${build_ver} ($(du -h artex | awk '{print $1}'))"
}

reset_admin_password() {
  local newpass="${1:-}"
  if [[ -z "$newpass" ]]; then
    read -rsp "Enter new ARTEX admin password (>=8 chars): " newpass; echo ""
  fi
  [[ "${#newpass}" -ge 8 ]] || die "Password must be at least 8 characters"
  export ARTEX_RESET_NEWPASS="$newpass"

  local psql_cmd=(psql --no-psqlrc -v ON_ERROR_STOP=1)
  if [[ -n "${ARTEX_PG_DSN:-}" ]]; then
    psql_cmd+=("$ARTEX_PG_DSN")
  elif [[ -f config.json ]] && command -v python3 >/dev/null 2>&1; then
    local db_dsn
    db_dsn="$(python3 -c '
import json, urllib.parse
c = json.load(open("config.json")).get("database", {})
if c.get("dsn"):
    print(c["dsn"])
elif c.get("user") and c.get("dbname"):
    u = urllib.parse.quote(str(c.get("user", "")), safe="")
    pw = urllib.parse.quote(str(c.get("password", "")), safe="")
    h = c.get("host") or "127.0.0.1"
    pt = c.get("port") or 5432
    db = urllib.parse.quote(str(c.get("dbname", "artex")), safe="")
    ssl = c.get("sslmode") or "disable"
    auth = f"{u}:{pw}@" if pw else f"{u}@"
    print(f"postgres://{auth}{h}:{pt}/{db}?sslmode={ssl}")
' 2>/dev/null || true)"
    if [[ -n "$db_dsn" ]]; then
      psql_cmd+=("$db_dsn")
    else
      psql_cmd+=(-d artex)
    fi
  elif [[ "${EUID:-$(id -u)}" -eq 0 ]] && id -u postgres >/dev/null 2>&1; then
    psql_cmd=(sudo -E -u postgres psql --no-psqlrc -d artex -v ON_ERROR_STOP=1)
  else
    psql_cmd+=(-d artex)
  fi

  "${psql_cmd[@]}" <<'SQL'
\getenv newpw ARTEX_RESET_NEWPASS
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO settings(key, value)
VALUES ('auth.password_hash', crypt(:'newpw', gen_salt('bf', 10)))
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();
SQL
  unset ARTEX_RESET_NEWPASS
  ok "ARTEX admin password updated successfully (login with username: ARTEX)"
}

CMD="${1:-full}"
shift || true
DOMAIN="_"
ENABLE_SSL=0
NEWPASS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain|-d) DOMAIN="${2:-_}"; shift 2 ;;
    --ssl|--tls) ENABLE_SSL=1; shift ;;
    -p|--new-password) NEWPASS="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) shift ;;
  esac
done

case "$CMD" in
  full|up)
    banner
    require_root
    install_system_deps
    install_golang
    install_nodejs
    install_playwright_globals
    setup_postgresql
    build_artex
    ./start.sh all
    if [[ "$DOMAIN" != "_" ]]; then
      if [[ "$ENABLE_SSL" -eq 1 ]]; then ./start.sh domain "$DOMAIN" --ssl; else ./start.sh domain "$DOMAIN"; fi
    else
      ./start.sh domain "_"
    fi
    ;;
  build)
    banner
    build_artex
    ;;
  local)
    banner
    build_artex
    ./start.sh all
    ;;
  docker)
    banner
    if [[ ! -f .env ]]; then
      local gen_pass
      gen_pass="$(rand_secret)"
      if [[ -f .env.example ]]; then
        sed "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${gen_pass}/" .env.example > .env
      else
        printf "POSTGRES_USER=artex\nPOSTGRES_PASSWORD=%s\nPOSTGRES_DB=artex\n" "$gen_pass" > .env
      fi
      chmod 600 .env
      ok "Initialized .env with generated PostgreSQL password"
    fi
    docker compose pull && docker compose up -d
    ok "Docker Compose deployment active -> http://localhost:8787"
    ;;
  update)
    banner
    git pull --ff-only || warn "git pull skipped or non-fast-forward"
    build_artex
    ./start.sh all
    ;;
  arsenal)
    banner
    install_security_arsenal
    ;;
  reset-password)
    banner
    reset_admin_password "$NEWPASS"
    ;;
  *)
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    ;;
esac
