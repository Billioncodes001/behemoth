#!/usr/bin/env bash
# ============================================================================
# BEHEMOTH — Unified Setup, Build, Update & Admin Maintenance Script
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
#   ./setup.sh arsenal                                   # Re-provision offensive CLI arsenal
#   sudo ./setup.sh gpu                                  # Provision GPU cracking stack (driver, CUDA/OpenCL, hashcat, john-jumbo)
#   sudo ./setup.sh searxng                              # Provision self-hosted SearXNG meta-search (127.0.0.1:8888, auto-enabled in BEHEMOTH)
#   ./setup.sh reset-password [-p 'NewPass!']            # Reset BEHEMOTH admin password in DB
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
  echo -e "${CYAN}║          BEHEMOTH — Autonomous Penetration Testing Platform         ║${NC}"
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
    nmap sqlmap dnsutils whois netcat-openbsd socat ripgrep \
    tesseract-ocr || true

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
  install_gpu_cracking_stack
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
arch_aliases = ["arm64", "aarch64"] if arch_tag == "arm64" else ["amd64", "x86_64", "64-bit", "64bit"]
req = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest", headers={"User-Agent": "behemoth-setup"})
with urllib.request.urlopen(req, timeout=15) as r:
    data = json.load(r)
for a in data.get("assets", []):
    n = a.get("name", "").lower()
    if n.endswith((".zip", ".tar.gz", ".tgz")) and not any(skip in n for skip in ("checksum", "sbom", "sigstore", ".1.zip")):
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
      # Handle nested .tar.gz inside .zip (e.g. RustScan's x86_64-linux-rustscan.tar.gz.zip)
      for nested_tar in "$tmpd"/*.tar.gz "$tmpd"/*.tgz; do
        [[ -f "$nested_tar" ]] && tar -xzf "$nested_tar" -C "$tmpd" >/dev/null 2>&1 || true
      done
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

# ensure_pipx_cli installs a Python CLI package into an isolated Python 3.12-safe
# virtualenv under /opt/behemoth-venvs (pre-seeding setuptools<71 + wheel so
# packages that import pkg_resources like scoutsuite/pacu install cleanly on
# Ubuntu 24.04 & Debian 12) and symlinks the CLI into /usr/local/bin.
ensure_pipx_cli() {
  local pkg="$1" cli="$2"
  command -v "$cli" >/dev/null 2>&1 && return 0
  mkdir -p /usr/local/bin /opt/pipx /opt/behemoth-venvs 2>/dev/null || true
  local vdir="/opt/behemoth-venvs/${pkg}"
  if [[ ! -x "$vdir/bin/pip" ]]; then
    rm -rf "$vdir" 2>/dev/null || true
    python3 -m venv "$vdir" >/dev/null 2>&1 || true
  fi
  if [[ -x "$vdir/bin/pip" ]]; then
    "$vdir/bin/pip" install --quiet --upgrade pip "setuptools<71" wheel >/dev/null 2>&1 || true
    "$vdir/bin/pip" install --quiet "$pkg" >/dev/null 2>&1 || true
    if [[ -f "$vdir/bin/$cli" ]]; then
      ln -sf "$vdir/bin/$cli" "/usr/local/bin/$cli" 2>/dev/null || true
      ok "Installed ${cli} -> /usr/local/bin/${cli} (venv ${vdir})"
      return 0
    fi
  fi
  if command -v pipx >/dev/null 2>&1; then
    PIPX_BIN_DIR=/usr/local/bin PIPX_HOME=/opt/pipx pipx install "$pkg" >/dev/null 2>&1 || true
    command -v "$cli" >/dev/null 2>&1 && return 0
  fi
}

# install_extended_arsenal provisions the heavier offensive/cloud/forensics
# tooling that agents commonly need: LinPEAS/WinPEAS (both winpeas.exe &
# winPEASx64.exe), smtp-user-enum, Responder (both responder & Responder),
# impacket (impacket-secretsdump / impacket-GetNPUsers / ...), Volatility 3
# (vol & volatility), Pacu, ScoutSuite (scout & scout-suite), Google Cloud SDK
# (gcloud), Azure CLI (az), and Metasploit (msfvenom). Fast tools run first so
# they become available within seconds; every step is idempotent and non-fatal.
install_extended_arsenal() {
  if [[ "${EUID:-$(id -u)}" -ne 0 && ! -w /usr/local/bin ]]; then
    info "Skipping extended arsenal (need root or writable /usr/local/bin)"
    return 0
  fi
  export PATH="/usr/local/bin:/opt/google-cloud-sdk/bin:$PATH"
  mkdir -p /usr/local/bin /opt/behemoth-venvs /opt/pipx 2>/dev/null || true
  info "Provisioning extended arsenal (PEASS, smtp-user-enum, Responder, impacket, Volatility, Pacu, ScoutSuite, gcloud, az, metasploit)..."

  # --- 1. LinPEAS / WinPEAS (both winPEASx64.exe and winpeas.exe) ---
  if ! command -v linpeas.sh >/dev/null 2>&1; then
    if curl -fsSL "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" -o /usr/local/bin/linpeas.sh 2>/dev/null; then
      chmod 0755 /usr/local/bin/linpeas.sh
      ln -sf /usr/local/bin/linpeas.sh /usr/local/bin/linpeas 2>/dev/null || true
      ok "linpeas.sh installed"
    else
      warn "linpeas.sh download failed"
    fi
  fi
  if ! command -v winPEASx64.exe >/dev/null 2>&1 || ! command -v winpeas.exe >/dev/null 2>&1; then
    if [[ -f /usr/local/bin/winpeas.exe && ! -f /usr/local/bin/winPEASx64.exe ]]; then
      cp -f /usr/local/bin/winpeas.exe /usr/local/bin/winPEASx64.exe
      chmod 0755 /usr/local/bin/winPEASx64.exe
    elif [[ -f /usr/local/bin/winPEASx64.exe && ! -f /usr/local/bin/winpeas.exe ]]; then
      ln -sf /usr/local/bin/winPEASx64.exe /usr/local/bin/winpeas.exe
    elif curl -fsSL "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe" -o /usr/local/bin/winPEASx64.exe 2>/dev/null; then
      chmod 0755 /usr/local/bin/winPEASx64.exe
      ln -sf /usr/local/bin/winPEASx64.exe /usr/local/bin/winpeas.exe 2>/dev/null || true
      ok "winPEASx64.exe & winpeas.exe installed"
    else
      warn "winPEASx64.exe download failed"
    fi
  fi

  # --- 2. smtp-user-enum (PentestMonkey official Perl script when apt lacks it) ---
  if ! command -v smtp-user-enum >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get install -y -qq perl smtp-user-enum >/dev/null 2>&1 || apt-get install -y -qq perl >/dev/null 2>&1 || true
    fi
    if ! command -v smtp-user-enum >/dev/null 2>&1; then
      if curl -fsSL "https://raw.githubusercontent.com/pentestmonkey/smtp-user-enum/master/smtp-user-enum.pl" -o /usr/local/bin/smtp-user-enum 2>/dev/null; then
        chmod 0755 /usr/local/bin/smtp-user-enum
        ok "smtp-user-enum installed -> /usr/local/bin/smtp-user-enum"
      fi
    fi
  fi

  # --- 3. Responder (both `responder` and `Responder` for Tool Catalog compatibility) ---
  if ! command -v responder >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    apt-get install -y -qq responder >/dev/null 2>&1 || true
  fi
  if ! command -v responder >/dev/null 2>&1; then
    if [[ ! -f /opt/Responder/Responder.py ]]; then
      rm -rf /opt/Responder 2>/dev/null || true
      git clone --depth 1 https://github.com/lgandx/Responder.git /opt/Responder >/dev/null 2>&1 || true
    fi
    if [[ -f /opt/Responder/Responder.py ]]; then
      for mod in netifaces aioquic; do
        if command -v apt-get >/dev/null 2>&1; then
          apt-get install -y -qq "python3-${mod}" >/dev/null 2>&1 || true
        fi
        python3 -m pip install --quiet --break-system-packages "$mod" >/dev/null 2>&1 || true
      done
      printf '#!/usr/bin/env bash\ncd /opt/Responder || exit 1\nexec python3 Responder.py "$@"\n' > /usr/local/bin/responder
      chmod 0755 /usr/local/bin/responder
      ok "Responder installed -> /usr/local/bin/responder"
    else
      warn "Responder clone failed"
    fi
  fi
  if command -v responder >/dev/null 2>&1 && ! command -v Responder >/dev/null 2>&1; then
    ln -sf "$(command -v responder)" /usr/local/bin/Responder 2>/dev/null || true
  fi

  # --- 4. impacket: guarantee impacket-secretsdump, impacket-GetNPUsers & all impacket-* on PATH ---
  if ! command -v impacket-secretsdump >/dev/null 2>&1 || ! command -v impacket-GetNPUsers >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get install -y -qq impacket-scripts python3-impacket >/dev/null 2>&1 || true
    fi
  fi
  if ! command -v impacket-secretsdump >/dev/null 2>&1 || ! command -v impacket-GetNPUsers >/dev/null 2>&1; then
    local ivdir="/opt/behemoth-venvs/impacket"
    rm -rf "$ivdir" 2>/dev/null || true
    if python3 -m venv "$ivdir" >/dev/null 2>&1; then
      "$ivdir/bin/pip" install --quiet --upgrade pip "setuptools<71" wheel >/dev/null 2>&1 || true
      "$ivdir/bin/pip" install --quiet impacket >/dev/null 2>&1 || true
      for script in "$ivdir"/bin/*.py; do
        [[ -f "$script" ]] || continue
        local base
        base="$(basename "$script")"
        chmod 0755 "$script" 2>/dev/null || true
        ln -sf "$script" "/usr/local/bin/impacket-${base%.py}" 2>/dev/null || true
        ln -sf "$script" "/usr/local/bin/${base}" 2>/dev/null || true
      done
    fi
  fi
  command -v impacket-secretsdump >/dev/null 2>&1 && ok "impacket (impacket-secretsdump, impacket-GetNPUsers, ...) ready" || warn "impacket console scripts unavailable"

  # --- 5. Volatility 3 (provides `vol`, `volatility`, and `vol.py`) ---
  if ! command -v vol >/dev/null 2>&1; then
    ensure_pipx_cli volatility3 vol
  fi
  if command -v vol >/dev/null 2>&1; then
    local vol_bin
    vol_bin="$(command -v vol)"
    ln -sf "$vol_bin" /usr/local/bin/volatility 2>/dev/null || true
    ln -sf "$vol_bin" /usr/local/bin/vol.py 2>/dev/null || true
    ok "Volatility 3 (vol & volatility) ready"
  else
    warn "Volatility 3 unavailable"
  fi

  # --- 6. Pacu (AWS exploitation framework) ---
  ensure_pipx_cli pacu pacu
  command -v pacu >/dev/null 2>&1 && ok "Pacu installed" || warn "pacu unavailable"

  # --- 7. ScoutSuite (provides both `scout` and `scout-suite`) ---
  if ! command -v scout >/dev/null 2>&1; then
    ensure_pipx_cli scoutsuite scout
  fi
  if command -v scout >/dev/null 2>&1; then
    ln -sf "$(command -v scout)" /usr/local/bin/scout-suite 2>/dev/null || true
    ok "ScoutSuite (scout & scout-suite) installed"
  else
    warn "scout-suite unavailable"
  fi

  # --- 8. Google Cloud SDK (gcloud, gsutil, bq) ---
  if ! command -v gcloud >/dev/null 2>&1; then
    local sdk_arch="x86_64"
    case "$(uname -m)" in
      aarch64|arm64) sdk_arch="arm" ;;
    esac
    local sdk_dir="/opt/google-cloud-sdk"
    if [[ ! -x "$sdk_dir/bin/gcloud" ]]; then
      if curl -fsSL "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-${sdk_arch}.tar.gz" -o /tmp/google-cloud-sdk.tar.gz 2>/dev/null; then
        rm -rf "$sdk_dir"
        tar -xzf /tmp/google-cloud-sdk.tar.gz -C /opt >/dev/null 2>&1 || true
        rm -f /tmp/google-cloud-sdk.tar.gz
      fi
    fi
    if [[ -x "$sdk_dir/bin/gcloud" ]]; then
      for gc_bin in gcloud gsutil bq; do
        [[ -x "$sdk_dir/bin/$gc_bin" ]] && ln -sf "$sdk_dir/bin/$gc_bin" "/usr/local/bin/$gc_bin" 2>/dev/null || true
      done
      ok "Google Cloud SDK (gcloud) installed -> $sdk_dir"
    else
      warn "gcloud install failed"
    fi
  fi

  # --- 9. Azure CLI (az) ---
  if ! command -v az >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      curl -sL "https://aka.ms/InstallAzureCLIDeb" 2>/dev/null | bash >/dev/null 2>&1 || true
    fi
    if ! command -v az >/dev/null 2>&1; then
      ensure_pipx_cli azure-cli az
    fi
    command -v az >/dev/null 2>&1 && ok "Azure CLI (az) installed" || warn "az install failed"
  fi

  # --- 10. Metasploit Framework (msfvenom & msfconsole) ---
  if ! command -v msfvenom >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get install -y -qq metasploit-framework >/dev/null 2>&1 || true
    fi
    if ! command -v msfvenom >/dev/null 2>&1; then
      curl -fsSL "https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb" 2>/dev/null | bash >/dev/null 2>&1 || true
    fi
    command -v msfvenom >/dev/null 2>&1 && ok "Metasploit Framework (msfvenom) installed" || warn "msfvenom install failed"
  fi

  ok "Extended arsenal ready"
}

install_security_arsenal() {
  info "Provisioning offensive, OCR & reconnaissance CLI arsenal..."
  if command -v apt-get >/dev/null 2>&1 && [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    export DEBIAN_FRONTEND=noninteractive
    local missing_apt=()
    for pkg in ca-certificates gnupg lsb-release tar gzip xz-utils perl git curl wget build-essential python3-dev libffi-dev libssl-dev tcpdump tor tesseract-ocr tesseract-ocr-eng nmap sqlmap whatweb nikto gobuster ffuf dirb hydra sslscan wafw00f default-mysql-client postgresql-client ftp dnsutils whois netcat-openbsd socat ripgrep masscan onesixtyone snmp jq python3-venv python3-pip pipx python3-requests python3-bs4 python3-dnspython python3-pymysql python3-psycopg2 hashcat john pocl-opencl-icd seclists impacket-scripts python3-impacket; do
      if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        missing_apt+=("$pkg")
      fi
    done
    if [[ "${#missing_apt[@]}" -gt 0 ]]; then
      apt-get update -y -qq 2>/dev/null || true
      apt-get install -y -qq "${missing_apt[@]}" >/dev/null 2>&1 || {
        for pkg in "${missing_apt[@]}"; do
          apt-get install -y -qq "$pkg" >/dev/null 2>&1 || true
        done
      }
    fi
    python3 -m pip install --quiet --break-system-packages pymysql psycopg2-binary redis pymongo PyJWT httpx websockets >/dev/null 2>&1 || true
    ensure_pipx_cli bloodhound bloodhound-python
    ensure_pipx_cli semgrep semgrep
    ensure_pipx_cli awscli aws
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
  install_gh_release_tool "aquasecurity/trivy" "trivy" "trivy"
  install_gh_release_tool "anchore/grype" "grype" "grype"
  install_gh_release_tool "RustScan/rustscan" "rustscan" "rustscan"

  if command -v nuclei >/dev/null 2>&1; then
    nuclei -update-templates -silent >/dev/null 2>&1 &
  fi
  install_extended_arsenal
  ok "Security CLI arsenal ready"
}

# GPU cracking stack: NVIDIA driver + OpenCL ICD + container toolkit + upstream
# hashcat + John jumbo (OpenCL). Opt-in: `./setup.sh gpu`, or automatically from
# `full` when an NVIDIA device is present / BEHEMOTH_GPU=1. Idempotent.
has_nvidia_gpu() {
  [[ -n "${BEHEMOTH_GPU:-}" ]] && return 0
  command -v nvidia-smi >/dev/null 2>&1 && return 0
  command -v lspci >/dev/null 2>&1 && lspci 2>/dev/null | grep -qiE 'nvidia|3d controller' && return 0
  return 1
}

install_gpu_cracking_stack() {
  has_nvidia_gpu || { info "No NVIDIA GPU detected; skipping GPU stack"; return 0; }
  info "Provisioning GPU cracking stack (driver, OpenCL, container runtime, hashcat, john-jumbo)..."
  export DEBIAN_FRONTEND=noninteractive

  if ! command -v nvidia-smi >/dev/null 2>&1; then
    apt-get install -y -qq ubuntu-drivers-common >/dev/null 2>&1 || true
    ubuntu-drivers autoinstall >/dev/null 2>&1 || warn "Driver autoinstall failed — install the NVIDIA driver manually, then rerun"
  fi
  apt-get install -y -qq linux-headers-"$(uname -r)" >/dev/null 2>&1 || true

  # OpenCL ICD loader: the driver ships the NVIDIA ICD, we only need the loader.
  apt-get install -y -qq ocl-icd-libopencl1 clinfo hashcat >/dev/null 2>&1 || true

  # Container GPU passthrough so sandbox_exec can see the device.
  if ! command -v nvidia-ctk >/dev/null 2>&1; then
    curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
      | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg 2>/dev/null || true
    curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
      | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
      > /etc/apt/sources.list.d/nvidia-container-toolkit.list 2>/dev/null || true
    apt-get update -y -qq >/dev/null 2>&1 || true
    apt-get install -y -qq nvidia-container-toolkit >/dev/null 2>&1 || warn "nvidia-container-toolkit install failed"
  fi
  if command -v nvidia-ctk >/dev/null 2>&1 && command -v docker >/dev/null 2>&1; then
    nvidia-ctk runtime configure --runtime=docker >/dev/null 2>&1 || true
    systemctl restart docker >/dev/null 2>&1 || true
  fi

  # John the Ripper jumbo (the distro package is CPU-only and stale).
  if [[ ! -x /usr/local/bin/john-jumbo ]]; then
    local build_dir
    build_dir="$(mktemp -d)"
    if git clone --depth 1 https://github.com/openwall/john.git "$build_dir/john" >/dev/null 2>&1; then
      ( cd "$build_dir/john/src" && ./configure >/dev/null 2>&1 && make -s clean >/dev/null 2>&1 && make -sj"$(nproc)" >/dev/null 2>&1 ) || true
      if [[ -x "$build_dir/john/run/john" ]]; then
        install -m 0755 "$build_dir/john/run/john" /usr/local/bin/john-jumbo
        ok "Installed john-jumbo -> /usr/local/bin/john-jumbo"
      else
        warn "john-jumbo build failed; distro john stays available"
      fi
    fi
    rm -rf "$build_dir"
  fi

  ok "GPU stack ready — set BEHEMOTH_SANDBOX_GPUS=all to expose the GPU to sandbox_exec"
}

# install_searxng provisions the self-hosted SearXNG meta-search as a local
# Docker container bound to 127.0.0.1:8888. Idempotent: a healthy instance is
# left untouched; an existing but stopped container is restarted. The BEHEMOTH
# server auto-detects and enables the instance at startup (SEARCH_SEARXNG_URL).
install_searxng() {
  [[ "${BEHEMOTH_SEARXNG:-1}" == "0" ]] && { info "BEHEMOTH_SEARXNG=0 — skipping local SearXNG"; return 0; }
  if curl -fsS --max-time 3 http://127.0.0.1:8888/healthz >/dev/null 2>&1; then
    ok "SearXNG meta-search already running at http://127.0.0.1:8888"
    return 0
  fi

  if ! command -v docker >/dev/null 2>&1; then
    info "Installing Docker (required for the local SearXNG meta-search)..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq docker.io >/dev/null 2>&1 \
      || curl -fsSL https://get.docker.com | sh >/dev/null 2>&1 \
      || { warn "Docker install failed — skipping local SearXNG (set SEARCH_SEARXNG_URL manually)"; return 0; }
  fi
  systemctl enable --now docker >/dev/null 2>&1 || true
  if ! docker info >/dev/null 2>&1; then
    warn "Docker daemon not reachable — skipping local SearXNG (set SEARCH_SEARXNG_URL manually)"
    return 0
  fi

  local cfg_dir="/opt/behemoth/searxng"
  mkdir -p "$cfg_dir"
  chmod 777 "$cfg_dir"
  if [[ ! -f "$cfg_dir/settings.yml" ]]; then
    cat > "$cfg_dir/settings.yml" <<SEARXNG_EOF
use_default_settings: true
server:
  secret_key: "$(rand_secret)$(rand_secret)"
  limiter: false
  image_proxy: false
  base_url: http://127.0.0.1:8888/
search:
  safe_search: 0
  formats:
    - html
    - json
SEARXNG_EOF
  fi
  chmod 644 "$cfg_dir/settings.yml"

  if docker ps -a --format '{{.Names}}' | grep -qx 'behemoth-searxng'; then
    info "Starting existing behemoth-searxng container..."
    docker start behemoth-searxng >/dev/null 2>&1 || true
  else
    info "Pulling and starting SearXNG (local meta-search on 127.0.0.1:8888)..."
    docker rm -f behemoth-searxng >/dev/null 2>&1 || true
    docker run -d --name behemoth-searxng --restart unless-stopped \
      -p 127.0.0.1:8888:8080 \
      -v "$cfg_dir:/etc/searxng:rw" \
      -e SEARXNG_BASE_URL=http://localhost:8888/ \
      searxng/searxng:latest >/dev/null || { warn "Failed to start SearXNG container"; return 0; }
  fi

  local i
  for i in $(seq 1 15); do
    if curl -fsS --max-time 3 http://127.0.0.1:8888/healthz >/dev/null 2>&1; then
      ok "SearXNG meta-search running at http://127.0.0.1:8888 — BEHEMOTH auto-enables it at startup"
      return 0
    fi
    sleep 2
  done
  warn "SearXNG container started but not healthy yet — BEHEMOTH picks it up once /healthz responds"
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
  su - postgres -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname = 'behemoth'\" | grep -q 1 || psql -c \"CREATE USER behemoth WITH PASSWORD '${db_pass}';\""
  su - postgres -c "psql -c \"ALTER USER behemoth WITH PASSWORD '${db_pass}';\""
  su - postgres -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname = 'behemoth'\" | grep -q 1 || psql -c \"CREATE DATABASE behemoth OWNER behemoth;\""
  su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE behemoth TO behemoth;\""

  cat > config.json <<EOF
{
  "database": {
    "host": "127.0.0.1",
    "port": 5432,
    "user": "behemoth",
    "password": "${db_pass}",
    "dbname": "behemoth",
    "sslmode": "disable"
  }
}
EOF
  chmod 600 config.json
  ok "PostgreSQL database 'behemoth' initialized and config.json created"
}

build_behemoth() {
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
  local build_ver="${BEHEMOTH_BUILD_VERSION:-}"
  if [[ -z "$build_ver" ]]; then
    build_ver="$(git describe --tags --abbrev=0 2>/dev/null || echo "2.4.0")"
  fi
  build_ver="${build_ver#v}"
  info "Compiling single-binary BEHEMOTH server (./behemoth v${build_ver})..."
  CGO_ENABLED=0 go build -tags embedui -trimpath -ldflags "-s -w -X main.version=${build_ver}" -o behemoth ./cmd/behemoth
  chmod +x behemoth start.sh
  ok "Compiled ./behemoth v${build_ver} ($(du -h behemoth | awk '{print $1}'))"
}

reset_admin_password() {
  local newpass="${1:-}"
  if [[ -z "$newpass" ]]; then
    read -rsp "Enter new BEHEMOTH admin password (>=8 chars): " newpass; echo ""
  fi
  [[ "${#newpass}" -ge 8 ]] || die "Password must be at least 8 characters"
  export BEHEMOTH_RESET_NEWPASS="$newpass"

  local psql_cmd=(psql --no-psqlrc -v ON_ERROR_STOP=1)
  if [[ -n "${BEHEMOTH_PG_DSN:-}" ]]; then
    psql_cmd+=("$BEHEMOTH_PG_DSN")
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
    db = urllib.parse.quote(str(c.get("dbname", "behemoth")), safe="")
    ssl = c.get("sslmode") or "disable"
    auth = f"{u}:{pw}@" if pw else f"{u}@"
    print(f"postgres://{auth}{h}:{pt}/{db}?sslmode={ssl}")
' 2>/dev/null || true)"
    if [[ -n "$db_dsn" ]]; then
      psql_cmd+=("$db_dsn")
    else
      psql_cmd+=(-d behemoth)
    fi
  elif [[ "${EUID:-$(id -u)}" -eq 0 ]] && id -u postgres >/dev/null 2>&1; then
    psql_cmd=(sudo -E -u postgres psql --no-psqlrc -d behemoth -v ON_ERROR_STOP=1)
  else
    psql_cmd+=(-d behemoth)
  fi

  "${psql_cmd[@]}" <<'SQL'
\getenv newpw BEHEMOTH_RESET_NEWPASS
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
  unset BEHEMOTH_RESET_NEWPASS
  ok "BEHEMOTH admin password updated successfully (login with username: BEHEMOTH)"
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
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) shift ;;
  esac
done

case "$CMD" in
  full|up)
    banner
    require_root
    install_system_deps
    install_searxng
    install_golang
    install_nodejs
    install_playwright_globals
    setup_postgresql
    build_behemoth
    ./start.sh all
    if [[ "$DOMAIN" != "_" ]]; then
      if [[ "$ENABLE_SSL" -eq 1 ]]; then ./start.sh domain "$DOMAIN" --ssl; else ./start.sh domain "$DOMAIN"; fi
    else
      ./start.sh domain "_"
    fi
    ;;
  build)
    banner
    build_behemoth
    ;;
  local)
    banner
    build_behemoth
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
        printf "POSTGRES_USER=behemoth\nPOSTGRES_PASSWORD=%s\nPOSTGRES_DB=behemoth\n" "$gen_pass" > .env
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
    build_behemoth
    install_searxng
    ./start.sh all
    ;;
  arsenal)
    banner
    install_security_arsenal
    ;;
  gpu)
    banner
    require_root gpu
    install_gpu_cracking_stack
    ;;
  searxng)
    banner
    require_root searxng
    install_searxng
    ;;
  reset-password)
    banner
    reset_admin_password "$NEWPASS"
    ;;
  *)
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
    ;;
esac
