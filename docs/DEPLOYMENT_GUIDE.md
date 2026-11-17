# ARTEX — Production Deployment & Administration Guide

This guide explains how to deploy, expose on a custom domain, and maintain ARTEX on an Ubuntu server or via Docker Compose.

---

## 1. Server Requirements

- **OS**: Ubuntu 22.04 LTS / 24.04 LTS or Debian 12 (x86_64 or arm64)
- **CPU / RAM**: Minimum 2 vCPU / 4 GB RAM (4+ vCPU / 8+ GB RAM recommended for concurrent browser automation & workers)
- **Disk**: 20+ GB SSD (stores PostgreSQL data, recorded HTTP traffic blobs, screenshots, and task workspace artifacts)
- **Network Ports**:
  - `80` / `443` (Public HTTP/HTTPS via Nginx reverse proxy)
  - `8787` (ARTEX Core API & Embedded UI — bound behind Nginx or accessible directly)
  - `8788` (`127.0.0.1:8788` local MITM traffic-recording proxy for worker processes)
  - `3000` (Next.js Web UI server when running in `tmux` multi-service mode)
  - `9222` (`127.0.0.1:9222` local headless Chrome DevTools endpoint)

---

## 2. One-Command Ubuntu Production Setup (`setup.sh`)

Run `setup.sh` as root on your Ubuntu server:

```bash
sudo ./setup.sh full
```

Or with automatic **Nginx domain binding + Let's Encrypt HTTPS**:

```bash
sudo ./setup.sh full --domain pentest.yourdomain.com --ssl
```

### What `sudo ./setup.sh full` Does Automatically:
1. Installs system packages (`postgresql`, `nginx`, `certbot`, `tmux`, `jq`, `curl`, `git`, `build-essential`, `python3`, `ripgrep`).
2. Installs offensive CLI tools (`nmap`, `sqlmap`, `nikto`, `dirb`, `whatweb`, `hydra`, `dnsutils`, `whois`, `netcat-openbsd`, `socat`) and headless `chromium` / `google-chrome`.
3. Installs **Go 1.26** and **Node.js 20 LTS** if not already installed.
4. Installs global **Playwright MCP & CLI** (`@playwright/mcp`, `@playwright/cli`) for browser automation and report step screenshots.
5. Starts PostgreSQL, provisions the `artex` database and credentials, and generates `config.json` (preserving any existing `config.json`).
6. Builds both the static frontend bundle (`server/webui/dist`) and the Next.js server runtime (`web/.next`), then compiles the single `./artex` binary.
7. Starts all services in a `tmux` session (`artex`) and configures Nginx on port 80/443.

---

## 3. Daily Service Management (`start.sh`)

```bash
# Start all services (Backend :8787 + Frontend :3000 + Headless Chrome :9222 + Logs) in tmux:
./start.sh all

# Check health & status of all services:
./start.sh status

# Attach to the running tmux session:
tmux attach -t artex
# (Inside tmux: Ctrl-B then 0 = backend, 1 = frontend, 2 = logs; Ctrl-B then D to detach)

# Link or change your custom domain on Nginx at any time:
sudo ./start.sh domain pentest.yourdomain.com
sudo ./start.sh domain pentest.yourdomain.com --ssl

# Follow live logs:
./start.sh logs

# Stop all services:
./start.sh stop
```

---

## 4. Updating & Password Recovery

- **Update to Latest Code**:
  ```bash
  ./setup.sh update
  ```
  Pulls the latest repository changes, rebuilds the frontend and `./artex` binary, and restarts the services. Database schema migrations run automatically on startup.

- **Reset Administrator Password**:
  ```bash
  ./setup.sh reset-password -p 'YourNewStrongPassword!'
  ```
  Updates the bcrypt password hash in PostgreSQL immediately without requiring a service restart.
