<div align="center">

# ARTEX

### Autonomous AI Penetration Testing & Offensive Security Platform

**Multi-Agent Exploration Graph · Live HTTP/S Traffic Capture · GeoIP Proxy Pool v2 · Anti-Detection & Stealth Engine · Evidence-Backed Reporting**

[![Go](https://img.shields.io/badge/Backend-Go_1.26-00ADD8?logo=go&logoColor=white)](#overview)
[![Next.js](https://img.shields.io/badge/Frontend-Next.js_16-000000?logo=next.js&logoColor=white)](#overview)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL_16-4169E1?logo=postgresql&logoColor=white)](#quick-start-ubuntu-production)
[![Edition](https://img.shields.io/badge/Edition-Enterprise_Offensive-crimson)](#key-capabilities)

[**Quick Start**](#-quick-start-ubuntu-production) · [**Service Management (`start.sh`)**](#-service-management--domain-routing) · [**Operator Wiki & How-To**](./docs/WIKI_HOW_TO_USE.md) · [**Deployment Guide**](./docs/DEPLOYMENT_GUIDE.md)

</div>

---

## Overview

**ARTEX** is a full-stack autonomous offensive security and penetration testing platform powered by a coordinated multi-agent reasoning engine (**Go** backend + **Next.js** control plane + **PostgreSQL** graph store).

Unlike linear AI wrappers, ARTEX models every engagement as a live **Exploration DAG (Directed Acyclic Graph)**—decomposing high-level objectives into measurable goals, scheduling parallel worker intents, recording MITM HTTP/HTTPS traffic packets as cryptographic evidence, rotating outbound proxies with GeoIP telemetry, and generating reproducible, artifact-rich technical reports.

---

## Key Capabilities

| Capability | Description |
| :--- | :--- |
| **Autonomous Multi-Agent Engine** | Coordinated **Goal Decomposer → Planner → Parallel Workers → Principal Report Writer → Finding Retester** pipeline backed by a persistent exploration blackboard. |
| **Chat-First Operations (`Auto` & `Solo Pentest`)** | Drive the entire platform from `/chat`. The **Auto** orchestrator automatically selects tools and skills, registers discovered assets (`/assets`), spawns tasks (`/function/tasks`), and records verified findings (`/function/findings`). |
| **8 Built-In Offensive Skills + Auto-Creation** | Ships with `api-recon`, `web-vuln-exploitation`, `auth-and-jwt-attacks`, `network-and-service-pentest`, `osint-and-surface-mapping`, `waf-and-filter-bypass`, `playwright-cli`, and `scopesentry`—plus autonomous on-the-fly skill creation (`create_skill`). |
| **End-to-End Evidence & Artifact Reporting** | Captures the complete chronological execution timeline, worker command traces, attack chain lineage, raw HTTP request/response packets, credentials, and workspace PoC scripts. Exportable as `.md`, `.csv`, `.json`, or full `.zip` evidence bundles. |
| **MITM Traffic Capture & Built-In Repeater** | Dedicated recording proxy (`127.0.0.1:8788`) captures all agent HTTP/HTTPS traffic, binds packets directly to vulnerability findings, and supports manual replay/fuzzing in the built-in **HTTP Repeater**. |
| **Unified Proxy Pool v2 & GeoIP Rotation** | Manage HTTP/HTTPS/SOCKS4/SOCKS5 proxy pools with automatic GeoIP country/city resolution, latency EMA scoring, health checks, and `round_robin` / `random` / `least_used` rotation synchronized across all agents and Browser MCP. |
| **Stealth, Anti-Detection & IOC Protection** | Dynamic User-Agent rotation, HTTP header randomization, JA3/TLS fingerprint spoofing, offensive intent reframing (`agent/security.go`), and IOC IP/scanner filtering. |
| **Multi-Engine Security Search** | Integrated search orchestrator across **DuckDuckGo**, **Sploitus / GitHub PoC & Exploit Advisories**, **Google CSE**, **Tavily AI**, and **SearXNG**. |

---

## Quick Start (Ubuntu Production)

ARTEX uses a streamlined **two-script workflow**:
- **`./setup.sh`** — One-time installation, dependency provisioning, frontend/backend compilation, updates, and password recovery.
- **`./start.sh`** — Daily service runner (`tmux` multi-service orchestration, Nginx custom domain/SSL routing, status checks, and live logs).

```bash
git clone https://github.com/Billioncodes001/myartex.git ARTEX
cd ARTEX

# 1. Full Ubuntu setup (installs PostgreSQL, Go 1.26, Node.js 20, Nginx, Certbot,
#    Headless Chrome, Nmap/SQLMap/Nikto/WhatWeb/Hydra, builds ARTEX, and starts services):
sudo ./setup.sh full

# 2. Or install and bind a custom domain with automatic Let's Encrypt HTTPS:
sudo ./setup.sh full --domain pentest.yourdomain.com --ssl
```

Once complete, open **`http://<server-ip>`** or **`https://pentest.yourdomain.com`** in your browser to access the dashboard.

---

## Service Management & Domain Routing

```bash
# Start Backend (:8787), Frontend (:3000), Headless Chrome (:9222), and Logs in tmux:
./start.sh all

# View running status of all services:
./start.sh status

# Attach to the live tmux control session (Windows: 0:backend, 1:frontend, 2:logs):
tmux attach -t artex

# Link or switch your custom domain via Nginx (Port 80 / 443) at any time:
sudo ./start.sh domain pentest.yourdomain.com --ssl

# Tail live system logs or stop all services:
./start.sh logs
./start.sh stop
```

### Maintenance & Upgrades (`./setup.sh`)

```bash
./setup.sh build                                    # Rebuild frontend + ./artex binary
./setup.sh update                                   # Pull latest git changes, rebuild & restart
./setup.sh reset-password -p 'NewStrongPassword!'   # Reset admin password in PostgreSQL
```

---

## Documentation & Wiki (`docs/`)

- **[Operator Wiki & How-To Guide (`docs/WIKI_HOW_TO_USE.md`)](./docs/WIKI_HOW_TO_USE.md)** — Complete step-by-step guide to LLM profiles (including Cline presets), Chat-driven operations, Task DAGs, Proxy Pool v2, Stealth settings, and End-to-End Reporting.
- **[Production Deployment & Administration Guide (`docs/DEPLOYMENT_GUIDE.md`)](./docs/DEPLOYMENT_GUIDE.md)** — Ubuntu server requirements, port architecture, `setup.sh` / `start.sh` reference, Nginx domain/SSL setup, and administration.

