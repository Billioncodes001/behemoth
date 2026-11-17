# ARTEX — Operator Wiki & How-To Guide

This guide covers the end-to-end operational workflow of ARTEX, from initial LLM setup to launching engagements via Chat or Tasks, managing proxies and stealth settings, and exporting deliverable reports.

---

## 1. Initial Login & LLM Profile Setup

1. **Sign In**:
   - On first visit (`http://<your-domain-or-ip>`), set your administrator password on the `/setup` screen (or log in with username **`ARTEX`** at `/login`).
   - To reset the administrator password from the server terminal at any time:
     ```bash
     ./setup.sh reset-password -p 'NewStrongPassword!'
     ```
2. **Configure Your LLM Provider (`/system/llm`)**:
   - Navigate to **System → LLM** (`/system/llm`).
   - Click any of the **Quick-Start Model Templates** (**+ Cline**, **+ Cline (Kimi)**, **+ OpenAI**, **+ Anthropic**, **+ DeepSeek**, **+ Moonshot (Kimi)**, **+ Zhipu GLM**, **+ Qwen**, **+ Gemini**, or **+ Ollama**).
   - Enter your API Key, click **Test Connection** to verify latency, and click **Save & Activate**.
   - **Automatic Failover Pool**: Add multiple LLM profiles to enable automatic failover across healthy providers if rate limits or quota errors occur.

---

## 2. Launching Engagements via Chat (`/chat`)

The fastest way to operate ARTEX is directly through **Chat** (`/chat`):

- **Default Agent (`Auto`)**:
  - `Auto` is the Lead Autonomous Operator & Orchestrator. Simply describe your target and objective:
    - *"Perform full reconnaissance and vulnerability testing on `https://target.example.com`"*
    - *"Enumerate all API endpoints and test for SQLi and broken authentication on `api.target.local`"*
    - *"Scan open ports and services on `10.10.10.0/24` and check for default credentials"*
- **Automatic UI Synchronization**:
  - Discovered domains, IPs, ports, and endpoints are automatically saved via `insert_assets` and appear in **Assets** (`/assets`) and the **Coverage Graph**.
  - Multi-stage assessments automatically launch via `spawn_task` and run live in **Tasks** (`/function/tasks`).
  - Verified vulnerabilities with PoC evidence are registered via `report_finding` in **Findings** (`/function/findings`) and automatically trigger the **Report Writer** agent.
- **8 Built-In Offensive Skills & Dynamic Skill Creation**:
  - Built-in skills: `api-recon`, `web-vuln-exploitation`, `auth-and-jwt-attacks`, `network-and-service-pentest`, `osint-and-surface-mapping`, `waf-and-filter-bypass`, `playwright-cli`, `scopesentry`.
  - Whenever an engagement requires a specialized technique not covered by existing skills, the Chat agent can automatically create and persist a new skill via `create_skill` and `update_skill_file` (visible in `/system/skills`).

---

## 3. Running Autonomous Tasks (`/function/tasks`)

1. Go to **Tasks** (`/function/tasks`) and click **New Task**.
2. Provide the **Target Description / Scope** and **Objective (Goal)**.
3. Inside **Task Detail** (`/function/tasks/detail?id=<id>`), monitor every stage across tabs:
   - **Sessions & Broadcast**: Live stream of Goal Decomposer, Planner, and Worker reasoning and tool calls.
   - **Exploration Graph**: Interactive DAG showing Goals, Intents, Facts, and Findings.
   - **Findings & Retests**: Confirmed vulnerabilities with one-click **AI Deep-Dive Writeup** and **Independent Retest**.
   - **Intelligence**: Captured credentials, API keys, tokens, sensitive data, and leads.
   - **Traffic & Files**: All captured HTTP/HTTPS packets and workspace scripts/artifacts (`i<intent_id>/...`).
   - **Report**: Full end-to-end engagement report with `.md` download, `.zip` evidence bundle export, and `.zip` workspace artifacts archive.

---

## 4. Proxy Pool v2, Stealth & Anti-Detection

- **Proxy Pool v2 (`/system/proxy` & `/system/settings`)**:
  - Import HTTP/HTTPS/SOCKS4/SOCKS5 proxies in bulk, click **Test All** for live latency + GeoIP (`Country`/`City`) resolution, and select a rotation strategy (`round_robin`, `random`, `least_used`, `fastest`, `sticky`).
  - Synchronized bidirectionally with the core agent proxy engine—all worker commands, HTTP tools, and Browser MCP route through the active proxy automatically.
- **Stealth & Anti-Detection (`/system/settings`)**:
  - **Stealth Mode**: Dynamic User-Agent rotation, browser header randomization, and TLS/JA3 fingerprint spoofing (ON by default).
  - **OPSEC Guidelines**: Instructs workers to reuse captured session headers/cookies and minimize scanner noise (ON by default).
  - **IOC Blocklist**: Blocks known malicious C2/scanner IPs while allowing authenticated operator requests.

---

## 5. Multi-Engine Search, Repeater, Notifications & Logs

- **Multi-Engine Search (`/search`)**: Search across **General**, **Exploit / CVE (Sploitus + GitHub PoCs)**, **Technical**, **OSINT**, and **News** modes.
- **HTTP Traffic & Repeater (`/function/traffic` & `/function/repeater`)**: Inspect captured HTTP/HTTPS packets and send any request to **Repeater** for manual payload testing.
- **Notifications (`/system/notify`)**: Real-time or digest alerts via **Webhook**, **Telegram**, **Feishu**, **DingTalk**, **WeCom**, or **Email (SMTP)**.
- **System Logs (`/system/logs`)**: Live SSE log stream with subsystem tag filters (`[engine]`, `[chat]`, `[planner]`, `[worker]`, `[security]`, `[proxy-v2]`, `[search]`, `[tools]`, `[traffic]`, `[mcp]`, `[pg]`) and `.log` download.
