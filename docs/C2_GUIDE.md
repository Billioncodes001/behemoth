# ARTEX C2 — Command & Control Guide

ARTEX ships a self-contained C2 capability: it can generate lightweight
implant scripts (bash / python3 / powershell), serve their check-in and
result endpoints on the main port or a dedicated listener, deploy them to
connected SSH targets, and drive them from the agent tool set or a
token-authed operator console at `/c2/ui/`.

The semantics follow the Mamba RMM (registry/task lifecycle, malleable
profile paths, per-implant secrets) but the implementation is original —
see `THIRD_PARTY.md` for attribution notes. No code is imported from `rmm/`.

## Concepts

- **Implant** — a single-file script with an embedded ID (`c2_<hex>`) and
  per-implant token. It POSTs a small JSON beacon on its sleep cycle and
  receives at most one queued command per check-in.
- **Task** — one queued command (`shell` or `kill`). Lifecycle:
  `pending → sent (dequeued on check-in) → done (result received)`.
- **Result** — command output (stdout+stderr, exit code). The last 500
  results are retained; output is capped at 256 KB per task.
- **State** — persisted as an append-only JSONL event log
  (`<dataDir>/c2/state.jsonl`), replayed on startup and auto-compacted
  beyond 8 MB. Restarts preserve implants, tasks, and results.
- **Malleable profile** — each implant declares its own `beacon_path` and
  `resp_path` (defaults `update` / `response`; e.g. `assets/font.css` / `assets/glyph.bin`); the server
  routes by matching profile paths under `/api/c2/`. Paths colliding with
  the management endpoints (`api/c2`, `c2/ui`) are rejected.
- **Encoding** — `none`: base64(JSON) over TLS; `aes`: AES-256-CBC with a
  random IV per message (IV in the `X-IV` header), key =
  `SHA-256("artex-c2:" + token)`. Not available for python3 (stdlib-only).

## Endpoints

| Path | Auth | Purpose |
|---|---|---|
| `POST /api/c2/<beacon_path>` | `X-Request-ID` (implant token) | check-in; 204 when idle, 200 + task when queued |
| `POST /api/c2/<resp_path>` | `X-Request-ID` | task result submission |
| other `/api/c2/*` paths | none | static health decoy `{"service":"update","status":"ok"}` |
| `/c2/ui/` (and `/c2/ui/data`, `/c2/ui/cmd`, `/c2/ui/file/...`) | `?t=<console token>` or `c2_token` cookie | operator console (single-page, 5 s polling) |

These endpoints are exempt from JWT and HTTP Basic Auth (following the
`oast-cb` precedent); implants authenticate with their token and the
console with its own token. The console token is generated on first use,
persisted in the state log, and surfaced by `c2_agents` /
`c2_build_implant`.

## Listener placement

- **Default**: beacon endpoints are mounted on the main server mux (port
  8787), next to the REST API.
- **Dedicated**: set `ARTEX_C2_ADDR` (e.g. `0.0.0.0:8443`) to start a
  separate listener serving only the beacon endpoints and the console.
  Add `ARTEX_C2_TLS_CERT` / `ARTEX_C2_TLS_KEY` for TLS.
- `ARTEX_C2_PUBLIC_URL` is the base URL baked into generated implants
  (e.g. `https://c2.example.com`).

## Agent tools

| Tool | Type | Description |
|---|---|---|
| `c2_build_implant` | write | Generate an implant (platform, runtime, encrypt, malleable paths, sleep/jitter, persistence) and its install helpers under `<dataDir>/c2/builds/<id>/`. |
| `c2_deploy` | write | SFTP-upload the build directory to a connected SSH target and run the chosen installer (`none`, `systemd`, `cron`). |
| `c2_agents` | read | List implants with live status (`registered` / `active` / `stale` / `killed`), host info, pending task counts, console URL + token. |
| `c2_task` | write | Queue a shell command for an implant (timeout default 120 s, max 3600 s). |
| `c2_results` | read | Read recent task results and task states. |
| `c2_kill` | write | Queue a `kill` command; the implant removes persistence (systemd unit / cron entry / scheduled task) and exits on its next check-in. |
| `c2_proxy_open` | write | Open a loopback SOCKS5 pivot tunnel through an implant (`socks5://user:pass@127.0.0.1:<port>`), optionally repointing the capture layer at it. |
| `c2_proxy_close` | write | Close one tunnel or every tunnel of an implant, optionally restoring direct egress. |
| `c2_proxy_list` | read | List live tunnels with usage, connections and expiry. |

The tools are seeded into the tools table and bound to the
`auto`/`pentest`/`worker`/`planner`/`mainagent`/`reporter` agents
(one-shots, settings flags `c2_tools_v1` and `c2_proxy_tools_v1`).

## Pivot tunnels

The last rung of the egress ladder — use it only when the target is
reachable from the implant and not from this host:

1. direct fetch
2. client-side proxy pool
3. **C2 pivot tunnel**
4. lure capture layer

`c2_proxy_open` starts a listener on `127.0.0.1` (ephemeral port) that
speaks SOCKS5 (CONNECT only) and relays every connection through the
implant over the existing beacon channel:

- Downlink frames are queued as internal `tunnel` tasks that are dequeued
  ahead of shell tasks; uplink frames ride the normal result endpoint with
  `task_id=tun`. No new endpoints or headers, so the malleable profile is
  untouched.
- The allowlist defaults to exactly the requested `host:port` — the
  implant never becomes an open relay. Add more with `allow`.
- Guards: 15 min TTL (max 240), 90 s idle, 5 min stall, 32 MB byte cap
  (max 512), 16 KB frames, 16 connections per tunnel, 128 queued frames
  per implant, 8 tunnels per process.
- Random per-tunnel SOCKS credentials (`auth` defaults to true).
- While a tunnel is open the implant's loop polls fast (~1 s bash,
  300 ms python/powershell) instead of its beacon interval.

Typical use: `c2_proxy_open{implant_id, target, use_for_capture}` then
drive tools through the returned proxy, and `c2_proxy_close` when done
(it also clears the global egress proxy if it still points there).

Expectations: throughput is bounded by the beacon round trip, so the
tunnel suits small request/response work (API calls, admin panels,
internal HTTP), not bulk file transfer. Implants relay with `bash`
`/dev/tcp` + FIFOs, `python3` sockets + threads, or `powershell`
`TcpClient` polling; binary-safe, but only TCP.

## Persistence helpers

Each build directory contains the implant plus installers:

- Linux: `install-none.sh` (nohup), `install-systemd.sh` (hidden
  `sysupd-<id>.service`, root with nohup fallback), `install-cron.sh`
  (`@reboot` + `*/10` entries under the `atx-<id>` marker).
- Windows: `install-none.ps1`, `install-schtasks.ps1`
  (`MicrosoftEdgeUpdateTask<id>` at logon).

A kill task removes the corresponding unit/cron entry/task and the
dropped script. `c2_deploy` runs one of these installers automatically
after uploading the build directory.

## Configuration

| Variable | Meaning |
|---|---|
| `ARTEX_C2_ADDR` | Dedicated listener address (empty = main mux). |
| `ARTEX_C2_PUBLIC_URL` | Callback base URL baked into implants. |
| `ARTEX_C2_SECRET` | Optional shared beacon secret accepted for every implant (per-implant tokens always work). |
| `ARTEX_C2_TLS_CERT` / `ARTEX_C2_TLS_KEY` | TLS for the dedicated listener. |
| `ARTEX_C2_PORT` | Host-side port mapping for docker-compose. |

## Validation rules

- platforms: `linux`, `windows` (windows ⇒ powershell only)
- runtimes: `bash`, `python3`, `powershell`
- encrypt: `none` | `aes` (python3 ⇒ `none` only)
- persistence: `none` | `systemd` | `cron` (linux); `none` | `schtasks` (windows)
- sleep 1–86400 s (default 30); jitter 0–80 % (default 20); task
  timeout ≤ 3600 s (default 120)
- beacon/resp paths sanitized, must differ, and must not collide with
  `api/c2` or `c2/ui`
