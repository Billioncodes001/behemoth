# Run Hardening: budgets, scope enforcement, sandbox, mock provider, evidence

This document covers the five per-run safety/cost mechanisms added to the agent
execution path. All of them are opt-in or no-ops when unconfigured, so existing
deployments behave exactly as before.

---

## 1. Run budgets: tokens and tool calls

A run was already bounded by turns (`agents.max_turns`) and wall clock
(`agents.run_seconds`). Two cost dimensions had no bound: cumulative tokens and
the number of tool calls. A cheap-model loop can stay inside both old caps while
burning millions of tokens or thousands of probes.

Two per-agent columns add them:

| Column | Meaning | Default |
|---|---|---|
| `agents.token_budget` | cumulative input+output (+cache) tokens per run | `0` = unlimited |
| `agents.tool_call_budget` | tool calls per run | `0` = unlimited |

Configure them in the console (Agent editor → config, next to max turns) or:

```bash
curl -s -u user:pass -X PUT localhost:8787/api/agents/worker/config \
  -H 'content-type: application/json' \
  -d '{"token_budget": 4000000, "tool_call_budget": 400}'
```

Behavior:

- Tokens are counted by a provider wrapper that folds every model call's usage
  in (the same accounting the trace uses).
- Tool calls are counted per execution. Once a dimension is exhausted, further
  **probing** tools return an error result that tells the model to stop and wrap
  up. Write-back tools (`record_fact`, `insert_assets`, `report_finding`,
  `mark_done`, `prove_goal`, `add_intent`, `set_goals`, `set_constraints`,
  `TodoWrite`, `Skill`) are always allowed, so the run can persist what it
  learned before ending.
- Each run emits a `budget` activity carrying `{max_tokens, max_tool_calls,
  tokens, tool_calls, exhausted}` for the trace.

Code: `agent/budget.go`; wiring in `agent/{worker,planner,mainagent,chat}.go`.

---

## 2. Scope enforcement

`task_scope` rows used to be *advisory* (prompt text). The agent could probe any
host, and an HTTP redirect could silently leave the allowlist. The scope guard
turns the rows into a mechanical boundary for the agent's own network tools:

- Every Bash command is scanned for literal URLs and IPv4 addresses.
- Every `WebFetch` URL is authorized.
- `http_request` (added to worker tools) authorizes the URL **and every redirect
  hop**, re-rate-limits each hop, and returns the body SHA-256.
- Unresolvable hosts are **denied** when a scope exists (fail-closed DNS): a
  typo'd or hijacked name cannot silently escape the allowlist.
- Per-host throttling uses a token bucket; set `BEHEMOTH_SCOPE_RPS` (requests per
  second per host, default `0` = off).

Scope language (from `task_scope`):

| Row kind | Becomes |
|---|---|
| `root_domain` | `*.example.com` (apex + subdomains, any port) |
| `subdomain` | exact host |
| `ip` | exact address |
| `cidr` | network |
| `keyword` | ignored (no host shape) |

Tasks without scope rows get a nil guard and every check passes (prior
behavior). When a guard is active the worker system prompt says so, so the model
knows probing is enforced.

Code: `agent/scope_guard.go`, `agent/scoped_http.go`.

Limitations: this is a guardrail, not a sandbox — only explicit literals in a
Bash command are checked (a script that computes targets at runtime is not
inspected). Use `sandbox_exec` when host isolation matters.

---

## 3. Docker sandbox backend

`sandbox_exec` runs one command in a throwaway container
(`docker run --rm`), with the run workspace mounted at `/work`:

```json
{"command": "nmap -sV -p- 10.10.0.5", "timeout_seconds": 900}
```

Environment:

| Variable | Default | Meaning |
|---|---|---|
| `BEHEMOTH_SANDBOX_IMAGE` | `kalilinux/kali-last-release` | container image |
| `BEHEMOTH_SANDBOX_NETWORK` | `host` | docker network mode (`host`/`bridge`/`none`) |
| `BEHEMOTH_SANDBOX_TIMEOUT` | `600` | seconds per run |
| `BEHEMOTH_SANDBOX_ARGS` | — | extra `docker run` flags (e.g. `--cap-add=NET_RAW`) |
| `BEHEMOTH_SANDBOX_GPUS` | — | GPU passthrough for the container (`all`, `device=0`); needs the NVIDIA container toolkit. See [GPU_HOST.md](GPU_HOST.md) |

If the docker CLI is missing the tool returns a clear "fall back to Bash"
error. Interactive programs still belong in the existing `shell_*` PTY session
tools.

Code: `agent/sandbox.go`.

### 3.1 Search engines (Firecrawl + self-hosted SearXNG)

| Variable | Default | Meaning |
| --- | --- | --- |
| `SEARCH_FIRECRAWL_API_KEY` | — | Firecrawl API key (cloud). Optional for self-hosted instances. |
| `SEARCH_FIRECRAWL_URL` | `https://api.firecrawl.dev` | Firecrawl base URL — point it at a self-hosted instance (e.g. `http://127.0.0.1:3002`). |
| `SEARCH_TAVILY_API_KEY` | — | Tavily AI search key. |
| `SEARCH_BRAVE_API_KEY` | — | Brave Search API key. |
| `SEARCH_SEARXNG_URL` | auto | Leave empty: the server auto-detects the local SearXNG that `./setup.sh` provisions on `127.0.0.1:8888` and enables it. |
| `BEHEMOTH_SEARXNG` | `1` | Set to `0` to skip SearXNG provisioning in `setup.sh full` / `update`. |

`sudo ./setup.sh searxng` (also runs automatically from `full` and `update`)
starts a `behemoth-searxng` Docker container bound to `127.0.0.1:8888` with the
loopback-only port, JSON format enabled and the rate limiter off. On startup the
server probes `/healthz` on `127.0.0.1:8888` and enables the engine without any
manual configuration; agents then rank SearXNG near the top of every fallback
chain (free, fast, no per-query quota).

---

## 4. Mock / scenario provider (offline demos and CI)

`provider: mock` replays a scripted list of assistant turns, so a full agent loop
(tool call → result → final text) runs with no network and no API key.

```bash
export BEHEMOTH_LLM_PROVIDER=mock
export BEHEMOTH_MOCK_RESPONSES='[
  {"text":"Probing /login","tools":[{"name":"Bash","input":{"command":"curl -i http://app.test/login"}}]},
  {"text":"The login page is reachable."}
]'
./behemoth
```

Note the server's precedence is **persisted DB LLM profile > env**, so the env
provider applies on a fresh instance with no saved profile (delete/deactivate the
saved profile, or use a scratch `data/` directory). In code, tests and the API can
use it directly via `agent.ConfigFrom("mock", …)`.


A scenario can also live in a file (`BEHEMOTH_MOCK_SCENARIO=/path/scenario.json`)
with `{"model":"mock-1","default_text":"...","turns":[...]}`. Selection is
deterministic: the first unused turn whose `match` substring appears in the
latest user message wins; otherwise turns are consumed in order; an exhausted
script repeats its last turn.

Tests use the same provider directly (`agent.NewMockProvider`), e.g.
`TestMockProviderOfflineSession` drives a real `agentcore` session.

Code: `agent/mock_provider.go`.

---

## 5. Evidence hashing + JSONL replay

Every worker run writes a tamper-evident JSONL log to
`<workspace>/tasks/<taskID>/i<intentID>/evidence/run.jsonl`. Each record
carries the SHA-256 of its detail blob plus the previous record's hash, forming a
chain. The run's terminal `evidence` activity stores the head hash, so the log on
disk can be tied to the engine's own record.

Verify a log (and any archive/copy of it):

```bash
./behemoth evidence verify data/tasks/12/i34/evidence/run.jsonl
# OK    .../run.jsonl  records=87  head=9f2c…
```

Tampering, reordering or dropping a record breaks the chain and the command
prints the exact record and reason, exiting non-zero.

Reopening a log (resumed intent) continues the same chain. Detail digests also
let you check one activity row's blob with `LogRecord.VerifyDetail`.

Code: `evidence/runlog.go`; wiring in `agent/worker.go`.

---

## 6. Proxy-provider etiquette on authentication pages

Rotating residential proxy providers meter authentication traffic far harder
than ordinary browsing. Webshare, for example, flags an account once its
"activity meter" for authentication pages trips: *large numbers of login attempts
with different credentials is strictly forbidden*, and repeated waves force
manual verification or suspend the pool. Agents used to brute-force logins
through the pool until it tripped.

The pacing policy is now code-owned and shipped in the OPSEC system-prompt block
(`agent/prompt.go`, bullet *Proxy-Provider Etiquette on Authentication Pages*),
so every role — planner, worker, main agent, chat, Auto — receives it no matter
how its DB prompt is edited, and it disappears only when `opsec_enabled` is off:

- Through shared/rotating provider proxies: **≤ ~20 auth-page loads and ≤ 5
  credential attempts per target domain per hour**, **≥ 10 s** apart.
- Credential testing goes **direct** (disable the proxy for that phase) or over
  operator-owned dedicated / self-hosted / script-managed exits, which provider
  meters do not count. Unauthenticated recon stays on the proxy.
- On `403` / `429` / CAPTCHA / `client_connect_auth_revoked`: stop the auth phase,
  cool down ≥ 30–60 min, persist attempts + a resume plan, and resume on a later
  run or operator calendar schedule instead of retrying in a tight loop.

`check_proxy_status` and `get_proxy_pool_status` also return an `auth_page_policy`
field — the full reminder when any outbound proxy is active, a no-op notice when
routing is direct — so the rule arrives at the moment the agent checks routing.
The `auth-and-jwt-attacks` skill repeats it in its pacing section.

### Mechanical throttle in the local forward proxy

Prompt text alone still relies on the model obeying it, so the local forwarder
enforces the budget too (`server/auth_page_throttle.go`, wired in
`server/manager.go`). For every request that would leave through an upstream
proxy:

| Guard | Behaviour |
|---|---|
| Auth-page budget | `GET/HEAD/POST` paths matching login/sign-in/sign-up/register/password/reset/OTP/MFA/SSO/OAuth/session/auth get a per-host window: **6/min, 20/hour** by default. Over budget → **429 + `Retry-After`** with an explanatory body, request never leaves. |
| Burst cap | Any proxied request: 180/min per host. CONNECT tunnels carry no path, so tunneled traffic is only burst-capped. |
| Cooldown | Upstream **407** (provider auth revoked — the WebShare "authentication pages" strike) or 429/403 **on an auth page** stops that host for 30 min. |

The 429 body names the host, the budget used and the wait, so a blocked agent can
`Bash sleep`, retry, or record the attempt and resume later. Everything is
env-tunable and can be switched off entirely:

```bash
BEHEMOTH_AUTH_THROTTLE=0                        # disable the throttle
BEHEMOTH_AUTH_THROTTLE_PER_MINUTE=6             # auth-page budget, minute window
BEHEMOTH_AUTH_THROTTLE_PER_HOUR=20              # auth-page budget, hour window
BEHEMOTH_AUTH_THROTTLE_HOST_PER_MINUTE=180      # all-traffic burst cap per host
BEHEMOTH_AUTH_THROTTLE_COOLDOWN_SECONDS=1800    # 407 / auth 429-403 cooldown
```

Raise the budgets when the operator runs dedicated/script-managed proxies instead
of a shared residential pool, or disable the throttle for a pure brute-force run.

Code: `server/auth_page_throttle.go`; hook wiring in `server/manager.go`,
`server/forward_proxy.go`; tests in `server/auth_page_throttle_test.go`.
