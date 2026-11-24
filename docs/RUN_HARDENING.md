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

If the docker CLI is missing the tool returns a clear "fall back to Bash"
error. Interactive programs still belong in the existing `shell_*` PTY session
tools.

Code: `agent/sandbox.go`.

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
