---
name: api-recon
description: Invoke this skill when collecting and enumerating website API endpoints.
---

# API Recon (Frontend & Endpoint Reconnaissance)

Under **authorized** conditions, comprehensively discover: **Backend APIs** (paths, methods, parameters, response bodies), **Frontend Routes**, and **UI Feature Triggers** (tabs, modals, table actions, etc.).

---

## Boundaries & Prohibitions (Mandatory for Agents)

This skill performs **API and parameter surface reconnaissance ONLY**, not vulnerability exploitation.

### Task Boundaries

| Scope | Permitted | Prohibited |
|---|---|---|
| **Objective** | Enumerate paths, methods, parameters, routes, and UI triggers | SQLi/XSS/IDOR/brute-force/fuzzing exploitation, destructive actions |
| **Auth** | Hook + stub/mock to bypass **client-side** login gates | Guessing credentials or submitting real login brute-force attempts |
| **Runtime** | Hook APIs without credentials, using mock responses so the SPA renders post-login views | Workflows requiring real backend sessions to proceed |

### Unauthenticated Dynamic Analysis (Phase 3 Default)

1. Use `preload.js` / `runtime_harvest.js` to **intercept and stub** login, permission, and menu bootstrap endpoints;
2. Return **structurally valid mock bodies with success status codes** for business query endpoints;
3. Allow the frontend to render post-login pages even in a 401 or offline environment, triggering additional XHR/fetch/WebSocket requests;
4. **Empty data, blank tables, and placeholder UI are expected** — do not pivot to real login brute-forcing or exploitation because of them.

**In short**: Use mocks to expand frontend routes and mount components, **recording outbound requests only**; what the backend returns does not matter — what matters is **which endpoints the frontend attempts to call**.

### Strict Workflow Prohibitions

| Prohibited | Required Alternative |
|---|---|
| Using grep/curl/Read on main `index-*.js` entry before Phase 1 completes | Run `OUTDIR/harvest_static.py` |
| Writing ad-hoc `extract_apis.py` scripts instead of using harvest | Customize `OUTDIR/harvest_static.py` and re-run |
| Repeating the same failed grep/command >= 2 times | Pivot strategy: inspect logs, adjust harvest, check reference |
| Skipping Gate A/B and running `scripts/` templates directly | Copy to `OUTDIR` and adapt to target |
| Real username/password, OTP, or OAuth brute-forcing | Use stub/mock (see above) |
| Skipping stubs to fetch "real data" via unauthorized access/injection | Record outbound requests only (recon boundary) |
| Deleting, exporting sensitive data, or bulk write operations | Same applies during coverage clicking |
| Claiming all pages and endpoints are found without runtime + dynamic enumeration | See "Definition of Done" or note limitations |
| Claiming all parameters are known without parameter trigger matrix + diff | Run Phase 3b matrix + Phase 5 diff |
| Inferring required/optional from a single runtime sample | Use multi-sample diff or validation rules / error inference |

---

## Two-Layer Model + Runtime Modes

| Layer | Output | Ceiling |
|---|---|---|
| **Static** (JS bundles) | Full endpoint paths, draft routes, callsite parameter candidates | No HTTP methods; parameters need Phase 1b; misses dynamically concatenated URLs |
| **Runtime** (live session) | Method + body + response + dynamic URLs + WS/SSE; multi-sample diff completes parameters | Pages must actually render to fire requests; single sample cannot distinguish required vs. optional |

| Runtime Mode | Engine | Best For |
|---|---|---|
| **depth** | `runtime_harvest.js` (Puppeteer) | API inventory, METHOD/params/response bodies, WS/SSE, reproducible batch runs |
| **coverage** | browser + `preload.js` | Clicking tabs/modals/tables for deeper feature coverage |
| **both** | depth first, then coverage | Most comprehensive |

**Parameter Methodology**: Paths via harvest/regex; parameters via **anchor window expansion + UI binding chain + multi-sample diff + error response inference** (see [reference.md](reference.md) Section J).

---

## Definition of Done

All items must be satisfied before claiming recon is complete:

- [ ] **Static**: Phase 1 harvest produces `api_static.txt`, `routes.txt`, and `js/`
- [ ] **Runtime**: At least one of depth or coverage; coverage/both requires **active hooks + dynamic enumeration loop**
- [ ] **Shell Entry**: Navigating to business paths does not redirect back to `/login` (watch out for hash routing)
- [ ] **Parameters**: coverage/both completes parameter trigger matrix + `param_samples.json`; Phase 5 merges `params_merged.json`
- [ ] **Depth** (if module pages are blank): Phase 4 reconstructs permission tree and re-runs until **module-level APIs** appear (beyond locale/bootstrap)
- [ ] **Deliverables**: All Phase 5 outputs complete; call `insert_assets` to register all discovered services and endpoints

---

## Scripts & Gates

Files in `scripts/` are reference templates only — **never** run them directly in place as final results.

**Rule**: Read -> adapt to target -> write into `OUTDIR` (e.g., `recon/`) -> log in `CHANGES.md`.

| Gate | When | Reference Script -> OUTDIR Copy | Common Customizations |
|---|---|---|---|
| **A (Static)** | After Phase 0, before **first** harvest/spider run | `harvest_static.py` / `spider_mpa.py` | Default regex works for most sites; adjust endpoint regex, webpack/Vite `publicPath`, or MPA exclude/cookie only if manifest/dialect differs |
| **B (Runtime)** | After Phase 2, before depth/coverage | `runtime_harvest.js` / `preload.js` + `config.json` | Cookie/localStorage keys, neutralize success values, stubs, login regex, API prefix, hash/history mode |

**Mandatory SPA Order**:

| Step | Required | Prohibited |
|---|---|---|
| After Phase 0 | Next Bash command = `python3 OUTDIR/harvest_static.py <URL> OUTDIR` | curl/grep/Read main entry `index-*.js` (typically >500KB) |
| Gate A | Copy script -> customize as needed -> **run immediately** | Manually extracting APIs before deciding whether to harvest |
| Before Phase 1 finishes | Verify output with `wc -l`; fix harvest on 404 and retry | Hand-writing extract scripts; repeatedly grepping undownloaded URLs |
| From Phase 1b onward | Grep only `OUTDIR/js/*.js` | Using main bundle instead of harvest |

- ✅ Copy `harvest_static.py` -> (optional) adjust regex -> **run immediately**
- ❌ curl main bundle -> grep repeatedly -> write temporary extract script -> harvest last
- **MPA**: Next Bash command after Phase 0 = `python3 OUTDIR/spider_mpa.py ...`

---

## Tool & Output Constraints

| Constraint | Details |
|---|---|
| Large files | **Never** Read/grep `index-*.js` >100KB into context; batch-process with OUTDIR scripts |
| grep output | Always pipe to `\| head -20` or `-m 5`; keep only path summaries in chat, do not paste raw bundle chunks |
| Verification | Use `wc -l`, `ls \| wc -l`; do not Read entire directories |
| Initial regex probe | Optional, <= 1 time, only on <= 50KB small chunks or HTML; formal static recon uses harvest |
| reference | Recipes/templates/troubleshooting are in [reference.md](reference.md); do not inline the entire file |

---

## Execution Roadmap

```
Phase 0 Classification + OUTDIR
  -> Gate A -> Phase 1 harvest (★ Run Immediately ★)
  -> Phase 1b Parameter Reverse Engineering
  -> Phase 2 Three Auth Gates -> config.json
  -> Gate B -> Phase 3 Runtime + Parameter Matrix
  -> Phase 4 Permission Tree (if needed) -> Re-run Phase 3
  -> Phase 5 Merge Report + insert_assets (batch insert all discovered service and endpoint API assets without omitting any)
```

Complete in order; **do not advance to the next Phase until the current one is finished**.

1. [ ] **Phase 0**: Classify SPA/MPA; create `OUTDIR` -> [Phase 0](#phase-0--classification)
2. [ ] **Gate A + Phase 1**: Copy script -> **immediately** harvest -> verify with `wc -l` -> [Phase 1](#phase-1--static)
3. [ ] **Phase 1b**: Anchor window expansion + binding layer -> `param_candidates.json` -> [Phase 1b](#phase-1b--parameter-reverse-engineering)
4. [ ] **Phase 2**: Three auth gates -> `config.json` -> [Phase 2](#phase-2--three-auth-gates)
5. [ ] **Gate B**: Customize runtime scripts -> [Phase 3](#phase-3--runtime)
6. [ ] **Phase 3**: depth / coverage / both; confirm shell entry; parameter trigger matrix -> `param_samples.json`
7. [ ] **Phase 4** (if needed): Permission tree -> patch stubs -> re-run Phase 3 -> [Phase 4](#phase-4--permission-tree-reconstruction)
8. [ ] **Phase 5**: Merge outputs + report + `insert_assets` -> [Phase 5](#phase-5--merge--report)

---

## Phase 0 — Classification

Fetch entry HTML and **create `OUTDIR`** (do not modify `scripts/` inside the skill directory):

- **SPA**: App shell + `<div id=app>` + chunks -> Phases 1–5
- **MPA**: SSR + `<form>`, no endpoint bundles -> after Gate A:

```bash
python3 recon/spider_mpa.py <BASE_URL> <OUTDIR> [--cookie "session=..."] [--max 300] [--depth 5] [--exclude "logout|delete|destroy"]
```

Produces `forms.txt`, `links.txt`, `api_inline.txt`. If forms ≈ 0 on an SPA -> switch to Phase 1.

---

## Phase 1 — Static

Follow [Scripts & Gates](#scripts--gates) and [Tool & Output Constraints](#tool--output-constraints).

```bash
python3 recon/harvest_static.py <BASE_URL> <OUTDIR>
```

harvest: parses HTML scripts -> webpack/Vite manifest -> downloads all lazy chunks -> produces `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt`.

```bash
wc -l OUTDIR/api_static.txt OUTDIR/routes.txt
ls OUTDIR/js | wc -l
```

- Chunk count vs. manifest: fix harvest and retry on 404, do not manually curl individual chunks
- Too few entries in `api_static.txt` -> broaden endpoint regex in OUTDIR and re-run (see reference)

### Phase 1b — Parameter Reverse Engineering

Paths come from Phase 1; parameter fields require dedicated recon.

**Completion Criteria**: For key endpoints, identify field names, transport location, inferred type, required/optional status, sample values, and confidence.

#### 1b.0 — Transport Forms

| Form | Where Parameters Live | What to Check Statically |
|---|---|---|
| REST JSON | body + query | `(params\|data\|body)\s*:\s*\{` near path anchor |
| GraphQL | `variables` | gql templates, `$page: Int` |
| Traditional form | urlencoded | `<form>`, `FormData` |
| File upload | multipart | `FormData.append` |
| Path parameters | `/user/:id` | Route table + `useParams` / `$route.params` |
| Encrypted/Signed | Wrapped in `sign`/`data` | Hook encryption function inputs (reference Section D) |

Output: annotate each endpoint with `transport: query|json|form|graphql|encrypted`.

#### 1b.1 — Anchor Window Expansion

Use known paths as anchors and expand the context window to locate payload construction objects:

```bash
grep -n '"/api/user/list"' OUTDIR/js/*.js | head -20
grep -rhoaE '.{0,120}("/api[^"]+").{0,200}' OUTDIR/js/*.js | head -20
grep -rhoaE '(params|data|body|payload)\s*:\s*\{' OUTDIR/js/*.js | head -20
```

| Wrapper Layer | Parameter Clues |
|---|---|
| axios instance | `data` / `params` |
| Unified request | Interceptors injecting global fields |
| OpenAPI client | Generated method signatures |
| React Query / SWR | Hook second argument |
| Vue composable | Composable parameters |

Validation artifacts: `yup`/`zod`/rules, `Form.Item name=`, embedded Swagger.

-> `param_candidates.json`: `{ path, fields[], source: "static-callsite", confidence }`

#### 1b.2 — Binding Layer

```
Form field -> onFinish/handleSubmit -> transform -> API payload
```

| Binding Source | Technique |
|---|---|
| Form submit | Trace submit -> transform -> API |
| Table search | `getFieldsValue()` -> `params` |
| Route | `:id` / `?tab=` |
| Interceptor | Global `tenantId`, pagination, `sign` |
| Enum select | `options` -> API enum values |

Trace the DevTools call stack upward from `fetch`/`XHR.send` to the payload builder function.

#### 1b.3 — Three Payload Questions (!= Phase 2 Auth Gates)

| Question | What to Answer |
|---|---|
| **Assembly** | Where the payload is built and transformed |
| **Validation** | required, pattern, enum |
| **Transport** | path / query / body / multipart / headers |

#### 1b.4 — Connecting to Phase 3

Candidate fields come from static/binding layers; **required/optional/conditional dependencies** require Phase 3 parameter matrix + diff + Phase 5 error inference.

---

## Phase 2 — Three Auth Gates

Grep in `OUTDIR/js/` (with `head`) and write findings to `config.json` (see reference for recipes):

| Gate | Question | Keywords |
|---|---|---|
| **Render Gate** | How does it check logged-in state? | `isLogin`, `getToken`, Cookie/localStorage |
| **Interceptor Gate** | What triggers redirect to `/login`? | `response_code`, `errno`, axios interceptor |
| **Content Gate** | Where do menus/permissions come from? | `menu`, `permission`, `role`, `acl`, `routes` |

**Exit = Gate B**: Record conclusions in `config.json` and update `OUTDIR/runtime_harvest.js` / `preload.js`.

### Phase 2b — API Observation (Optional)

Use `preload.js` in OUTDIR to confirm session key names, Authorization headers, and nested API URLs:

| Config | Output |
|---|---|
| `recordDetail: true` | `__API_RECON_DETAIL__` |
| `observe.xhrHeaders: true` | Header observations |
| `extractUrlsFromResponse: true` | Sub-APIs inside responses |
| `observe.storageReads/cookieReads: true` | Backfill config |
| `neutralizeVueRouter: true` | `__API_RECON_ROUTES__` |

Export each coverage round: `__API_RECON_LOG__`, `__API_RECON_DETAIL__`, `__API_RECON_ROUTES__`, `__API_RECON_OBSERVE__`.

---

## Phase 3 — Runtime

Must pass Gate B first; follow [Boundaries & Prohibitions](#boundaries--prohibitions-mandatory-for-agents) and unauthenticated mock strategy.

Set `"runtimeMode": "depth" | "coverage" | "both"` in `config.json` (see reference for template).

### Hooks & Stubs (Shared by depth + coverage)

| Layer | Scope | Purpose |
|---|---|---|
| L1 Exact | auth/permission/bootstrap stubs | Pass initial screen auth |
| L2 Negative Patch | All JSON responses | Rewrite unauthenticated error codes -> success |
| L3 Fallback | Unmatched `/api` calls | Empty success body to keep UI mounted |

- **depth**: fake auth + `forward` code rewrite + `stubs`; traverse `routes` (hash/history); produces `runtime_api.json`
- **coverage**: inject `preload.js` at **document-start** (CDP `addScriptToEvaluateOnNewDocument` or Userscript)

Verify: `window.__API_RECON_PRELOAD__` is present and business paths do not redirect to `/login`.

```bash
cd recon && npm install
node runtime_harvest.js config.json
```

### 3b — Coverage Dynamic Enumeration (Required)

1. Main navigation / sidebar — click each item, wait 1–3s for network
2. Tabs — `role=tab`, `.ant-tabs-tab`
3. Tables — first row View / Edit / Detail
4. Toolbars — Export, Filter, New (**avoid irreversible deletions**)
5. On each module — merge discovered APIs/routes
6. SPA — controlled `pushState` for paths in `routes.txt` not yet visited (prohibited on MPA)

**Parameter Trigger Matrix** (Required): Record once per action type in each module and **diff multiple samples**:

| Action | Typical Additional Parameters |
|---|---|
| Initial list load | Pagination + default filters |
| Search click | keyword, filter |
| Advanced filter | Additional optional fields |
| Create / Edit | Full entity fields |
| Batch / Export / Sort | `ids[]`, `exportType`, `sortField` |

**Outbound body/headers remain authentic under stubs** — rely on the captured requests. Save recordings to `scan_raw.json`, `param_samples.json`, and `api_detail.json`.

- **Vue**: `neutralizeVueRouter: true` + document-start preload
- **React**: `routes.txt` + sidebar clicks + `pushState`
- **both**: run 3a depth first, then 3b coverage

---

## Phase 4 — Permission Tree Reconstruction

**Trigger**: Module pages are blank / every route only fires bootstrap requests (e.g., locale) -> Content Gate not passed.

| Symptom | Meaning |
|---|---|
| Shell entered | Render Gate + Interceptor Gate passed |
| Missing sidebar items / blank clicks | Incomplete stub shape or permission codes |
| Identical minimal APIs on every route | `v-if permission` check not satisfied |
| `routes.txt` far smaller than bundle | Needs completion from auth module |

```bash
grep -rhoaE '"/api[^"]*(permission|perm|role|menu|acl)[^"]*"' OUTDIR/js/*.js | sort -u | head -30
grep -rhoaE 'userRouteAuth|getResultTree|routeMap|routeLink|menuList|authList' OUTDIR/js/*.js | head -20
```

Typical chain: `role_permissions` (flat codes) + `permissions/all` (tree) -> `getResultTree` -> `userRouteAuth[CODE].url`.

```bash
python3 recon/extract_route_map.py recon/js recon/
python3 recon/build_perm_tree.py recon/js recon/ --config recon/config.json
```

Intermediate outputs: `route_map.json`, `userRouteAuth.json`, `permissions_tree.json`, `*_stub.json`, `perm_codes_all.txt`.

Update `config.json` and **re-run Phase 3**.

---

## Phase 5 — Merge & Report

### Deliverables Table

| File | Phase | Content |
|---|---|---|
| `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt` | 1 | Static bundles and paths |
| `param_candidates.json` | 1b | Static parameter field candidates |
| `config.json` | 2 | Three gates + runtime config |
| `runtime_api.json` | 3a | Depth detailed recording (incl. WS/SSE) |
| `param_samples.json`, `scan_raw.json`, `api_detail.json` | 3b | Multi-samples, click logs, details |
| `route_map.json`, etc. | 4 | Permission tree intermediate files (if run) |
| `params_merged.json` | 5 | Merged parameter fields + confidence |
| `api_merged.txt` | 5 | `METHOD /path [params] [static\|runtime\|both]` |
| `site_map.json` | 5 | Routes, APIs, params, features, limitations |
| **insert_assets** | 5 | Write all discovered services and endpoint assets into the asset database |

### 5b — Parameter Merging

Diff from `param_samples.json`. See reference J7 for confidence rules (High / Medium / Low / Pending Trigger).

### 5c — Error Response Inference

Within authorized scope, send incomplete requests to inspect 400 responses (**parameter recon, not exploitation**): e.g., `field 'x' is required` or enum validation errors.

`site_map.json` recommended structure:

```json
{
  "site": "https://example.com",
  "runtimeMode": "both",
  "appType": "vue-spa",
  "routeGuardStrategy": ["nav-neutralize", "L1-auth", "L2-patch", "forward"],
  "apisFromStatic": [],
  "apisFromRuntime": [],
  "apis": [],
  "params": [{ "method": "POST", "path": "/api/user/list", "transport": "json", "fields": [] }],
  "frontendRoutes": [],
  "routesVerifiedByClick": [],
  "featuresTriggered": [],
  "limitations": ""
}
```

See [reference.md](reference.md) for additional fields and grep recipes.

---

## General Notes

- **Framework-agnostic**: Same approach applies to webpack/Vite/Angular lazy loading
- **Transports**: REST/JSON, GraphQL, WebSocket, SSE
- **SSR**: Client-side fetches can be recorded; RSC/Server Actions are partially enumerable
- **Blind spots**: JSVMP, WASM, strict HMAC/mTLS -> fall back to static analysis and document limitations
- **Static is the safety net**: When runtime is blocked, static analysis still enumerates endpoints

---

## Additional Resources

- Grep recipes, `config.json` templates, troubleshooting, Hooks, Parameter Reverse Engineering Section J, site_map templates: **[reference.md](reference.md)**
