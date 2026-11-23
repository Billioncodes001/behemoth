# Third-party components

ARTEX is distributed with the Go modules listed in `go.mod` / `go.sum` and the
npm packages listed in `web/package.json` / `package-lock.json`. The table below
covers the direct Go dependencies and the license each publishes with its module
(verified against the module sources). Indirect dependencies carry the licenses
declared by their own modules.

## Direct Go dependencies

| Module | Version | License |
|---|---|---|
| `github.com/Autumn-27/norma` | v0.4.3 | No `LICENSE` file is published in the module — confirm with the upstream repository before redistribution. |
| `github.com/chromedp/chromedp` | v0.23.1 | MIT |
| `github.com/golang-jwt/jwt/v5` | v5.3.1 | MIT |
| `github.com/google/uuid` | v1.6.0 | BSD-3-Clause |
| `github.com/jackc/pgx/v5` | v5.10.0 | MIT |
| `github.com/klauspost/compress` | v1.18.6 | BSD-3-Clause |
| `github.com/lqqyt2423/go-mitmproxy` | v1.9.5 | MIT |
| `github.com/masterzen/winrm` | v0.0.0-20261114181639 | Apache-2.0 |
| `github.com/miekg/dns` | v1.1.72 | BSD-3-Clause |
| `github.com/pkg/sftp` | v1.13.12 | BSD-2-Clause |
| `github.com/projectdiscovery/dnsx` | v1.2.3 | MIT |
| `github.com/refraction-networking/utls` | v1.8.2 | BSD-3-Clause |
## Frontend

The web console is a Next.js application; its direct dependencies and licenses
are those declared in each package's `package.json` under
`web/node_modules` (React, Next.js — MIT; Tailwind CSS — MIT; Radix/shadcn
primitives — MIT; lucide-react — ISC; date-fns — MIT; i18next — MIT; TanStack
Table — MIT; CodeMirror — MIT; AntV G6 — MIT).

## Bundled data / tooling

- **SecLists** — installed at deploy time by `setup.sh` (MIT).
- **hashcat / john / pocl-opencl-icd** — installed at deploy time by `setup.sh`
  from the distribution repositories; each ships its own license.
- **Docker images** used by `sandbox_exec` (default `kalilinux/kali-last-release`)
  are pulled at runtime and carry the licenses of the packages they contain.

## Design references

- **Mamba RMM** (`rmm/`, reference-only, not linked or imported) — the ARTEX
  C2 capability (`c2/` package) models its semantics (implant registry,
  pending→sent→done task lifecycle, malleable profile paths, per-implant
  secrets, operator console) but is implemented from scratch; no Mamba
  source is redistributed.
- **ProfGinx** (`ProfGinx_custom/`, reference-only, BSD-3-Clause) and
  **Gophish** (MIT) are consulted as design references for the deferred
  proxy-capture and tracked-mail campaign features; neither is imported
  or redistributed yet.

## Adding a dependency

When a new direct dependency is added, update this file in the same change and
include the license declared by the module.
