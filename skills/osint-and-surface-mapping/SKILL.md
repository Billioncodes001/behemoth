---
name: osint-and-surface-mapping
description: External attack surface discovery, subdomain enumeration, crt.sh certificate transparency, virtual host fuzzing, exposed .git/.env/backup hunting, and technology stack fingerprinting.
---

# OSINT & Attack Surface Mapping Playbook

Use this skill at the start of an engagement or when expanding the attack surface for a root domain, company, or IP block.

## 1. Subdomain & DNS Discovery
1. Query Certificate Transparency logs (`curl -s "https://crt.sh/?q=%25.<domain>&output=json" | jq -r '.[].name_value' | sort -u`).
2. Perform DNS record enumeration (`dig ANY <domain>`, `dig AXFR <domain> @<ns>`, `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `SPF`, `DMARC`).
3. Probe Virtual Hosts (`Host: <sub.domain>`) against discovered IP addresses to uncover unindexed internal/staging virtual hosts.
4. Persist every verified subdomain, IP, and service using `insert_assets`.

## 2. Exposed Artifacts & Sensitive Files
Probe web roots for high-impact exposures (verify content type and body to avoid false positives on SPA catch-all routes):
- Version control & CI: `/.git/HEAD`, `/.svn/entries`, `/.gitlab-ci.yml`, `/.github/workflows/`
- Environment & secrets: `/.env`, `/.env.backup`, `/.env.production`, `/config.json`, `/phpinfo.php`, `/actuator/env`, `/actuator/heapdump`, `/debug/pprof/`
- API documentation: `/swagger-ui.html`, `/v2/api-docs`, `/v3/api-docs`, `/openapi.json`, `/graphql`
