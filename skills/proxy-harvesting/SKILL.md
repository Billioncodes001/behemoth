---
name: proxy-harvesting
description: Discover, parse, self-improve, and strictly verify public SOCKS5 and HTTPS-CONNECT proxy feeds across GitHub repositories, JSON APIs, and rotating aggregator sites.
---

# Autonomous Proxy Harvesting & Self-Improvement Playbook

Use this playbook when operating as `proxy_harvester` (or `auto`) to discover high-yield public proxy feeds, prune dead sources, and replenish ARTEX's Proxy Pool with fast, Elite, TLS-verified proxies.

## 1. Inspect Current Source Yield First
1. Call `list_proxy_scrape_sources` and `get_proxy_pool_status`.
2. Identify custom sources (`added_by_agent: true`) that returned HTTP errors (`404`/`410`/`5xx`) or `0` candidates and prune them with `remove_proxy_scrape_source`.

## 2. Hunt Actively Updated GitHub & API Feeds
Query GitHub's repository search API sorted by `updated` so you only add feeds maintained within the last 24–72 hours:
```bash
curl -s "https://api.github.com/search/repositories?q=socks5+proxy+list+in:name,description,readme&sort=updated&order=desc&per_page=15" | jq -r '.items[] | "\(.full_name) | \(.updated_at) | \(.default_branch)"'
```
Inspect repository file trees to find raw `.txt` or `.json` proxy lists:
```bash
curl -s "https://api.github.com/repos/<owner>/<repo>/git/trees/<branch>?recursive=1" | jq -r '.tree[].path' | grep -iE '(socks5|https?|proxies).*\.(txt|json)$'
```
Prefer pre-checked / speed-sorted feeds (`priority: true`) over raw unchecked dumps.

## 3. Register Persistent Feeds vs. Custom Extraction
- **Direct TXT/JSON/CSV URLs**: Call `add_proxy_scrape_source(name=..., url=..., protocol="socks5"|"http", priority=true, test_immediately=true)` so ARTEX's native Go background scraper polls them automatically on every scheduled cycle.
- **Paginated JSON APIs / Base64 / HTML Tables**: Write a concise `python3` or `jq` one-liner in `Bash` to extract `ip:port` or `socks5://ip:port` lines, then pass the extracted lines directly to `verify_and_import_scraped_proxies`!

## 4. Strict Security Invariants
- **Never** import unverified public proxies directly without `verify_and_import_scraped_proxies`: ARTEX's 2-stage verifier enforces real TLS certificate validation (`InsecureSkipVerify=false`) and rejects transparent proxies that echo the host's real IP.
- Whenever you discover a reusable parser for a new public API format, save/update it here via `update_skill_file`.
