---
name: proxy-harvesting
description: Discover, crawl, parse, self-improve, and strictly verify fast HTTP/HTTPS CONNECT and United States (US) proxy feeds across premium provider daily free pages, live JSON/HTML crawlers, and GitHub country shards.
---

# Autonomous Proxy Harvesting & Self-Improvement Playbook

Use this playbook when operating as `proxy_harvester` (or `auto`) to discover high-yield **HTTP / HTTPS CONNECT** and **United States (US)** proxy feeds, crawl premium proxy providers' daily free proxy lists, prune dead sources, and replenish BEHEMOTH's Proxy Pool with fast, Elite, TLS-verified proxies.

## 1. Priorities: HTTP/HTTPS CONNECT First + United States (US) Exit IPs
- **Always prefer `http` (HTTPS `CONNECT`-capable HTTP proxies)** over `socks5`: HTTP proxies are faster than Tor, avoid multi-hop relay latency, and work natively with 100% of security scanners and web tools.
- **Prioritize United States (`US`) exit IPs** (`country_hint: "US"` / `country_mode: "us_preferred"`): US datacenter/ISP exit IPs minimize geo-fencing blocks and deliver low-latency HTTPS connections.
- Note for operational agents: BEHEMOTH also runs a local `mubeng`-style HTTP/CONNECT protocol bridge (`$HTTP_PROXY`), which translates any HTTP-only tool over upstream HTTP or SOCKS5 pool entries automatically.

## 2. Inspect Current Source Yield First
1. Call `list_proxy_scrape_sources` and `get_proxy_pool_status`.
2. Identify custom sources (`added_by_agent: true`) that returned HTTP errors (`404`/`410`/`5xx`) or `0` candidates and prune them with `remove_proxy_scrape_source`.

## 3. Hunt Live Crawler APIs, Premium Provider Daily Free Lists & Country Shards
1. **Live JSON / HTML Crawler Endpoints & Premium Daily Free Pages**:
   - Look for structured JSON proxy APIs filtered by `country=US` and `protocol=http` (similar to `proxylist.geonode.com/api/proxy-list`, `api.proxyscrape.com/v4/free-proxy-list/get`, `roundproxies.com/api/get-free-proxies/`, `pubproxy.com/api/proxy?country=US&type=http&https=true`).
   - Check premium proxy websites that publish daily refreshed free HTTP/US test lists (such as `iproyal.com/free-proxy-list/`, `fineproxy.org/free-proxies/`, `proxynova.com/proxy-server-list/country-us/`, `free-proxy-list.net/us-proxy.html`, `spys.me/proxy.txt`).
2. **Actively Updated GitHub Country×Protocol Shards**:
   ```bash
   curl -s "https://api.github.com/search/repositories?q=free+proxy+list+http+countries+in:name,description,readme&sort=updated&order=desc&per_page=15" | jq -r '.items[] | "\(.full_name) | \(.updated_at) | \(.default_branch)"'
   ```
   Inspect repository file trees for `countries/US` or `http` / `https` shards:
   ```bash
   curl -s "https://api.github.com/repos/<owner>/<repo>/git/trees/<branch>?recursive=1" | jq -r '.tree[].path' | grep -iE '(us|united|https?|proxies).*\.(txt|json|csv)$'
   ```

## 4. Register Persistent Feeds vs. Custom Extraction
- **Direct JSON / HTML Table / TXT / CSV URLs**: Call `add_proxy_scrape_source(name=..., url=..., protocol="http", country_hint="US", priority=true, test_immediately=true)` — BEHEMOTH's native Go crawler automatically parses GeoNode/ProxyScrape/RoundProxies JSON, IPRoyal SSR records, ProxyNova `document.write` obfuscation, `spys.me` tags, HTML `<tr><td>` tables, and `ip:port` lists!
- **Custom JS / Base64 / Paginated APIs**: Write a concise `python3` or `jq` extractor in `Bash` and pass the extracted `http://ip:port` lines to `verify_and_import_scraped_proxies(proxies=..., default_protocol="http")`.

## 5. Strict Security Invariants
- **Never** import unverified public proxies without `verify_and_import_scraped_proxies`: BEHEMOTH's 2-stage verifier enforces real TLS certificate validation (`InsecureSkipVerify=false`), resolves the true exit country via Cloudflare HTTPS trace, and rejects transparent proxies that leak the host IP.
- Whenever you discover a reusable parser for a new provider's daily free proxy format, document it here via `update_skill_file`.
