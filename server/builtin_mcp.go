package server

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// seedRecommendedPlatformDefaultsAndMCPsV1 enables high-insight platform & agent
// behavioral settings out of the box and seeds built-in offensive/research MCP servers.
// Gated by version flags in PostgreSQL so any subsequent manual toggle by the operator
// in System -> Settings or System -> MCP is permanently respected across restarts.
func (s *Server) seedRecommendedPlatformDefaultsAndMCPsV1() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	pg := s.m.pg

	const settingsFlag = "recommended_platform_defaults_v1"
	if v, _, _ := pg.GetSetting(settingsFlag); v != "true" {
		on := true
		// 1. Traffic, Evidence & Visual Insights
		_ = pg.SetBool(settingAgentTrafficBinding, true)
		_ = pg.SetBool(settingBrowserScreenshot, true)
		_ = pg.SetBool(settingScreenshotTimestamp, true)
		_ = pg.SetBool(settingOpsecEnabled, true)
		_ = s.setReporterBrowserScreenshotVisibility(true)

		// 2. Agent Behavioral Settings: Auto Titles + Task Intelligence + Credential Processing
		_ = pg.SetBool(db.SettingTaskAutoTitle, true)
		_ = pg.SetBool(db.SettingChatAutoTitle, true)
		_ = pg.SetIntelligenceSettings(context.Background(), &on, &on, &on)
		_, _ = pg.Exec(`UPDATE agents SET enabled = true WHERE key IN ('credential_processor', 'reporter', 'retester')`)

		_ = pg.SetSetting(settingsFlag, "true")
		log.Printf("[settings] Enabled recommended agent & platform defaults (traffic binding, screenshots, auto-titles, task intelligence, credential processor)")
	}

	// Materialize embedded Python MCP scripts on every boot so paths stay fresh even if dataDir moved.
	mcpDir := filepath.Join(s.m.dir, "builtin-mcp")
	_ = os.MkdirAll(mcpDir, 0o755)
	scripts := map[string]string{
		"vuln_intel_mcp.py":       vulnIntelMCPScript,
		"recon_osint_mcp.py":      reconOSINTMCPScript,
		"web_sec_analyzer_mcp.py": webSecAnalyzerMCPScript,
	}
	for name, body := range scripts {
		full := filepath.Join(mcpDir, name)
		_ = os.WriteFile(full, []byte(body), 0o755)
	}

	pyPath := s.pythonInterpreter()
	if pyPath == "" {
		pyPath = "python3"
	}

	// Refresh command/args on Python built-in MCP servers if dataDir or python3 path changed.
	type builtinMCPSpec struct {
		name      string
		command   string
		args      []string
		env       map[string]string
		agents    []string
		needsNPX  bool
	}
	specs := []builtinMCPSpec{
		{
			name:    "vuln_intel",
			command: pyPath,
			args:    []string{filepath.Join(mcpDir, "vuln_intel_mcp.py")},
			agents:  []string{"auto", "pentest", "worker", "mainagent", "patch_watch", "planner", "reporter", "retester"},
		},
		{
			name:    "recon_osint",
			command: pyPath,
			args:    []string{filepath.Join(mcpDir, "recon_osint_mcp.py")},
			agents:  []string{"auto", "pentest", "worker", "mainagent", "patch_watch", "asset_mapper", "planner"},
		},
		{
			name:    "web_sec_analyzer",
			command: pyPath,
			args:    []string{filepath.Join(mcpDir, "web_sec_analyzer_mcp.py")},
			agents:  []string{"auto", "pentest", "worker", "mainagent", "patch_watch", "retester"},
		},
		{
			name:     "sequential_thinking",
			command:  "npx",
			args:     []string{"-y", "@modelcontextprotocol/server-sequential-thinking"},
			agents:   []string{"auto", "pentest", "planner", "mainagent", "worker"},
			needsNPX: true,
		},
		{
			name:     "knowledge_memory",
			command:  "npx",
			args:     []string{"-y", "@modelcontextprotocol/server-memory"},
			env:      map[string]string{"MEMORY_FILE_PATH": filepath.Join(s.m.dir, "mcp-memory.json")},
			agents:   []string{"auto", "pentest", "mainagent", "patch_watch", "asset_mapper"},
			needsNPX: true,
		},
	}

	_, hasNPXErr := exec.LookPath("npx")
	hasNPX := hasNPXErr == nil

	const mcpSeedFlag = "builtin_security_mcps_v1"
	alreadySeeded, _, _ := pg.GetSetting(mcpSeedFlag)

	existingList, _ := pg.ListMCP()
	byName := map[string]*db.MCPServer{}
	for _, m := range existingList {
		byName[m.Name] = m
	}

	needDiscovery := false
	for _, sp := range specs {
		if sp.needsNPX && !hasNPX {
			continue
		}
		argsJSON, _ := json.Marshal(sp.args)
		envMap := sp.env
		if envMap == nil {
			envMap = map[string]string{}
		}
		envJSON, _ := json.Marshal(envMap)

		if cur, exists := byName[sp.name]; exists {
			// Keep Python script path / memory file path synchronized if dataDir relocated
			if !sp.needsNPX && (cur.Command != sp.command || string(cur.Args) != string(argsJSON)) {
				cur.Command = sp.command
				cur.Args = argsJSON
				_, _ = pg.SaveMCP(cur)
			}
			if cur.Enabled && len(cur.Tools) == 0 {
				needDiscovery = true
			}
			continue
		}
		if alreadySeeded == "true" {
			// Operator deleted it intentionally; do not re-create.
			continue
		}

		srv := &db.MCPServer{
			Name:      sp.name,
			Transport: "stdio",
			Command:   sp.command,
			Args:      argsJSON,
			Env:       envJSON,
			Enabled:   true,
		}
		id, err := pg.SaveMCP(srv)
		if err != nil {
			log.Printf("[mcp] failed to seed built-in MCP %s: %v", sp.name, err)
			continue
		}
		for _, agKey := range sp.agents {
			if ag, aerr := pg.GetAgentByKey(agKey); aerr == nil && ag != nil {
				_, _ = pg.Exec(`
INSERT INTO agent_visibility(agent_id, resource_kind, resource_id, mcp_tool_name, enabled)
VALUES($1, 'mcp', $2, '', true)
ON CONFLICT (agent_id, resource_kind, resource_id, mcp_tool_name) DO UPDATE SET enabled = true`, ag.ID, id)
			}
		}
		needDiscovery = true
		log.Printf("[mcp] Seeded built-in MCP server %q (%s %s)", sp.name, sp.command, strings.Join(sp.args, " "))
	}

	_ = pg.SetSetting(mcpSeedFlag, "true")
	if needDiscovery && s.ctx != nil && s.ctx.Err() == nil {
		go s.discoverEmptyMCPsOnStartup()
	}
}

const vulnIntelMCPScript = `#!/usr/bin/env python3
"""ARTEX Built-in Vulnerability & Exploitability Intelligence MCP Server (JSON-RPC 2.0 over stdio)."""
import json
import sys
import urllib.parse
import urllib.request
import ssl

SSL_CTX = ssl.create_default_context()
UA = "ARTEX-VulnIntel-MCP/2.2 (+https://github.com/Billioncodes001/myartex)"

def http_json(url, method="GET", payload=None, timeout=15):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler(),
        urllib.request.HTTPSHandler(context=SSL_CTX),
    )
    with opener.open(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))

TOOLS = [
    {
        "name": "cve_nvd_lookup",
        "description": "Fetch full CVE details, CVSS v3.1/v4.0 score & vector, CWEs, and references from NIST NVD 2.0.",
        "inputSchema": {
            "type": "object",
            "properties": {"cve_id": {"type": "string", "description": "CVE identifier, e.g. CVE-2024-4577"}},
            "required": ["cve_id"],
        },
    },
    {
        "name": "epss_exploit_probability",
        "description": "Query FIRST.org EPSS API for real-world 30-day exploitation probability and percentile of CVE(s).",
        "inputSchema": {
            "type": "object",
            "properties": {"cve_ids": {"type": "string", "description": "Comma-separated CVE IDs, e.g. CVE-2024-4577,CVE-2024-3400"}},
            "required": ["cve_ids"],
        },
    },
    {
        "name": "cisa_kev_search",
        "description": "Search CISA Known Exploited Vulnerabilities (KEV) catalog by CVE ID, vendor, or product keyword.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "CVE ID, vendor, or product name (e.g. Fortinet, PAN-OS, CVE-2024-3400)"}},
            "required": ["query"],
        },
    },
    {
        "name": "osv_package_vulns",
        "description": "Query Google OSV.dev for known vulnerabilities affecting an open-source package and version.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_name": {"type": "string", "description": "Package name (e.g. django, express, lodash, spring-webmvc)"},
                "ecosystem": {"type": "string", "description": "Ecosystem: PyPI | npm | Go | Maven | Packagist | NuGet | crates.io | RubyGems"},
                "version": {"type": "string", "description": "Optional exact package version (e.g. 4.2.1)"},
            },
            "required": ["package_name", "ecosystem"],
        },
    },
    {
        "name": "github_advisory_search",
        "description": "Search GitHub Security Advisories (GHSA) by keyword, ecosystem, or CVE ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "CVE ID, package name, or keyword"},
                "ecosystem": {"type": "string", "description": "Optional ecosystem: npm | pip | go | maven | composer | rubygems | nuget | rust"},
            },
            "required": ["query"],
        },
    },
]

def call_tool(name, args):
    if name == "cve_nvd_lookup":
        cve = str(args.get("cve_id", "")).strip().upper()
        data = http_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cve)}")
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"cve_id": cve, "found": False}
        c = vulns[0].get("cve", {})
        descs = [d.get("value") for d in c.get("descriptions", []) if d.get("lang") == "en"]
        metrics = c.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
            if metrics.get(key):
                cvss = metrics[key][0].get("cvssData")
                break
        cwes = [desc.get("value") for w in c.get("weaknesses", []) for desc in w.get("description", [])]
        refs = [r.get("url") for r in c.get("references", [])[:10]]
        return {"cve_id": cve, "found": True, "published": c.get("published"), "description": descs[0] if descs else "", "cvss": cvss, "cwes": cwes, "references": refs}

    if name == "epss_exploit_probability":
        cves = ",".join([x.strip().upper() for x in str(args.get("cve_ids", "")).split(",") if x.strip()])
        data = http_json(f"https://api.first.org/data/v1/epss?cve={urllib.parse.quote(cves)}")
        return {"total": data.get("total", 0), "scores": data.get("data", [])}

    if name == "cisa_kev_search":
        q = str(args.get("query", "")).strip().lower()
        data = http_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=20)
        matches = []
        for v in data.get("vulnerabilities", []):
            blob = f"{v.get('cveID','')} {v.get('vendorProject','')} {v.get('product','')} {v.get('vulnerabilityName','')} {v.get('shortDescription','')}".lower()
            if q in blob:
                matches.append(v)
                if len(matches) >= 15:
                    break
        return {"query": q, "count": len(matches), "matches": matches}

    if name == "osv_package_vulns":
        body = {"package": {"name": args.get("package_name", ""), "ecosystem": args.get("ecosystem", "")}}
        if args.get("version"):
            body["version"] = str(args["version"])
        data = http_json("https://api.osv.dev/v1/query", method="POST", payload=body)
        out = []
        for v in data.get("vulns", [])[:15]:
            out.append({
                "id": v.get("id"),
                "aliases": v.get("aliases", []),
                "summary": v.get("summary", ""),
                "details": (v.get("details") or "")[:500],
                "severity": v.get("severity", []),
            })
        return {"count": len(out), "vulnerabilities": out}

    if name == "github_advisory_search":
        q = str(args.get("query", "")).strip()
        params = {"per_page": "15"}
        if q.upper().startswith("CVE-"):
            params["cve_id"] = q.upper()
        elif q.upper().startswith("GHSA-"):
            params["ghsa_id"] = q
        if args.get("ecosystem"):
            params["ecosystem"] = str(args["ecosystem"]).strip().lower()
        data = http_json("https://api.github.com/advisories?" + urllib.parse.urlencode(params))
        ql = q.lower()
        out = []
        for adv in (data if isinstance(data, list) else []):
            blob = f"{adv.get('ghsa_id','')} {adv.get('cve_id','')} {adv.get('summary','')} {adv.get('description','')}".lower()
            if not q or q.upper().startswith(("CVE-", "GHSA-")) or ql in blob:
                out.append({
                    "ghsa_id": adv.get("ghsa_id"),
                    "cve_id": adv.get("cve_id"),
                    "severity": adv.get("severity"),
                    "summary": adv.get("summary"),
                    "html_url": adv.get("html_url"),
                    "published_at": adv.get("published_at"),
                })
        return {"count": len(out), "advisories": out[:15]}

    raise ValueError(f"Unknown tool: {name}")

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        req_id = req.get("id")
        if req_id is None:
            continue
        method = req.get("method", "")
        try:
            if method == "initialize":
                res = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "vuln_intel", "version": "2.2.0"}}
            elif method == "tools/list":
                res = {"tools": TOOLS}
            elif method == "tools/call":
                p = req.get("params") or {}
                out = call_tool(p.get("name", ""), p.get("arguments") or {})
                res = {"content": [{"type": "text", "text": json.dumps(out, indent=2)}]}
            else:
                res = {}
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": res}) + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}}) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
`

const reconOSINTMCPScript = `#!/usr/bin/env python3
"""ARTEX Built-in Passive Recon, CT Logs, TLS, Wayback & Security.txt MCP Server."""
import json
import os
import re
import socket
import ssl
import sys
import urllib.parse
import urllib.request

SSL_CTX = ssl.create_default_context()
UA = "Mozilla/5.0 (compatible; ARTEX-ReconOSINT-MCP/2.3)"

def http_get(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler(),
        urllib.request.HTTPSHandler(context=SSL_CTX),
    )
    with opener.open(req, timeout=timeout) as r:
        return r.status, dict(r.headers), r.read().decode("utf-8", errors="replace")

def open_tcp_via_env_proxy(host, port, timeout=10):
    """Tunnels raw TCP (e.g. TLS inspection) via HTTP CONNECT when HTTPS_PROXY/HTTP_PROXY is set so the server IP is never exposed."""
    px = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy") or "").strip()
    if not px or host in ("127.0.0.1", "localhost", "::1"):
        return socket.create_connection((host, port), timeout=timeout)
    u = urllib.parse.urlparse(px if "://" in px else "http://" + px)
    px_host = u.hostname or "127.0.0.1"
    px_port = u.port or 8080
    sock = socket.create_connection((px_host, px_port), timeout=timeout)
    try:
        connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
        sock.sendall(connect_req.encode("ascii"))
        resp = b""
        while b"\r\n\r\n" not in resp and len(resp) < 8192:
            chunk = sock.recv(1024)
            if not chunk:
                break
            resp += chunk
        status_line = resp.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
        if " 200 " not in status_line and not status_line.endswith(" 200"):
            raise RuntimeError(f"Proxy CONNECT tunnel failed: {status_line}")
        return sock
    except Exception:
        sock.close()
        raise

TOOLS = [
    {
        "name": "crtsh_ct_subdomains",
        "description": "Enumerate subdomains passively via Certificate Transparency logs (crt.sh) without touching the target.",
        "inputSchema": {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "Root domain, e.g. example.com"}},
            "required": ["domain"],
        },
    },
    {
        "name": "rdap_whois_lookup",
        "description": "Query RDAP (IANA/ARIN/RIPE/ICANN) for domain or IP registration, nameservers, ASN, and abuse/security contacts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain name (example.com) or IPv4/IPv6 address"},
                "kind": {"type": "string", "description": "domain (default) or ip"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "wayback_cdx_endpoints",
        "description": "Query Internet Archive Wayback Machine CDX API for historical URLs, forgotten API routes, and sensitive file paths.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain or host, e.g. api.example.com"},
                "limit": {"type": "integer", "description": "Max URLs to return (default 50, max 200)"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "tls_certificate_inspect",
        "description": "Inspect a host's live TLS certificate (subject, issuer, SANs, expiry, protocol version, and cipher suite).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname, e.g. console.example.com"},
                "port": {"type": "integer", "description": "TLS port (default 443)"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "security_txt_contacts",
        "description": "Fetch RFC 9116 /.well-known/security.txt (and /security.txt) to retrieve official vulnerability disclosure contacts for notifying site owners.",
        "inputSchema": {
            "type": "object",
            "properties": {"domain_or_url": {"type": "string", "description": "Domain or base URL, e.g. example.com"}},
            "required": ["domain_or_url"],
        },
    },
]

def call_tool(name, args):
    if name == "crtsh_ct_subdomains":
        dom = str(args.get("domain", "")).strip().lstrip("*.")
        _, _, raw = http_get(f"https://crt.sh/?q=%25.{urllib.parse.quote(dom)}&output=json", timeout=20)
        rows = json.loads(raw)
        subs = sorted({h.strip().lower().lstrip("*.") for r in rows for h in str(r.get("name_value", "")).splitlines() if h.strip() and dom.lower() in h.lower()})
        return {"domain": dom, "count": len(subs), "subdomains": subs[:150]}

    if name == "rdap_whois_lookup":
        tgt = str(args.get("target", "")).strip()
        kind = str(args.get("kind", "domain")).strip().lower()
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", tgt) or ":" in tgt:
            kind = "ip"
        _, _, raw = http_get(f"https://rdap.org/{kind}/{urllib.parse.quote(tgt)}", timeout=15)
        data = json.loads(raw)
        return {
            "handle": data.get("handle"),
            "ldhName": data.get("ldhName") or data.get("name"),
            "status": data.get("status", []),
            "events": data.get("events", []),
            "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")],
            "entities": data.get("entities", [])[:5],
        }

    if name == "wayback_cdx_endpoints":
        dom = str(args.get("domain", "")).strip()
        lim = min(max(int(args.get("limit") or 50), 1), 200)
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{urllib.parse.quote(dom)}/*&output=json&fl=original,mimetype,statuscode&collapse=urlkey&limit={lim}"
        _, _, raw = http_get(url, timeout=20)
        rows = json.loads(raw)
        items = [{"url": r[0], "mime": r[1], "status": r[2]} for r in rows[1:]] if len(rows) > 1 else []
        return {"domain": dom, "count": len(items), "endpoints": items}

    if name == "tls_certificate_inspect":
        host = str(args.get("host", "")).strip()
        port = int(args.get("port") or 443)
        ctx = ssl.create_default_context()
        with open_tcp_via_env_proxy(host, port, timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
                return {
                    "host": host,
                    "port": port,
                    "tls_version": ssock.version(),
                    "cipher": ssock.cipher(),
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "san_dns": sans[:100],
                }

    if name == "security_txt_contacts":
        raw_in = str(args.get("domain_or_url", "")).strip()
        base = raw_in if raw_in.startswith(("http://", "https://")) else f"https://{raw_in}"
        u = urllib.parse.urlparse(base)
        origin = f"{u.scheme}://{u.netloc}"
        for path in ("/.well-known/security.txt", "/security.txt"):
            try:
                st, _, body = http_get(origin + path, timeout=8)
                if st == 200 and ("contact:" in body.lower() or "policy:" in body.lower()):
                    contacts = re.findall(r"(?im)^Contact:\s*(.+)$", body)
                    return {"origin": origin, "found": True, "url": origin + path, "contacts": [c.strip() for c in contacts], "raw": body[:2000]}
            except Exception:
                continue
        return {"origin": origin, "found": False, "fallback_contacts": [f"security@{u.hostname}", f"abuse@{u.hostname}"]}

    raise ValueError(f"Unknown tool: {name}")

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        req_id = req.get("id")
        if req_id is None:
            continue
        method = req.get("method", "")
        try:
            if method == "initialize":
                res = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "recon_osint", "version": "2.2.0"}}
            elif method == "tools/list":
                res = {"tools": TOOLS}
            elif method == "tools/call":
                p = req.get("params") or {}
                out = call_tool(p.get("name", ""), p.get("arguments") or {})
                res = {"content": [{"type": "text", "text": json.dumps(out, indent=2)}]}
            else:
                res = {}
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": res}) + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}}) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
`

const webSecAnalyzerMCPScript = `#!/usr/bin/env python3
"""ARTEX Built-in Web Security Header, JWT, JS Bundle & CORS Analyzer MCP Server."""
import base64
import json
import re
import ssl
import sys
import urllib.parse
import urllib.request

SSL_CTX = ssl.create_default_context()
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"

def fetch_url(url, extra_headers=None, timeout=12):
    hdrs = {"User-Agent": UA}
    if extra_headers:
        hdrs.update(extra_headers)
    req = urllib.request.Request(url, headers=hdrs)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler(),
        urllib.request.HTTPSHandler(context=SSL_CTX),
    )
    with opener.open(req, timeout=timeout) as r:
        raw_cookies = r.headers.get_all("Set-Cookie") or []
        return r.status, {k.lower(): v for k, v in r.headers.items()}, raw_cookies, r.read(512 * 1024).decode("utf-8", errors="replace")

TOOLS = [
    {
        "name": "http_security_headers_audit",
        "description": "Audit a URL's HTTP security headers (CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy), Set-Cookie attributes, and Server/tech disclosures.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "Target HTTP/HTTPS URL"}},
            "required": ["url"],
        },
    },
    {
        "name": "jwt_decode_and_audit",
        "description": "Decode a JWT token's header & claims and audit for alg:none, kid/jku/x5u injection vectors, key confusion, and missing expiration claims.",
        "inputSchema": {
            "type": "object",
            "properties": {"token": {"type": "string", "description": "Raw JWT string (eyJ...)"}},
            "required": ["token"],
        },
    },
    {
        "name": "js_bundle_endpoint_extractor",
        "description": "Fetch an HTML page or JavaScript bundle and extract REST/GraphQL endpoints, hidden query parameters, cloud buckets, and potential exposed client tokens.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "URL of JS bundle or web page"}},
            "required": ["url"],
        },
    },
    {
        "name": "cors_policy_analyzer",
        "description": "Safely test passive CORS Origin reflection (arbitrary origin, null origin, prefix/subdomain) and Access-Control-Allow-Credentials exposure.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "Target API or web URL"}},
            "required": ["url"],
        },
    },
]

def b64url_decode(seg):
    pad = "=" * ((4 - len(seg) % 4) % 4)
    return base64.urlsafe_b64decode((seg + pad).encode("ascii"))

def call_tool(name, args):
    if name == "http_security_headers_audit":
        st, hdrs, cookies, _ = fetch_url(str(args.get("url", "")).strip())
        required = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"]
        missing = [h for h in required if h not in hdrs]
        cookie_issues = []
        for c in cookies:
            cl = c.lower()
            cname = c.split("=", 1)[0].strip()
            if "httponly" not in cl:
                cookie_issues.append(f"{cname}: missing HttpOnly")
            if "secure" not in cl:
                cookie_issues.append(f"{cname}: missing Secure")
            if "samesite" not in cl:
                cookie_issues.append(f"{cname}: missing SameSite")
        return {
            "status": st,
            "present_security_headers": {h: hdrs[h] for h in required if h in hdrs},
            "missing_security_headers": missing,
            "tech_disclosure": {k: hdrs[k] for k in ("server", "x-powered-by", "x-aspnet-version", "x-generator", "via") if k in hdrs},
            "cookie_findings": cookie_issues,
        }

    if name == "jwt_decode_and_audit":
        tok = str(args.get("token", "")).strip()
        if tok.lower().startswith("bearer "):
            tok = tok[7:].strip()
        parts = tok.split(".")
        if len(parts) < 2:
            raise ValueError("Invalid JWT format (expected header.payload[.signature])")
        header = json.loads(b64url_decode(parts[0]).decode("utf-8", errors="replace"))
        payload = json.loads(b64url_decode(parts[1]).decode("utf-8", errors="replace"))
        risks = []
        alg = str(header.get("alg", ""))
        if alg.lower() == "none" or not alg:
            risks.append("CRITICAL: alg is 'none' or empty — test signature stripping")
        if alg.upper().startswith("RS") or alg.upper().startswith("ES"):
            risks.append("Check RS256->HS256 public-key confusion if server uses legacy JWT library")
        if alg.upper().startswith("HS"):
            risks.append("Symmetric HMAC signing — test weak/default HMAC secret dictionary offline")
        for hkey in ("jku", "x5u", "jwk"):
            if hkey in header:
                risks.append(f"HIGH: '{hkey}' header present ({header[hkey]}) — test SSRF / rogue key injection")
        if "kid" in header:
            risks.append(f"INFO: 'kid' header present ({header['kid']}) — test path traversal (/dev/null) or SQLi")
        if "exp" not in payload:
            risks.append("MEDIUM: Token lacks 'exp' expiration claim (non-expiring token)")
        return {"header": header, "payload": payload, "has_signature": len(parts) >= 3 and bool(parts[2]), "audit_notes": risks}

    if name == "js_bundle_endpoint_extractor":
        _, _, _, body = fetch_url(str(args.get("url", "")).strip())
        routes = sorted(set(re.findall(r"""['"` + "`" + `]((?:/api/|/v[1-9]/|/graphql|/admin/|/internal/|/auth/|/oauth/)[^'"` + "`" + `\s<>]{1,140})['"` + "`" + `]""", body)))
        full_urls = sorted(set(re.findall(r"""https?://[a-zA-Z0-9._-]+(?::\d+)?/[a-zA-Z0-9._/~%&?=-]{2,140}""", body)))
        buckets = sorted(set(re.findall(r"""(?:[a-z0-9.-]+\.s3[a-z0-9.-]*\.amazonaws\.com|storage\.googleapis\.com/[a-zA-Z0-9._-]+|[a-z0-9-]+\.blob\.core\.windows\.net)""", body)))
        return {"api_routes": routes[:100], "referenced_urls": full_urls[:60], "cloud_buckets": buckets[:30]}

    if name == "cors_policy_analyzer":
        target = str(args.get("url", "")).strip()
        u = urllib.parse.urlparse(target)
        probes = [f"https://evil-{u.hostname or 'check'}.example.com", "null", f"https://{u.hostname}.attacker.example.com"]
        results = []
        for origin in probes:
            try:
                st, hdrs, _, _ = fetch_url(target, extra_headers={"Origin": origin})
                acao = hdrs.get("access-control-allow-origin", "")
                acac = hdrs.get("access-control-allow-credentials", "")
                vulnerable = (acao == origin) or (acao == "*" and acac.lower() == "true") or (origin == "null" and acao == "null")
                results.append({"probe_origin": origin, "status": st, "acao": acao, "acac": acac, "potentially_exploitable": vulnerable and acac.lower() == "true"})
            except Exception as e:
                results.append({"probe_origin": origin, "error": str(e)})
        return {"url": target, "cors_tests": results}

    raise ValueError(f"Unknown tool: {name}")

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        req_id = req.get("id")
        if req_id is None:
            continue
        method = req.get("method", "")
        try:
            if method == "initialize":
                res = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "web_sec_analyzer", "version": "2.2.0"}}
            elif method == "tools/list":
                res = {"tools": TOOLS}
            elif method == "tools/call":
                p = req.get("params") or {}
                out = call_tool(p.get("name", ""), p.get("arguments") or {})
                res = {"content": [{"type": "text", "text": json.dumps(out, indent=2)}]}
            else:
                res = {}
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": res}) + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}}) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
`
