package db

import "fmt"

// defaultTaskTemplate is one prebuilt, ready-to-run pentesting template seeded
// into task_templates on first startup. Non-technical users pick one in the
// task creation dialog and immediately have a professional engagement brief.
type defaultTaskTemplate struct {
	Name        string
	Description string
	Goal        string
	Remark      string
}

// defaultTaskTemplates covers the most common authorized engagement types,
// written against current public methodology (PTES, OWASP WSTG v4.2,
// OWASP Top 10 2021, OWASP API Security Top 10 2023, MITRE ATT&CK recon
// tactics, ASVS 4.0). Goals are phrased as final outcomes — the goals
// decomposer and planner turn them into intents.
//
// Seed policy matches every other builtin seed: insert-if-absent by the
// case-insensitive name key so user edits are never clobbered on restart.
var defaultTaskTemplates = []defaultTaskTemplate{
	{
		Name: "Web Application Pentest (OWASP Top 10)",
		Description: "Full black-box web application penetration test following the OWASP Testing Guide v4.2 and OWASP Top 10 2021. " +
			"Covers reconnaissance, content discovery, authentication, session management, access control, injection, " +
			"misconfiguration, and business-logic testing, ending in verified findings with reproduction steps.",
		Goal: "Perform an authorized black-box penetration test of the target web application. " +
			"Phase 1 - Recon: enumerate subdomains, technologies, framework fingerprints, security headers (CSP, HSTS, CORS), robots.txt/sitemap, and JS bundles for leaked endpoints. " +
			"Phase 2 - Content discovery: brute-force directories and parameter names, enumerate API routes, and map the attack surface. " +
			"Phase 3 - Vulnerability assessment per OWASP Top 10 2021: broken access control (IDOR, forced browsing), cryptographic failures, injection (SQLi, SSTI, command injection), insecure design, misconfiguration, vulnerable components (match versions against known CVEs), authentication and session flaws (weak passwords, missing lockout, predictable cookies, JWT alg=none/kid confusion), SSRF, and logging failures. " +
			"Phase 4 - Validation: confirm every finding with a harmless proof-of-concept, record raw request/response evidence, rate severity (CVSS v3.1), and produce a remediation summary. " +
			"Stay strictly within the authorized scope; never exfiltrate real user data; stop at proof of exploitability.",
		Remark: "Scope: replace TARGET with your authorized URL. Safe for shared hosting: PoCs are non-destructive.",
	},
	{
		Name: "REST / GraphQL API Security Audit (OWASP API Top 10)",
		Description: "Dedicated API security assessment per the OWASP API Security Top 10 2023, for REST and GraphQL backends. " +
			"Focuses on broken object-level and function-level authorization, mass assignment, unrestricted resource consumption, " +
			"and business-logic abuse - the classes automated scanners miss most.",
		Goal: "Assess the target API against OWASP API Security Top 10 2023. " +
			"First map the surface: discover OpenAPI/Swagger docs (swagger.json, openapi.yaml, /api-docs), GraphQL introspection (also try introspection via GET and __typename probing when POST is blocked), versioned routes (/v1, /v2), and undocumented endpoints from JS bundles. " +
			"Then test: API1 broken object-level authorization (swap IDs/UUIDs between two test accounts), API2 broken authentication (token handling, expiry, refresh flows), API3 broken object-property-level authorization (mass assignment by adding fields like role/is_admin/owner to PATCH/POST bodies), API4 unrestricted resource consumption (large page sizes, deep nesting, no rate limiting), API5 broken function-level authorization (call admin verbs as a normal user), API6 sensitive business flows (automation-resistant), API7 SSRF (webhook/URL-import parameters), API8 security misconfiguration (verbose errors, CORS, HTTP methods), API9 improper inventory (old versions, debug endpoints), API10 unsafe consumption of third-party APIs. " +
			"For GraphQL: batched queries, field suggestions, depth limits, mutations with missing authorization. " +
			"Confirm each finding with two-account evidence where applicable and log severity with reproducible requests.",
		Remark: "Requires two low-privileged test accounts for authorization-differential testing.",
	},
	{
		Name: "External Attack Surface Reconnaissance",
		Description: "Outside-in reconnaissance of an organization's internet-facing footprint per MITRE ATT&CK Enterprise Reconnaissance tactics " +
			"(T1595 Active Scanning, T1592 Gather Victim Host Info, T1591 Gather Victim Org Info). " +
			"Produces an asset inventory, technology map, exposed services list, and prioritized exposure report.",
		Goal: "Map the external attack surface of the authorized organization. " +
			"Enumerate: subdomains via passive sources and DNS brute force with permutation, certificate transparency logs (crt.sh), MX/TXT/SPF/DMARC/DKIM records for cloud providers and mail infrastructure, ASN and netblock ownership, exposed cloud storage buckets (S3/GCS/Azure), exposed admin panels and login portals (vpn., mail., remote., jenkins., git., kibana., grafana.), staging and legacy environments (dev., test., uat., old.). " +
			"Fingerprint technologies and versions via HTTP signals, flag expired or weak TLS configurations, scan open ports on the authorized IP ranges (top-1000 then targeted), and list default-credential candidates for found services (report only, do not brute-force aggressively). " +
			"Deliverable: a deduplicated asset inventory with ownership inference, risk-ranked exposure list (critical first), and quick-win hardening recommendations. " +
			"Rate-limit all active scanning; passive sources first, active probes second.",
		Remark: "Set the authorized domains/IP ranges in the description. Passive-heavy: safe for continuous runs.",
	},
	{
		Name: "WordPress / CMS Security Audit",
		Description: "Security audit for WordPress and other common CMS deployments: core/plugin/theme version enumeration, " +
			"known-CVE matching, user enumeration, auth hardening, file-upload and REST API exposure, and misconfiguration checks.",
		Goal: "Audit the target CMS installation. " +
			"Enumerate CMS core version (meta generator, readme.html, feed fingerprints, /wp-admin/install.php), all plugins and themes (wp-content paths, passive plugin detection, REST /wp-json probes), and map each version against known CVEs. " +
			"Test: user enumeration (/wp-json/wp/v2/users, ?author=N scans, login error differentiation), xmlrpc.php exposure (pingback, system.listMethods, multicall brute-force with a small wordlist at low rate), REST API privilege issues (user creation via /wp/v2/users when registration is open), file upload risks (unrestricted upload via plugin endpoints, /wp-content/uploads listing), directory listing, debug files (debug.log, wp-config.bak, .env), default table prefixes, admin-ajax.php abuse, and cache/backup artifacts (.sql, .zip, .tar.gz in webroot). " +
			"For non-WordPress CMS detect the platform first (Joomla, Drupal, Ghost, Strapi, custom) and adapt. " +
			"Verify exploitable findings with safe PoCs only; never persist webshells or modify content.",
		Remark: "Read-only audit: no content modification, no destructive plugin tests.",
	},
	{
		Name: "Authentication & Session Security Assessment",
		Description: "Deep-dive on identity: login flows, password policy, MFA, password reset, session cookies, JWT handling, " +
			"OAuth/OIDC flows and SSO, per OWASP ASVS 4.0 chapters V2 (Authentication) and V3 (Session Management).",
		Goal: "Evaluate authentication and session security of the target per OWASP ASVS V2/V3. " +
			"Test credential handling: username enumeration via response/timing differentials, weak password policy acceptance (123456, Password1!), missing rate limiting or lockout (measured, low-volume checks). " +
			"Test password reset: predictable or non-expiring tokens, token leakage via referrer, host-header poisoning to hijack the reset link, account takeover via response manipulation, enumeration through reset responses. " +
			"Test sessions: cookie flags (Secure, HttpOnly, SameSite), session fixation, logout invalidation (reuse old cookie), concurrent session policy, idle timeout, session ID entropy and rotation on privilege change. " +
			"Test JWT (if present): alg=none, HS/RS confusion, kid injection, jku/jwk header abuse, missing exp/aud verification, weak HMAC secrets against a common-secret list. " +
			"Test OAuth/OIDC (if present): redirect_uri validation, missing state (CSRF), code interception (PKCE absent), open redirectors, token substitution between clients, id_token aud/iss validation. " +
			"Test MFA: bypass via response tampering, brute-forceable OTP, remember-device abuse, missing MFA on sensitive operations. " +
			"Every finding needs a working reproduction with sanitized evidence.",
		Remark: "Use the provided test accounts. Keep brute-force checks under 20 requests/minute.",
	},
	{
		Name: "Injection Vulnerability Deep Dive (SQLi / Command / SSTI)",
		Description: "Focused hunt for injection classes: SQL injection (error/boolean/time-based), NoSQL injection, " +
			"OS command injection, template injection (SSTI), LDAP, and header injection. Methodology follows sqlmap-level " +
			"thoroughness with manual confirmation and safe, data-preserving PoCs.",
		Goal: "Hunt injection vulnerabilities across the authorized target. " +
			"SQL injection: probe every parameter (GET/POST/header/JSON path) with error-based single-quote breaks, boolean differential (AND 1=1 vs AND 1=2 with response-diffing), time-based delay (SLEEP/BENCHMARK/pg_sleep/dbms_pipe) at low rate, UNION column-count discovery with ORDER BY and NULL-folding; identify DBMS from error signatures; where a boolean oracle exists, extract only the current database name and version banner as proof - never dump user tables. " +
			"NoSQL injection: MongoDB $where/$ne/$regex operators in JSON bodies and URL params, Mongo error leakage. " +
			"Command injection: out-of-band-safe detection with echo-markers and bounded sleep on parameters reaching exec contexts (report, do not run further commands). " +
			"SSTI: detect via {{7*7}}, ${7*7}, <%= 7*7 %>, #{7*7} polyglots and identify the template engine from the arithmetic result. " +
			"LDAP/XML (XXE): blind detection with error differentials, external entity probes against a harmless internal URL like http://127.0.0.1:80. " +
			"Header injection: CRLF in reflected headers, response splitting on Host/X-Forwarded-Host. " +
			"Log DBMS type, injection point, technique class, and a minimal proof for each confirmed instance.",
		Remark: "Data-preserving: extract DB version/banner only. Time-based tests capped at 5s delays.",
	},
	{
		Name: "XSS & Client-Side Vulnerability Assessment",
		Description: "Cross-site scripting in all its forms (reflected, stored, DOM-based, blind), plus client-side weaknesses: " +
			"dangerous DOM sinks, postMessage handlers, prototype pollution, CSP bypass, and unsafe JS dependency usage.",
		Goal: "Assess client-side security of the target web application. " +
			"Reflected XSS: fuzz every reflected parameter (path, query, headers with reflection) with context-aware payloads - HTML context, attribute context, JS string context, URL context - and account for filters/encoding. " +
			"Stored XSS: test every persistence point (profile fields, comments, filenames, HTML imports) and trace where the payload executes, including admin-only rendering surfaces if a low-priv test account can reach them. " +
			"DOM XSS: crawl JS bundles for dangerous sinks (innerHTML, document.write, eval, setTimeout-with-string, location.href assignment, jQuery $(location.hash)) and source-to-sink tracing of hash/query/postMessage inputs. " +
			"Blind XSS: where a callback server is available in scope, inject tagged payloads into support-contact and log-viewing fields. " +
			"Client-side extras: postMessage handlers missing origin validation, client-side prototype pollution (__proto__[a]=b in URL params reaching merge/clone sinks), CORS misconfigurations reflecting Origin with credentials, CSP weaknesses (unsafe-inline/unsafe-eval, wildcard domains, missing frame-ancestors), and library versions with known prototype-pollution or XSS CVEs. " +
			"Prove execution with alert-markers only (no cookie theft), and record the exact injection context and sink.",
		Remark: "Proof-of-concept limited to visible alert markers; no exfiltration payloads.",
	},
	{
		Name: "Access Control & Authorization Testing (IDOR/BOLA)",
		Description: "Systematic broken-access-control hunt per OWASP Top 10 A01: horizontal privilege escalation (IDOR/BOLA), " +
			"vertical escalation (forced browsing, role tampering), and multi-tenant isolation. Two-account differential testing.",
		Goal: "Test access control of the target with differential, two-account methodology. " +
			"Horizontal (IDOR/BOLA): as low-priv user A, enumerate object references of user B's resources (IDs, UUIDs, incremental sequence, email/username in place of IDs) across every endpoint that reads or mutates objects - REST resources, file downloads (/download?id=, /files/{uuid}), export features, message/notification endpoints; attempt both GET (read) and PUT/PATCH/DELETE (write) where authorized. " +
			"Vertical: as low-priv user, request high-priv endpoints and pages directly (/admin, /users/delete, role-gated API routes), attempt role escalation via mass-assignment on profile update (role, is_admin, permissions arrays), test whether JWT/cookie role claims are client-trusted, and probe for hidden functionality via JS-bundle route extraction. " +
			"Multi-tenant isolation: where the platform hosts multiple organizations, attempt cross-tenant reads with swapped tenant IDs in path, header (X-Tenant-ID), and subdomain positions. " +
			"Infrastructure: verify security of direct object references in cloud storage (signed-URL reuse, predictable object keys). " +
			"Deliverable: table of endpoint / method / parameter / impact / evidence for each confirmed authorization gap; include a control-level fix (server-side deny-by-default object ownership checks).",
		Remark: "Requires two test accounts (user A + user B). Highest-value class: prioritize depth here.",
	},
	{
		Name: "Server Misconfiguration & Infrastructure Hardening Review",
		Description: "Configuration review of the serving stack: TLS, headers, HTTP methods, default files, debug endpoints, " +
			"container/cloud metadata exposure, and dependency versions with known CVEs (CIS benchmark-aligned).",
		Goal: "Review server and infrastructure configuration of the authorized target. " +
			"TLS: protocol versions (reject TLS 1.0/1.1), cipher strength, certificate validity/expiry/SAN coverage, HSTS presence and max-age. " +
			"Headers: CSP, X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy, Permissions-Policy, cookie flags; report each gap with the recommended value. " +
			"HTTP surface: dangerous methods enabled (TRACE, TRACK, DELETE/PUT on static servers), OPTIONS disclosure, default virtual-host responses, request smuggling signals (CL.TE differential only - report, do not escalate). " +
			"Default artifacts: /.git, /.svn, /.env, /.DS_Store, /server-status, /actuator (Spring: env/heapdump), /debug, /phpinfo.php, /elmah.axd, /metrics, /swagger, /graphql, admin panels at default paths, sample apps. " +
			"Cloud/container: metadata service reachability via SSRF (169.254.169.254 / 169.254.170.2), exposed Docker socket paths, Kubernetes API unauthenticated probes on authorized hosts only. " +
			"Components: fingerprint server/framework/library versions and map against known CVEs; report exploitable ones with evidence, others as hardening items. " +
			"Deliverable: prioritized hardening checklist mapped to CIS benchmark sections.",
		Remark: "Non-intrusive: no smuggling exploitation, no service disruption.",
	},
	{
		Name: "Known Vulnerability (CVE) Sweep & Prioritized Patch Report",
		Description: "Component-driven assessment: fingerprint all technologies and versions, match against known CVEs and " +
			"CISA KEV, verify exploitability where safe, and produce a patch-priority report with CVSS and KEV context.",
		Goal: "Inventory the authorized target's technology stack and map it against known vulnerabilities. " +
			"Fingerprint versions: HTTP response headers (Server, X-Powered-By), generator meta tags, framework-specific artifact paths and hashes (favicon hash, JS bundle paths), robots/footer strings, exposed package manifests (package-lock.json, composer.lock, requirements.txt if listed), and admin-panel version disclosures. " +
			"For each identified component/version, cross-reference known CVEs with exploitability signals: CWE class, CVSS base score, whether the product appears in CISA KEV, and public-exploit availability. " +
			"Where a PoC is safe and clearly authorized (e.g., a version-only check endpoint, an unauthenticated info-disclosure bug), verify the finding is real rather than version-mismatch noise; do not run destructive exploits. " +
			"Deliverable: a patch-priority report ordered by (1) KEV-listed + internet-exposed, (2) critical CVSS, (3) likely-exploitable chain potential; each entry with component, version, CVE list, evidence of the version fingerprint, affected-feature impact, and the fixed-version recommendation. " +
			"Include an executive summary written for non-technical stakeholders.",
		Remark: "Best for: periodic hygiene runs. Pairs well with the recon template for scope discovery.",
	},
	{
		Name: "GraphQL Security Assessment",
		Description: "GraphQL-specific audit: introspection and schema mapping, authorization on queries/mutations/subscriptions, " +
			"resource-exhaustion (depth, aliases, batching), and injection inside GraphQL arguments.",
		Goal: "Assess the target GraphQL endpoint (probe /graphql, /graphiql, /api/graphql, /v1/graphql, alternate methods GET with ?query=). " +
			"Map the schema: full introspection; if disabled, infer via field-suggestion error mining (Did you mean), __typename probing, and fragments from client JS. " +
			"Authorization: for every query/mutation in the schema, test with a low-priv token whether object-level authorization is enforced (BOLA via ID arguments), whether mutations skip role checks, and whether subscriptions leak other users' events. " +
			"Over-fetching: deep-query nesting (10+ levels), alias-based batching to smuggle many operations per request, duplicated fields to amplify cost - test with modest sizes that a production rate limiter should reject. " +
			"Classic injection inside arguments: GraphQL-specific NoSQL/operator injection ($ne in where), SQLi in string args, IDOR in custom scalars. " +
			"Surface issues: GraphiQL/Playground exposed in production, introspection enabled in production, GET-based queries (CSRF surface), error tracebacks including stack/paths, persisted-query tampering. " +
			"Deliverable: schema map, findings with exact query documents as evidence, and mitigation (field-level authz, depth/complexity limits, introspection off in prod).",
		Remark: "Keep resource-exhaustion probes small: single requests, no sustained load.",
	},
	{
		Name: "Post-Remediation Re-Test & Regression Validation",
		Description: "Verification pass after a previous engagement: confirm each prior finding is fixed, check for regressions " +
			"and fix-introduced issues, and update the risk register. Ideal for continuous monitoring runs.",
		Goal: "Validate remediation of previously reported findings on the authorized target. " +
			"For each finding in scope, re-run the original proof-of-concept: fixed = the attack no longer succeeds and a compensating control is observable (e.g., the endpoint now 403s, the header is present, the input is rejected); not-fixed = original PoC still works; partially-fixed = the specific vector is closed but an adjacent bypass exists (test it). " +
			"Regression sweep: re-run a fast targeted scan of the previously affected areas to ensure the fix did not break neighboring functionality or introduce a new weakness (e.g., a WAF rule that now blocks the scanner but not the attacker, an access-control check that now over-blocks or misses a new parameter). " +
			"New-surface check: enumerate anything deployed since the last test (new endpoints, new parameters, new subdomains) and give it a quick triage pass. " +
			"Deliverable: per-finding status table (fixed / not fixed / partially fixed / new finding) with fresh evidence for every non-fixed item and a delta summary versus the prior report.",
		Remark: "Load the previous findings/IDs into the description before launching.",
	},
}

// seedDefaultTaskTemplates inserts the built-in engagement templates once on
// first startup. CreateTaskTemplate already upserts by the case-insensitive
// name key (ON CONFLICT (nkey) DO NOTHING), so re-running after user edits
// never resurrects a deleted template nor overwrites a renamed one.
func (d *DB) seedDefaultTaskTemplates() error {
	for i, t := range defaultTaskTemplates {
		if _, err := d.CreateTaskTemplate(TaskTemplateInput{
			Name:        t.Name,
			Description: t.Description,
			Goal:        t.Goal,
			Remark:      t.Remark,
		}); err != nil && err != ErrTaskTemplateNameConflict {
			return fmt.Errorf("seed task template %d (%s): %w", i+1, t.Name, err)
		}
	}
	return nil
}
