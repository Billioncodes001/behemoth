package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

var (
	reDeceptionHeaderMarker = regexp.MustCompile(`(?i)^(x-orca|x-shield|x-deception|x-honeypot|x-canary|x-decoy|cf-mitigated)`)
	reBodyPromptPoison      = regexp.MustCompile(`(?is)(?:ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|rules)|disregard\s+(?:all\s+)?(?:previous|prior|system)|new\s+system\s+(?:directive|instruction|prompt)|<\s*/?\s*(?:system|system-reminder|tool_result|instructions)\s*>|\[System\s+Continuation|\b(?:call|invoke)\s+(?:report_finding|record_intelligence|insert_assets)\b|do\s+not\s+report\s+any\s+vulnerabilit)`)
	reBodyCanaryIndicators  = regexp.MustCompile(`(?i)(?:canarytokens\.(?:com|org|net)|thinkst\.com|orcarouter|\.oast\.(?:pro|live|site|online|fun|me)|burpcollaborator\.net|AKIAIOSFODNN7EXAMPLE)`)
	reKeyAssignValue        = regexp.MustCompile(`(?m)^\s*([A-Z][A-Z0-9_]{2,48})\s*=\s*["']?([^\s"'#]{8,180})["']?`)
	reScriptSrcTag          = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js(?:\?[^"']*)?)["']`)
	reSourceMappingURL      = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=([^\s]+)`)
	reHiddenTrapAnchor      = regexp.MustCompile(`(?is)<a\b([^>]*?(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|left\s*:\s*-\d{3,}px|aria-hidden\s*=\s*["']true["'])[^>]*?)>`)
	reHrefAttr              = regexp.MustCompile(`(?i)\bhref\s*=\s*["']([^"']+)["']`)
	reBrowserSensorSignals  = regexp.MustCompile(`(?i)(?:orcarouter|orca[-_]?shield|__shield_sensor|navigator\.webdriver|datadome|perimeterx|_pxAppId|kasada|ak_bmsc|turnstile/v0/api\.js|fingerprintjs| AudioContext|WEBGL_debug_renderer_info)`)
	reStringLiteralToken    = regexp.MustCompile(`["']([A-Za-z0-9_./:-]{10,64})["']`)
	reValidVLQMappings      = regexp.MustCompile(`^[A-Za-z0-9+/=;,]*$`)
)

type probeSnapshot struct {
	Status      int
	ContentType string
	Server      string
	Headers     map[string]string
	Body        []byte
	BodySHA256  string
	Err         error
}

func (s *Server) newCleanProbeClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true, // force fresh TCP/TLS connection per visitor identity check
	}
	if s.m != nil && s.m.HasOutboundProxy() {
		if raw := strings.TrimSpace(s.m.ProxyAddr()); raw != "" {
			if pu, err := url.Parse(raw); err == nil && pu.Host != "" {
				tr.Proxy = http.ProxyURL(pu)
			}
		}
	}
	return &http.Client{
		Timeout:   12 * time.Second,
		Transport: tr,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // inspect exact edge status without following decoy redirects
		},
	}
}

func fetchWithProfile(ctx context.Context, client *http.Client, targetURL, ua, acceptLang string) probeSnapshot {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return probeSnapshot{Err: err}
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", acceptLang)
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := client.Do(req)
	if err != nil {
		return probeSnapshot{Err: err}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	sum := sha256.Sum256(body)
	hdrs := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		hdrs[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	return probeSnapshot{
		Status:      resp.StatusCode,
		ContentType: strings.ToLower(resp.Header.Get("Content-Type")),
		Server:      resp.Header.Get("Server"),
		Headers:     hdrs,
		Body:        body,
		BodySHA256:  hex.EncodeToString(sum[:]),
	}
}

func randomControlPath() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "/artex-404-check-" + hex.EncodeToString(b) + ".txt"
}

func extractEnvMap(body []byte) map[string]string {
	out := map[string]string{}
	for _, m := range reKeyAssignValue.FindAllSubmatch(body, 60) {
		out[string(m[1])] = string(m[2])
	}
	return out
}

func (s *Server) toolDetectDeceptionAndHoneypot() actool.CoreTool {
	return roTool("detect_deception_and_honeypot",
		"Forensically analyze a target website, exposed config (/.env, /.git/config), or JavaScript source map (.js.map) to detect AI-targeted deception layers, synthetic honeypot mazes (such as OrcaRouter Shield, Cloudflare Decoy, Thinkst Canarytokens), per-visitor HMAC-bound canary credentials, honey source maps, client-side browser sensors, and indirect prompt-injection / memory-poisoning payloads. ALWAYS run this BEFORE trusting, replaying, or reporting exposed /.env, /.git, .map files, or credentials.",
		objSchema(map[string]any{
			"target_url":      strParam("Base URL or full suspect URL on the target (e.g. https://target.example.com or https://target.example.com/.env)"),
			"suspect_path":    strParam("Optional specific path to verify for synthetic/canary deception (e.g. '/.env', '/.git/config', '/static/main.js.map')"),
			"real_bundle_url": strParam("Optional live JavaScript bundle URL served to normal browsers to cross-check against a suspect .js.map"),
		}, "target_url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TargetURL     string `json:"target_url"`
				SuspectPath   string `json:"suspect_path"`
				RealBundleURL string `json:"real_bundle_url"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input JSON: " + err.Error()), nil
			}
			rawTarget := strings.TrimSpace(a.TargetURL)
			if rawTarget == "" {
				return actool.Errorf("target_url is required"), nil
			}
			if !strings.HasPrefix(strings.ToLower(rawTarget), "http://") && !strings.HasPrefix(strings.ToLower(rawTarget), "https://") {
				rawTarget = "https://" + rawTarget
			}
			u, err := url.Parse(rawTarget)
			if err != nil || u.Host == "" {
				return actool.Errorf("invalid target_url"), nil
			}
			origin := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
			suspectPath := strings.TrimSpace(a.SuspectPath)
			if suspectPath == "" && u.Path != "" && u.Path != "/" {
				suspectPath = u.RequestURI()
			}
			if suspectPath != "" && !strings.HasPrefix(suspectPath, "/") && !strings.HasPrefix(suspectPath, "http") {
				suspectPath = "/" + suspectPath
			}

			uaProfileA := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
			uaProfileB := "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"

			clientA := s.newCleanProbeClient()
			clientB := s.newCleanProbeClient()

			var (
				score          int
				detectedLayers []string
				evidence       []string
				sensorDetails  []string
			)
			addLayer := func(layer string, pts int, proof string) {
				score += pts
				for _, ex := range detectedLayers {
					if ex == layer {
						evidence = append(evidence, proof)
						return
					}
				}
				detectedLayers = append(detectedLayers, layer)
				evidence = append(evidence, proof)
			}

			// ── 1. Human Baseline ("Humans get your real site, byte-for-byte") & 404 Control ──
			homeA := fetchWithProfile(ctx, clientA, origin+"/", uaProfileA, "en-US,en;q=0.9")
			homeB := fetchWithProfile(ctx, clientB, origin+"/", uaProfileB, "en-GB,en;q=0.8")
			if homeA.Err != nil {
				return actool.Errorf("failed to reach target origin " + origin + ": " + homeA.Err.Error()), nil
			}
			ctrlSnap := fetchWithProfile(ctx, clientA, origin+randomControlPath(), uaProfileA, "en-US,en;q=0.9")
			humanPinnedIdentical := homeA.Status == homeB.Status && homeA.BodySHA256 == homeB.BodySHA256

			// Scan headers on homepage for explicit deception/edge shield markers or per-source Retry-After buckets
			for k, v := range homeA.Headers {
				if reDeceptionHeaderMarker.MatchString(k) {
					addLayer("edge_deception_header", 35, fmt.Sprintf("Response header %q: %q indicates an active edge deception/mitigation proxy.", k, v))
				}
			}

			// ── 2. Client-Side Browser Sensor [DETECT] & Hidden DOM Honeypot Link Audit ──
			homeHTML := string(homeA.Body)
			for _, m := range reHiddenTrapAnchor.FindAllStringSubmatch(homeHTML, 10) {
				if hm := reHrefAttr.FindStringSubmatch(m[1]); len(hm) == 2 {
					href := hm[1]
					if href != "#" && href != "/" && !strings.HasPrefix(href, "javascript:") {
						addLayer("hidden_dom_honeypot_trap", 30, fmt.Sprintf("Hidden CSS/ARIA anchor trap found in homepage DOM pointing to %q — crawling this path flags the visitor IP as an automated bot/agent!", href))
					}
				}
			}
			sensorMatches := reBrowserSensorSignals.FindAllString(homeHTML, 10)
			if len(sensorMatches) > 0 {
				seenS := map[string]bool{}
				for _, sm := range sensorMatches {
					low := strings.ToLower(strings.TrimSpace(sm))
					if !seenS[low] {
						seenS[low] = true
						sensorDetails = append(sensorDetails, sm)
					}
				}
				if strings.Contains(strings.ToLower(strings.Join(sensorDetails, " ")), "orca") || strings.Contains(strings.ToLower(strings.Join(sensorDetails, " ")), "shield") {
					addLayer("browser_sensor_detect", 40, fmt.Sprintf("Explicit OrcaRouter/Shield browser telemetry sensor detected in page HTML (%s).", strings.Join(sensorDetails, ", ")))
				}
			}

			// ── 3. Per-Visitor Seeded Decoy & HMAC-Bound Canary Differential Check ──
			pathsToInspect := []string{}
			if suspectPath != "" {
				pathsToInspect = append(pathsToInspect, suspectPath)
			} else {
				pathsToInspect = append(pathsToInspect, "/.env", "/.git/config")
			}

			for _, p := range pathsToInspect {
				fullURL := p
				if !strings.HasPrefix(p, "http://") && !strings.HasPrefix(p, "https://") {
					fullURL = origin + p
				}
				snapA := fetchWithProfile(ctx, clientA, fullURL, uaProfileA, "en-US,en;q=0.9")
				if snapA.Err != nil || snapA.Status != http.StatusOK || len(snapA.Body) == 0 {
					continue
				}
				// Ignore soft-404 SPA shell fallbacks identical to homepage
				if snapA.BodySHA256 == homeA.BodySHA256 || (ctrlSnap.Status == http.StatusOK && snapA.BodySHA256 == ctrlSnap.BodySHA256) {
					evidence = append(evidence, fmt.Sprintf("Path %s returned HTTP 200 soft-404 SPA fallback identical to control/homepage (not a real exposed file).", p))
					continue
				}

				snapB := fetchWithProfile(ctx, clientB, fullURL, uaProfileB, "en-GB,en;q=0.8")
				for k, v := range snapA.Headers {
					if reDeceptionHeaderMarker.MatchString(k) {
						addLayer("decoy_routing_poison", 45, fmt.Sprintf("Suspect path %s carries deception header %s=%q.", p, k, v))
					}
				}
				if homeA.Server != "" && snapA.Server != "" && !strings.EqualFold(homeA.Server, snapA.Server) {
					addLayer("decoy_routing_poison", 25, fmt.Sprintf("Server header mismatch: human homepage served by %q while %s served by %q (edge decoy routing signature).", homeA.Server, p, snapA.Server))
				}

				// Compare Session A vs Session B on the exact same static config file!
				if snapB.Err == nil && snapB.Status == http.StatusOK && snapA.BodySHA256 != snapB.BodySHA256 {
					envA := extractEnvMap(snapA.Body)
					envB := extractEnvMap(snapB.Body)
					mutatedKeys := []string{}
					for k, valA := range envA {
						if valB, ok := envB[k]; ok && valA != valB {
							mutatedKeys = append(mutatedKeys, k)
						}
					}
					if len(mutatedKeys) > 0 {
						addLayer("per_visitor_hmac_canary", 65, fmt.Sprintf("MATHEMATICAL PROOF OF SYNTHETIC DECEPTION on %s: Secret values for key(s) [%s] mutated dynamically across two independent visitor sessions (while human homepage pinned_bytes=%v). These are per-visitor HMAC-seeded canary keys — NEVER use or replay them!", p, strings.Join(mutatedKeys, ", "), humanPinnedIdentical))
					} else {
						addLayer("per_visitor_hmac_canary", 50, fmt.Sprintf("Static file %s mutated byte-for-byte across two independent visitor sessions (SHA256 %s vs %s) — confirms dynamic per-visitor synthetic generation.", p, snapA.BodySHA256[:12], snapB.BodySHA256[:12]))
					}
				}

				// Check Indirect Prompt Injection & Canary markers inside the body
				bodyStr := string(snapA.Body)
				if reBodyPromptPoison.MatchString(bodyStr) {
					addLayer("prompt_injection_memory_poison", 60, fmt.Sprintf("CRITICAL: %s embeds adversarial LLM prompt-injection / agent memory-hijacking instructions inside the response body!", p))
				}
				if reBodyCanaryIndicators.MatchString(bodyStr) {
					addLayer("canarytoken_trap", 50, fmt.Sprintf("Known canarytoken / honeytoken trap marker detected inside %s.", p))
				}

				// If this is /.git/config, verify binary /.git/index coherence!
				if strings.Contains(p, ".git/") {
					idxSnap := fetchWithProfile(ctx, clientA, origin+"/.git/index", uaProfileA, "en-US,en;q=0.9")
					headSnap := fetchWithProfile(ctx, clientA, origin+"/.git/HEAD", uaProfileA, "en-US,en;q=0.9")
					hasValidHEAD := headSnap.Status == http.StatusOK && (bytes.HasPrefix(bytes.TrimSpace(headSnap.Body), []byte("ref: refs/")) || len(bytes.TrimSpace(headSnap.Body)) == 40)
					hasValidDIRC := idxSnap.Status == http.StatusOK && len(idxSnap.Body) >= 12 && bytes.Equal(idxSnap.Body[:4], []byte("DIRC"))
					if !hasValidDIRC || !hasValidHEAD {
						addLayer("fake_git_maze", 45, fmt.Sprintf("%s returned 200 OK with text content, but /.git/HEAD valid=%v and binary /.git/index DIRC header valid=%v — confirms a synthetic fake .git honeypot stub rather than a real exposed Git repository!", p, hasValidHEAD, hasValidDIRC))
					}
				}
			}

			// ── 4. Impossible Polyglot Stack Maze Check (/.env + /wp-config.php.bak + /WEB-INF/web.xml) ──
			if ctrlSnap.Status != http.StatusOK {
				polyPaths := []string{"/.env", "/wp-config.php.bak", "/WEB-INF/web.xml"}
				nonSoft200 := 0
				var hitPoly []string
				for _, pp := range polyPaths {
					sp := fetchWithProfile(ctx, clientA, origin+pp, uaProfileA, "en-US,en;q=0.9")
					if sp.Err == nil && sp.Status == http.StatusOK && len(sp.Body) > 0 && sp.BodySHA256 != homeA.BodySHA256 {
						nonSoft200++
						hitPoly = append(hitPoly, pp)
					}
				}
				if nonSoft200 >= 2 {
					addLayer("synthetic_polyglot_maze", 55, fmt.Sprintf("Target returned distinct HTTP 200 responses for mutually incompatible framework files (%s) while random 404 control returned HTTP %d — confirms an edge Synthetic Decoy Maze!", strings.Join(hitPoly, ", "), ctrlSnap.Status))
				}
			}

			// ── 5. Honey Source Map [MISDIRECT] vs. Pinned JS Bundle Cross-Validator ──
			bundleURL := strings.TrimSpace(a.RealBundleURL)
			mapURL := ""
			if strings.HasSuffix(strings.ToLower(suspectPath), ".map") {
				if strings.HasPrefix(suspectPath, "http") {
					mapURL = suspectPath
				} else {
					mapURL = origin + suspectPath
				}
			}
			if bundleURL == "" {
				if m := reScriptSrcTag.FindStringSubmatch(homeHTML); len(m) == 2 {
					src := m[1]
					if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
						bundleURL = src
					} else if strings.HasPrefix(src, "/") {
						bundleURL = origin + src
					} else {
						bundleURL = origin + "/" + src
					}
				}
			}
			if bundleURL != "" {
				jsSnap := fetchWithProfile(ctx, clientA, bundleURL, uaProfileA, "en-US,en;q=0.9")
				if jsSnap.Err == nil && jsSnap.Status == http.StatusOK && len(jsSnap.Body) > 0 {
					if mapURL == "" {
						if sm := reSourceMappingURL.FindSubmatch(jsSnap.Body); len(sm) == 2 {
							ref := strings.TrimSpace(string(sm[1]))
							if !strings.HasPrefix(ref, "data:") {
								if bu, berr := url.Parse(bundleURL); berr == nil {
									if resolved, rerr := bu.Parse(ref); rerr == nil {
										mapURL = resolved.String()
									}
								}
							}
						} else {
							mapURL = bundleURL + ".map"
						}
					}
					if mapURL != "" {
						mapSnapA := fetchWithProfile(ctx, clientA, mapURL, uaProfileA, "en-US,en;q=0.9")
						if mapSnapA.Err == nil && mapSnapA.Status == http.StatusOK && len(mapSnapA.Body) > 0 && mapSnapA.BodySHA256 != homeA.BodySHA256 {
							var smObj struct {
								Version        int      `json:"version"`
								Sources        []string `json:"sources"`
								Mappings       string   `json:"mappings"`
								SourcesContent []string `json:"sourcesContent"`
							}
							if jerr := json.Unmarshal(mapSnapA.Body, &smObj); jerr != nil || smObj.Version != 3 {
								addLayer("honey_source_map", 40, fmt.Sprintf("Source map %s returned 200 OK but failed SourceMap v3 JSON validation.", mapURL))
							} else {
								if !reValidVLQMappings.MatchString(smObj.Mappings) {
									addLayer("honey_source_map", 45, fmt.Sprintf("Source map %s contains invalid non-VLQ characters in 'mappings'!", mapURL))
								}
								// Cross-validate string literals in sourcesContent against the pinned JS bundle served to humans!
								joinedSrc := strings.Join(smObj.SourcesContent, "\n")
								if reBodyPromptPoison.MatchString(joinedSrc) {
									addLayer("prompt_injection_memory_poison", 60, fmt.Sprintf("Source map %s embeds prompt-injection instructions inside sourcesContent!", mapURL))
								}
								literals := reStringLiteralToken.FindAllStringSubmatch(joinedSrc, 40)
								checked, matchedLit := 0, 0
								seenLit := map[string]bool{}
								jsStr := string(jsSnap.Body)
								for _, lm := range literals {
									tok := lm[1]
									if seenLit[tok] || strings.HasPrefix(tok, "./") || strings.HasPrefix(tok, "../") {
										continue
									}
									seenLit[tok] = true
									checked++
									if strings.Contains(jsStr, tok) {
										matchedLit++
									}
								}
								if checked >= 6 && float64(matchedLit)/float64(checked) < 0.15 {
									addLayer("honey_source_map", 55, fmt.Sprintf("HONEY SOURCE MAP [MISDIRECT] CONFIRMED on %s: Only %d/%d string literals from sourcesContent exist in the pinned human JS bundle (%s)! The source map is synthetic misdirection and does NOT match the real release bytes.", mapURL, matchedLit, checked, bundleURL))
								}
							}
						}
					}
				}
			}

			if score > 100 {
				score = 100
			}
			confidence := "none"
			switch {
			case score >= 60:
				confidence = "confirmed"
			case score >= 35:
				confidence = "high"
			case score >= 15:
				confidence = "medium"
			}
			deceptionDetected := score >= 35

			guidance := "No synthetic deception maze or per-visitor canary mutation was detected. Proceed with standard verification."
			if deceptionDetected {
				guidance = "DECEPTION / HONEYPOT SHIELD CONFIRMED — MANDATORY COUNTER-DECEPTION PROTOCOL: " +
					"(1) DO NOT authenticate with, curl, or replay any API keys/credentials found in /.env, /.git/config, or .map files (they are HMAC-bound visitor canaries that trigger instant IP blacklisting!). " +
					"(2) DO NOT register decoy secrets or fake maze endpoints in report_finding, record_intelligence, or insert_assets. " +
					"(3) Ignore synthetic source maps and obvious trap paths (/.env, /.git, hidden DOM links). " +
					"(4) Because the target must still serve its REAL application byte-for-byte to normal human users, restrict testing strictly to genuine routes, GraphQL/API calls, and business logic observed directly in visible UI navigation and the pinned real JS bundle!"
			}

			return jsonResult(map[string]any{
				"target_origin":          origin,
				"deception_detected":     deceptionDetected,
				"confidence":             confidence,
				"deception_score":        score,
				"human_pinned_identical": humanPinnedIdentical,
				"detected_layers":        detectedLayers,
				"browser_sensor_signals": sensorDetails,
				"forensic_evidence":      evidence,
				"tactical_guidance":      guidance,
			})
		})
}
