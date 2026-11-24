package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	proxyv2 "github.com/Autumn-27/artex/server/proxy/v2"
	actool "github.com/Autumn-27/norma/tool"
)

func (s *Server) proxyPoolAgentTools() []actool.CoreTool {
	return append([]actool.CoreTool{
		s.toolCheckProxyStatus(),
		s.toolImportAndTestProxies(),
		s.toolGetProxyPoolStatus(),
		s.toolManageProxyPool(),
	}, s.proxyScraperAgentTools()...)
}

func (s *Server) syncProxyPoolNow() {
	if ppV2 == nil || ppV2.Pool == nil {
		return
	}
	raw, activeID, cfg := ppV2.Pool.GetRawState()
	s.syncProxyPoolV2ToV1(raw, activeID, cfg)
}

func (s *Server) toolImportAndTestProxies() actool.CoreTool {
	return wrTool("import_and_test_proxies",
		"Import one or more proxies (from pasted text in any format such as ip:port:user:pass, user:pass@ip:port, http/socks5 URLs, CSV, or JSON — or from an uploaded proxy file) into the ARTEX Proxy Pool page, automatically health-test all proxies in parallel, enable the Proxy Pool, and activate a verified healthy egress proxy before running scans.",
		objSchema(map[string]any{
			"proxies":           strParam("Raw proxy list pasted by the user (supports host:port:user:pass, user:pass@host:port, scheme://user:pass@host:port, host:port, CSV, or JSON)"),
			"file_path":         strParam("Optional path to an uploaded proxy file (.txt, .csv, .json) in the session workspace"),
			"default_type":      strParam("Default protocol for scheme-less entries: http (default) | https | socks5 | socks4"),
			"replace_existing":  map[string]any{"type": "boolean", "description": "If true, clear existing pool entries before importing (default false)"},
			"auto_test":         map[string]any{"type": "boolean", "description": "Automatically test all proxies for live connectivity, latency, and GeoIP before returning (default true)"},
			"remove_failed":     map[string]any{"type": "boolean", "description": "If true, automatically remove dead/unreachable proxies after auto-testing (default false)"},
			"rotation_strategy": strParam("Optional rotation strategy: round_robin | random | least_used"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if ppV2 == nil || ppV2.Pool == nil {
				return actool.Errorf("Proxy Pool v2 is not initialized"), nil
			}
			var a struct {
				Proxies          string `json:"proxies"`
				FilePath         string `json:"file_path"`
				DefaultType      string `json:"default_type"`
				ReplaceExisting  bool   `json:"replace_existing"`
				AutoTest         *bool  `json:"auto_test"`
				RemoveFailed     bool   `json:"remove_failed"`
				RotationStrategy string `json:"rotation_strategy"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
			}

			var chunks []string
			if strings.TrimSpace(a.Proxies) != "" {
				chunks = append(chunks, a.Proxies)
			}
			if fp := strings.TrimSpace(a.FilePath); fp != "" {
				b, err := os.ReadFile(fp)
				if err != nil {
					return actool.Errorf(fmt.Sprintf("failed to read file_path %q: %v", fp, err)), nil
				}
				chunks = append(chunks, string(b))
			}
			combined := strings.TrimSpace(strings.Join(chunks, "\n"))
			if combined == "" {
				return actool.Errorf("provide either 'proxies' text or 'file_path' pointing to a proxy file"), nil
			}

			defType := proxyv2.ProxyType(strings.ToLower(strings.TrimSpace(a.DefaultType)))
			if defType == "" {
				defType = proxyv2.ProxyTypeHTTP
			}

			if a.ReplaceExisting {
				_, _ = ppV2.Pool.ClearAllProxies()
			}

			impRes, err := ppV2.Pool.ImportProxies(combined, defType)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("proxy import failed: %v", err)), nil
			}

			autoTest := true
			if a.AutoTest != nil {
				autoTest = *a.AutoTest
			}

			var tested, healthyCount, failedCount, removedDead int
			if autoTest && ppV2.Pool.GetStats().Total > 0 {
				testCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
				results, _ := ppV2.Pool.TestAllProxies(testCtx)
				cancel()
				tested = len(results)
				for _, tr := range results {
					if tr.Success {
						healthyCount++
					} else {
						failedCount++
					}
				}
				if a.RemoveFailed && failedCount > 0 {
					removedDead, _ = ppV2.Pool.ClearFailedProxies()
				}
			}

			cfg := ppV2.Pool.GetConfig()
			cfg.Enabled = true
			if rs := strings.ToLower(strings.TrimSpace(a.RotationStrategy)); rs == "round_robin" || rs == "random" || rs == "least_used" {
				cfg.RotationMode = proxyv2.RotationStrategy(rs)
				cfg.RotationStrategyAlias = cfg.RotationMode
			}
			_ = ppV2.Pool.UpdateConfig(cfg)

			// Synchronously push updated v2 state into the core v1/forward-proxy engine so
			// the very next Bash / WebFetch / scanner / browser tool call routes through it!
			s.syncProxyPoolNow()

			stats := ppV2.Pool.GetStats()
			proxies := ppV2.Pool.GetProxies()
			var activeProxy *proxyv2.ProxyInfo
			for i := range proxies {
				if proxies[i].ID == stats.ActiveProxyID {
					cp := proxies[i]
					activeProxy = &cp
					break
				}
			}

			return jsonResult(map[string]any{
				"imported":          impRes.Imported,
				"skipped_duplicate": impRes.Skipped,
				"parse_errors":      impRes.Errors,
				"auto_tested":       autoTest,
				"tested":            tested,
				"healthy":           healthyCount,
				"failed":            failedCount,
				"removed_failed":    removedDead,
				"pool_enabled":      cfg.Enabled,
				"rotation_strategy": cfg.RotationMode,
				"active_proxy_id":   stats.ActiveProxyID,
				"active_proxy":      activeProxy,
				"total_in_pool":     stats.Total,
				"proxies":           proxies,
			})
		})
}

func (s *Server) buildProxyStatusPayload() (map[string]any, error) {
	var (
		cfg         *proxyv2.ProxyPoolConfig
		stats       *proxyv2.PoolStats
		proxies     []proxyv2.ProxyInfo
		activeProxy *proxyv2.ProxyInfo
	)
	if ppV2 != nil && ppV2.Pool != nil {
		cfg = ppV2.Pool.GetConfig()
		stats = ppV2.Pool.GetStats()
		proxies = ppV2.Pool.GetProxies()
		if stats != nil {
			for i := range proxies {
				if proxies[i].ID == stats.ActiveProxyID {
					cp := proxies[i]
					activeProxy = &cp
					break
				}
			}
		}
	}
	globalRaw := ""
	override := ""
	trafficCapture := false
	if s.m != nil {
		override = strings.TrimSpace(s.m.CaptureEgressOverride())
		globalRaw = strings.TrimSpace(s.m.GlobalProxy())
		if override != "" {
			globalRaw = ""
		}
		trafficCapture = s.m.TrafficEnabled()
	}
	poolEnabled := cfg != nil && cfg.Enabled
	exclusiveTor := s.isExclusiveTorActive()
	torSnap := s.torStatusSnapshot()
	torHealthyCount, _ := torSnap["circuits_healthy"].(int)
	totalInPool := 0
	activeProxyID := ""
	if stats != nil {
		totalInPool = stats.Total
		activeProxyID = stats.ActiveProxyID
	}
	poolActive := poolEnabled && totalInPool > 0 && activeProxy != nil
	poolExhausted := poolEnabled && !poolActive
	globalActive := override == "" && !exclusiveTor && !poolEnabled && globalRaw != ""
	routingMode := "direct"
	if override != "" {
		routingMode = "tunnel_override"
	} else if exclusiveTor {
		// Failed circuits are pruned from the rotation, so a non-empty live list
		// (or a healthy snapshot entry) is the only "routing works" signal; an empty
		// list means fail-closed exhaustion, not a healthy Tor tunnel.
		if torHealthyCount > 0 || (s.m != nil && s.m.ExclusiveTorCircuitCount() > 0) {
			routingMode = "exclusive_tor"
		} else {
			routingMode = "exclusive_tor_exhausted_fail_closed"
		}
	} else if poolActive {
		if hyb, _ := torSnap["hybrid_pool_active"].(bool); hyb {
			routingMode = "hybrid_tor_pool"
		} else {
			routingMode = "proxy_pool"
		}
	} else if poolExhausted {
		routingMode = "proxy_pool_exhausted_fail_closed"
	} else if globalActive {
		routingMode = "static_global_proxy"
	}
	anyOutbound := routingMode != "direct"
	localForwarder := ""
	if s.m != nil {
		localForwarder = s.m.OutboundProxyAddr()
	}
	instruction := "NO outbound proxy is enabled (Tor is OFF, Proxy Pool is OFF, and Global Proxy is NOT configured). Connect directly to targets — do NOT pass -x or --proxy flags to curl/scanners, and never treat 127.0.0.1:8788 (local HTTP packet capture) as an external proxy."
	switch routingMode {
	case "tunnel_override":
		instruction = "C2 TUNNEL EGRESS OVERRIDE ACTIVE: all server-side egress (capture layer, Bash HTTP_PROXY/HTTPS_PROXY/ALL_PROXY, MCP servers, scanner tools) currently exits through an operator C2 pivot tunnel, even if a Proxy Pool or Tor is also enabled. Targets reachable only from the implant are now reachable; every byte is slow and capped, so avoid bulk fuzzing. Close with c2_proxy_close to restore the Pool/Tor/direct route."
	case "exclusive_tor":
		instruction = "EXCLUSIVE TOR NETWORK ACTIVE (Proxy Pool is auto-disabled): 100% of external target requests automatically route over isolated Tor SOCKS5 exit circuits ($0 bandwidth). Running agents pick up switches live per command without restarting. If a target WAF/Cloudflare challenges a Tor exit IP (403/429/Captcha), call manage_proxy_pool(action='tor_newnym') to rotate exit IPs or manage_proxy_pool(action='enable_tor', tor_mode='hybrid') to allow fallback to pool proxies."
	case "exclusive_tor_exhausted_fail_closed":
		instruction = "STOP WORK IMMEDIATELY — FAIL-CLOSED TOR GUARD ACTIVE: Exclusive Tor is ENABLED, and 0 Tor circuits are currently reachable/bootstrapped! Direct target connections are strictly blocked to protect the server IP. Call manage_proxy_pool(action='tor_newnym') once or stop and inform the operator."
	case "hybrid_tor_pool":
		instruction = "HYBRID TOR + PROXY POOL MODE ACTIVE: Both free Tor SOCKS5 circuits (tor-circuit-*) and non-Tor pool proxies are enabled together! Running agents automatically pick up pool changes on every request without restarting. Use free Tor circuits for bulk scanning/fuzzing ($0 bandwidth); if a target WAF/Cloudflare challenges Tor exit IPs (403/429/Captcha), call manage_proxy_pool(action='activate', proxy_id='<non-tor-proxy-id>') or manage_proxy_pool(action='tor_newnym')."
	case "proxy_pool":
		instruction = "Proxy Pool is ENABLED. ZERO-IP-LEAK RULE: WebFetch, MCP servers (browser, vuln_intel, recon_osint, web_sec_analyzer), run_security_tool, browser_inspect, detect_deception_and_honeypot, and Bash HTTP_PROXY/HTTPS_PROXY/ALL_PROXY automatically route through the active proxy (picking up Tor/pool switches live mid-run). In Bash, NEVER run raw unproxied socket/SYN/UDP commands that bypass HTTP_PROXY. If a proxy slows down or gets 403/429'd, call manage_proxy_pool(action='rotate' or 'disable_proxy') or scrape_online_proxies."
	case "proxy_pool_exhausted_fail_closed":
		instruction = "STOP WORK IMMEDIATELY — FAIL-CLOSED PROXY GUARD ACTIVE: Proxy Pool is ENABLED, and ALL configured proxies are currently unhealthy or out of bandwidth! ARTEX has strictly blocked all direct target connections to protect the server IP. Do NOT attempt any target scans or bypasses. Immediately stop and inform the user that all proxies in the Proxy Pool are down/exhausted, and let them know they can click 'Enable Free Tor Network' in System -> Proxy Pool (or ask you to call manage_proxy_pool(action='enable_tor')) or import working proxies."
	case "static_global_proxy":
		instruction = "Static Global Proxy is ENABLED in System Settings. ZERO-IP-LEAK RULE: All built-in tools, MCP servers, and Bash HTTP_PROXY/HTTPS_PROXY/ALL_PROXY route through the Global Proxy. For CLI tools in Bash that ignore env vars (sqlmap, gobuster, nmap, openssl s_client), pass \"$HTTP_PROXY\" explicitly via their proxy flag so the server's real IP is never exposed."
	}
	return map[string]any{
		"proxy_enabled":           anyOutbound,
		"any_proxy_enabled":       anyOutbound,
		"effective_routing_mode":  routingMode,
		"local_proxy_env_url":     localForwarder,
		"capture_egress_override": override,
		"exclusive_tor_active":    exclusiveTor,
		"proxy_pool_enabled":      poolEnabled,
		"proxy_pool_active":       poolActive,
		"proxy_pool_exhausted":    poolExhausted || routingMode == "exclusive_tor_exhausted_fail_closed",
		"fail_closed":             poolEnabled || exclusiveTor,
		"global_proxy_enabled":    globalActive,
		"static_global_proxy": maskSecrets(func() string {
			if s.m != nil {
				return s.m.StaticGlobalProxy()
			}
			return ""
		}()),
		"local_traffic_capture_only": trafficCapture && !anyOutbound,
		"traffic_capture":            trafficCapture,
		"active_proxy_id":            activeProxyID,
		"active_proxy":               activeProxy,
		"tor":                        torSnap,
		"instruction":                instruction,
		"config":                     cfg,
		"stats":                      stats,
		"proxies":                    proxies,
	}, nil
}

func (s *Server) toolCheckProxyStatus() actool.CoreTool {
	return roTool("check_proxy_status",
		"Always call this tool BEFORE attempting to use any proxy. Checks whether the user enabled Proxy Pool or configured a Global Proxy in Settings. If proxy_enabled is false, NO proxy is enabled and you must connect directly without -x / --proxy flags.",
		objSchema(map[string]any{}),
		func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			payload, err := s.buildProxyStatusPayload()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(payload)
		})
}

func (s *Server) toolGetProxyPoolStatus() actool.CoreTool {
	return roTool("get_proxy_pool_status",
		"Check whether outbound proxies are enabled anywhere in ARTEX (Proxy Pool or static Global Proxy), inspect active egress proxy IP/location/latency, pool health counts, rotation/sticky settings, and all configured proxies.",
		objSchema(map[string]any{}),
		func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			if ppV2 == nil || ppV2.Pool == nil {
				return actool.Errorf("Proxy Pool v2 is not initialized"), nil
			}
			payload, err := s.buildProxyStatusPayload()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(payload)
		})
}

func (s *Server) toolManageProxyPool() actool.CoreTool {
	return wrTool("manage_proxy_pool",
		"Control and reconfigure ARTEX proxy routing mid-operation: rotate (switch away from a slow/rate-limited/failing proxy immediately), enable_tor (start built-in free unlimited-bandwidth Tor SOCKS5 circuits in Proxy Pool), tor_newnym (request brand-new Tor exit IPs via SIGNAL NEWNYM), disable_tor, tor_status, test_all, test_one (probe proxy_id), activate (pin proxy_id), disable_proxy (quarantine a failing proxy_id and auto-failover), enable_proxy, clear_failed, clear_all, enable, disable, configure, or delete.",
		objSchema(map[string]any{
			"action":                        strParam("Action: rotate | enable_tor | tor_newnym | disable_tor | tor_status | test_all | test_one | activate | disable_proxy | enable_proxy | clear_failed | clear_all | enable | disable | configure | delete"),
			"proxy_id":                      strParam("Target proxy ID (used by test_one, activate, disable_proxy, enable_proxy, delete)"),
			"tor_circuits":                  map[string]any{"type": "integer", "description": "Optional number of isolated Tor SOCKS5 circuits (1-10, default 5) when action=enable_tor"},
			"tor_mode":                      strParam("Optional Tor coexistence mode when action=enable_tor: exclusive (default: auto-disables Proxy Pool and routes 100% via Tor) | hybrid (enables Proxy Pool and rotates Tor + Pool proxies together)"),
			"rotation_strategy":             strParam("Optional rotation strategy: round_robin | random | least_used"),
			"rotation_interval_seconds":     map[string]any{"type": "integer", "description": "Optional rotation interval in seconds (>= 5)"},
			"auto_rotate_on_failure":        map[string]any{"type": "boolean", "description": "Optional toggle to auto-rotate when a proxy fails"},
			"session_sticky":                map[string]any{"type": "boolean", "description": "Optional toggle to keep one proxy sticky per session until failure"},
			"max_consecutive_failures":      map[string]any{"type": "integer", "description": "Optional failure threshold before marking unhealthy (>= 1)"},
			"cooldown_seconds":              map[string]any{"type": "integer", "description": "Optional cooldown in seconds (>= 10)"},
			"health_check_interval_seconds": map[string]any{"type": "integer", "description": "Optional background health check interval in seconds (>= 10)"},
		}, "action"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if ppV2 == nil || ppV2.Pool == nil {
				return actool.Errorf("Proxy Pool v2 is not initialized"), nil
			}
			var a struct {
				Action                     string `json:"action"`
				ProxyID                    string `json:"proxy_id"`
				TorCircuits                int    `json:"tor_circuits"`
				TorMode                    string `json:"tor_mode"`
				RotationStrategy           string `json:"rotation_strategy"`
				RotationIntervalSeconds    *int   `json:"rotation_interval_seconds"`
				AutoRotateOnFailure        *bool  `json:"auto_rotate_on_failure"`
				SessionSticky              *bool  `json:"session_sticky"`
				MaxConsecutiveFailures     *int   `json:"max_consecutive_failures"`
				CooldownSeconds            *int   `json:"cooldown_seconds"`
				HealthCheckIntervalSeconds *int   `json:"health_check_interval_seconds"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
			}
			act := strings.ToLower(strings.TrimSpace(a.Action))
			var actionOut map[string]any

			applyConfigOverrides := func(cfg *proxyv2.ProxyPoolConfig) {
				if rs := strings.ToLower(strings.TrimSpace(a.RotationStrategy)); rs == "round_robin" || rs == "random" || rs == "least_used" {
					cfg.RotationMode = proxyv2.RotationStrategy(rs)
					cfg.RotationStrategyAlias = cfg.RotationMode
				}
				if a.RotationIntervalSeconds != nil && *a.RotationIntervalSeconds >= 5 {
					cfg.RotationIntervalSeconds = *a.RotationIntervalSeconds
				}
				if a.AutoRotateOnFailure != nil {
					cfg.AutoRotateOnFailure = *a.AutoRotateOnFailure
					cfg.FailoverEnabled = *a.AutoRotateOnFailure
				}
				if a.SessionSticky != nil {
					cfg.SessionSticky = *a.SessionSticky
				}
				if a.MaxConsecutiveFailures != nil && *a.MaxConsecutiveFailures >= 1 {
					cfg.MaxConsecutiveFailures = *a.MaxConsecutiveFailures
				}
				if a.CooldownSeconds != nil && *a.CooldownSeconds >= 10 {
					cfg.CooldownSeconds = *a.CooldownSeconds
				}
				if a.HealthCheckIntervalSeconds != nil && *a.HealthCheckIntervalSeconds >= 10 {
					cfg.HealthCheckIntervalSeconds = *a.HealthCheckIntervalSeconds
				}
			}

			switch act {
			case "test_all":
				testCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
				results, err := ppV2.Pool.TestAllProxies(testCtx)
				cancel()
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				passed, failed := 0, 0
				for _, r := range results {
					if r.Success {
						passed++
					} else {
						failed++
					}
				}
				actionOut = map[string]any{"action": act, "tested": len(results), "healthy": passed, "failed": failed, "results": results}

			case "test_one":
				if strings.TrimSpace(a.ProxyID) == "" {
					return actool.Errorf("proxy_id is required for action=test_one"), nil
				}
				res, err := ppV2.Pool.TestProxy(strings.TrimSpace(a.ProxyID))
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				actionOut = map[string]any{"action": act, "result": res}

			case "rotate":
				px, err := ppV2.Pool.ForceRotate("agent_rotate")
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				actionOut = map[string]any{"action": act, "rotated_to": px.ID, "host": px.Host, "port": px.Port, "response_ip": px.ResponseIP}

			case "activate":
				if strings.TrimSpace(a.ProxyID) == "" {
					return actool.Errorf("proxy_id is required for action=activate"), nil
				}
				if err := ppV2.Pool.ActivateProxy(strings.TrimSpace(a.ProxyID)); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				actionOut = map[string]any{"action": act, "active_proxy_id": strings.TrimSpace(a.ProxyID)}

			case "disable_proxy", "enable_proxy":
				if strings.TrimSpace(a.ProxyID) == "" {
					return actool.Errorf("proxy_id is required for action=" + act), nil
				}
				enableFlag := act == "enable_proxy"
				if err := ppV2.Pool.SetProxyActive(strings.TrimSpace(a.ProxyID), enableFlag, true); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				actionOut = map[string]any{"action": act, "proxy_id": strings.TrimSpace(a.ProxyID), "active": enableFlag}

			case "clear_failed":
				removed, err := ppV2.Pool.ClearFailedProxies()
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				actionOut = map[string]any{"action": act, "removed": removed}

			case "clear_all":
				removed, err := ppV2.Pool.ClearAllProxies()
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				actionOut = map[string]any{"action": act, "removed": removed}

			case "enable", "disable", "configure":
				cfg := ppV2.Pool.GetConfig()
				if act == "enable" {
					cfg.Enabled = true
				} else if act == "disable" {
					cfg.Enabled = false
				}
				applyConfigOverrides(cfg)
				if err := ppV2.Pool.UpdateConfig(cfg); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				actionOut = map[string]any{"action": act, "config": cfg}

			case "tor_status":
				return jsonResult(s.torStatusSnapshot())

			case "enable_tor":
				out, err := s.enableTorInPool(ctx, a.TorCircuits, a.TorMode)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				actionOut = out

			case "tor_newnym":
				out, err := s.rotateTorIdentity(ctx)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				actionOut = out

			case "disable_tor":
				out, err := s.disableTorInPool()
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				actionOut = out

			case "delete":
				if strings.TrimSpace(a.ProxyID) == "" {
					return actool.Errorf("proxy_id is required for action=delete"), nil
				}
				if err := ppV2.Pool.RemoveProxy(strings.TrimSpace(a.ProxyID)); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				actionOut = map[string]any{"action": act, "deleted": strings.TrimSpace(a.ProxyID)}

			default:
				return actool.Errorf(fmt.Sprintf("unsupported action %q (use rotate, enable_tor, tor_newnym, disable_tor, tor_status, test_all, test_one, activate, disable_proxy, enable_proxy, clear_failed, clear_all, enable, disable, configure, or delete)", a.Action)), nil
			}

			s.syncProxyPoolNow()
			stats := ppV2.Pool.GetStats()
			actionOut["active_proxy_id"] = stats.ActiveProxyID
			actionOut["stats"] = stats
			return jsonResult(actionOut)
		})
}
