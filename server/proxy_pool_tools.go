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
	return []actool.CoreTool{
		s.toolCheckProxyStatus(),
		s.toolImportAndTestProxies(),
		s.toolGetProxyPoolStatus(),
		s.toolManageProxyPool(),
	}
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

			cfg := ppV2.Pool.GetConfig()
			cfg.Enabled = true
			if rs := strings.ToLower(strings.TrimSpace(a.RotationStrategy)); rs == "round_robin" || rs == "random" || rs == "least_used" {
				cfg.RotationMode = proxyv2.RotationStrategy(rs)
				cfg.RotationStrategyAlias = cfg.RotationMode
			}
			_ = ppV2.Pool.UpdateConfig(cfg)

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
	trafficCapture := false
	if s.m != nil {
		globalRaw = strings.TrimSpace(s.m.GlobalProxy())
		trafficCapture = s.m.TrafficEnabled()
	}
	poolEnabled := cfg != nil && cfg.Enabled
	totalInPool := 0
	activeProxyID := ""
	if stats != nil {
		totalInPool = stats.Total
		activeProxyID = stats.ActiveProxyID
	}
	poolActive := poolEnabled && totalInPool > 0 && activeProxy != nil
	globalActive := globalRaw != ""
	routingMode := "direct"
	if poolActive {
		routingMode = "proxy_pool"
	} else if globalActive {
		routingMode = "static_global_proxy"
	}
	anyOutbound := routingMode != "direct"
	instruction := "NO outbound proxy is enabled (Proxy Pool is OFF and Global Proxy is NOT configured). Connect directly to targets — do NOT pass -x or --proxy flags to curl/scanners, and never treat 127.0.0.1:8788 (local HTTP packet capture) as an external proxy."
	if routingMode == "proxy_pool" {
		instruction = "Proxy Pool is ENABLED. Outbound traffic automatically routes through the active pool proxy via environment variables; do not hardcode localhost ports with -x. If a proxy times out or gets rate-limited/403'd, call manage_proxy_pool(action='rotate' or 'disable_proxy')."
	} else if routingMode == "static_global_proxy" {
		instruction = "Static Global Proxy is ENABLED in System Settings. Outbound traffic automatically routes through the configured Global Proxy."
	}
	return map[string]any{
		"proxy_enabled":              anyOutbound,
		"any_proxy_enabled":          anyOutbound,
		"effective_routing_mode":     routingMode,
		"proxy_pool_enabled":         poolEnabled,
		"proxy_pool_active":          poolActive,
		"global_proxy_enabled":       globalActive,
		"static_global_proxy":        maskSecrets(globalRaw),
		"local_traffic_capture_only": trafficCapture && !anyOutbound,
		"traffic_capture":            trafficCapture,
		"active_proxy_id":            activeProxyID,
		"active_proxy":               activeProxy,
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
		"Control and reconfigure ARTEX proxy routing mid-operation: rotate (switch away from a slow/rate-limited/failing proxy immediately), test_all, test_one (probe proxy_id), activate (pin proxy_id), disable_proxy (quarantine a failing proxy_id and auto-failover), enable_proxy, clear_failed, clear_all, enable, disable, configure (adjust rotation_strategy, rotation_interval_seconds, auto_rotate_on_failure, session_sticky, max_consecutive_failures, cooldown_seconds), or delete.",
		objSchema(map[string]any{
			"action":                       strParam("Action: rotate | test_all | test_one | activate | disable_proxy | enable_proxy | clear_failed | clear_all | enable | disable | configure | delete"),
			"proxy_id":                     strParam("Target proxy ID (used by test_one, activate, disable_proxy, enable_proxy, delete)"),
			"rotation_strategy":            strParam("Optional rotation strategy: round_robin | random | least_used"),
			"rotation_interval_seconds":    map[string]any{"type": "integer", "description": "Optional rotation interval in seconds (>= 5)"},
			"auto_rotate_on_failure":       map[string]any{"type": "boolean", "description": "Optional toggle to auto-rotate when a proxy fails"},
			"session_sticky":               map[string]any{"type": "boolean", "description": "Optional toggle to keep one proxy sticky per session until failure"},
			"max_consecutive_failures":     map[string]any{"type": "integer", "description": "Optional failure threshold before marking unhealthy (>= 1)"},
			"cooldown_seconds":             map[string]any{"type": "integer", "description": "Optional cooldown in seconds (>= 10)"},
			"health_check_interval_seconds": map[string]any{"type": "integer", "description": "Optional background health check interval in seconds (>= 10)"},
		}, "action"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if ppV2 == nil || ppV2.Pool == nil {
				return actool.Errorf("Proxy Pool v2 is not initialized"), nil
			}
			var a struct {
				Action                     string `json:"action"`
				ProxyID                    string `json:"proxy_id"`
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
				if err := ppV2.Pool.SetProxyActive(strings.TrimSpace(a.ProxyID), enableFlag); err != nil {
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

			case "delete":
				if strings.TrimSpace(a.ProxyID) == "" {
					return actool.Errorf("proxy_id is required for action=delete"), nil
				}
				if err := ppV2.Pool.RemoveProxy(strings.TrimSpace(a.ProxyID)); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				actionOut = map[string]any{"action": act, "deleted": strings.TrimSpace(a.ProxyID)}

			default:
				return actool.Errorf(fmt.Sprintf("unsupported action %q (use rotate, test_all, test_one, activate, disable_proxy, enable_proxy, clear_failed, clear_all, enable, disable, configure, or delete)", a.Action)), nil
			}

			s.syncProxyPoolNow()
			stats := ppV2.Pool.GetStats()
			actionOut["active_proxy_id"] = stats.ActiveProxyID
			actionOut["stats"] = stats
			return jsonResult(actionOut)
		})
}
