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

func (s *Server) toolGetProxyPoolStatus() actool.CoreTool {
	return roTool("get_proxy_pool_status",
		"Inspect the current Proxy Pool status, enabled state, rotation strategy, active egress proxy & exit IP, health counts, and masked proxy entries.",
		objSchema(map[string]any{}),
		func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			if ppV2 == nil || ppV2.Pool == nil {
				return actool.Errorf("Proxy Pool v2 is not initialized"), nil
			}
			cfg := ppV2.Pool.GetConfig()
			stats := ppV2.Pool.GetStats()
			proxies := ppV2.Pool.GetProxies()
			return jsonResult(map[string]any{
				"enabled":         cfg.Enabled,
				"config":          cfg,
				"stats":           stats,
				"active_proxy_id": stats.ActiveProxyID,
				"proxies":         proxies,
			})
		})
}

func (s *Server) toolManageProxyPool() actool.CoreTool {
	return wrTool("manage_proxy_pool",
		"Manage the Proxy Pool: test_all (re-test all proxies), rotate (switch to next healthy proxy), activate (pin a specific proxy_id), clear_failed (prune dead proxies), clear_all, enable, disable, or delete (remove proxy_id).",
		objSchema(map[string]any{
			"action":            strParam("Action: test_all | rotate | activate | clear_failed | clear_all | enable | disable | delete"),
			"proxy_id":          strParam("Target proxy ID (required only for activate or delete)"),
			"rotation_strategy": strParam("Optional rotation strategy when enabling/configuring: round_robin | random | least_used"),
		}, "action"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if ppV2 == nil || ppV2.Pool == nil {
				return actool.Errorf("Proxy Pool v2 is not initialized"), nil
			}
			var a struct {
				Action           string `json:"action"`
				ProxyID          string `json:"proxy_id"`
				RotationStrategy string `json:"rotation_strategy"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
			}
			act := strings.ToLower(strings.TrimSpace(a.Action))
			var actionOut map[string]any

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

			case "enable", "disable":
				cfg := ppV2.Pool.GetConfig()
				cfg.Enabled = act == "enable"
				if rs := strings.ToLower(strings.TrimSpace(a.RotationStrategy)); rs == "round_robin" || rs == "random" || rs == "least_used" {
					cfg.RotationMode = proxyv2.RotationStrategy(rs)
					cfg.RotationStrategyAlias = cfg.RotationMode
				}
				if err := ppV2.Pool.UpdateConfig(cfg); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				actionOut = map[string]any{"action": act, "enabled": cfg.Enabled, "rotation_strategy": cfg.RotationMode}

			case "delete":
				if strings.TrimSpace(a.ProxyID) == "" {
					return actool.Errorf("proxy_id is required for action=delete"), nil
				}
				if err := ppV2.Pool.RemoveProxy(strings.TrimSpace(a.ProxyID)); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				actionOut = map[string]any{"action": act, "deleted": strings.TrimSpace(a.ProxyID)}

			default:
				return actool.Errorf(fmt.Sprintf("unsupported action %q (use test_all, rotate, activate, clear_failed, clear_all, enable, disable, or delete)", a.Action)), nil
			}

			s.syncProxyPoolNow()
			actionOut["stats"] = ppV2.Pool.GetStats()
			return jsonResult(actionOut)
		})
}
