package server

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/behemoth/db"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	settingBountyScannerConfig = "bounty_scanner_config_v1"
	maxBountyScannerLogs       = 250
)

type BountyScannerConfig struct {
	Enabled       bool   `json:"enabled"`
	IntervalHours int    `json:"interval_hours"`
	AgentAssist   bool   `json:"agent_assist"`
	LLMProfileID  *int64 `json:"llm_profile_id,omitempty"`
	PaidOnly      bool   `json:"paid_only"`
}

type BountyScannerLogEntry struct {
	Seq       int64  `json:"seq"`
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"` // "info" | "source" | "success" | "warn" | "error"
	Message   string `json:"message"`
}

var (
	bountyScanMu        sync.Mutex
	bountyScanRunning   atomic.Bool
	bountyLogMu         sync.Mutex
	bountyLogs          []BountyScannerLogEntry
	bountyLogSeq        int64
	bountyLastRunAt     time.Time
	bountyLastAdded     int
	bountyLastRefreshed int
	reBountyDomainToken = regexp.MustCompile(`(?i)^(?:\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$`)
)

func appendBountyLog(level, msg string) {
	bountyLogMu.Lock()
	defer bountyLogMu.Unlock()
	bountyLogSeq++
	entry := BountyScannerLogEntry{
		Seq:       bountyLogSeq,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level,
		Message:   msg,
	}
	bountyLogs = append(bountyLogs, entry)
	if len(bountyLogs) > maxBountyScannerLogs {
		bountyLogs = append([]BountyScannerLogEntry(nil), bountyLogs[len(bountyLogs)-maxBountyScannerLogs:]...)
	}
}

func snapshotBountyLogs() []BountyScannerLogEntry {
	bountyLogMu.Lock()
	defer bountyLogMu.Unlock()
	out := make([]BountyScannerLogEntry, len(bountyLogs))
	copy(out, bountyLogs)
	return out
}

func defaultBountyScannerConfig() BountyScannerConfig {
	return BountyScannerConfig{
		Enabled:       false,
		IntervalHours: 12,
		AgentAssist:   true,
		PaidOnly:      false,
	}
}

func (s *Server) loadBountyScannerConfig() BountyScannerConfig {
	cfg := defaultBountyScannerConfig()
	if s == nil || s.m == nil || s.m.pg == nil {
		return cfg
	}
	raw, ok, err := s.m.pg.GetSetting(settingBountyScannerConfig)
	if err != nil || !ok || strings.TrimSpace(raw) == "" {
		return cfg
	}
	_ = json.Unmarshal([]byte(raw), &cfg)
	if cfg.IntervalHours <= 0 {
		cfg.IntervalHours = 12
	}
	if cfg.IntervalHours > 168 {
		cfg.IntervalHours = 168
	}
	return cfg
}

func (s *Server) saveBountyScannerConfig(cfg BountyScannerConfig) error {
	if s == nil || s.m == nil || s.m.pg == nil {
		return fmt.Errorf("database not initialized")
	}
	if cfg.IntervalHours <= 0 {
		cfg.IntervalHours = 12
	}
	if cfg.IntervalHours > 168 {
		cfg.IntervalHours = 168
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return s.m.pg.SetSetting(settingBountyScannerConfig, string(b))
}

func (s *Server) startBountyScannerLoop(ctx context.Context) {
	if flag.Lookup("test.v") != nil {
		return
	}
	go func() {
		// Seed initial directory in background on first startup if table is completely empty
		if s.m != nil && s.m.pg != nil {
			if summary, err := s.m.pg.GetBountyStatsSummary(); err == nil && summary.TotalDiscovered == 0 {
				s.runOnlineBountyScan(ctx, false, false)
			}
		}
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cfg := s.loadBountyScannerConfig()
				if !cfg.Enabled {
					continue
				}
				bountyLogMu.Lock()
				lastRun := bountyLastRunAt
				bountyLogMu.Unlock()
				if lastRun.IsZero() || time.Since(lastRun) >= time.Duration(cfg.IntervalHours)*time.Hour {
					s.runOnlineBountyScan(ctx, cfg.AgentAssist, false)
				}
			}
		}
	}()
}

func (s *Server) bountyHTTPClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
	}
	if s != nil && s.m != nil {
		if px := strings.TrimSpace(s.m.ActiveOutboundProxyAddr()); px != "" {
			if u, err := url.Parse(px); err == nil {
				tr.Proxy = http.ProxyURL(u)
			}
		}
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}

// runOnlineBountyScan pulls live public bug bounty directories (ProjectDiscovery Chaos
// self-hosted programs, HackerOne, Bugcrowd, Intigriti, YesWeHack, Federacy) and
// optionally dispatches the autonomous `bounty_scout` AI agent for open-web discovery.
func (s *Server) runOnlineBountyScan(ctx context.Context, dispatchScoutAgent bool, forceScoutOnly bool) (added int, refreshed int, scoutConvID int64) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return 0, 0, 0
	}
	if !bountyScanMu.TryLock() {
		return 0, 0, 0
	}
	defer bountyScanMu.Unlock()

	bountyScanRunning.Store(true)
	defer bountyScanRunning.Store(false)

	cfg := s.loadBountyScannerConfig()
	if !forceScoutOnly {
		appendBountyLog("info", "Starting multi-platform public Bug Bounty & VDP feed harvest...")
		client := s.bountyHTTPClient(35 * time.Second)

		type feedFetcher struct {
			name string
			fn   func(context.Context, *http.Client) ([]*db.BountyProgram, error)
		}
		feeds := []feedFetcher{
			{"ProjectDiscovery Chaos (Self-Hosted & Public Bounties)", fetchChaosBountyFeed},
			{"HackerOne Public Directory", fetchHackerOneBountyFeed},
			{"Bugcrowd Public Directory", fetchBugcrowdBountyFeed},
			{"Intigriti Public Directory", fetchIntigritiBountyFeed},
			{"YesWeHack Public Directory", fetchYesWeHackBountyFeed},
			{"Federacy Public Directory", fetchFederacyBountyFeed},
		}

		for _, f := range feeds {
			if ctx.Err() != nil {
				break
			}
			fctx, cancel := context.WithTimeout(ctx, 35*time.Second)
			progs, err := f.fn(fctx, client)
			cancel()
			if err != nil {
				appendBountyLog("warn", fmt.Sprintf("[%s] feed fetch warning: %v", f.name, err))
				continue
			}
			feedAdded, feedUpdated := 0, 0
			for _, p := range progs {
				if cfg.PaidOnly && !p.OffersBounty {
					continue
				}
				_, isNew, uerr := s.m.pg.UpsertBountyProgram(p)
				if uerr != nil {
					continue
				}
				if isNew {
					feedAdded++
					added++
				} else {
					feedUpdated++
					refreshed++
				}
			}
			appendBountyLog("source", fmt.Sprintf("[%s] Processed %d active programs (+%d new, %d updated)", f.name, feedAdded+feedUpdated, feedAdded, feedUpdated))
		}

		bountyLogMu.Lock()
		bountyLastRunAt = time.Now()
		bountyLastAdded = added
		bountyLastRefreshed = refreshed
		bountyLogMu.Unlock()
		appendBountyLog("success", fmt.Sprintf("Online bounty scan complete: +%d newly discovered programs, %d refreshed.", added, refreshed))
	}

	if dispatchScoutAgent || forceScoutOnly {
		scoutConvID = s.launchBountyScoutAgentRun(cfg.LLMProfileID)
		if scoutConvID > 0 {
			appendBountyLog("info", fmt.Sprintf("Dispatched autonomous Bounty Scout AI agent (Conversation #%d) to discover self-hosted & Web3 bounties and inspect enrollment steps.", scoutConvID))
		}
	}
	return added, refreshed, scoutConvID
}

// ---------- Public Bug Bounty Feed Parsers ----------

func fetchChaosBountyFeed(ctx context.Context, client *http.Client) ([]*db.BountyProgram, error) {
	body, err := fetchFeedBytes(ctx, client, "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/chaos-bugbounty-list.json", 12<<20)
	if err != nil {
		return nil, err
	}
	var root struct {
		Programs []struct {
			Name    string   `json:"name"`
			URL     string   `json:"url"`
			Bounty  bool     `json:"bounty"`
			Swag    bool     `json:"swag"`
			Domains []string `json:"domains"`
		} `json:"programs"`
	}
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, err
	}
	var out []*db.BountyProgram
	for _, item := range root.Programs {
		name := strings.TrimSpace(item.Name)
		pURL := strings.TrimSpace(item.URL)
		if name == "" || pURL == "" || len(item.Domains) == 0 {
			continue
		}
		lowerURL := strings.ToLower(pURL)
		plat := "self_hosted"
		regType := "open_direct"
		regSteps := "No platform registration required. Test published in-scope domains under the organization's Safe Harbor / security policy and submit reports directly via " + pURL
		switch {
		case strings.Contains(lowerURL, "hackerone.com"):
			plat = "hackerone"
			regType = "free_platform_account"
			regSteps = "Open public program on HackerOne. Submit verified vulnerability reports via " + pURL
		case strings.Contains(lowerURL, "bugcrowd.com"):
			plat = "bugcrowd"
			regType = "free_platform_account"
			regSteps = "Open public program on Bugcrowd. Submit verified vulnerability reports via " + pURL
		case strings.Contains(lowerURL, "intigriti.com"):
			plat = "intigriti"
			regType = "free_platform_account"
			regSteps = "Open public program on Intigriti. Submit verified vulnerability reports via " + pURL
		case strings.Contains(lowerURL, "yeswehack.com"):
			plat = "yeswehack"
			regType = "free_platform_account"
			regSteps = "Open public program on YesWeHack. Submit verified vulnerability reports via " + pURL
		case strings.Contains(lowerURL, "immunefi.com"):
			plat = "immunefi"
			regType = "free_platform_account"
			regSteps = "Open Web3/Infrastructure bounty on Immunefi. Submit reports via " + pURL
		}

		assets := make([]db.BountyScopeAsset, 0, min(len(item.Domains), 40))
		for i, dom := range item.Domains {
			dom = strings.TrimSpace(dom)
			if dom == "" {
				continue
			}
			if i < 40 {
				assets = append(assets, db.BountyScopeAsset{
					Target:            "*." + strings.TrimPrefix(dom, "*."),
					AssetType:         "WILDCARD",
					EligibleForBounty: item.Bounty,
					MaxSeverity:       "critical",
				})
			}
		}
		if len(assets) == 0 {
			continue
		}
		slug := slugifyBountyKey(name)
		desc := fmt.Sprintf("Public security program for %s covering %d authorized root domain(s).", name, len(item.Domains))
		if item.Bounty {
			desc = fmt.Sprintf("Paid public bug bounty program for %s covering %d authorized root domain(s).", name, len(item.Domains))
		}
		out = append(out, &db.BountyProgram{
			ProgramKey:        "chaos:" + slug,
			Name:              name,
			Platform:          plat,
			ProgramURL:        pURL,
			SubmissionURL:     pURL,
			OffersBounty:      item.Bounty,
			RegistrationType:  regType,
			RegistrationSteps: regSteps,
			SafeHarbor:        true,
			InScopeAssets:     assets,
			InScopeCount:      len(item.Domains),
			Description:       desc,
			FocusVulns:        "RCE, SQLi, SSRF, Auth Bypass, IDOR/BOLA, Subdomain Takeover, Account Takeover",
			SourceFeed:        "projectdiscovery-chaos",
		})
		if len(out) >= 140 {
			break
		}
	}
	return out, nil
}

func fetchHackerOneBountyFeed(ctx context.Context, client *http.Client) ([]*db.BountyProgram, error) {
	body, err := fetchFeedBytes(ctx, client, "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json", 25<<20)
	if err != nil {
		return nil, err
	}
	var items []struct {
		Handle                  string `json:"handle"`
		Name                    string `json:"name"`
		URL                     string `json:"url"`
		OffersBounties          bool   `json:"offers_bounties"`
		SubmissionState         string `json:"submission_state"`
		GoldStandardSafeHarbor  bool   `json:"allows_bounty_splitting"`
		Targets                 struct {
			InScope []struct {
				AssetIdentifier   string `json:"asset_identifier"`
				AssetType         string `json:"asset_type"`
				EligibleForBounty bool   `json:"eligible_for_bounty"`
				MaxSeverity       string `json:"max_severity"`
				Instruction       string `json:"instruction"`
			} `json:"in_scope"`
			OutOfScope []struct {
				AssetIdentifier string `json:"asset_identifier"`
				AssetType       string `json:"asset_type"`
				Instruction     string `json:"instruction"`
			} `json:"out_of_scope"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, err
	}
	var out []*db.BountyProgram
	for _, it := range items {
		if !strings.EqualFold(it.SubmissionState, "open") || !it.OffersBounties || len(it.Targets.InScope) == 0 {
			continue
		}
		var inScope []db.BountyScopeAsset
		for _, t := range it.Targets.InScope {
			if len(inScope) >= 40 {
				break
			}
			inScope = append(inScope, db.BountyScopeAsset{
				Target:            strings.TrimSpace(t.AssetIdentifier),
				AssetType:         t.AssetType,
				EligibleForBounty: t.EligibleForBounty,
				MaxSeverity:       t.MaxSeverity,
				Instruction:       truncateRunes(strings.TrimSpace(t.Instruction), 240),
			})
		}
		var outScope []db.BountyScopeAsset
		for _, t := range it.Targets.OutOfScope {
			if len(outScope) >= 25 {
				break
			}
			outScope = append(outScope, db.BountyScopeAsset{
				Target:      strings.TrimSpace(t.AssetIdentifier),
				AssetType:   t.AssetType,
				Instruction: truncateRunes(strings.TrimSpace(t.Instruction), 180),
			})
		}
		pURL := strings.TrimSpace(it.URL)
		if pURL == "" {
			pURL = "https://hackerone.com/" + strings.TrimSpace(it.Handle)
		}
		out = append(out, &db.BountyProgram{
			ProgramKey:        "hackerone:" + strings.ToLower(strings.TrimSpace(it.Handle)),
			Name:              strings.TrimSpace(it.Name),
			Platform:          "hackerone",
			ProgramURL:        pURL,
			SubmissionURL:     pURL + "/reports/new",
			OffersBounty:      true,
			RegistrationType:  "free_platform_account",
			RegistrationSteps: "Open public HackerOne bounty program (submission_state=open). Sign in with a free HackerOne researcher account and submit directly at " + pURL + "/reports/new",
			SafeHarbor:        true,
			InScopeAssets:     inScope,
			OutOfScopeAssets:  outScope,
			InScopeCount:      len(it.Targets.InScope),
			Description:       fmt.Sprintf("Active paid HackerOne bug bounty program (%d in-scope assets, %d out-of-scope exclusions).", len(it.Targets.InScope), len(it.Targets.OutOfScope)),
			FocusVulns:        "Critical/High RCE, SQLi, SSRF, Auth Bypass, IDOR, Privilege Escalation, XSS",
			SourceFeed:        "hackerone-public",
		})
		if len(out) >= 90 {
			break
		}
	}
	return out, nil
}

func fetchBugcrowdBountyFeed(ctx context.Context, client *http.Client) ([]*db.BountyProgram, error) {
	body, err := fetchFeedBytes(ctx, client, "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json", 15<<20)
	if err != nil {
		return nil, err
	}
	var items []struct {
		Name             string  `json:"name"`
		URL              string  `json:"url"`
		MaxPayout        float64 `json:"max_payout"`
		AllowsDisclosure bool    `json:"allows_disclosure"`
		SafeHarbor       string  `json:"safe_harbor"`
		Targets          struct {
			InScope []struct {
				Target      string `json:"target"`
				Type        string `json:"type"`
				Description string `json:"description"`
			} `json:"in_scope"`
			OutOfScope []struct {
				Target      string `json:"target"`
				Type        string `json:"type"`
				Description string `json:"description"`
			} `json:"out_of_scope"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, err
	}
	var out []*db.BountyProgram
	for _, it := range items {
		if it.MaxPayout <= 0 || len(it.Targets.InScope) == 0 || strings.TrimSpace(it.Name) == "" {
			continue
		}
		var inScope []db.BountyScopeAsset
		for _, t := range it.Targets.InScope {
			if len(inScope) >= 40 {
				break
			}
			inScope = append(inScope, db.BountyScopeAsset{
				Target:            strings.TrimSpace(t.Target),
				AssetType:         t.Type,
				EligibleForBounty: true,
				Instruction:       truncateRunes(strings.TrimSpace(t.Description), 220),
			})
		}
		var outScope []db.BountyScopeAsset
		for _, t := range it.Targets.OutOfScope {
			if len(outScope) >= 25 {
				break
			}
			outScope = append(outScope, db.BountyScopeAsset{
				Target:      strings.TrimSpace(t.Target),
				AssetType:   t.Type,
				Instruction: truncateRunes(strings.TrimSpace(t.Description), 180),
			})
		}
		pURL := strings.TrimSpace(it.URL)
		out = append(out, &db.BountyProgram{
			ProgramKey:        "bugcrowd:" + slugifyBountyKey(it.Name),
			Name:              strings.TrimSpace(it.Name),
			Platform:          "bugcrowd",
			ProgramURL:        pURL,
			SubmissionURL:     pURL,
			OffersBounty:      true,
			MaxBountyUSD:      it.MaxPayout,
			RegistrationType:  "free_platform_account",
			RegistrationSteps: "Open public Bugcrowd bounty program (up to $" + strconv.FormatFloat(it.MaxPayout, 'f', 0, 64) + "). Submit findings with a free Bugcrowd researcher account at " + pURL,
			SafeHarbor:        it.SafeHarbor != "" && !strings.EqualFold(it.SafeHarbor, "none"),
			InScopeAssets:     inScope,
			OutOfScopeAssets:  outScope,
			InScopeCount:      len(it.Targets.InScope),
			Description:       fmt.Sprintf("Paid Bugcrowd bug bounty program offering up to $%.0f USD (%d in-scope targets).", it.MaxPayout, len(it.Targets.InScope)),
			FocusVulns:        "P1/P2 RCE, SQLi, SSRF, Broken Access Control, Authentication Bypass, Business Logic",
			SourceFeed:        "bugcrowd-public",
		})
		if len(out) >= 70 {
			break
		}
	}
	return out, nil
}

func fetchIntigritiBountyFeed(ctx context.Context, client *http.Client) ([]*db.BountyProgram, error) {
	body, err := fetchFeedBytes(ctx, client, "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json", 12<<20)
	if err != nil {
		return nil, err
	}
	var items []struct {
		Handle               string `json:"handle"`
		Name                 string `json:"name"`
		URL                  string `json:"url"`
		ConfidentialityLevel string `json:"confidentiality_level"`
		Status               string `json:"status"`
		MinBounty            struct {
			Value    float64 `json:"value"`
			Currency string  `json:"currency"`
		} `json:"min_bounty"`
		MaxBounty struct {
			Value    float64 `json:"value"`
			Currency string  `json:"currency"`
		} `json:"max_bounty"`
		Targets struct {
			InScope []struct {
				Endpoint    string `json:"endpoint"`
				Type        string `json:"type"`
				Impact      string `json:"impact"`
				Description string `json:"description"`
			} `json:"in_scope"`
			OutOfScope []struct {
				Endpoint    string `json:"endpoint"`
				Type        string `json:"type"`
				Description string `json:"description"`
			} `json:"out_of_scope"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, err
	}
	var out []*db.BountyProgram
	for _, it := range items {
		if it.MaxBounty.Value <= 0 || len(it.Targets.InScope) == 0 || strings.EqualFold(it.Status, "closed") || strings.EqualFold(it.Status, "suspended") {
			continue
		}
		var inScope []db.BountyScopeAsset
		for _, t := range it.Targets.InScope {
			if len(inScope) >= 40 {
				break
			}
			inScope = append(inScope, db.BountyScopeAsset{
				Target:            strings.TrimSpace(t.Endpoint),
				AssetType:         t.Type,
				EligibleForBounty: !strings.EqualFold(t.Impact, "none"),
				MaxSeverity:       t.Impact,
				Instruction:       truncateRunes(strings.TrimSpace(t.Description), 220),
			})
		}
		var outScope []db.BountyScopeAsset
		for _, t := range it.Targets.OutOfScope {
			if len(outScope) >= 25 {
				break
			}
			outScope = append(outScope, db.BountyScopeAsset{
				Target:      strings.TrimSpace(t.Endpoint),
				AssetType:   t.Type,
				Instruction: truncateRunes(strings.TrimSpace(t.Description), 180),
			})
		}
		regType := "free_platform_account"
		regSteps := "Public Intigriti bounty program. Submit directly via " + it.URL
		if strings.EqualFold(it.ConfidentialityLevel, "application") || strings.EqualFold(it.ConfidentialityLevel, "registered") {
			regType = "application_or_kyc"
			regSteps = fmt.Sprintf("Intigriti %s tier program — log into Intigriti and complete researcher registration/ID check at %s before testing.", it.ConfidentialityLevel, it.URL)
		}
		curr := it.MaxBounty.Currency
		if curr == "" {
			curr = "EUR"
		}
		out = append(out, &db.BountyProgram{
			ProgramKey:        "intigriti:" + slugifyBountyKey(firstNonEmptyBounty(it.Handle, it.Name)),
			Name:              strings.TrimSpace(it.Name),
			Platform:          "intigriti",
			ProgramURL:        strings.TrimSpace(it.URL),
			SubmissionURL:     strings.TrimSpace(it.URL),
			OffersBounty:      true,
			MinBountyUSD:      it.MinBounty.Value,
			MaxBountyUSD:      it.MaxBounty.Value,
			Currency:          curr,
			RegistrationType:  regType,
			RegistrationSteps: regSteps,
			SafeHarbor:        true,
			InScopeAssets:     inScope,
			OutOfScopeAssets:  outScope,
			InScopeCount:      len(it.Targets.InScope),
			Description:       fmt.Sprintf("Intigriti bug bounty program (%s %.0f – %.0f, %d in-scope targets).", curr, it.MinBounty.Value, it.MaxBounty.Value, len(it.Targets.InScope)),
			FocusVulns:        "Exceptional/Critical RCE, SQLi, SSRF, IDOR, Authentication Bypass",
			SourceFeed:        "intigriti-public",
		})
		if len(out) >= 50 {
			break
		}
	}
	return out, nil
}

func fetchYesWeHackBountyFeed(ctx context.Context, client *http.Client) ([]*db.BountyProgram, error) {
	body, err := fetchFeedBytes(ctx, client, "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json", 10<<20)
	if err != nil {
		return nil, err
	}
	var items []struct {
		ID        string  `json:"id"`
		Name      string  `json:"name"`
		Public    bool    `json:"public"`
		Disabled  bool    `json:"disabled"`
		Bounty    bool    `json:"bounty"`
		MinBounty float64 `json:"min_bounty"`
		MaxBounty float64 `json:"max_bounty"`
		Targets   struct {
			InScope []struct {
				Target        string `json:"target"`
				Type          string `json:"type"`
				SecurityValue string `json:"security_value"`
			} `json:"in_scope"`
			OutOfScope []string `json:"out_of_scope"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, err
	}
	var out []*db.BountyProgram
	for _, it := range items {
		if it.Disabled || !it.Bounty || len(it.Targets.InScope) == 0 {
			continue
		}
		var inScope []db.BountyScopeAsset
		for _, t := range it.Targets.InScope {
			if len(inScope) >= 40 {
				break
			}
			inScope = append(inScope, db.BountyScopeAsset{
				Target:            strings.TrimSpace(t.Target),
				AssetType:         t.Type,
				EligibleForBounty: true,
				MaxSeverity:       t.SecurityValue,
			})
		}
		var outScope []db.BountyScopeAsset
		for _, o := range it.Targets.OutOfScope {
			if len(outScope) >= 20 {
				break
			}
			outScope = append(outScope, db.BountyScopeAsset{Target: strings.TrimSpace(o)})
		}
		pURL := "https://yeswehack.com/programs/" + strings.TrimSpace(it.ID)
		regType := "free_platform_account"
		if !it.Public {
			regType = "application_or_kyc"
		}
		out = append(out, &db.BountyProgram{
			ProgramKey:        "yeswehack:" + slugifyBountyKey(firstNonEmptyBounty(it.ID, it.Name)),
			Name:              strings.TrimSpace(it.Name),
			Platform:          "yeswehack",
			ProgramURL:        pURL,
			SubmissionURL:     pURL,
			OffersBounty:      true,
			MinBountyUSD:      it.MinBounty,
			MaxBountyUSD:      it.MaxBounty,
			Currency:          "EUR",
			RegistrationType:  regType,
			RegistrationSteps: "YesWeHack public bounty program. Submit reports via " + pURL,
			SafeHarbor:        true,
			InScopeAssets:     inScope,
			OutOfScopeAssets:  outScope,
			InScopeCount:      len(it.Targets.InScope),
			Description:       fmt.Sprintf("YesWeHack bug bounty program (€%.0f – €%.0f, %d in-scope assets).", it.MinBounty, it.MaxBounty, len(it.Targets.InScope)),
			FocusVulns:        "Critical/High RCE, SQLi, SSRF, Auth Bypass, Broken Access Control",
			SourceFeed:        "yeswehack-public",
		})
		if len(out) >= 40 {
			break
		}
	}
	return out, nil
}

func fetchFederacyBountyFeed(ctx context.Context, client *http.Client) ([]*db.BountyProgram, error) {
	body, err := fetchFeedBytes(ctx, client, "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/federacy_data.json", 5<<20)
	if err != nil {
		return nil, err
	}
	var items []struct {
		ID           string `json:"id"`
		Name         string `json:"name"`
		URL          string `json:"url"`
		OffersAwards bool   `json:"offers_awards"`
		Targets      struct {
			InScope []struct {
				Target string `json:"target"`
				Type   string `json:"type"`
			} `json:"in_scope"`
			OutOfScope []struct {
				Target string `json:"target"`
				Type   string `json:"type"`
			} `json:"out_of_scope"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, err
	}
	var out []*db.BountyProgram
	for _, it := range items {
		if len(it.Targets.InScope) == 0 || strings.TrimSpace(it.Name) == "" {
			continue
		}
		var inScope []db.BountyScopeAsset
		for _, t := range it.Targets.InScope {
			inScope = append(inScope, db.BountyScopeAsset{
				Target:            strings.TrimSpace(t.Target),
				AssetType:         t.Type,
				EligibleForBounty: it.OffersAwards,
			})
		}
		var outScope []db.BountyScopeAsset
		for _, t := range it.Targets.OutOfScope {
			outScope = append(outScope, db.BountyScopeAsset{
				Target:    strings.TrimSpace(t.Target),
				AssetType: t.Type,
			})
		}
		out = append(out, &db.BountyProgram{
			ProgramKey:        "federacy:" + slugifyBountyKey(firstNonEmptyBounty(it.ID, it.Name)),
			Name:              strings.TrimSpace(it.Name),
			Platform:          "federacy",
			ProgramURL:        strings.TrimSpace(it.URL),
			SubmissionURL:     strings.TrimSpace(it.URL),
			OffersBounty:      it.OffersAwards,
			RegistrationType:  "free_platform_account",
			RegistrationSteps: "Public Federacy program. Submit findings via " + strings.TrimSpace(it.URL),
			SafeHarbor:        true,
			InScopeAssets:     inScope,
			OutOfScopeAssets:  outScope,
			InScopeCount:      len(inScope),
			Description:       fmt.Sprintf("Federacy security program (%d in-scope targets).", len(inScope)),
			FocusVulns:        "Web/API vulnerabilities, Auth Bypass, IDOR, Injection",
			SourceFeed:        "federacy-public",
		})
	}
	return out, nil
}

func fetchFeedBytes(ctx context.Context, client *http.Client, feedURL string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "BEHEMOTH-BountyScout/2.4")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}

func slugifyBountyKey(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	res := strings.Trim(b.String(), "-")
	if res == "" {
		return fmt.Sprintf("prog-%d", time.Now().UnixNano())
	}
	return res
}

func firstNonEmptyBounty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ---------- Autonomous Bounty Scout Agent Launcher ----------

func (s *Server) launchBountyScoutAgentRun(profileID *int64) int64 {
	if s == nil || s.m == nil || s.m.pg == nil {
		return 0
	}
	title := fmt.Sprintf("Bounty Scout · %s", time.Now().Format("2006-01-02 15:04"))
	conv, err := s.m.pg.CreateConversation("bounty_scout", title, nil)
	if err != nil || conv == nil {
		log.Printf("[bounty-scout] create conversation failed: %v", err)
		return 0
	}
	if profileID != nil && *profileID > 0 {
		_ = s.m.pg.UpdateConversationProfile(conv.ID, profileID)
		conv.LLMProfileID = profileID
	}

	prompt := "Execute an autonomous Bug Bounty Discovery & Enrollment Scout cycle now:\n" +
		"1. Call `check_proxy_status` and `list_bounty_programs(limit=50)` to inspect existing programs.\n" +
		"2. Use `multi_engine_search` (across `searxng`, `firecrawl`, `tavily`, `brave`, `duckduckgo`), `WebFetch`, and `browser_inspect` to discover 5–10 high-value, active **paid bug bounty programs** — prioritizing standalone/self-hosted company bug bounties (`registration_type='open_direct'` requiring NO platform signup!), SaaS/Cloud/AI/Fintech `/security` & `/.well-known/security.txt` bounty programs, and high-payout Web3/Infrastructure programs.\n" +
		"3. Inspect each program's policy page to extract accurate `in_scope_assets`, `out_of_scope_assets`, `min_bounty_usd` / `max_bounty_usd`, `submission_url`, `registration_type` (`open_direct` | `free_platform_account` | `application_or_kyc`), and clear `registration_steps`.\n" +
		"4. Persist every verified program via `register_bounty_program` so it appears immediately in BEHEMOTH's **Bug Bounty Finder** page for the operator to review and hunt.\n" +
		"5. Conclude with a concise briefing highlighting the top newly added programs (especially immediate No-Registration opportunities and top max payouts)."

	_, _ = s.m.pg.AppendConvActivity(conv.ID, db.Activity{
		Worker: "bounty_scout", Kind: "user", Summary: title, Detail: prompt,
	})
	busyKey := s.convBusyKey(conv.ID)
	s.chatMu.Lock()
	s.chatBusy[busyKey] = true
	s.chatMu.Unlock()
	s.runConversation(conv, prompt, busyKey)
	return conv.ID
}

// ---------- One-Click Automated Bounty Hunt & Scope Enrollment ----------

var knownBountyPlatformHosts = map[string]bool{
	"bugcrowd.com":       true,
	"hackerone.com":      true,
	"intigriti.com":      true,
	"app.intigriti.com":  true,
	"yeswehack.com":      true,
	"federacy.com":       true,
	"immunefi.com":       true,
	"huntr.com":          true,
	"openbugbounty.org":  true,
	"code4rena.com":      true,
	"sherlock.xyz":       true,
	"cantina.xyz":        true,
	"hackenproof.com":    true,
	"inspectiv.com":      true,
	"synack.com":         true,
	"cobalt.io":          true,
	"yogosha.com":        true,
}

func isKnownBountyPlatformHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(host, "*.")))
	if h == "" {
		return false
	}
	if knownBountyPlatformHosts[h] {
		return true
	}
	for plat := range knownBountyPlatformHosts {
		if strings.HasSuffix(h, "."+plat) {
			return true
		}
	}
	return false
}

func isHeavyNativeBinaryBountyAsset(a db.BountyScopeAsset) bool {
	at := strings.ToLower(strings.TrimSpace(a.AssetType))
	switch at {
	case "android", "ios", "mobile", "google_play_app_id", "apple_store_app_id",
		"other_apk", "other_ipa", "windows_app_store_app_id", "executable", "hardware", "iot":
		return true
	}
	targetLower := strings.ToLower(strings.TrimSpace(a.Target))
	if strings.Contains(targetLower, "chrome extension") || strings.Contains(targetLower, "browser extension") || strings.Contains(targetLower, "firefox") {
		return false
	}
	for _, kw := range []string{
		"desktop application", "macos application", "windows application",
		"android app", "ios app", "mobile application", ".apk", ".ipa", ".dmg", ".exe", ".msi",
	} {
		if strings.Contains(targetLower, kw) {
			return true
		}
	}
	return false
}

func extractCleanTargetHost(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
			v = u.Hostname()
		}
	} else if idx := strings.IndexByte(v, '/'); idx > 0 {
		v = v[:idx]
	}
	v = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "*.")
	if m := reBountyDomainToken.FindStringSubmatch(v); len(m) >= 2 {
		return m[1]
	}
	return ""
}

func (s *Server) startBountyHuntForProgram(ctx context.Context, progID int64, customFocus string, llmProfileID *int64) (*db.BountyProgram, string, error) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return nil, "", fmt.Errorf("server not initialized")
	}
	prog, err := s.m.pg.GetBountyProgram(progID)
	if err != nil {
		return nil, "", err
	}
	if prog == nil {
		return nil, "", fmt.Errorf("bounty program #%d not found", progID)
	}

	// If already linked to an active running/paused task, revive & return it if requested.
	if prog.LinkedTaskID != nil && *prog.LinkedTaskID > 0 {
		tidStr := strconv.FormatInt(*prog.LinkedTaskID, 10)
		if existingTask, ok := s.m.Task(tidStr); ok {
			st := existingTask.lifecycleSnapshot()
			if !isTerminalStatus(st.Status) {
				if strings.TrimSpace(customFocus) != "" {
					hintPayload, _ := json.Marshal(map[string]any{
						"task_id": existingTask.ID,
						"text":    "Operator bounty hunting focus update: " + strings.TrimSpace(customFocus),
					})
					_, _ = s.toolAddHint().Call(ctx, hintPayload, nil)
				}
				s.reviveTask(existingTask)
				statusStr := "hunting"
				updated, _ := s.m.pg.UpdateBountyTracking(prog.ID, &statusStr, prog.LinkedTaskID, nil, nil, nil, nil)
				if updated != nil {
					prog = updated
				}
				return prog, existingTask.ID, nil
			}
		}
	}

	// 1. Collect authorized in-scope targets & out-of-scope exclusions, separating
	// live Web/API/Extension targets from heavy Desktop/Mobile binary installers so
	// workers do not burn hundreds of MiB of proxy bandwidth downloading installers.
	var webInScopeAssets, binaryInScopeAssets []db.BountyScopeAsset
	for _, a := range prog.InScopeAssets {
		if strings.TrimSpace(a.Target) == "" {
			continue
		}
		if isHeavyNativeBinaryBountyAsset(a) {
			binaryInScopeAssets = append(binaryInScopeAssets, a)
		} else {
			webInScopeAssets = append(webInScopeAssets, a)
		}
	}
	primaryScopeAssets := webInScopeAssets
	var deferredBinaryAssets []db.BountyScopeAsset
	if len(primaryScopeAssets) > 0 {
		deferredBinaryAssets = binaryInScopeAssets
	} else {
		// Mobile/desktop-only bounty program with zero web/API assets: keep them primary.
		primaryScopeAssets = binaryInScopeAssets
	}

	formatScopeLine := func(a db.BountyScopeAsset) string {
		line := "- `" + strings.TrimSpace(a.Target) + "`"
		if a.AssetType != "" {
			line += " (" + a.AssetType + ")"
		}
		if a.EligibleForBounty {
			line += " [Bounty Eligible"
			if a.MaxSeverity != "" {
				line += " · Max: " + a.MaxSeverity
			}
			line += "]"
		}
		if a.Instruction != "" {
			line += " — " + a.Instruction
		}
		return line
	}

	var inScopeLines []string
	var deferredBinaryLines []string
	var scopeRuleLines []string
	var seedDomains []string
	seenHost := map[string]bool{}
	for _, a := range primaryScopeAssets {
		if len(inScopeLines) < 30 {
			inScopeLines = append(inScopeLines, formatScopeLine(a))
		}
		if host := extractCleanTargetHost(a.Target); host != "" && !seenHost[host] {
			seenHost[host] = true
			seedDomains = append(seedDomains, host)
			if strings.HasPrefix(strings.TrimSpace(a.Target), "*.") {
				scopeRuleLines = append(scopeRuleLines, "*."+host)
			} else {
				scopeRuleLines = append(scopeRuleLines, host)
			}
		}
	}
	for _, a := range deferredBinaryAssets {
		if len(deferredBinaryLines) < 12 {
			deferredBinaryLines = append(deferredBinaryLines, formatScopeLine(a))
		}
	}
	if len(inScopeLines) == 0 {
		inScopeLines = []string{"- Refer to in-scope targets for " + prog.Name}
	}

	type blockedRule struct {
		kind, pattern string
	}
	var outScopeLines []string
	var blockedHosts []blockedRule
	seenBlocked := map[string]bool{}
	addBlockedHost := func(kind, host string) {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || seenHost[host] || seenBlocked[kind+":"+host] {
			return
		}
		seenBlocked[kind+":"+host] = true
		blockedHosts = append(blockedHosts, blockedRule{kind: kind, pattern: host})
	}
	for _, o := range prog.OutOfScopeAssets {
		t := strings.TrimSpace(o.Target)
		if t == "" {
			continue
		}
		if len(outScopeLines) < 20 {
			line := "- OUT OF SCOPE: `" + t + "`"
			if o.Instruction != "" {
				line += " (" + o.Instruction + ")"
			}
			outScopeLines = append(outScopeLines, line)
		}
		if host := extractCleanTargetHost(t); host != "" {
			kind := "exact_domain"
			if strings.HasPrefix(t, "*.") {
				kind = "fuzzy_domain"
			}
			addBlockedHost(kind, host)
		}
	}
	// Mechanically protect the Bug Bounty platform host itself (e.g. bugcrowd.com,
	// hackerone.com, intigriti.com, yeswehack.com) from ever being probed as a target
	// unless the operator is explicitly hunting that platform's own program!
	for _, metaURL := range []string{prog.ProgramURL, prog.SubmissionURL} {
		if platHost := extractCleanTargetHost(metaURL); platHost != "" && !seenHost[platHost] {
			addBlockedHost("fuzzy_domain", platHost)
			outScopeLines = append(outScopeLines, fmt.Sprintf("- OUT OF SCOPE (Bounty Platform Host — NEVER probe): `%s`", platHost))
		}
	}

	// 2. Register Company & In-Scope rules in BEHEMOTH's Asset Store.
	if as := s.m.Assets(); as != nil && len(scopeRuleLines) > 0 {
		if compID, cerr := as.Companies().UpsertByName(prog.Name); cerr == nil && compID > 0 {
			_, _, _, _ = as.Companies().AddScope(compID, scopeRuleLines, "Bug Bounty Program Scope: "+prog.ProgramURL)
		}
	}

	payoutNote := "VDP / Reputation"
	if prog.OffersBounty {
		if prog.MaxBountyUSD > 0 {
			payoutNote = fmt.Sprintf("Paid Bounty (%s %.0f – %.0f)", prog.Currency, prog.MinBountyUSD, prog.MaxBountyUSD)
		} else {
			payoutNote = "Paid Cash Bug Bounty"
		}
	}

	focus := prog.FocusVulns
	if strings.TrimSpace(customFocus) != "" {
		focus = strings.TrimSpace(customFocus) + " | " + focus
	}
	if strings.TrimSpace(focus) == "" {
		focus = "Critical/High RCE, SQLi, SSRF, Authentication Bypass, Account Takeover, IDOR/BOLA, Subdomain Takeover, Business Logic Flaws"
	}

	desc := fmt.Sprintf("Bug Bounty Hunt · %s (%s)", prog.Name, strings.ToUpper(prog.Platform))
	if len(seedDomains) > 0 {
		desc += " — " + seedDomains[0]
	}

	deferredSection := ""
	if len(deferredBinaryLines) > 0 {
		deferredSection = "\n\n### Deferred Native/Mobile Binary Targets (Skip Large Installer Downloads by Default):\n" +
			strings.Join(deferredBinaryLines, "\n") +
			"\n*(Do NOT download multi-hundred-MB desktop/mobile binary installers `.dmg`/`.exe`/`.apk`/`.ipa` over Proxy Pool unless explicitly requested by the operator — focus worker budgets on live Web/API endpoints and lightweight JS/extension bundles.)*"
	}

	goal := fmt.Sprintf(
		"Autonomous Bug Bounty Hunting Engagement for **%s** (%s · %s)\n"+
			"Program Reference: `%s` | Submission Reference: `%s`\n\n"+
			"### Authorized In-Scope Web/API Assets (Hunt ONLY within these targets):\n%s%s\n\n"+
			"### Strict Out-of-Scope Exclusions (NEVER touch):\n%s\n\n"+
			"### Priority Bounty-Eligible Vulnerability Focus:\n%s\n\n"+
			"### Execution & Bounty Reporting Mandate:\n"+
			"1. Check `check_proxy_status` first and strictly honor proxy routing & auth-page rate discipline (use `schedule_cooldown_resume` if cooling down between batches).\n"+
			"2. Map the attack surface across the authorized in-scope domains/APIs (`subfinder`, `dnsx`, `httpx`, `whatweb`, `ffuf`, `nuclei`, `audit_frontend_api_surface`, `browser_inspect`), checking `detect_deception_and_honeypot` on any exposed `.env`/`.git`/`.map` files.\n"+
			"3. Do NOT probe the Bug Bounty platform host (`bugcrowd.com`, `hackerone.com`, etc.) and do NOT download massive native OS/mobile binary installers over proxy unless explicitly asked.\n"+
			"4. Prioritize **high/critical impact, bounty-eligible vulnerabilities** (RCE, SQLi, SSRF, Auth Bypass, IDOR/BOLA, Privilege Escalation, Business Logic flaws) over low-value informational headers.\n"+
			"5. Drive every candidate vulnerability all the way to a **deterministic, non-destructive Proof-of-Concept**, persist it via `report_finding` + `update_finding_report` (with complete submission-ready Reproduction Steps, HTTP request/response evidence, Impact, and Remediation), and immediately call `update_bounty_tracker(program_id=%d, tracker_status=\"bug_found\", notes=\"...\")` once a reportable vulnerability is verified!",
		prog.Name, strings.ToUpper(prog.Platform), payoutNote,
		prog.ProgramURL, firstNonEmptyBounty(prog.SubmissionURL, prog.ProgramURL),
		strings.Join(inScopeLines, "\n"),
		deferredSection,
		func() string {
			if len(outScopeLines) == 0 {
				return "- Respect standard Safe Harbor rules: no DoS/DDoS, no social engineering, no third-party infrastructure attacks."
			}
			return strings.Join(outScopeLines, "\n")
		}(),
		focus,
		prog.ID,
	)

	var llmIDs []int64
	if llmProfileID != nil && *llmProfileID > 0 {
		if _, ok := s.loadProfileConfig(*llmProfileID); ok {
			llmIDs = []int64{*llmProfileID}
		}
	}

	taskObj, err := s.m.CreateTaskWithOptions(desc, goal, db.TaskCreateOptions{
		Name:          fmt.Sprintf("Bounty · %s", prog.Name),
		LLMProfileIDs: llmIDs,
	})
	if err != nil {
		return nil, "", fmt.Errorf("create bounty task: %w", err)
	}

	// Mechanically enforce task-scoped block rules on explicit out-of-scope hosts + seed in-scope hosts.
	if tidNum, perr := strconv.ParseInt(taskObj.ID, 10, 64); perr == nil && tidNum > 0 {
		if as := s.m.Assets(); as != nil {
			for _, dom := range seedDomains {
				_, _ = as.UpsertRootDomain(db.UpsertRootDomainReq{Domain: dom, TaskID: tidNum})
				_ = as.AddAutoScope(tidNum, "root_domain", dom, "", "")
			}
			for _, br := range blockedHosts {
				_, _ = as.CreateTaskInterceptRule(tidNum, "block", br.kind, br.pattern, "Out-of-scope exclusion for "+prog.Name, true)
			}
		}
		statusStr := "hunting"
		updated, uerr := s.m.pg.UpdateBountyTracking(prog.ID, &statusStr, &tidNum, nil, nil, nil, nil)
		if uerr == nil && updated != nil {
			prog = updated
		}
	}

	seedTarget := ""
	if len(seedDomains) > 0 {
		seedTarget = "https://" + seedDomains[0]
	}
	s.launchTask(taskObj, seedTarget, false)
	appendBountyLog("success", fmt.Sprintf("Started automated Bounty Hunt for %q -> Task #%s (%d in-scope seed domains)", prog.Name, taskObj.ID, len(seedDomains)))
	return prog, taskObj.ID, nil
}

// reconcileBountyTaskScopeIsolation cleans up any historical bounty tasks where
// `seed()` previously parsed the Bug Bounty platform URL (e.g. bugcrowd.com,
// hackerone.com) out of `Program Policy URL:` and attached it as a Test Asset,
// while also installing protective out-of-scope block rules on those tasks.
func (s *Server) reconcileBountyTaskScopeIsolation() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	const flag = "bounty_scope_isolation_reconcile_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	progs, err := s.m.pg.ListBountyPrograms(db.BountyProgramFilter{TrackerOnly: true})
	if err != nil {
		return
	}
	as := s.m.Assets()
	for _, p := range progs {
		if p.LinkedTaskID == nil || *p.LinkedTaskID <= 0 {
			continue
		}
		tid := *p.LinkedTaskID
		inScopeHosts := map[string]bool{}
		for _, a := range p.InScopeAssets {
			if h := extractCleanTargetHost(a.Target); h != "" {
				inScopeHosts[h] = true
			}
		}
		var platHosts []string
		for _, rawURL := range []string{p.ProgramURL, p.SubmissionURL} {
			if ph := extractCleanTargetHost(rawURL); ph != "" && !inScopeHosts[ph] && isKnownBountyPlatformHost(ph) {
				platHosts = append(platHosts, ph)
			}
		}
		for plat := range knownBountyPlatformHosts {
			if !inScopeHosts[plat] {
				platHosts = append(platHosts, plat)
			}
		}
		seenPlat := map[string]bool{}
		for _, ph := range platHosts {
			if seenPlat[ph] {
				continue
			}
			seenPlat[ph] = true
			// Detach accidental bounty-platform asset links & auto-scope rows on this task.
			rows, qerr := s.m.pg.Query(`
				SELECT id FROM assets
				WHERE $1 = ANY(task_ids)
				  AND (LOWER(COALESCE(domain, '')) = $2
				       OR LOWER(COALESCE(domain, '')) LIKE '%.' || $2
				       OR LOWER(COALESCE(root_domain, '')) = $2
				       OR LOWER(COALESCE(url, '')) LIKE 'https://' || $2 || '%'
				       OR LOWER(COALESCE(url, '')) LIKE 'http://' || $2 || '%')
			`, tid, ph)
			if qerr == nil {
				var detachIDs []int64
				for rows.Next() {
					var aid int64
					if rows.Scan(&aid) == nil && aid > 0 {
						detachIDs = append(detachIDs, aid)
					}
				}
				rows.Close()
				for _, aid := range detachIDs {
					if as != nil {
						_, _ = as.DetachAssetFromTask(tid, aid)
					}
					_, _ = s.m.pg.Exec(`DELETE FROM task_asset_links WHERE task_id = $1 AND asset_id = $2`, tid, aid)
					log.Printf("[bounty-scope] Detached accidental platform asset #%d (%s) from bounty Task #%d", aid, ph, tid)
				}
			}
			_, _ = s.m.pg.Exec(`DELETE FROM task_asset_scopes WHERE task_id = $1 AND LOWER(value) IN ($2, '*.' || $2)`, tid, ph)
		}
		// Ensure explicit out-of-scope block rule exists for the program's hosting platform.
		if as != nil {
			if ph := extractCleanTargetHost(p.ProgramURL); ph != "" && !inScopeHosts[ph] {
				_, _ = as.CreateTaskInterceptRule(tid, "block", "fuzzy_domain", ph, "Bounty platform host protection for "+p.Name, true)
			}
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// syncBountyTrackerFromTaskFindings automatically promotes any Bounty Program
// linked to taskID from discovered/registered/hunting -> bug_found as soon as
// a parallel Worker records at least one real finding on that task (without ever
// downgrading already-submitted or rewarded programs).
func (s *Server) syncBountyTrackerFromTaskFindings(taskID int64) {
	if s == nil || s.m == nil || s.m.pg == nil || taskID <= 0 {
		return
	}
	findings, err := s.m.pg.ListTaskFindingsAfter(taskID, 0)
	if err != nil || len(findings) == 0 {
		return
	}
	latest := findings[len(findings)-1]
	title := strings.TrimSpace(latest.Name)
	if title == "" {
		title = strings.TrimSpace(latest.VulnClass)
	}
	autoNote := fmt.Sprintf("[Auto-Tracked from Task #%d] %d confirmed finding(s); latest: [%s] %s",
		taskID, len(findings), strings.ToUpper(strings.TrimSpace(latest.Severity)), title)

	_, _ = s.m.pg.Exec(`
		UPDATE bounty_programs
		SET tracker_status = 'bug_found',
		    submission_notes = CASE
		        WHEN COALESCE(submission_notes, '') = '' THEN $2
		        WHEN POSITION($2 IN submission_notes) > 0 THEN submission_notes
		        ELSE submission_notes || E'\n' || $2
		    END,
		    updated_at = now()
		WHERE linked_task_id = $1
		  AND tracker_status IN ('discovered', 'registered', 'hunting')
	`, taskID, autoNote)
}

func (s *Server) syncAllBountyTrackersFromFindings() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	rows, err := s.m.pg.Query(`
		SELECT DISTINCT linked_task_id
		FROM bounty_programs
		WHERE linked_task_id IS NOT NULL
		  AND linked_task_id > 0
		  AND tracker_status IN ('discovered', 'registered', 'hunting')
	`)
	if err != nil {
		return
	}
	var taskIDs []int64
	for rows.Next() {
		var tid int64
		if rows.Scan(&tid) == nil && tid > 0 {
			taskIDs = append(taskIDs, tid)
		}
	}
	rows.Close()
	for _, tid := range taskIDs {
		s.syncBountyTrackerFromTaskFindings(tid)
	}
}

// ---------- Enriched DTOs & HTTP API Handlers ----------

type EnrichedBountyProgramDTO struct {
	*db.BountyProgram
	TaskStatus   string         `json:"task_status,omitempty"`
	FindingStats map[string]int `json:"finding_stats"`
}

func (s *Server) enrichBountyPrograms(list []*db.BountyProgram) []EnrichedBountyProgramDTO {
	out := make([]EnrichedBountyProgramDTO, 0, len(list))
	for _, p := range list {
		dto := EnrichedBountyProgramDTO{
			BountyProgram: p,
			FindingStats: map[string]int{
				"critical": 0,
				"high":     0,
				"medium":   0,
				"low":      0,
				"total":    0,
			},
		}
		if p.LinkedTaskID != nil && *p.LinkedTaskID > 0 && s != nil && s.m != nil {
			tidStr := strconv.FormatInt(*p.LinkedTaskID, 10)
			if t, ok := s.m.Task(tidStr); ok && t != nil {
				dto.TaskStatus = s.deriveTaskStatus(t)
			}
			if s.m.pg != nil {
				if dbFindings, ferr := s.m.pg.ListFindingsForExport(db.FindingFilter{TaskID: tidStr}, nil); ferr == nil {
					for _, fn := range dbFindings {
						if strings.EqualFold(fn.Status, "false_positive") {
							continue
						}
						sev := strings.ToLower(strings.TrimSpace(fn.Severity))
						if _, ok := dto.FindingStats[sev]; ok {
							dto.FindingStats[sev]++
						}
						dto.FindingStats["total"]++
					}
				}
				// Auto-promote active hunting status to bug_found when high/critical findings exist!
				if p.TrackerStatus == "hunting" && (dto.FindingStats["critical"]+dto.FindingStats["high"]) > 0 {
					bf := "bug_found"
					if updated, err := s.m.pg.UpdateBountyTracking(p.ID, &bf, nil, nil, nil, nil, nil); err == nil && updated != nil {
						dto.BountyProgram = updated
					}
				}
			}
		}
		out = append(out, dto)
	}
	return out
}

func (s *Server) handleListBountyPrograms(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "database not initialized")
		return
	}
	q := r.URL.Query()
	tab := strings.ToLower(strings.TrimSpace(q.Get("tab")))
	limit, _ := strconv.Atoi(q.Get("limit"))
	filter := db.BountyProgramFilter{
		Query:            q.Get("q"),
		Platform:         q.Get("platform"),
		RegistrationType: q.Get("registration_type"),
		TrackerOnly:      tab == "tracker",
		FinderOnly:       tab == "finder" || tab == "",
		PaidOnly:         q.Get("paid_only") == "true" || q.Get("paid_only") == "1",
		SortBy:           q.Get("sort"),
		Limit:            limit,
	}
	progs, err := s.m.pg.ListBountyPrograms(filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	summary, _ := s.m.pg.GetBountyStatsSummary()
	writeJSON(w, http.StatusOK, map[string]any{
		"programs": s.enrichBountyPrograms(progs),
		"summary":  summary,
	})
}

func (s *Server) handleCreateBountyProgram(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "database not initialized")
		return
	}
	var req struct {
		Name              string                `json:"name"`
		Platform          string                `json:"platform"`
		ProgramURL        string                `json:"program_url"`
		SubmissionURL     string                `json:"submission_url"`
		OffersBounty      *bool                 `json:"offers_bounty"`
		MinBountyUSD      float64               `json:"min_bounty_usd"`
		MaxBountyUSD      float64               `json:"max_bounty_usd"`
		Currency          string                `json:"currency"`
		RegistrationType  string                `json:"registration_type"`
		RegistrationSteps string                `json:"registration_steps"`
		SafeHarbor        bool                  `json:"safe_harbor"`
		InScopeTargets    []string              `json:"in_scope_targets"`
		OutOfScopeTargets []string              `json:"out_of_scope_targets"`
		InScopeAssets     []db.BountyScopeAsset `json:"in_scope_assets"`
		OutOfScopeAssets  []db.BountyScopeAsset `json:"out_of_scope_assets"`
		Description       string                `json:"description"`
		FocusVulns        string                `json:"focus_vulns"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request JSON")
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.ProgramURL) == "" {
		writeErr(w, http.StatusBadRequest, "name and program_url are required")
		return
	}
	offers := true
	if req.OffersBounty != nil {
		offers = *req.OffersBounty
	}
	inAssets := req.InScopeAssets
	for _, t := range req.InScopeTargets {
		if strings.TrimSpace(t) != "" {
			inAssets = append(inAssets, db.BountyScopeAsset{Target: strings.TrimSpace(t), EligibleForBounty: offers})
		}
	}
	outAssets := req.OutOfScopeAssets
	for _, t := range req.OutOfScopeTargets {
		if strings.TrimSpace(t) != "" {
			outAssets = append(outAssets, db.BountyScopeAsset{Target: strings.TrimSpace(t)})
		}
	}
	plat := strings.ToLower(strings.TrimSpace(req.Platform))
	if plat == "" {
		plat = "custom"
	}
	p := &db.BountyProgram{
		ProgramKey:        plat + ":" + slugifyBountyKey(req.Name),
		Name:              req.Name,
		Platform:          plat,
		ProgramURL:        req.ProgramURL,
		SubmissionURL:     firstNonEmptyBounty(req.SubmissionURL, req.ProgramURL),
		OffersBounty:      offers,
		MinBountyUSD:      req.MinBountyUSD,
		MaxBountyUSD:      req.MaxBountyUSD,
		Currency:          req.Currency,
		RegistrationType:  req.RegistrationType,
		RegistrationSteps: req.RegistrationSteps,
		SafeHarbor:        req.SafeHarbor,
		InScopeAssets:     inAssets,
		OutOfScopeAssets:  outAssets,
		Description:       req.Description,
		FocusVulns:        req.FocusVulns,
		SourceFeed:        "manual",
	}
	id, _, err := s.m.pg.UpsertBountyProgram(p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	saved, _ := s.m.pg.GetBountyProgram(id)
	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) handleStartBountyHunt(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid program id")
		return
	}
	var req struct {
		CustomFocus  string `json:"custom_focus"`
		LLMProfileID *int64 `json:"llm_profile_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	prog, taskID, err := s.startBountyHuntForProgram(r.Context(), id, req.CustomFocus, req.LLMProfileID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	enriched := s.enrichBountyPrograms([]*db.BountyProgram{prog})
	var item any = prog
	if len(enriched) > 0 {
		item = enriched[0]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"task_id": taskID,
		"program": item,
	})
}

func (s *Server) handleUpdateBountyProgram(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid program id")
		return
	}
	var req struct {
		TrackerStatus   *string  `json:"tracker_status"`
		EarnedUSD       *float64 `json:"earned_usd"`
		SubmissionURL   *string  `json:"submission_url"`
		SubmissionNotes *string  `json:"submission_notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	updated, err := s.m.pg.UpdateBountyTracking(id, req.TrackerStatus, nil, nil, req.EarnedUSD, req.SubmissionURL, req.SubmissionNotes)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if updated == nil {
		writeErr(w, http.StatusNotFound, "program not found")
		return
	}
	enriched := s.enrichBountyPrograms([]*db.BountyProgram{updated})
	writeJSON(w, http.StatusOK, enriched[0])
}

func (s *Server) handleDeleteBountyProgram(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid program id")
		return
	}
	if err := s.m.pg.DeleteBountyProgram(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleGetBountyScanner(w http.ResponseWriter, r *http.Request) {
	cfg := s.loadBountyScannerConfig()
	bountyLogMu.Lock()
	lastRun := bountyLastRunAt
	lastAdded := bountyLastAdded
	lastRef := bountyLastRefreshed
	bountyLogMu.Unlock()

	var lastRunStr string
	if !lastRun.IsZero() {
		lastRunStr = lastRun.UTC().Format(time.RFC3339)
	}
	summary, _ := s.m.pg.GetBountyStatsSummary()
	writeJSON(w, http.StatusOK, map[string]any{
		"config":         cfg,
		"running":        bountyScanRunning.Load(),
		"last_run_at":    lastRunStr,
		"last_added":     lastAdded,
		"last_refreshed": lastRef,
		"logs":           snapshotBountyLogs(),
		"summary":        summary,
	})
}

func (s *Server) handlePutBountyScanner(w http.ResponseWriter, r *http.Request) {
	var cfg BountyScannerConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.saveBountyScannerConfig(cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cfg.Enabled && !bountyScanRunning.Load() {
		go s.runOnlineBountyScan(s.ctx, cfg.AgentAssist, false)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": s.loadBountyScannerConfig()})
}

func (s *Server) handleRunBountyScannerNow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DispatchScout *bool  `json:"dispatch_scout"`
		ScoutOnly     bool   `json:"scout_only"`
		LLMProfileID  *int64 `json:"llm_profile_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	cfg := s.loadBountyScannerConfig()
	if req.LLMProfileID != nil {
		cfg.LLMProfileID = req.LLMProfileID
		_ = s.saveBountyScannerConfig(cfg)
	}
	dispatch := cfg.AgentAssist
	if req.DispatchScout != nil {
		dispatch = *req.DispatchScout
	}
	if bountyScanRunning.Load() && !req.ScoutOnly {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "already_running": true})
		return
	}
	if req.ScoutOnly {
		convID := s.launchBountyScoutAgentRun(cfg.LLMProfileID)
		appendBountyLog("info", fmt.Sprintf("Dispatched Bounty Scout AI agent (Conversation #%d).", convID))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "scout_conversation_id": convID})
		return
	}
	go s.runOnlineBountyScan(s.ctx, dispatch, false)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "started": true})
}

// ---------- Native Agent Tools for bounty_scout, auto, pentest, worker ----------

func (s *Server) bountyHunterAgentTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolListBountyPrograms(),
		s.toolRegisterBountyProgram(),
		s.toolStartBountyHunt(),
		s.toolUpdateBountyTracker(),
	}
}

func (s *Server) toolListBountyPrograms() actool.CoreTool {
	return roTool("list_bounty_programs",
		"Query BEHEMOTH's Bug Bounty Finder & Tracker database by keyword, platform ('self_hosted', 'hackerone', 'bugcrowd', 'intigriti', 'yeswehack', 'immunefi'), registration_type ('open_direct' for no-signup programs, 'free_platform_account', 'application_or_kyc'), or tab ('finder' | 'tracker').",
		objSchema(map[string]any{
			"query":             strParam("Optional search keyword (program name, domain, technology)"),
			"platform":          strParam("Optional platform filter: all | self_hosted | hackerone | bugcrowd | intigriti | yeswehack | immunefi | federacy"),
			"registration_type": strParam("Optional registration filter: all | open_direct | free_platform_account | application_or_kyc"),
			"tab":               strParam("finder (all discovered) | tracker (actively hunted/submitted)"),
			"paid_only":         map[string]any{"type": "boolean", "description": "Only return programs offering monetary rewards"},
			"limit":             map[string]any{"type": "integer", "description": "Max items to return (default 40)"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil || s.m == nil || s.m.pg == nil {
				return actool.Errorf("database not initialized"), nil
			}
			var a struct {
				Query            string `json:"query"`
				Platform         string `json:"platform"`
				RegistrationType string `json:"registration_type"`
				Tab              string `json:"tab"`
				PaidOnly         bool   `json:"paid_only"`
				Limit            int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Limit <= 0 || a.Limit > 100 {
				a.Limit = 40
			}
			progs, err := s.m.pg.ListBountyPrograms(db.BountyProgramFilter{
				Query:            a.Query,
				Platform:         a.Platform,
				RegistrationType: a.RegistrationType,
				TrackerOnly:      strings.EqualFold(a.Tab, "tracker"),
				FinderOnly:       !strings.EqualFold(a.Tab, "tracker"),
				PaidOnly:         a.PaidOnly,
				Limit:            a.Limit,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			summary, _ := s.m.pg.GetBountyStatsSummary()
			return jsonResult(map[string]any{
				"count":    len(progs),
				"summary":  summary,
				"programs": s.enrichBountyPrograms(progs),
			})
		})
}

func (s *Server) toolRegisterBountyProgram() actool.CoreTool {
	return wrTool("register_bounty_program",
		"Register or update a discovered public or self-hosted Bug Bounty Program in BEHEMOTH's Bug Bounty Finder database with its authorized in-scope targets, out-of-scope exclusions, payout range, and registration/enrollment instructions.",
		objSchema(map[string]any{
			"name":                strParam("Organization or Bug Bounty Program name (e.g. 'Cloudflare', 'Supabase', 'Acme Security Bounty')"),
			"platform":            strParam("Platform: self_hosted | hackerone | bugcrowd | intigriti | yeswehack | immunefi | openbugbounty | custom"),
			"program_url":         strParam("Official bug bounty policy URL"),
			"submission_url":      strParam("Direct vulnerability report submission URL or mailto: address"),
			"offers_bounty":       map[string]any{"type": "boolean", "description": "True if the program pays monetary rewards (default true)"},
			"min_bounty_usd":      map[string]any{"type": "number", "description": "Minimum bounty payout in USD (0 if unspecified)"},
			"max_bounty_usd":      map[string]any{"type": "number", "description": "Maximum critical bounty payout in USD"},
			"currency":            strParam("Currency code (default USD)"),
			"registration_type":   strParam("open_direct (no signup required — test & submit directly) | free_platform_account (standard researcher account) | application_or_kyc (application/ID check required)"),
			"registration_steps":  strParam("Clear step-by-step instructions on how to register (or submit directly if no registration is needed)"),
			"safe_harbor":         map[string]any{"type": "boolean", "description": "True if the program provides legal Safe Harbor for good-faith testing"},
			"in_scope_targets":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Authorized in-scope domains, wildcards (*.example.com), or API URLs"},
			"out_of_scope_targets": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Out-of-scope domains/hosts/endpoints"},
			"description":         strParam("Concise program overview, rules, and special testing headers/requirements"),
			"focus_vulns":         strParam("High-priority eligible vulnerability classes for this program"),
		}, "name", "program_url", "in_scope_targets"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil || s.m == nil || s.m.pg == nil {
				return actool.Errorf("database not initialized"), nil
			}
			var a struct {
				Name              string   `json:"name"`
				Platform          string   `json:"platform"`
				ProgramURL        string   `json:"program_url"`
				SubmissionURL     string   `json:"submission_url"`
				OffersBounty      *bool    `json:"offers_bounty"`
				MinBountyUSD      float64  `json:"min_bounty_usd"`
				MaxBountyUSD      float64  `json:"max_bounty_usd"`
				Currency          string   `json:"currency"`
				RegistrationType  string   `json:"registration_type"`
				RegistrationSteps string   `json:"registration_steps"`
				SafeHarbor        bool     `json:"safe_harbor"`
				InScopeTargets    []string `json:"in_scope_targets"`
				OutOfScopeTargets []string `json:"out_of_scope_targets"`
				Description       string   `json:"description"`
				FocusVulns        string   `json:"focus_vulns"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input JSON: " + err.Error()), nil
			}
			offers := true
			if a.OffersBounty != nil {
				offers = *a.OffersBounty
			}
			var inAssets []db.BountyScopeAsset
			for _, t := range a.InScopeTargets {
				if strings.TrimSpace(t) != "" {
					inAssets = append(inAssets, db.BountyScopeAsset{
						Target:            strings.TrimSpace(t),
						AssetType:         "DOMAIN",
						EligibleForBounty: offers,
					})
				}
			}
			var outAssets []db.BountyScopeAsset
			for _, t := range a.OutOfScopeTargets {
				if strings.TrimSpace(t) != "" {
					outAssets = append(outAssets, db.BountyScopeAsset{Target: strings.TrimSpace(t)})
				}
			}
			plat := strings.ToLower(strings.TrimSpace(a.Platform))
			if plat == "" {
				plat = "self_hosted"
			}
			prog := &db.BountyProgram{
				ProgramKey:        plat + ":" + slugifyBountyKey(a.Name),
				Name:              a.Name,
				Platform:          plat,
				ProgramURL:        a.ProgramURL,
				SubmissionURL:     firstNonEmptyBounty(a.SubmissionURL, a.ProgramURL),
				OffersBounty:      offers,
				MinBountyUSD:      a.MinBountyUSD,
				MaxBountyUSD:      a.MaxBountyUSD,
				Currency:          a.Currency,
				RegistrationType:  a.RegistrationType,
				RegistrationSteps: a.RegistrationSteps,
				SafeHarbor:        a.SafeHarbor,
				InScopeAssets:     inAssets,
				OutOfScopeAssets:  outAssets,
				Description:       a.Description,
				FocusVulns:        a.FocusVulns,
				SourceFeed:        "bounty_scout_agent",
			}
			id, isNew, err := s.m.pg.UpsertBountyProgram(prog)
			if err != nil {
				return actool.Errorf("register_bounty_program failed: " + err.Error()), nil
			}
			appendBountyLog("success", fmt.Sprintf("[Bounty Scout Agent] Registered %q (%s, reg=%s, max=$%.0f)", prog.Name, prog.Platform, prog.RegistrationType, prog.MaxBountyUSD))
			return jsonResult(map[string]any{
				"ok":             true,
				"program_id":     id,
				"newly_inserted": isNew,
				"program_key":    prog.ProgramKey,
			})
		})
}

func (s *Server) toolStartBountyHunt() actool.CoreTool {
	return wrTool("start_bounty_hunt",
		"Enroll a discovered Bug Bounty Program into BEHEMOTH's Active Bounty Tracker, register its authorized in-scope domains & out-of-scope block rules, and spawn an autonomous Bug Bounty Hunting Task against it.",
		objSchema(map[string]any{
			"program_id":   map[string]any{"type": "integer", "description": "Bounty program ID from list_bounty_programs"},
			"custom_focus": strParam("Optional custom hunting instructions or specific endpoints/vulnerability classes to prioritize"),
		}, "program_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ProgramID   int64  `json:"program_id"`
				CustomFocus string `json:"custom_focus"`
			}
			if err := json.Unmarshal(in, &a); err != nil || a.ProgramID <= 0 {
				return actool.Errorf("valid program_id is required"), nil
			}
			prog, taskID, err := s.startBountyHuntForProgram(ctx, a.ProgramID, a.CustomFocus, nil)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"ok":      true,
				"task_id": taskID,
				"program": prog,
			})
		})
}

func (s *Server) toolUpdateBountyTracker() actool.CoreTool {
	return wrTool("update_bounty_tracker",
		"Update an active Bug Bounty Tracker entry's status ('hunting' | 'bug_found' | 'submitted' | 'triaged' | 'rewarded' | 'paused'), submission notes, or earned bounty USD once a reportable vulnerability is verified.",
		objSchema(map[string]any{
			"program_id":     map[string]any{"type": "integer", "description": "Bounty program ID"},
			"tracker_status": strParam("New tracker status: hunting | bug_found | submitted | triaged | rewarded | paused"),
			"notes":          strParam("Summary of confirmed reportable bug(s), finding IDs, or submission details"),
			"earned_usd":     map[string]any{"type": "number", "description": "Optional confirmed bounty payout in USD"},
		}, "program_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if s == nil || s.m == nil || s.m.pg == nil {
				return actool.Errorf("database not initialized"), nil
			}
			var a struct {
				ProgramID     int64    `json:"program_id"`
				TrackerStatus *string  `json:"tracker_status"`
				Notes         *string  `json:"notes"`
				EarnedUSD     *float64 `json:"earned_usd"`
			}
			if err := json.Unmarshal(in, &a); err != nil || a.ProgramID <= 0 {
				return actool.Errorf("valid program_id is required"), nil
			}
			updated, err := s.m.pg.UpdateBountyTracking(a.ProgramID, a.TrackerStatus, nil, nil, a.EarnedUSD, nil, a.Notes)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if updated == nil {
				return actool.Errorf("bounty program not found"), nil
			}
			return jsonResult(map[string]any{"ok": true, "program": updated})
		})
}
