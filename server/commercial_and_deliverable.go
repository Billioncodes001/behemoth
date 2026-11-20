package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

const (
	licenseTokenPrefix          = "ARTEX-LIC-"
	defaultVendorSigningSecret  = "artex-commercial-vendor-signing-key-v2-2026"
	settingLicenseKey           = "commercial_license_key"
	settingBrandName            = "commercial_brand_name"
	settingBrandTagline         = "commercial_brand_tagline"
	settingCompanyFooter        = "commercial_company_footer"
	settingReportClassification = "commercial_report_classification"
	settingSupportURL           = "commercial_support_url"
)

// CommercialLicenseClaims is the signed payload inside an ARTEX-LIC-* license key.
type CommercialLicenseClaims struct {
	Customer   string `json:"customer"`
	Tier       string `json:"tier"` // Starter | Professional | Enterprise
	MaxWorkers int    `json:"max_workers"`
	IssuedAt   string `json:"issued_at"`
	ExpiresAt  string `json:"expires_at"`
}

// BrandingConfig holds white-label UI and client report deliverable branding.
type BrandingConfig struct {
	BrandName            string `json:"brand_name"`
	BrandTagline         string `json:"brand_tagline"`
	CompanyFooter        string `json:"company_footer"`
	ReportClassification string `json:"report_classification"`
	SupportURL           string `json:"support_url"`
}

func licenseSigningSecret() []byte {
	if s := strings.TrimSpace(os.Getenv("ARTEX_LICENSE_SIGNING_SECRET")); s != "" {
		return []byte(s)
	}
	return []byte(defaultVendorSigningSecret)
}

// GenerateCommercialLicense creates a cryptographically signed ARTEX-LIC-* key for a customer.
func GenerateCommercialLicense(customer, tier string, validDays, maxWorkers int) (string, *CommercialLicenseClaims, error) {
	customer = strings.TrimSpace(customer)
	if customer == "" {
		return "", nil, fmt.Errorf("customer name is required")
	}
	tier = strings.TrimSpace(tier)
	if tier == "" {
		tier = "Enterprise"
	}
	if validDays <= 0 {
		validDays = 365
	}
	if maxWorkers <= 0 {
		maxWorkers = 20
	}
	now := time.Now().UTC()
	claims := &CommercialLicenseClaims{
		Customer:   customer,
		Tier:       tier,
		MaxWorkers: maxWorkers,
		IssuedAt:   now.Format(time.RFC3339),
		ExpiresAt:  now.AddDate(0, 0, validDays).Format(time.RFC3339),
	}
	rawJSON, err := json.Marshal(claims)
	if err != nil {
		return "", nil, err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(rawJSON)
	mac := hmac.New(sha256.New, licenseSigningSecret())
	mac.Write([]byte(payloadB64))
	sig := hex.EncodeToString(mac.Sum(nil))[:32]
	return licenseTokenPrefix + payloadB64 + "." + sig, claims, nil
}

// VerifyCommercialLicense validates the HMAC-SHA256 signature and expiration of an ARTEX-LIC-* key.
func VerifyCommercialLicense(rawKey string) (*CommercialLicenseClaims, error) {
	key := strings.TrimSpace(rawKey)
	if !strings.HasPrefix(key, licenseTokenPrefix) {
		return nil, fmt.Errorf("invalid license format (must begin with %s)", licenseTokenPrefix)
	}
	rest := strings.TrimPrefix(key, licenseTokenPrefix)
	payloadB64, sig, ok := strings.Cut(rest, ".")
	if !ok || payloadB64 == "" || sig == "" {
		return nil, fmt.Errorf("malformed license key structure")
	}
	mac := hmac.New(sha256.New, licenseSigningSecret())
	mac.Write([]byte(payloadB64))
	expectedSig := hex.EncodeToString(mac.Sum(nil))[:32]
	if !hmac.Equal([]byte(strings.ToLower(sig)), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid license signature")
	}
	rawJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("invalid license payload encoding")
	}
	var claims CommercialLicenseClaims
	if err := json.Unmarshal(rawJSON, &claims); err != nil {
		return nil, fmt.Errorf("corrupt license payload")
	}
	exp, err := time.Parse(time.RFC3339, claims.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("invalid license expiration timestamp")
	}
	if time.Now().UTC().After(exp) {
		return &claims, fmt.Errorf("license expired on %s", exp.Format("2006-01-02"))
	}
	return &claims, nil
}

func (s *Server) currentBranding() BrandingConfig {
	cfg := BrandingConfig{
		BrandName:            "ARTEX",
		BrandTagline:         "Autonomous AI Security & Penetration Testing Platform",
		CompanyFooter:        "Prepared by ARTEX Autonomous Security Operations",
		ReportClassification: "CONFIDENTIAL — AUTHORIZED SECURITY ASSESSMENT",
		SupportURL:           "",
	}
	if s == nil || s.m == nil || s.m.pg == nil {
		return cfg
	}
	pg := s.m.pg
	if v, ok, _ := pg.GetSetting(settingBrandName); ok && strings.TrimSpace(v) != "" {
		cfg.BrandName = strings.TrimSpace(v)
	}
	if v, ok, _ := pg.GetSetting(settingBrandTagline); ok && strings.TrimSpace(v) != "" {
		cfg.BrandTagline = strings.TrimSpace(v)
	}
	if v, ok, _ := pg.GetSetting(settingCompanyFooter); ok && strings.TrimSpace(v) != "" {
		cfg.CompanyFooter = strings.TrimSpace(v)
	}
	if v, ok, _ := pg.GetSetting(settingReportClassification); ok && strings.TrimSpace(v) != "" {
		cfg.ReportClassification = strings.TrimSpace(v)
	}
	if v, ok, _ := pg.GetSetting(settingSupportURL); ok {
		cfg.SupportURL = strings.TrimSpace(v)
	}
	return cfg
}

func (s *Server) commercialStatusPayload() map[string]any {
	branding := s.currentBranding()
	requireLicense := strings.EqualFold(strings.TrimSpace(os.Getenv("ARTEX_REQUIRE_LICENSE")), "true") ||
		strings.TrimSpace(os.Getenv("ARTEX_REQUIRE_LICENSE")) == "1"

	rawKey := strings.TrimSpace(os.Getenv("ARTEX_LICENSE_KEY"))
	if s != nil && s.m != nil && s.m.pg != nil {
		if dbKey, ok, _ := s.m.pg.GetSetting(settingLicenseKey); ok && strings.TrimSpace(dbKey) != "" {
			rawKey = strings.TrimSpace(dbKey)
		}
	}

	var (
		licensed  bool
		licErrStr string
		claims    *CommercialLicenseClaims
	)
	if rawKey != "" {
		c, err := VerifyCommercialLicense(rawKey)
		claims = c
		if err == nil {
			licensed = true
		} else {
			licErrStr = err.Error()
		}
	}

	mode := "vendor_unrestricted"
	if licensed {
		mode = "commercial_licensed"
	} else if requireLicense {
		mode = "license_required"
	}

	maskedKey := ""
	if len(rawKey) > 18 {
		maskedKey = rawKey[:14] + "..." + rawKey[len(rawKey)-6:]
	}

	return map[string]any{
		"mode":            mode,
		"require_license": requireLicense,
		"licensed":        licensed,
		"license_set":     rawKey != "",
		"masked_key":      maskedKey,
		"license_error":   licErrStr,
		"claims":          claims,
		"branding":        branding,
		"version":         BuildVersion,
	}
}

// GET /api/branding — public white-label metadata used by Login & Sidebar.
func (s *Server) handleGetPublicBranding(w http.ResponseWriter, r *http.Request) {
	b := s.currentBranding()
	writeJSON(w, http.StatusOK, map[string]any{
		"brand_name":    b.BrandName,
		"brand_tagline": b.BrandTagline,
		"support_url":   b.SupportURL,
		"version":       BuildVersion,
	})
}

// GET /api/commercial/status — admin endpoint returning license & white-label configuration.
func (s *Server) handleGetCommercialStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.commercialStatusPayload())
}

// PUT /api/commercial/branding — updates white-label branding settings.
func (s *Server) handlePutCommercialBranding(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req BrandingConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid request JSON")
		return
	}
	_ = pg.SetSetting(settingBrandName, strings.TrimSpace(req.BrandName))
	_ = pg.SetSetting(settingBrandTagline, strings.TrimSpace(req.BrandTagline))
	_ = pg.SetSetting(settingCompanyFooter, strings.TrimSpace(req.CompanyFooter))
	_ = pg.SetSetting(settingReportClassification, strings.TrimSpace(req.ReportClassification))
	_ = pg.SetSetting(settingSupportURL, strings.TrimSpace(req.SupportURL))
	writeJSON(w, http.StatusOK, s.commercialStatusPayload())
}

// POST /api/commercial/license — verifies and activates (or clears) a commercial license key.
func (s *Server) handlePostCommercialLicense(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		LicenseKey string `json:"license_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid request JSON")
		return
	}
	key := strings.TrimSpace(req.LicenseKey)
	if key == "" {
		_ = pg.SetSetting(settingLicenseKey, "")
		writeJSON(w, http.StatusOK, s.commercialStatusPayload())
		return
	}
	claims, err := VerifyCommercialLicense(key)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "License verification failed: "+err.Error())
		return
	}
	if err := pg.SetSetting(settingLicenseKey, key); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if claims.MaxWorkers > 0 && s.m != nil && s.m.Workers() > claims.MaxWorkers {
		_ = s.m.SetWorkers(claims.MaxWorkers)
	}
	writeJSON(w, http.StatusOK, s.commercialStatusPayload())
}

// ── Client-Ready Executive + Technical HTML / Print-to-PDF Deliverable Exporter ──

var (
	reInlineCodeSpan = regexp.MustCompile("`([^`\n]+)`")
	reBoldSpan       = regexp.MustCompile(`\*\*([^*]+)\*\*`)
)

func formatInlineMarkdownHTML(line string) string {
	esc := html.EscapeString(line)
	esc = reInlineCodeSpan.ReplaceAllString(esc, `<code class="inline-code">$1</code>`)
	esc = reBoldSpan.ReplaceAllString(esc, `<strong>$1</strong>`)
	return esc
}

func renderDeliverableMarkdownHTML(md string) string {
	md = strings.ReplaceAll(md, "\r\n", "\n")
	lines := strings.Split(md, "\n")
	var b strings.Builder
	inCode := false
	inList := false

	closeList := func() {
		if inList {
			b.WriteString("</ul>\n")
			inList = false
		}
	}

	for _, rawLine := range lines {
		trimmed := strings.TrimSpace(rawLine)
		if strings.HasPrefix(trimmed, "```") {
			closeList()
			if !inCode {
				inCode = true
				b.WriteString(`<pre class="code-block"><code>`)
			} else {
				inCode = false
				b.WriteString("</code></pre>\n")
			}
			continue
		}
		if inCode {
			b.WriteString(html.EscapeString(rawLine))
			b.WriteByte('\n')
			continue
		}
		if trimmed == "" {
			closeList()
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "#### "):
			closeList()
			b.WriteString("<h4>" + formatInlineMarkdownHTML(strings.TrimPrefix(trimmed, "#### ")) + "</h4>\n")
		case strings.HasPrefix(trimmed, "### "):
			closeList()
			b.WriteString("<h3>" + formatInlineMarkdownHTML(strings.TrimPrefix(trimmed, "### ")) + "</h3>\n")
		case strings.HasPrefix(trimmed, "## "):
			closeList()
			b.WriteString("<h2>" + formatInlineMarkdownHTML(strings.TrimPrefix(trimmed, "## ")) + "</h2>\n")
		case strings.HasPrefix(trimmed, "# "):
			closeList()
			b.WriteString("<h2>" + formatInlineMarkdownHTML(strings.TrimPrefix(trimmed, "# ")) + "</h2>\n")
		case strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* "):
			if !inList {
				b.WriteString("<ul>\n")
				inList = true
			}
			b.WriteString("<li>" + formatInlineMarkdownHTML(trimmed[2:]) + "</li>\n")
		default:
			closeList()
			b.WriteString("<p>" + formatInlineMarkdownHTML(trimmed) + "</p>\n")
		}
	}
	if inCode {
		b.WriteString("</code></pre>\n")
	}
	closeList()
	return b.String()
}

func severityBadgeColor(sev string) (bg, fg, border string) {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "#fef2f2", "#b91c1c", "#fca5a5"
	case "high":
		return "#fff7ed", "#c2410c", "#fdba74"
	case "medium":
		return "#fefce8", "#a16207", "#fde047"
	case "low":
		return "#eff6ff", "#1d4ed8", "#93c5fd"
	default:
		return "#f4f4f5", "#3f3f46", "#d4d4d8"
	}
}

// GET /api/deliverables/report — renders a standalone, client-ready Executive + Technical
// Security Assessment Report in HTML with Print-to-PDF (@media print) styling.
// Query params:
//   - finding_id=<id> (single finding deliverable)
//   - task_id=<id>    (full engagement deliverable)
//   - print=1         (auto-open browser Print / Save-as-PDF dialog)
//   - download=1      (send Content-Disposition: attachment)
func (s *Server) handleExportDeliverableReport(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	branding := s.currentBranding()
	q := r.URL.Query()
	findingIDStr := strings.TrimSpace(q.Get("finding_id"))
	taskIDStr := strings.TrimSpace(q.Get("task_id"))
	autoPrint := q.Get("print") == "1" || q.Get("print") == "true"

	var (
		reportTitle string
		scopeNote   string
		findings    []*db.DBFinding
		filename    string
	)

	if findingIDStr != "" {
		fid, err := strconv.ParseInt(findingIDStr, 10, 64)
		if err != nil || fid <= 0 {
			writeErr(w, http.StatusBadRequest, "Invalid finding_id")
			return
		}
		f, err := pg.GetFinding(fid)
		if err != nil || f == nil {
			writeErr(w, http.StatusNotFound, "Finding not found")
			return
		}
		findings = []*db.DBFinding{f}
		tName := strings.TrimSpace(f.Name)
		if tName == "" {
			tName = f.VulnClass
		}
		reportTitle = fmt.Sprintf("Vulnerability Advisory Report — #%d %s", f.ID, tName)
		scopeNote = fmt.Sprintf("Single Vulnerability Technical Deliverable · Finding #%d", f.ID)
		filename = fmt.Sprintf("security-advisory-finding-%d.html", f.ID)
	} else if taskIDStr != "" {
		list, _, err := pg.ListFindingsPage(db.FindingFilter{TaskID: taskIDStr}, 1, 500)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		findings = list
		taskLabel := "Task #" + taskIDStr
		if tid, perr := strconv.ParseInt(taskIDStr, 10, 64); perr == nil {
			if tRow, gerr := pg.GetTask(tid); gerr == nil && tRow != nil {
				if strings.TrimSpace(tRow.Name) != "" {
					taskLabel = tRow.Name
				} else if strings.TrimSpace(tRow.Description) != "" {
					taskLabel = tRow.Description
				}
				scopeNote = "Objective: " + strings.TrimSpace(tRow.Goal)
			}
		}
		reportTitle = "Penetration Testing Assessment Report — " + taskLabel
		if scopeNote == "" {
			scopeNote = "Engagement Task #" + taskIDStr
		}
		filename = fmt.Sprintf("pentest-report-task-%s.html", taskIDStr)
	} else {
		list, _, err := pg.ListFindingsPage(db.FindingFilter{
			Severity: strings.TrimSpace(q.Get("severity")),
			Status:   strings.TrimSpace(q.Get("status")),
		}, 1, 500)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		findings = list
		reportTitle = "Executive & Technical Vulnerability Assessment Report"
		scopeNote = fmt.Sprintf("Portfolio Security Assessment · %d Recorded Finding(s)", len(findings))
		filename = "security-assessment-report.html"
	}

	assetMap := s.resolveFindingAssets(findings)
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	uniqueAssets := map[string]bool{}
	for _, f := range findings {
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if _, ok := counts[sev]; ok {
			counts[sev]++
		}
		dto := findingFromDB(f, assetMap)
		for _, a := range dto.Assets {
			if a.Label != "" {
				uniqueAssets[a.Label] = true
			}
		}
	}

	overallRisk := "LOW"
	switch {
	case counts["critical"] > 0:
		overallRisk = "CRITICAL"
	case counts["high"] > 0:
		overallRisk = "HIGH"
	case counts["medium"] > 0:
		overallRisk = "MEDIUM"
	}

	var doc strings.Builder
	doc.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + html.EscapeString(reportTitle+" · "+branding.BrandName) + `</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif; color: #18181b; background: #f4f4f5; line-height: 1.6; }
  .toolbar { position: sticky; top: 0; z-index: 50; display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px; background: #09090b; color: #fafafa; padding: 12px 24px; border-bottom: 1px solid #27272a; }
  .toolbar-brand { font-weight: 700; font-size: 14px; letter-spacing: 0.03em; }
  .toolbar-actions { display: flex; gap: 8px; }
  .btn { cursor: pointer; border-radius: 6px; border: 1px solid #3f3f46; background: #18181b; color: #fafafa; padding: 7px 14px; font-size: 13px; font-weight: 500; text-decoration: none; }
  .btn-primary { background: #2563eb; border-color: #2563eb; color: #fff; }
  .page { max-width: 960px; margin: 28px auto; background: #ffffff; padding: 48px 56px; border-radius: 12px; box-shadow: 0 8px 30px rgba(0,0,0,0.08); }
  .classification { display: inline-block; font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #991b1b; background: #fef2f2; border: 1px solid #fecaca; padding: 4px 10px; border-radius: 4px; margin-bottom: 16px; }
  .cover-header { border-bottom: 2px solid #18181b; padding-bottom: 24px; margin-bottom: 28px; display: flex; justify-content: space-between; align-items: flex-start; gap: 20px; }
  .brand-title { font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: #52525b; margin-bottom: 6px; }
  h1 { margin: 0 0 8px 0; font-size: 26px; line-height: 1.25; color: #09090b; }
  .meta-line { font-size: 13px; color: #52525b; }
  .kpi-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 24px 0 32px 0; }
  .kpi-card { border: 1px solid #e4e4e7; border-radius: 8px; padding: 14px 16px; background: #fafafa; }
  .kpi-num { font-size: 26px; font-weight: 700; line-height: 1.1; }
  .kpi-label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #71717a; margin-top: 4px; }
  .toc-table { width: 100%; border-collapse: collapse; margin: 16px 0 36px 0; font-size: 13px; }
  .toc-table th { text-align: left; background: #f4f4f5; padding: 10px 12px; border-bottom: 2px solid #d4d4d8; font-weight: 600; }
  .toc-table td { padding: 10px 12px; border-bottom: 1px solid #e4e4e7; vertical-align: middle; }
  .sev-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; }
  .finding-card { border: 1px solid #d4d4d8; border-radius: 10px; padding: 24px 28px; margin-bottom: 28px; page-break-inside: avoid; break-inside: avoid-page; }
  .finding-head { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; border-bottom: 1px solid #e4e4e7; padding-bottom: 14px; margin-bottom: 16px; }
  .finding-title { margin: 0; font-size: 19px; font-weight: 700; color: #09090b; }
  .asset-tags { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }
  .asset-tag { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; background: #f4f4f5; border: 1px solid #e4e4e7; padding: 2px 8px; border-radius: 4px; color: #27272a; }
  .report-body h2 { font-size: 15px; text-transform: uppercase; letter-spacing: 0.04em; color: #18181b; border-left: 3px solid #2563eb; padding-left: 10px; margin: 20px 0 8px 0; }
  .report-body h3 { font-size: 14px; color: #27272a; margin: 14px 0 6px 0; }
  .report-body p, .report-body li { font-size: 13.5px; color: #27272a; }
  .code-block { background: #09090b; color: #e4e4e7; padding: 14px 16px; border-radius: 8px; overflow-x: auto; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; line-height: 1.5; white-space: pre-wrap; word-break: break-word; margin: 10px 0; }
  .inline-code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; background: #f4f4f5; padding: 1px 5px; border-radius: 4px; border: 1px solid #e4e4e7; }
  .footer { margin-top: 40px; padding-top: 18px; border-top: 1px solid #e4e4e7; display: flex; justify-content: space-between; font-size: 11px; color: #71717a; }
  @media print {
    body { background: #ffffff; }
    .toolbar { display: none !important; }
    .page { max-width: 100%; margin: 0; padding: 18px 24px; box-shadow: none; border-radius: 0; }
    .finding-card { break-inside: auto; }
  }
</style>
</head>
<body>
<div class="toolbar">
  <div class="toolbar-brand">` + html.EscapeString(branding.BrandName+" — Deliverable Preview") + `</div>
  <div class="toolbar-actions">
    <button class="btn btn-primary" onclick="window.print()">Print / Save as PDF</button>
    <a class="btn" href="` + html.EscapeString(r.URL.Path+"?"+r.URL.RawQuery+"&download=1") + `">Download Standalone .html</a>
  </div>
</div>
<div class="page">
  <div class="classification">` + html.EscapeString(branding.ReportClassification) + `</div>
  <div class="cover-header">
    <div>
      <div class="brand-title">` + html.EscapeString(branding.BrandName+" · "+branding.BrandTagline) + `</div>
      <h1>` + html.EscapeString(reportTitle) + `</h1>
      <div class="meta-line">` + html.EscapeString(scopeNote) + `</div>
    </div>
    <div style="text-align:right" class="meta-line">
      <div><strong>Generated:</strong> ` + time.Now().UTC().Format("2006-01-02 15:04 UTC") + `</div>
      <div><strong>Overall Risk:</strong> ` + overallRisk + `</div>
      <div><strong>Assets Affected:</strong> ` + strconv.Itoa(len(uniqueAssets)) + `</div>
    </div>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card"><div class="kpi-num">` + strconv.Itoa(len(findings)) + `</div><div class="kpi-label">Total Findings</div></div>
    <div class="kpi-card" style="background:#fef2f2;border-color:#fca5a5"><div class="kpi-num" style="color:#b91c1c">` + strconv.Itoa(counts["critical"]) + `</div><div class="kpi-label">Critical</div></div>
    <div class="kpi-card" style="background:#fff7ed;border-color:#fdba74"><div class="kpi-num" style="color:#c2410c">` + strconv.Itoa(counts["high"]) + `</div><div class="kpi-label">High</div></div>
    <div class="kpi-card" style="background:#fefce8;border-color:#fde047"><div class="kpi-num" style="color:#a16207">` + strconv.Itoa(counts["medium"]) + `</div><div class="kpi-label">Medium</div></div>
    <div class="kpi-card" style="background:#eff6ff;border-color:#93c5fd"><div class="kpi-num" style="color:#1d4ed8">` + strconv.Itoa(counts["low"]) + `</div><div class="kpi-label">Low</div></div>
  </div>
`)

	if len(findings) > 0 {
		doc.WriteString(`  <h2 style="font-size:16px;margin-bottom:8px">Executive Summary of Findings</h2>
  <table class="toc-table">
    <thead><tr><th>ID</th><th>Severity</th><th>Title / Vulnerability Class</th><th>Status</th><th>Affected Assets</th></tr></thead>
    <tbody>
`)
		for _, f := range findings {
			dto := findingFromDB(f, assetMap)
			bg, fg, br := severityBadgeColor(f.Severity)
			fTitle := strings.TrimSpace(f.Name)
			if fTitle == "" {
				fTitle = f.VulnClass
			}
			var assetLabels []string
			for _, a := range dto.Assets {
				assetLabels = append(assetLabels, a.Label)
			}
			assetsCell := "—"
			if len(assetLabels) > 0 {
				assetsCell = strings.Join(assetLabels, ", ")
			}
			doc.WriteString(fmt.Sprintf(`      <tr>
        <td><code>#%d</code></td>
        <td><span class="sev-badge" style="background:%s;color:%s;border:1px solid %s">%s</span></td>
        <td><strong>%s</strong> <span style="color:#71717a">(%s)</span></td>
        <td>%s</td>
        <td style="font-family:monospace;font-size:12px">%s</td>
      </tr>`+"\n",
				f.ID, bg, fg, br, html.EscapeString(strings.ToUpper(f.Severity)),
				html.EscapeString(fTitle), html.EscapeString(f.VulnClass),
				html.EscapeString(f.Status), html.EscapeString(assetsCell)))
		}
		doc.WriteString("    </tbody>\n  </table>\n")
	}

	for _, f := range findings {
		dto := findingFromDB(f, assetMap)
		bg, fg, br := severityBadgeColor(f.Severity)
		fTitle := strings.TrimSpace(f.Name)
		if fTitle == "" {
			fTitle = f.VulnClass
		}
		doc.WriteString(fmt.Sprintf(`  <section class="finding-card">
    <div class="finding-head">
      <h2 class="finding-title">#%d · %s</h2>
      <div>
        <span class="sev-badge" style="background:%s;color:%s;border:1px solid %s">%s</span>
        <span class="sev-badge" style="background:#f4f4f5;color:#27272a;border:1px solid #d4d4d8;margin-left:6px">%s</span>
      </div>
    </div>
`, f.ID, html.EscapeString(fTitle), bg, fg, br, html.EscapeString(strings.ToUpper(f.Severity)), html.EscapeString(f.VulnClass)))

		if len(dto.Assets) > 0 {
			doc.WriteString(`    <div class="asset-tags">`)
			for _, a := range dto.Assets {
				doc.WriteString(`<span class="asset-tag">` + html.EscapeString(a.Type+": "+a.Label) + `</span>`)
			}
			doc.WriteString("</div>\n")
		}

		doc.WriteString(`    <div class="report-body">` + "\n")
		if strings.TrimSpace(f.Report) != "" {
			doc.WriteString(renderDeliverableMarkdownHTML(f.Report))
		} else {
			if strings.TrimSpace(f.Summary) != "" {
				doc.WriteString("<h2>Summary</h2>\n<p>" + formatInlineMarkdownHTML(f.Summary) + "</p>\n")
			}
			if strings.TrimSpace(f.Evidence) != "" {
				doc.WriteString("<h2>Verified Proof-of-Concept Evidence</h2>\n<pre class=\"code-block\"><code>" + html.EscapeString(f.Evidence) + "</code></pre>\n")
			}
		}
		doc.WriteString("    </div>\n  </section>\n")
	}

	doc.WriteString(`  <div class="footer">
    <span>` + html.EscapeString(branding.CompanyFooter) + `</span>
    <span>` + html.EscapeString(branding.BrandName+" v"+BuildVersion+" · "+branding.ReportClassification) + `</span>
  </div>
</div>
`)
	if autoPrint && q.Get("download") != "1" {
		doc.WriteString(`<script>window.addEventListener("load", function(){ setTimeout(function(){ window.print(); }, 350); });</script>` + "\n")
	}
	doc.WriteString("</body>\n</html>\n")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if q.Get("download") == "1" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(doc.String()))
}
