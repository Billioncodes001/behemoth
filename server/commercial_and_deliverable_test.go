package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCommercialLicensingBrandingAndDeliverableReportExport(t *testing.T) {
	// 1. Offline cryptographic license generation & verification
	licKey, claims, err := GenerateCommercialLicense("Acme Cyber Defense Ltd", "Enterprise", 365, 16)
	if err != nil || !strings.HasPrefix(licKey, "ARTEX-LIC-") {
		t.Fatalf("GenerateCommercialLicense failed: err=%v key=%q", err, licKey)
	}
	verified, err := VerifyCommercialLicense(licKey)
	if err != nil || verified.Customer != "Acme Cyber Defense Ltd" || verified.Tier != "Enterprise" || verified.MaxWorkers != 16 {
		t.Fatalf("VerifyCommercialLicense mismatch: err=%v verified=%+v (orig=%+v)", err, verified, claims)
	}
	if _, err := VerifyCommercialLicense(licKey + "tampered"); err == nil {
		t.Fatal("expected tampered license signature to be rejected")
	}

	// 2. End-to-end HTTP test for Branding, License Activation, and Client Deliverable HTML/PDF Export
	s, initial, request := trafficEvidenceServer(t)

	// Update white-label branding
	r := request("PUT", "/api/commercial/branding", `{
		"brand_name": "CyberSentinel Pro",
		"brand_tagline": "Enterprise Offensive AI Security",
		"company_footer": "Prepared by CyberSentinel Red Team",
		"report_classification": "STRICTLY CONFIDENTIAL — CLIENT DELIVERABLE"
	}`)
	if r.Code != http.StatusOK {
		t.Fatalf("PUT /api/commercial/branding status=%d body=%s", r.Code, r.Body.String())
	}

	// Public /api/branding endpoint must work WITHOUT JWT auth!
	pubReq := httptest.NewRequest(http.MethodGet, "/api/branding", nil)
	pubW := httptest.NewRecorder()
	s.Handler().ServeHTTP(pubW, pubReq)
	if pubW.Code != http.StatusOK || !strings.Contains(pubW.Body.String(), "CyberSentinel Pro") {
		t.Fatalf("public GET /api/branding failed: code=%d body=%s", pubW.Code, pubW.Body.String())
	}

	// Activate signed commercial license via API
	licBody, _ := json.Marshal(map[string]string{"license_key": licKey})
	r = request("POST", "/api/commercial/license", string(licBody))
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"licensed":true`) || !strings.Contains(r.Body.String(), "Acme Cyber Defense Ltd") {
		t.Fatalf("POST /api/commercial/license failed: code=%d body=%s", r.Code, r.Body.String())
	}

	// Export client-ready HTML/PDF deliverable for single finding
	repW := request("GET", fmt.Sprintf("/api/deliverables/report?finding_id=%d&print=1", initial.FindingID), "")
	if repW.Code != http.StatusOK {
		t.Fatalf("GET /api/deliverables/report status=%d body=%s", repW.Code, repW.Body.String())
	}
	htmlOut := repW.Body.String()
	for _, want := range []string{
		"CyberSentinel Pro",
		"STRICTLY CONFIDENTIAL — CLIENT DELIVERABLE",
		"Prepared by CyberSentinel Red Team",
		"Executive Summary of Findings",
		"Evidence API",
		"window.print()",
	} {
		if !strings.Contains(htmlOut, want) {
			t.Fatalf("deliverable report missing %q", want)
		}
	}
}
