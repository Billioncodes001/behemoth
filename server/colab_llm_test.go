package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestColabG4ExtractOAuthCodeAndStatusAPI(t *testing.T) {
	// 1. Verify extractOAuthCodeFromInput handles raw codes AND full redirect URLs
	if got := extractOAuthCodeFromInput("4/0AeaYSHB_test_code_123"); got != "4/0AeaYSHB_test_code_123" {
		t.Fatalf("unexpected raw code: %q", got)
	}
	if got := extractOAuthCodeFromInput("https://sdk.cloud.google.com/applicationdefaultauthcode.html?code=4%2F0AeaYSHB_url_code&scope=email"); got != "4/0AeaYSHB_url_code" {
		t.Fatalf("unexpected URL code extraction: %q", got)
	}

	// 2. Verify GET /api/llm/colab-g4/status returns clean JSON shape
	s, _, req := trafficEvidenceServer(t)
	w := req(http.MethodGet, "/api/llm/colab-g4/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/llm/colab-g4/status, got %d: %s", w.Code, w.Body.String())
	}
	var st ColabG4Status
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("unmarshal ColabG4Status: %v", err)
	}
	if st.Port != colabDefaultPort || st.EndpointURL == "" || st.ModelName == "" {
		t.Fatalf("unexpected ColabG4Status defaults: %+v", st)
	}

	// 3. Verify upsertColabLLMProfile saves and updates the profile idempotently in PostgreSQL
	id1, err := s.upsertColabLLMProfile("3.05", 131072, 18100, false)
	if err != nil || id1 <= 0 {
		t.Fatalf("upsertColabLLMProfile first call failed: id=%d err=%v", id1, err)
	}
	id2, err := s.upsertColabLLMProfile("2.51", 262144, 18100, false)
	if err != nil || id2 != id1 {
		t.Fatalf("expected upsertColabLLMProfile to update existing profile #%d, got #%d err=%v", id1, id2, err)
	}
	prof, err := s.m.pg.ProfileByID(id2)
	if err != nil || prof == nil || prof.Model != "glm-5.3-flash-uncensored-2.51bpw" || prof.ContextWindowK != 256 || prof.MaxTokens != 8192 {
		t.Fatalf("unexpected persisted Colab G4 LLMProfile: %+v (err=%v)", prof, err)
	}
}
