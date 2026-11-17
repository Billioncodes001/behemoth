package search

import (
	"context"
	"testing"
	"time"
)

func TestDuckDuckGoParseResults(t *testing.T) {
	sampleHTML := `
<div class="links_main links_deep result__body">
  <h2 class="result__title">
    <a rel="nofollow" class="result__a" href="https://dictionary.cambridge.org/dictionary/english/hi">HI | English meaning - Cambridge Dictionary</a>
  </h2>
  <div class="result__extras">
    <div class="result__extras__url">
      <a class="result__url" href="https://dictionary.cambridge.org/dictionary/english/hi">dictionary.cambridge.org</a>
    </div>
  </div>
  <a class="result__snippet" href="https://dictionary.cambridge.org/dictionary/english/hi"><b>HI</b> definition: 1. used as an informal greeting.</a>
</div>`
	ddg := NewDuckDuckGoSearchEngine(true)
	res := ddg.parseResults(sampleHTML, 5)
	if len(res) != 1 {
		t.Fatalf("expected 1 parsed result, got %d", len(res))
	}
	if res[0].URL != "https://dictionary.cambridge.org/dictionary/english/hi" {
		t.Fatalf("unexpected URL: %s", res[0].URL)
	}
	if res[0].Title != "HI | English meaning - Cambridge Dictionary" {
		t.Fatalf("unexpected Title: %s", res[0].Title)
	}
}

func TestOrchestratorLiveSearch(t *testing.T) {
	orch := NewOrchestrator(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for _, tc := range []struct {
		mode  SearchMode
		query string
	}{
		{ModeGeneral, "hi"},
		{ModeExploit, "CVE-2024"},
		{ModeTechnical, "sql injection"},
	} {
		sr, err := orch.Search(ctx, Request{Query: tc.query, Mode: tc.mode, MaxResults: 5})
		if err != nil {
			t.Fatalf("mode %s search failed: %v", tc.mode, err)
		}
		t.Logf("mode=%s query=%q -> total=%d engines=%v duration=%dms",
			tc.mode, tc.query, sr.TotalResults, sr.EnginesUsed, sr.QueryTimeMS)
		if sr.TotalResults == 0 {
			t.Errorf("expected >0 results for mode=%s query=%q, got 0 (warnings=%v)", tc.mode, tc.query, sr.Warnings)
		}
		for i, r := range sr.Results {
			t.Logf("  [%d] %s (%s) — %s", i+1, r.Title, r.Engine, r.URL)
		}
	}
}

