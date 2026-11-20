package proxyv2

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseSingleProxyLineAllCommonFormats(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		defType  ProxyType
		wantType ProxyType
		wantHost string
		wantPort int
		wantUser string
		wantPass string
		wantName string
	}{
		{
			name:     "Webshare ip:port:user:pass",
			line:     "107.180.188.171:6602:demoUser:demoPass99",
			defType:  ProxyTypeHTTP,
			wantType: ProxyTypeHTTP, wantHost: "107.180.188.171", wantPort: 6602,
			wantUser: "demoUser", wantPass: "demoPass99",
		},
		{
			name:     "socks5://ip:port:user:pass",
			line:     "socks5://84.37.41.192:7384:demoUser:demoPass99|US-East|Residential",
			defType:  ProxyTypeHTTP,
			wantType: ProxyTypeSOCKS5, wantHost: "84.37.41.192", wantPort: 7384,
			wantUser: "demoUser", wantPass: "demoPass99", wantName: "US-East",
		},
		{
			name:     "scheme-less user:pass@host:port",
			line:     "alice:s3cr3t@207.137.88.71:9816",
			defType:  ProxyTypeHTTP,
			wantType: ProxyTypeHTTP, wantHost: "207.137.88.71", wantPort: 9816,
			wantUser: "alice", wantPass: "s3cr3t",
		},
		{
			name:     "host:port@user:pass",
			line:     "135.137.86.182:8903@bob:pw123",
			defType:  ProxyTypeSOCKS5,
			wantType: ProxyTypeSOCKS5, wantHost: "135.137.86.182", wantPort: 8903,
			wantUser: "bob", wantPass: "pw123",
		},
		{
			name:     "user:pass:host:port",
			line:     "carol:myPass:153.58.39.39:8504",
			defType:  ProxyTypeHTTP,
			wantType: ProxyTypeHTTP, wantHost: "153.58.39.39", wantPort: 8504,
			wantUser: "carol", wantPass: "myPass",
		},
		{
			name:     "standard URL with special chars",
			line:     "http://user%40org:p%40ss@48.45.4.47:8768|Primary",
			defType:  ProxyTypeHTTP,
			wantType: ProxyTypeHTTP, wantHost: "48.45.4.47", wantPort: 8768,
			wantUser: "user@org", wantPass: "p@ss", wantName: "Primary",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			px, err := ParseSingleProxyLine(tc.line, tc.defType)
			if err != nil {
				t.Fatalf("ParseSingleProxyLine(%q): %v", tc.line, err)
			}
			if px.Type != tc.wantType || px.Host != tc.wantHost || px.Port != tc.wantPort ||
				px.Username != tc.wantUser || px.Password != tc.wantPass || px.Name != tc.wantName {
				t.Fatalf("got %+v", px)
			}
		})
	}
}

func TestImportCSVAndJSONFormatsAndMultipartUpload(t *testing.T) {
	p := NewPool(nil)

	// 1) 4-column CSV with header
	csvData := "ip,port,username,password\n10.0.0.1,8001,u1,p1\n10.0.0.2,8002,u2,p2\n"
	res, err := p.ImportProxies(csvData, ProxyTypeHTTP)
	if err != nil || res.Imported != 2 {
		t.Fatalf("CSV import: err=%v res=%+v", err, res)
	}

	// 2) Webshare-style JSON wrapper {"results": [...]}
	jsonData := `{"results":[{"proxy_address":"10.0.0.3","port":8003,"username":"u3","password":"p3"}]}`
	res, err = p.ImportProxies(jsonData, ProxyTypeSOCKS5)
	if err != nil || res.Imported != 1 {
		t.Fatalf("JSON import: err=%v res=%+v", err, res)
	}

	// 3) Multipart file upload (.txt with Webshare lines)
	h := NewHandler(p)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "Webshare 10 proxies.txt")
	_, _ = fw.Write([]byte("107.180.188.171:6602:u4:p4\n84.37.41.192:7384:u5:p5\n"))
	_ = mw.WriteField("default_type", "http")
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v2/proxy-pool/import", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("multipart upload status=%d body=%s", w.Code, w.Body.String())
	}
	var out ImportResult
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Imported != 2 {
		t.Fatalf("multipart upload result: err=%v out=%+v", err, out)
	}
	if stats := p.GetStats(); stats.Total != 5 || p.GetConfig().Enabled || stats.ActiveProxyID != "" {
		t.Fatalf("expected 5 total proxies, pool disabled, and NO proxy auto-put in use on import, got stats=%+v enabled=%v", stats, p.GetConfig().Enabled)
	}
}

func TestImportTenProxiesAndDisableNeverAutoJumpsToNextRow(t *testing.T) {
	p := NewPool(nil)
	tenProxies := "" +
		"107.180.188.171:6602:u:p\n" +
		"84.37.41.192:7384:u:p\n" +
		"63.127.58.215:8433:u:p\n" +
		"48.45.4.47:8768:u:p\n" +
		"153.58.39.39:8504:u:p\n" +
		"207.137.88.71:9816:u:p\n" +
		"207.137.95.219:8172:u:p\n" +
		"153.58.38.58:8779:u:p\n" +
		"135.137.86.182:8903:u:p\n" +
		"135.137.87.8:8473:u:p\n"

	res, err := p.ImportProxies(tenProxies, ProxyTypeHTTP)
	if err != nil || res.Imported != 10 {
		t.Fatalf("expected 10 imported, got err=%v res=%+v", err, res)
	}

	// 1. Right after import, NO proxy is automatically "In Use" and Pool is NOT auto-enabled!
	if stats := p.GetStats(); stats.ActiveProxyID != "" || p.GetConfig().Enabled {
		t.Fatalf("expected ActiveProxyID='' and Enabled=false on import, got stats=%+v enabled=%v", stats, p.GetConfig().Enabled)
	}

	proxies := p.GetProxies()
	row4ID := proxies[3].ID
	row5ID := proxies[4].ID

	// 2. User explicitly clicks "Use" on Row #4 -> ONLY Row #4 becomes In Use!
	if err := p.ActivateProxy(row4ID); err != nil {
		t.Fatalf("ActivateProxy: %v", err)
	}
	if stats := p.GetStats(); stats.ActiveProxyID != row4ID || !p.GetConfig().Enabled {
		t.Fatalf("expected Row #4 (%s) in use, got stats=%+v", row4ID, stats)
	}

	// 3. User clicks "Disable" on Row #4 -> Row #4 becomes Disabled AND Row #5 is NOT auto-put In Use!
	if err := p.ToggleProxyActive(row4ID); err != nil {
		t.Fatalf("ToggleProxyActive: %v", err)
	}
	statsAfterDisable := p.GetStats()
	if statsAfterDisable.ActiveProxyID != "" || p.GetConfig().Enabled {
		t.Fatalf("clicking Disable must NEVER auto-put next row (%s) in use! got ActiveProxyID=%q enabled=%v",
			row5ID, statsAfterDisable.ActiveProxyID, p.GetConfig().Enabled)
	}

	// 4. User clicks "Use" on Row #5, then clicks "Stop Using" (DeactivateProxy) -> Row #5 stays enabled (not disabled) and no proxy is In Use!
	if err := p.ActivateProxy(row5ID); err != nil {
		t.Fatalf("ActivateProxy row5: %v", err)
	}
	if err := p.DeactivateProxy(row5ID); err != nil {
		t.Fatalf("DeactivateProxy row5: %v", err)
	}
	if stats := p.GetStats(); stats.ActiveProxyID != "" || p.GetConfig().Enabled {
		t.Fatalf("expected no proxy in use after Stop Using, got stats=%+v", stats)
	}
	for _, px := range p.GetProxies() {
		if px.ID == row5ID && (px.Status == StatusDisabled || !px.Active) {
			t.Fatalf("expected Stop Using to leave Row #5 enabled in pool, got %+v", px)
		}
	}
}

