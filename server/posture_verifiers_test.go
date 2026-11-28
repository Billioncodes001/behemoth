package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestInterceptRulesV6AllowSocketShutdownWhileBlockingHostShutdown(t *testing.T) {
	shutdownPat := regexp.MustCompile(`(?m)(?:^|[;&|]\s*)(?:sudo\s+)?(?:/usr/sbin/|/sbin/)?(?:shutdown|reboot|poweroff|halt|init\s+[06])(?:\s+-[a-zA-Z0-9]+|\s+now|\s+\+[0-9]+|\s*[;&|\r\n]|\s*$)`)
	destructivePat := regexp.MustCompile(`(?im)(?:\b(?:rm\s+-rf\s+/|mkfs|dd\s+if=|:\(\)\s*\{)|>\s*/dev/sd|(?:^|[;&|]\s*)(?:sudo\s+)?(?:/usr/sbin/|/sbin/)?(?:shutdown|reboot)(?:\s+-[a-zA-Z0-9]+|\s+now|\s*$))`)

	safeInputs := []string{
		`python3 -c "import socket; b = socket.socket(); b.shutdown(socket.SHUT_WR)"`,
		`curl -s https://target.example.com/api/shutdown-status`,
		`node -e "server.shutdown()"`,
	}
	for _, cmd := range safeInputs {
		if shutdownPat.MatchString(cmd) || destructivePat.MatchString(cmd) {
			t.Fatalf("expected safe socket/API command not to match host shutdown rule: %q", cmd)
		}
	}

	blockedInputs := []string{
		`shutdown -h now`,
		`sudo reboot`,
		`echo ok; /sbin/poweroff`,
	}
	for _, cmd := range blockedInputs {
		if !shutdownPat.MatchString(cmd) {
			t.Fatalf("expected host shutdown command to remain blocked: %q", cmd)
		}
	}
}

func TestLoopbackHostPortBypass(t *testing.T) {
	for _, hp := range []string{"127.0.0.1:8899", "localhost:3000", "[::1]:8080", "127.0.0.5:9000"} {
		if !isLoopbackHostPort(hp) {
			t.Fatalf("expected %q to be recognized as loopback", hp)
		}
	}
	for _, hp := range []string{"example.com:443", "107.180.188.171:6602"} {
		if isLoopbackHostPort(hp) {
			t.Fatalf("expected %q NOT to be loopback", hp)
		}
	}
}

func TestProxiedTCPRelayAndPostureVerifiers(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	ctx := context.Background()

	// 1. Test proxied_tcp_relay (check_port, open_relay, list_relays, close_relay)
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.WriteString(conn, "220 TestService Ready\r\n")
				buf := make([]byte, 64)
				n, _ := conn.Read(buf)
				if n > 0 {
					_, _ = conn.Write(buf[:n])
				}
			}(c)
		}
	}()
	_, portStr, _ := net.SplitHostPort(tcpLn.Addr().String())
	portNum, _ := strconv.Atoi(portStr)

	relayTool := s.toolProxiedTCPRelay()
	checkRes, err := relayTool.Call(ctx, json.RawMessage(`{"action":"check_port","host":"127.0.0.1","port":`+strconv.Itoa(portNum)+`}`), nil)
	if err != nil || checkRes.IsError {
		t.Fatalf("check_port failed: err=%v res=%s", err, checkRes.Flatten())
	}
	if !strings.Contains(checkRes.Flatten(), "220 TestService Ready") {
		t.Fatalf("expected greeting in check_port output, got %s", checkRes.Flatten())
	}

	openRes, err := relayTool.Call(ctx, json.RawMessage(`{"action":"open_relay","host":"127.0.0.1","port":`+strconv.Itoa(portNum)+`,"ttl_seconds":60}`), nil)
	if err != nil || openRes.IsError {
		t.Fatalf("open_relay failed: err=%v res=%s", err, openRes.Flatten())
	}
	var opened map[string]any
	_ = json.Unmarshal([]byte(openRes.Flatten()), &opened)
	localAddr, _ := opened["local_addr"].(string)
	relayID, _ := opened["relay_id"].(string)
	if localAddr == "" || relayID == "" {
		t.Fatalf("unexpected open_relay payload: %s", openRes.Flatten())
	}

	rc, err := net.DialTimeout("tcp", localAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial local relay %s: %v", localAddr, err)
	}
	_ = rc.SetDeadline(time.Now().Add(3 * time.Second))
	greetBuf := make([]byte, 64)
	gn, _ := rc.Read(greetBuf)
	if !strings.Contains(string(greetBuf[:gn]), "220 TestService Ready") {
		t.Fatalf("expected tunneled greeting, got %q", string(greetBuf[:gn]))
	}
	_ = rc.Close()

	_, _ = relayTool.Call(ctx, json.RawMessage(`{"action":"close_relay","relay_id":"`+relayID+`"}`), nil)

	// 2. Test public /api/oast-cb/ webhook callback collector
	cbCreate := s.toolCreateCallbackListener()
	cbPoll := s.toolPollCallbackEvents()
	createRes, err := cbCreate.Call(ctx, json.RawMessage(`{"label":"webhook-test","public_base_url":"https://console.example.com"}`), nil)
	if err != nil || createRes.IsError {
		t.Fatalf("create_callback_listener failed: %v %s", err, createRes.Flatten())
	}
	var createdCB map[string]any
	_ = json.Unmarshal([]byte(createRes.Flatten()), &createdCB)
	tok, _ := createdCB["token"].(string)
	cbPath, _ := createdCB["callback_path"].(string)

	// Hit through full Server HTTP handler (which wraps requireBasicAuth + requireAuth + securityMiddleware)
	httpSrv := httptest.NewServer(s.Handler())
	defer httpSrv.Close()
	resp, err := http.Post(httpSrv.URL+cbPath, "application/json", bytes.NewBufferString(`{"ping":true}`))
	if err != nil {
		t.Fatalf("POST callback failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on unauthenticated callback endpoint, got %d", resp.StatusCode)
	}

	pollRes, err := cbPoll.Call(ctx, json.RawMessage(`{"token":"`+tok+`"}`), nil)
	if err != nil || pollRes.IsError || !strings.Contains(pollRes.Flatten(), `"count":1`) {
		t.Fatalf("expected 1 callback event, got err=%v out=%s", err, pollRes.Flatten())
	}

	// 3. Test multi-role access-control matrix, frontend bundle auditor, and idempotency verifier
	var txHits atomic.Int64
	appMux := http.NewServeMux()
	appMux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><head><script src="/static/app.js"></script></head><body>App</body></html>`)
	})
	appMux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = io.WriteString(w, `const api = "/api/v1/orders"; //# sourceMappingURL=app.js.map`)
	})
	appMux.HandleFunc("/api/v1/orders/42", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Intentionally lacks tenant check so user_b also gets 200
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"order_id":42,"owner":"user_a"}`)
	})
	appMux.HandleFunc("/api/v1/redeem", func(w http.ResponseWriter, r *http.Request) {
		if txHits.Add(1) == 1 {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusConflict)
	})
	targetApp := httptest.NewServer(appMux)
	defer targetApp.Close()

	manageAuth := s.toolManageAuthSessions()
	_, _ = manageAuth.Call(ctx, json.RawMessage(`{"action":"clear"}`), nil)
	_, _ = manageAuth.Call(ctx, json.RawMessage(`{"action":"set","role":"user_a","bearer_token":"tok_a"}`), nil)
	_, _ = manageAuth.Call(ctx, json.RawMessage(`{"action":"set","role":"user_b","bearer_token":"tok_b"}`), nil)

	matrixRes, err := s.toolVerifyAccessControlMatrix().Call(ctx, json.RawMessage(`{"url":"`+targetApp.URL+`/api/v1/orders/42","expected_authorized":["user_a"]}`), nil)
	if err != nil || matrixRes.IsError || !strings.Contains(matrixRes.Flatten(), `"role":"user_b"`) || !strings.Contains(matrixRes.Flatten(), "expected_authorized") {
		t.Fatalf("expected policy discrepancy for user_b, got err=%v out=%s", err, matrixRes.Flatten())
	}

	feRes, err := s.toolAuditFrontendAPISurface().Call(ctx, json.RawMessage(`{"url":"`+targetApp.URL+`/app"}`), nil)
	if err != nil || feRes.IsError || !strings.Contains(feRes.Flatten(), "/api/v1/orders") || !strings.Contains(feRes.Flatten(), "SourceMap Reference") {
		t.Fatalf("expected route & sourcemap posture finding, got err=%v out=%s", err, feRes.Flatten())
	}

	idemRes, err := s.toolVerifyEndpointIdempotency().Call(ctx, json.RawMessage(`{"url":"`+targetApp.URL+`/api/v1/redeem","concurrency":4}`), nil)
	if err != nil || idemRes.IsError || !strings.Contains(idemRes.Flatten(), `"success_2xx_count":1`) {
		t.Fatalf("expected atomic 1-winner idempotency result, got err=%v out=%s", err, idemRes.Flatten())
	}

	// 4. Test static source route auditor
	tmpDir := t.TempDir()
	sampleRouteFile := filepath.Join(tmpDir, "routes.js")
	if err := os.WriteFile(sampleRouteFile, []byte("app.get('/api/public-export', handler);\napp.post('/api/profile', requireAuth, updateProfile);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srcIn, _ := json.Marshal(map[string]any{"source_dir": tmpDir})
	srcRes, err := s.toolAuditSourceRoutes().Call(ctx, srcIn, nil)
	if err != nil || srcRes.IsError || !strings.Contains(srcRes.Flatten(), `"routes_count":2`) || !strings.Contains(srcRes.Flatten(), `"routes_missing_apparent_auth":1`) {
		t.Fatalf("unexpected audit_source_routes output: err=%v out=%s", err, srcRes.Flatten())
	}
}

func TestTaskDeduplicationDomainWorkspaceAndModelParser(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	ctx := context.Background()

	// 1. Verify spawn_task deduplicates active tasks targeting the same domain
	spawn := s.toolSpawnTask()
	firstRes, err := spawn.Call(ctx, json.RawMessage(`{"description":"Pentest portal.acme-corp.example","goal":"Scan https://portal.acme-corp.example for vulnerabilities"}`), nil)
	if err != nil || firstRes.IsError || !strings.Contains(firstRes.Flatten(), "task created:") {
		t.Fatalf("first spawn_task failed: err=%v out=%s", err, firstRes.Flatten())
	}
	secondRes, err := spawn.Call(ctx, json.RawMessage(`{"description":"Follow-up on portal.acme-corp.example","goal":"Exploit XSS on portal.acme-corp.example"}`), nil)
	if err != nil || secondRes.IsError || !strings.Contains(secondRes.Flatten(), "reused existing active task:") {
		t.Fatalf("expected second spawn_task on same domain to reuse existing active task, got err=%v out=%s", err, secondRes.Flatten())
	}

	// 2. Verify domain workspace structure + session display_name enrichment
	conv, err := s.m.pg.CreateConversation("auto", "portal.acme-corp.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	sessID := s.convBusyKey(conv.ID)
	s.ensureDomainWorkspaceStructure("portal.acme-corp.example", sessID)

	w := httptest.NewRecorder()
	s.wsList(w, httptest.NewRequest(http.MethodGet, "/api/workspace/list?path=sessions", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "acme-corp.example ("+sessID+")") {
		t.Fatalf("expected base-domain session display_name, got status=%d body=%s", w.Code, w.Body.String())
	}

	w2 := httptest.NewRecorder()
	s.wsList(w2, httptest.NewRequest(http.MethodGet, "/api/workspace/list?path=domains/acme-corp.example", nil))
	if w2.Code != http.StatusOK || !strings.Contains(w2.Body.String(), "CREDENTIALS.md") {
		t.Fatalf("expected CREDENTIALS.md in consolidated root domain workspace, got status=%d body=%s", w2.Code, w2.Body.String())
	}

	// 3. Verify multi-provider model catalog parser (OpenAI, Gemini models/ prefix, Ollama)
	models := parseProviderModelListJSON([]byte(`{"models":[{"name":"models/gemini-2.5-pro"},{"id":"deepseek-r1"}],"data":[{"id":"gpt-4o"}]}`))
	if len(models) != 3 || models[0] != "gpt-4o" || models[1] != "gemini-2.5-pro" || models[2] != "deepseek-r1" {
		t.Fatalf("unexpected parsed model list: %+v", models)
	}
}
