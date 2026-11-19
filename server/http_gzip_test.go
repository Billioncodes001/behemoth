package server

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGzipAPICompressesLargeJSONAndSkipsSmallOrSSE(t *testing.T) {
	largeJSON := `{"items":["` + strings.Repeat("vulnerability-evidence-payload-", 40) + `"]}`
	h := gzipAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/small":
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		case "/api/large":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(largeJSON))
		case "/api/logs/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("data: hello\n\n"))
		}
	}))

	// 1) Large JSON with Accept-Encoding: gzip -> compressed
	r := httptest.NewRequest(http.MethodGet, "/api/large", nil)
	r.Header.Set("Accept-Encoding", "gzip, deflate, br")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected gzip encoding, got status=%d ce=%q", w.Code, w.Header().Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	decoded, err := io.ReadAll(zr)
	_ = zr.Close()
	if err != nil || string(decoded) != largeJSON {
		t.Fatalf("decoded mismatch: err=%v len=%d", err, len(decoded))
	}

	// 2) Small JSON -> stays uncompressed
	r = httptest.NewRequest(http.MethodGet, "/api/small", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Content-Encoding") != "" {
		t.Fatalf("small payload should not be gzipped, got %q", w.Header().Get("Content-Encoding"))
	}

	// 3) SSE stream -> never buffered or gzipped
	r = httptest.NewRequest(http.MethodGet, "/api/logs/stream", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Content-Encoding") != "" || w.Body.String() != "data: hello\n\n" {
		t.Fatalf("SSE stream altered: ce=%q body=%q", w.Header().Get("Content-Encoding"), w.Body.String())
	}
}

func TestBasicAuthAllowsPrivateBrowserCacheForHashedStaticAssets(t *testing.T) {
	s, _ := basicAuthTestServer(t)
	initResp := saveBasicAuthForTest(s, `{"enabled":true,"username":"entry","password":"test-password"}`)
	if initResp.Code != http.StatusOK {
		t.Fatal(initResp.Body.String())
	}
	gateCookie := initResp.Result().Cookies()[0]

	inner := s.requireBasicAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if w.Header().Get("Cache-Control") == "" && strings.HasPrefix(r.URL.Path, "/_next/static/") {
			w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Unauthenticated static asset -> 401 with no-store
	w := httptest.NewRecorder()
	inner.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/_next/static/chunks/app.js", nil))
	if w.Code != http.StatusUnauthorized || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unauthed asset must be 401 no-store: code=%d cc=%q", w.Code, w.Header().Get("Cache-Control"))
	}

	// Authenticated cookie on static chunk -> preserves private immutable cache
	req := httptest.NewRequest(http.MethodGet, "/_next/static/chunks/app.js", nil)
	req.AddCookie(gateCookie)
	w = httptest.NewRecorder()
	inner.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "private, max-age=31536000, immutable" {
		t.Fatalf("authed static chunk lost private cache header: code=%d cc=%q", w.Code, w.Header().Get("Cache-Control"))
	}

	// Authenticated cookie on HTML document -> still forced to no-store
	req = httptest.NewRequest(http.MethodGet, "/system/llm/", nil)
	req.AddCookie(gateCookie)
	w = httptest.NewRecorder()
	inner.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("authed HTML document must stay no-store: code=%d cc=%q", w.Code, w.Header().Get("Cache-Control"))
	}
}
