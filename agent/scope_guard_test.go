package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/behemoth/db"
	actool "github.com/Autumn-27/norma/tool"
)

// fixedResolver maps every host to a fixed public address so tests never touch
// real DNS.
func fixedResolver(ip string) func(string) []string {
	return func(string) []string { return []string{ip} }
}

func TestScopeGuardHostWildcardAndCIDR(t *testing.T) {
	g := NewScopeGuard([]string{"example.com", "*.example.org", "10.0.0.0/24", "api.test:8443"}, nil, 0)
	g.SetResolver(fixedResolver("93.184.216.34"))

	cases := []struct {
		host  string
		port  int
		allow bool
	}{
		{"example.com", 443, true},
		{"deep.sub.example.org", 80, true},
		{"sub.example.org", 443, true},
		{"other.org", 443, false},
		{"10.0.0.7", 0, true},
		{"10.0.1.7", 0, false},
		{"api.test", 8443, true},
		{"api.test", 443, false},
	}
	for _, c := range cases {
		if got := g.AuthorizeHost(c.host, c.port); got.Allowed != c.allow {
			t.Errorf("AuthorizeHost(%s:%d) = %v (%s); want %v", c.host, c.port, got.Allowed, got.Reason, c.allow)
		}
	}
}

// A host that cannot be resolved must be denied when a scope is configured:
// otherwise a typo'd or hijacked name silently escapes the allowlist.
func TestScopeGuardFailClosedDNS(t *testing.T) {
	g := NewScopeGuard([]string{"*.example.test"}, nil, 0)
	g.SetResolver(func(string) []string { return nil })
	d := g.AuthorizeHost("app.example.test", 443)
	if d.Allowed {
		t.Fatal("unresolvable host should be denied (fail-closed)")
	}
	if !strings.Contains(d.Reason, "fail-closed") {
		t.Fatalf("reason = %q; want fail-closed explanation", d.Reason)
	}
}

func TestScopeGuardUnscopedAllowsAll(t *testing.T) {
	g := NewScopeGuard(nil, nil, 0)
	if g.ScopeEnabled() {
		t.Fatal("empty guard should be unscoped")
	}
	if d := g.AuthorizeURL("https://anything.example/x"); !d.Allowed {
		t.Fatalf("unscoped guard denied a URL: %s", d.Reason)
	}
	var nilGuard *ScopeGuard
	if d := nilGuard.AuthorizeURL("https://anything.example/x"); !d.Allowed {
		t.Fatal("nil guard should allow")
	}
}

func TestScopeGuardURLPrefixAndTraversal(t *testing.T) {
	g := NewScopeGuard([]string{"https://app.example.test/api"}, nil, 0)
	g.SetResolver(fixedResolver("93.184.216.34"))

	for _, u := range []string{
		"https://app.example.test/api",
		"https://app.example.test/api/v1/users?x=1",
	} {
		if d := g.AuthorizeURL(u); !d.Allowed {
			t.Errorf("%s denied: %s", u, d.Reason)
		}
	}
	for _, u := range []string{
		"https://app.example.test/admin",
		"https://app.example.test/api/../admin",
		"https://app.example.test/api/%2e%2e/admin",
		"https://app.example.test/api//admin",
		"https://other.example.test/api/v1",
		"ftp://app.example.test/api",
	} {
		if d := g.AuthorizeURL(u); d.Allowed {
			t.Errorf("%s should be denied", u)
		}
	}
}

func TestScopeGuardDenyBeatsAllow(t *testing.T) {
	g := NewScopeGuard([]string{"*.example.test"}, []string{"secret.example.test"}, 0)
	g.SetResolver(fixedResolver("93.184.216.34"))
	if d := g.AuthorizeHost("secret.example.test", 443); d.Allowed {
		t.Fatalf("deny rule ignored: %s", d.Reason)
	}
	if d := g.AuthorizeHost("public.example.test", 443); !d.Allowed {
		t.Fatalf("allowed host denied: %s", d.Reason)
	}
}

// A redirect to a different host:port must fail rather than quietly extend the
// engagement to a new target.
func TestScopeHTTPClientReauthorizesRedirects(t *testing.T) {
	var outOfScope string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("next"))
	}))
	defer other.Close()
	outOfScope = other.URL // 127.0.0.1:<other port> — same IP, different port

	inScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, outOfScope+"/next", http.StatusFound)
	}))
	defer inScope.Close()

	// Loopback is always reachable, so denial comes from an explicit deny rule on the
	// second server's port: the redirect hop must still be re-authorized.
	hostPort := strings.TrimPrefix(inScope.URL, "http://")
	otherHostPort := strings.TrimPrefix(other.URL, "http://")
	g := NewScopeGuard([]string{"127.0.0.1"}, []string{otherHostPort}, 0)
	_, err := g.HTTPClient(2 * time.Second).Get(inScope.URL)
	if err == nil {
		t.Fatal("redirect to a denied host:port should fail")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Fatalf("error = %v; want a scope denial", err)
	}
	_ = hostPort
}

func TestScopeGuardCheckCommand(t *testing.T) {
	g := NewScopeGuard([]string{"example.test"}, nil, 0)
	g.SetResolver(fixedResolver("93.184.216.34"))
	if d := g.CheckCommand("curl -s http://example.test/login"); !d.Allowed {
		t.Fatalf("in-scope URL denied: %s", d.Reason)
	}
	if d := g.CheckCommand("nmap -sV 8.8.8.8"); d.Allowed {
		t.Fatal("out-of-scope literal IP should be denied")
	}
	if d := g.CheckCommand("ls -la /tmp"); !d.Allowed {
		t.Fatalf("command without targets denied: %s", d.Reason)
	}
}

// The Bash wrapper converts a denial into a tool error the model can read, and
// never runs the command.
func TestScopeGuardWrappedBashDeniesOutOfScope(t *testing.T) {
	g := NewScopeGuard([]string{"example.test"}, nil, 0)
	g.SetResolver(fixedResolver("93.184.216.34"))
	ran := 0
	tools := wrapScopeGuardTools([]actool.CoreTool{countingTool("Bash", &ran)}, g)
	res, err := tools[0].Call(context.Background(), json.RawMessage(`{"command":"curl http://8.8.8.8/"}`), nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !res.IsError || ran != 0 {
		t.Fatalf("expected denial before execution (isError=%v ran=%d)", res.IsError, ran)
	}
	if res, err = tools[0].Call(context.Background(), json.RawMessage(`{"command":"curl http://example.test/"}`), nil); err != nil || res.IsError || ran != 1 {
		t.Fatalf("in-scope call failed: err=%v isError=%v ran=%d", err, res.IsError, ran)
	}
}

func TestScopeRateLimitPacesPerHost(t *testing.T) {
	g := NewScopeGuard([]string{"example.test"}, nil, 50) // 50 rps → 20ms spacing
	g.SetResolver(fixedResolver("93.184.216.34"))
	start := time.Now()
	for i := 0; i < 3; i++ {
		g.RateLimit(context.Background(), "example.test")
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Fatalf("rate limiter did not pace requests: %s", elapsed)
	}
}

// Local host addresses are never engagement targets: with a scope configured, the
// recording proxy (127.0.0.1) and bind addresses (0.0.0.0) must still pass.
func TestScopeGuardAllowsLocalAddresses(t *testing.T) {
	g := NewScopeGuard([]string{"example.test"}, nil, 0)
	g.SetResolver(fixedResolver("93.184.216.34"))
	for _, host := range []string{"127.0.0.1", "::1", "0.0.0.0"} {
		if d := g.AuthorizeHost(host, 0); !d.Allowed {
			t.Errorf("%s denied: %s", host, d.Reason)
		}
	}
	if d := g.CheckCommand("python3 -m http.server 8000 --bind 0.0.0.0"); !d.Allowed {
		t.Fatalf("bind command denied: %s", d.Reason)
	}
}

func TestScopePatternsFromTaskScopes(t *testing.T) {
	scopes := []db.TaskScope{
		{Kind: "root_domain", Domain: "acme.test"},
		{Kind: "subdomain", Value: "api.acme.test"},
		{Kind: "ip", Value: "203.0.113.9"},
		{Kind: "cidr", Net: "203.0.113.0/24"},
		{Kind: "keyword", Value: "ACME"},
	}
	got := ScopePatternsFromTaskScopes(scopes)
	want := []string{"*.acme.test", "api.acme.test", "203.0.113.9", "203.0.113.0/24"}
	if len(got) != len(want) {
		t.Fatalf("patterns = %v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("patterns[%d] = %q; want %q", i, got[i], want[i])
		}
	}
}

// The scoped HTTP tool returns status/body/hash for an authorized target.
func TestScopedHTTPToolSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Test", "yes")
		_, _ = w.Write([]byte("hello scope"))
	}))
	defer srv.Close()
	hostPort := strings.TrimPrefix(srv.URL, "http://")
	g := NewScopeGuard([]string{hostPort}, nil, 0)
	tool := ScopedHTTPTool(g)
	res, err := tool.Call(context.Background(), json.RawMessage(`{"url":"`+srv.URL+`/"}`), nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", blocksText(res.Content))
	}
	out := blocksText(res.Content)
	for _, want := range []string{`"status":200`, "hello scope", `"body_sha256"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("result missing %q: %s", want, out)
		}
	}
	// Same tool, out-of-scope URL.
	res, _ = tool.Call(context.Background(), json.RawMessage(`{"url":"http://8.8.8.8/"}`), nil)
	if !res.IsError {
		t.Fatal("out-of-scope URL should produce an error result")
	}
}
