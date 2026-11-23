package c2

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeImplant drives the tunnel protocol in-process: it dequeues downlink
// frames, relays them to real sockets, and posts uplink frames the way an
// implant would (one base64 batch per POST, task_id "tun").
type fakeImplant struct {
	m     *Manager
	id    string
	mu    sync.Mutex
	conns map[uint32]net.Conn
}

func newFakeImplant(m *Manager, id string) *fakeImplant {
	f := &fakeImplant{m: m, id: id, conns: map[uint32]net.Conn{}}
	go f.loop()
	return f
}

func (f *fakeImplant) deliver(fr tunnelFrame) {
	raw := buildFrame(fr.TunnelID, fr.ConnID, fr.Op, fr.Payload)
	_ = f.m.IngestTunnelFrames(f.id, base64.StdEncoding.EncodeToString([]byte(raw)))
}

func (f *fakeImplant) loop() {
	for {
		t, ok := f.m.Dequeue(f.id)
		if !ok {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		for _, fr := range parseFrames(t.Args + "\n") {
			f.handle(fr)
		}
	}
}

func (f *fakeImplant) handle(fr tunnelFrame) {
	switch fr.Op {
	case "open":
		c, err := net.Dial("tcp", string(fr.Payload))
		if err != nil {
			f.deliver(tunnelFrame{TunnelID: fr.TunnelID, ConnID: fr.ConnID, Op: "close"})
			return
		}
		f.mu.Lock()
		f.conns[fr.ConnID] = c
		f.mu.Unlock()
		f.deliver(tunnelFrame{TunnelID: fr.TunnelID, ConnID: fr.ConnID, Op: "open"})
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					f.deliver(tunnelFrame{TunnelID: fr.TunnelID, ConnID: fr.ConnID, Op: "data", Payload: buf[:n]})
				}
				if err != nil {
					f.drop(fr.TunnelID, fr.ConnID)
					return
				}
			}
		}()
	case "data":
		f.mu.Lock()
		c := f.conns[fr.ConnID]
		f.mu.Unlock()
		if c != nil {
			_, _ = c.Write(fr.Payload)
		}
	case "close":
		f.drop(fr.TunnelID, fr.ConnID)
	}
}

func (f *fakeImplant) drop(tun string, cid uint32) {
	f.mu.Lock()
	c, ok := f.conns[cid]
	delete(f.conns, cid)
	f.mu.Unlock()
	if ok {
		_ = c.Close()
		f.deliver(tunnelFrame{TunnelID: tun, ConnID: cid, Op: "close"})
	}
}

// socksDial performs the client half of a SOCKS5 CONNECT and returns the
// relayed stream plus the SOCKS reply code.
func socksDial(t *testing.T, addr, user, pass, target string) (net.Conn, byte) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	greet := []byte{5, 1, 0}
	if user != "" {
		greet = []byte{5, 1, 2}
	}
	if _, err := c.Write(greet); err != nil {
		t.Fatalf("greet: %v", err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		t.Fatalf("method reply: %v", err)
	}
	if sel[1] == 2 {
		msg := []byte{1, byte(len(user))}
		msg = append(msg, user...)
		msg = append(msg, byte(len(pass)))
		msg = append(msg, pass...)
		if _, err := c.Write(msg); err != nil {
			t.Fatalf("auth: %v", err)
		}
		var ar [2]byte
		if _, err := io.ReadFull(c, ar[:]); err != nil {
			t.Fatalf("auth reply: %v", err)
		}
		if ar[1] != 0 {
			return c, socksRepTTL
		}
	}
	host, portStr, _ := net.SplitHostPort(target)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatalf("connect: %v", err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	return c, rep[1]
}

func TestTunnelRelayEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pivot-ok"))
	}))
	defer srv.Close()

	m := newTestManager(t)
	im, err := m.BuildImplant(BuildOpts{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	newFakeImplant(m, im.ID)

	tun, err := m.TunnelMgr().OpenTunnel(TunnelOpts{ImplantID: im.ID, Target: strings.TrimPrefix(srv.URL, "http://"), Auth: true})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer m.TunnelMgr().CloseTunnel(tun.ID)

	c, code := socksDial(t, tun.Addr, tun.User, tun.Pass, tun.Target)
	if code != socksRepOK {
		t.Fatalf("socks reply %d", code)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	req := "GET / HTTP/1.1\r\nHost: " + tun.Target + "\r\nConnection: close\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "pivot-ok") {
		t.Fatalf("unexpected body %q", body)
	}
	info, ok := m.TunnelMgr().GetTunnel(tun.ID)
	if !ok || info.UpBytes == 0 || info.DownBytes == 0 {
		t.Fatalf("counters not updated: %+v", info)
	}
	if !strings.HasPrefix(info.Proxy, "socks5://u") {
		t.Fatalf("proxy string: %s", info.Proxy)
	}
}

func TestTunnelAuthAndAllowlist(t *testing.T) {
	m := newTestManager(t)
	im, _ := m.BuildImplant(BuildOpts{})
	newFakeImplant(m, im.ID)
	tun, err := m.TunnelMgr().OpenTunnel(TunnelOpts{ImplantID: im.ID, Target: "127.0.0.1:9", Auth: true})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer m.TunnelMgr().CloseTunnel(tun.ID)

	// Wrong password: rejected during auth.
	c, code := socksDial(t, tun.Addr, tun.User, "nope", "127.0.0.1:9")
	defer c.Close()
	if code != socksRepTTL {
		t.Fatalf("bad auth reply code %d", code)
	}
	// Target outside the allowlist: refused with an unreachable reply.
	c2c, code2 := socksDial(t, tun.Addr, tun.User, tun.Pass, "127.0.0.1:2222")
	defer c2c.Close()
	if code2 != socksRepHostUnreachable {
		t.Fatalf("disallowed target reply %d", code2)
	}
}

func TestParseFramesSkipsGarbage(t *testing.T) {
	in := "aa|1|open|MTI3LjAuMC4xOjgw\n\ngarbage\nbb|x|data|!!!\ncc|2|data|aGk=\n"
	frames := parseFrames(in)
	if len(frames) != 2 {
		t.Fatalf("want 2 frames, got %d: %+v", len(frames), frames)
	}
	if frames[1].ConnID != 2 || string(frames[1].Payload) != "hi" {
		t.Fatalf("bad frame: %+v", frames[1])
	}
}

func TestTunnelQueueLimitAndClose(t *testing.T) {
	m := newTestManager(t)
	im, _ := m.BuildImplant(BuildOpts{})
	tun, err := m.TunnelMgr().OpenTunnel(TunnelOpts{ImplantID: im.ID, Target: "127.0.0.1:9"})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < tunnelMaxPending+5; i++ {
		_ = m.enqueueTunnel(im.ID, buildFrame(tun.ID, 1, "data", []byte("x")))
	}
	if got := len(m.tunPending[im.ID]); got != tunnelMaxPending {
		t.Fatalf("queue len %d, want %d", got, tunnelMaxPending)
	}
	if !m.TunnelMgr().CloseTunnel(tun.ID) {
		t.Fatalf("close: tunnel not found")
	}
	if _, ok := m.TunnelMgr().GetTunnel(tun.ID); ok {
		t.Fatalf("tunnel still listed after close")
	}
}
