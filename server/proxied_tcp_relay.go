package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

type localProxyRelay struct {
	ID         string    `json:"id"`
	LocalAddr  string    `json:"local_addr"`
	RemoteAddr string    `json:"remote_addr"`
	ViaProxy   bool      `json:"via_proxy"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	ln         net.Listener
	cancel     context.CancelFunc
}

var (
	relayRegistryMu sync.Mutex
	relayRegistry   = map[string]*localProxyRelay{}
)

// newProxyAwareHTTPClient returns an HTTP client that routes through the active
// credential-free local dynamic forwarder when OutboundProxyAddr is enabled.
func (s *Server) newProxyAwareHTTPClient(timeout time.Duration, followRedirects bool) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true},
	}
	if s != nil && s.m != nil && s.m.HasOutboundProxy() {
		if raw := strings.TrimSpace(s.m.OutboundProxyAddr()); raw != "" {
			if pu, err := url.Parse(raw); err == nil && pu.Host != "" {
				tr.Proxy = http.ProxyURL(pu)
			}
		}
	}
	cl := &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
	if !followRedirects {
		cl.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return cl
}

// dialProxyAwareTCP dials host:port through s.m.OutboundProxyAddr() via HTTP CONNECT
// whenever an outbound proxy is configured (unless the target is loopback), keeping
// upstream proxy credentials out of agent scripts.
func (s *Server) dialProxyAwareTCP(ctx context.Context, targetHostPort string, timeout time.Duration) (net.Conn, bool, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	useProxy := false
	var proxyHost string
	if s != nil && s.m != nil && s.m.HasOutboundProxy() && !isLoopbackHostPort(targetHostPort) {
		if raw := strings.TrimSpace(s.m.OutboundProxyAddr()); raw != "" {
			if pu, err := url.Parse(raw); err == nil && pu.Host != "" {
				useProxy = true
				proxyHost = pu.Host
			}
		}
	}
	if !useProxy {
		c, err := (&net.Dialer{Timeout: timeout}).DialContext(dialCtx, "tcp", targetHostPort)
		return c, false, err
	}

	rawConn, err := (&net.Dialer{Timeout: timeout}).DialContext(dialCtx, "tcp", proxyHost)
	if err != nil {
		return nil, true, fmt.Errorf("dial local proxy forwarder: %w", err)
	}
	_ = rawConn.SetDeadline(time.Now().Add(timeout))
	reqLine := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetHostPort, targetHostPort)
	if _, err := io.WriteString(rawConn, reqLine); err != nil {
		_ = rawConn.Close()
		return nil, true, fmt.Errorf("write CONNECT request: %w", err)
	}
	br := bufio.NewReader(rawConn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = rawConn.Close()
		return nil, true, fmt.Errorf("read CONNECT response: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = rawConn.Close()
		return nil, true, fmt.Errorf("proxy CONNECT returned status %d (%s)", resp.StatusCode, resp.Status)
	}
	_ = rawConn.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		buf := make([]byte, br.Buffered())
		_, _ = io.ReadFull(br, buf)
		return &prefixedConn{Conn: rawConn, prefix: buf}, true, nil
	}
	return rawConn, true, nil
}

type prefixedConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func randomShortHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) toolProxiedTCPRelay() actool.CoreTool {
	return wrTool("proxied_tcp_relay",
		"Verify TCP service connectivity through the active BEHEMOTH outbound proxy or open a managed localhost (127.0.0.1) TCP relay so standard clients (psql, mysql, redis-cli, curl) connect cleanly without raw socket scripts or exposed proxy credentials.",
		objSchema(map[string]any{
			"action":          strParam("Operation: check_port | open_relay | list_relays | close_relay"),
			"host":            strParam("Target hostname or IP (required for check_port and open_relay)"),
			"port":            map[string]any{"type": "integer", "description": "Target TCP port (1-65535, required for check_port and open_relay)"},
			"relay_id":        strParam("Relay ID to close when action=close_relay"),
			"ttl_seconds":     map[string]any{"type": "integer", "description": "Auto-close TTL in seconds for open_relay (default 600, max 3600)"},
			"timeout_seconds": map[string]any{"type": "integer", "description": "Connection timeout in seconds (default 8, max 30)"},
		}, "action"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Action         string `json:"action"`
				Host           string `json:"host"`
				Port           int    `json:"port"`
				RelayID        string `json:"relay_id"`
				TTLSeconds     int    `json:"ttl_seconds"`
				TimeoutSeconds int    `json:"timeout_seconds"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input JSON: " + err.Error()), nil
			}
			action := strings.ToLower(strings.TrimSpace(a.Action))
			timeout := 8 * time.Second
			if a.TimeoutSeconds > 0 {
				if a.TimeoutSeconds > 30 {
					a.TimeoutSeconds = 30
				}
				timeout = time.Duration(a.TimeoutSeconds) * time.Second
			}

			switch action {
			case "list_relays":
				now := time.Now()
				relayRegistryMu.Lock()
				items := make([]map[string]any, 0, len(relayRegistry))
				for id, r := range relayRegistry {
					if now.After(r.ExpiresAt) {
						r.cancel()
						_ = r.ln.Close()
						delete(relayRegistry, id)
						continue
					}
					items = append(items, map[string]any{
						"relay_id":    r.ID,
						"local_addr":  r.LocalAddr,
						"remote_addr": r.RemoteAddr,
						"via_proxy":   r.ViaProxy,
						"expires_at":  r.ExpiresAt.Format(time.RFC3339),
					})
				}
				relayRegistryMu.Unlock()
				return jsonResult(map[string]any{"active_relays": items, "count": len(items)})

			case "close_relay":
				id := strings.TrimSpace(a.RelayID)
				if id == "" {
					return actool.Errorf("relay_id is required for close_relay"), nil
				}
				relayRegistryMu.Lock()
				r, ok := relayRegistry[id]
				if ok {
					delete(relayRegistry, id)
				}
				relayRegistryMu.Unlock()
				if !ok {
					return jsonResult(map[string]any{"closed": false, "message": "relay not found or already expired"})
				}
				r.cancel()
				_ = r.ln.Close()
				return jsonResult(map[string]any{"closed": true, "relay_id": id})

			case "check_port":
				host := strings.TrimSpace(a.Host)
				if host == "" || a.Port < 1 || a.Port > 65535 {
					return actool.Errorf("valid host and port (1-65535) are required"), nil
				}
				addr := net.JoinHostPort(host, strconv.Itoa(a.Port))
				start := time.Now()
				conn, viaProxy, err := s.dialProxyAwareTCP(ctx, addr, timeout)
				latency := time.Since(start).Milliseconds()
				if err != nil {
					return jsonResult(map[string]any{
						"reachable":  false,
						"target":     addr,
						"via_proxy":  viaProxy,
						"latency_ms": latency,
						"error":      err.Error(),
					})
				}
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
				buf := make([]byte, 256)
				n, _ := conn.Read(buf)
				greeting := strings.TrimSpace(toSafeASCII(buf[:n]))
				return jsonResult(map[string]any{
					"reachable":        true,
					"target":           addr,
					"via_proxy":        viaProxy,
					"latency_ms":       latency,
					"service_greeting": greeting,
				})

			case "open_relay":
				host := strings.TrimSpace(a.Host)
				if host == "" || a.Port < 1 || a.Port > 65535 {
					return actool.Errorf("valid host and port (1-65535) are required"), nil
				}
				ttl := 600 * time.Second
				if a.TTLSeconds > 0 {
					if a.TTLSeconds > 3600 {
						a.TTLSeconds = 3600
					}
					ttl = time.Duration(a.TTLSeconds) * time.Second
				}
				remoteAddr := net.JoinHostPort(host, strconv.Itoa(a.Port))
				// Verify connectivity once before binding local relay.
				probeConn, viaProxy, err := s.dialProxyAwareTCP(ctx, remoteAddr, timeout)
				if err != nil {
					return jsonResult(map[string]any{
						"opened":      false,
						"remote_addr": remoteAddr,
						"via_proxy":   viaProxy,
						"error":       err.Error(),
					})
				}
				_ = probeConn.Close()

				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					return actool.Errorf("bind local relay listener: " + err.Error()), nil
				}
				parentCtx := context.Background()
				if s != nil && s.ctx != nil && s.ctx.Err() == nil {
					parentCtx = s.ctx
				}
				relayCtx, cancel := context.WithTimeout(parentCtx, ttl)
				id := "relay-" + randomShortHex(4)
				entry := &localProxyRelay{
					ID:         id,
					LocalAddr:  ln.Addr().String(),
					RemoteAddr: remoteAddr,
					ViaProxy:   viaProxy,
					CreatedAt:  time.Now().UTC(),
					ExpiresAt:  time.Now().UTC().Add(ttl),
					ln:         ln,
					cancel:     cancel,
				}
				relayRegistryMu.Lock()
				relayRegistry[id] = entry
				relayRegistryMu.Unlock()

				go func() {
					defer func() {
						cancel()
						_ = ln.Close()
						relayRegistryMu.Lock()
						delete(relayRegistry, id)
						relayRegistryMu.Unlock()
					}()
					go func() {
						<-relayCtx.Done()
						_ = ln.Close()
					}()
					for {
						clientConn, acceptErr := ln.Accept()
						if acceptErr != nil {
							return
						}
						go func(c net.Conn) {
							defer c.Close()
							upConn, _, dialErr := s.dialProxyAwareTCP(relayCtx, remoteAddr, timeout)
							if dialErr != nil {
								return
							}
							defer upConn.Close()
							done := make(chan struct{}, 2)
							go func() { _, _ = io.Copy(upConn, c); done <- struct{}{} }()
							go func() { _, _ = io.Copy(c, upConn); done <- struct{}{} }()
							<-done
						}(clientConn)
					}
				}()

				_, localPortStr, _ := net.SplitHostPort(entry.LocalAddr)
				return jsonResult(map[string]any{
					"opened":      true,
					"relay_id":    entry.ID,
					"local_addr":  entry.LocalAddr,
					"local_host":  "127.0.0.1",
					"local_port":  localPortStr,
					"remote_addr": entry.RemoteAddr,
					"via_proxy":   entry.ViaProxy,
					"expires_at":  entry.ExpiresAt.Format(time.RFC3339),
				})

			default:
				return actool.Errorf("unsupported action; choose check_port, open_relay, list_relays, or close_relay"), nil
			}
		})
}

func toSafeASCII(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 32 && c < 127 {
			sb.WriteByte(c)
		} else if c == '\n' || c == '\r' || c == '\t' {
			sb.WriteByte(' ')
		}
	}
	return sb.String()
}
