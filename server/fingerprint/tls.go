package fingerprint

import (
	"context"
	"crypto/rand"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TLSSpec defines a TLS client hello fingerprint.
type TLSSpec struct {
	ID          string
	Name        string
	ClientHello utls.ClientHelloID
	Description string
}

// Built-in TLS fingerprints that mimic real browsers.
var tlsSpecs = []TLSSpec{
	{ID: "chrome_120", Name: "Chrome 120", ClientHello: utls.HelloChrome_Auto, Description: "Latest Chrome fingerprint"},
	{ID: "firefox_120", Name: "Firefox 120", ClientHello: utls.HelloFirefox_Auto, Description: "Latest Firefox fingerprint"},
	{ID: "safari_17", Name: "Safari 17", ClientHello: utls.HelloSafari_Auto, Description: "Safari iOS 17"},
	{ID: "edge_120", Name: "Edge 120", ClientHello: utls.HelloEdge_Auto, Description: "Microsoft Edge"},
	{ID: "ios_17", Name: "iOS 17", ClientHello: utls.HelloIOS_Auto, Description: "iOS Safari"},
	{ID: "randomized", Name: "Randomized", ClientHello: utls.HelloRandomized, Description: "Randomized JA3"},
}

// GetTLSSpec returns a TLS spec by ID (defaults to Chrome).
func GetTLSSpec(id string) TLSSpec {
	for _, spec := range tlsSpecs {
		if spec.ID == id {
			return spec
		}
	}
	return tlsSpecs[0] // Default to Chrome
}

// GetAllTLSSpecs returns all available TLS specs.
func GetAllTLSSpecs() []TLSSpec {
	return tlsSpecs
}

// RandomTLSSpec returns a random TLS spec.
func RandomTLSSpec() TLSSpec {
	if len(tlsSpecs) == 0 {
		return TLSSpec{}
	}
	b := make([]byte, 4)
	rand.Read(b)
	idx := int(b[0]) % len(tlsSpecs)
	return tlsSpecs[idx]
}

// NewTLSHTTPClient creates an *http.Client with uTLS fingerprint.
func NewTLSHTTPClient(spec TLSSpec) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := net.Dial(network, addr)
				if err != nil {
					return nil, err
				}

				host, _, _ := net.SplitHostPort(addr)
				if host == "" {
					host = addr
				}

				uconn := utls.UClient(conn, &utls.Config{
					ServerName: host,
				}, spec.ClientHello)

				if err := uconn.HandshakeContext(ctx); err != nil {
					conn.Close()
					return nil, err
				}

				return uconn, nil
			},
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
		},
	}
}
