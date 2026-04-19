// Anti-crash HTTP transport and socket exhaustion detection adapted from
// cloudflare-site-scanner/engine (see ATTRIBUTION.md).
package scanner

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// IsSocketExhaustion reports whether err indicates OS-level socket / FD exhaustion
// (e.g. EMFILE, ENFILE). Used to back off instead of tight retry loops.
func IsSocketExhaustion(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	for _, pattern := range []string{
		"too many open files",
		"socket: too many open files",
		"resource temporarily unavailable",
		"EMFILE",
		"ENFILE",
		"wsaemfile",
		"An operation on a socket could not be performed",
	} {
		if containsInsensitive(errStr, pattern) {
			return true
		}
	}
	return false
}

func containsInsensitive(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			sc := s[i+j]
			pc := substr[j]
			if sc >= 'A' && sc <= 'Z' {
				sc += 32
			}
			if pc >= 'A' && pc <= 'Z' {
				pc += 32
			}
			if sc != pc {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// NewAntiCrashHTTPTransport builds an http.Transport tuned for high concurrency:
// no connection pooling / keep-alives, tight per-host limits, and dialer keep-alive
// disabled to reduce FD churn. Dial always uses addr (ip:port) with TLS ServerName sni.
func NewAntiCrashHTTPTransport(addr, sni string, timeout time.Duration) *http.Transport {
	tlsTimeout := timeout / 2
	if tlsTimeout < time.Second {
		tlsTimeout = time.Second
	}
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: -1,
	}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		},
		DisableKeepAlives:   true,
		MaxIdleConns:        0,
		MaxConnsPerHost:     2,
		MaxIdleConnsPerHost: 0,
		IdleConnTimeout:     5 * time.Second,
		TLSHandshakeTimeout: tlsTimeout,
		ForceAttemptHTTP2:   false,
	}
}
