package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"time"
)

// DefaultFragmentSizes lists TLS ClientHello fragment sizes to enumerate when
// searching for the best DPI bypass. Smaller fragments are more likely to evade
// simple pattern-matching DPI but add overhead.
var DefaultFragmentSizes = []int{10, 50, 100, 200, 500}

// DefaultSNIList contains well-known Cloudflare-served domains used for SNI
// fronting tests. The probe sends a TLS ClientHello with each SNI and checks
// whether the connection succeeds through the given IP.
var DefaultSNIList = []string{
	"www.cloudflare.com",
	"cloudflare.com",
	"discord.com",
	"cdnjs.cloudflare.com",
	"ajax.cloudflare.com",
	"pages.dev",
	"workers.dev",
	"speed.cloudflare.com",
	"blog.cloudflare.com",
	"one.one.one.one",
}

// ProbeDPI enumerates fragment sizes by splitting the TLS ClientHello across
// multiple TCP writes. For each size it attempts a TLS handshake through the
// target address and records whether the handshake succeeds and its RTT.
// Returns the fragment size with the lowest latency, or 0 if none succeeded.
func ProbeDPI(ctx context.Context, addr, sni string, timeout time.Duration, sizes []int) (bestSize int, err error) {
	if len(sizes) == 0 {
		sizes = DefaultFragmentSizes
	}

	type result struct {
		size    int
		latency time.Duration
	}

	var best *result

	for _, sz := range sizes {
		if ctx.Err() != nil {
			break
		}

		lat, ok := probeFragment(ctx, addr, sni, timeout, sz)
		if !ok {
			continue
		}

		if best == nil || lat < best.latency {
			best = &result{size: sz, latency: lat}
		}
	}

	if best == nil {
		return 0, fmt.Errorf("no fragment size succeeded against %s", addr)
	}
	return best.size, nil
}

// probeFragment dials TCP to addr, then writes the TLS ClientHello in chunks
// of fragSize bytes. Returns the total handshake latency if successful.
func probeFragment(ctx context.Context, addr, sni string, timeout time.Duration, fragSize int) (time.Duration, bool) {
	d := net.Dialer{Timeout: timeout}
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, false
	}
	defer rawConn.Close()
	rawConn.SetDeadline(time.Now().Add(timeout))

	// Wrap the raw connection with a fragmenting writer that splits writes
	// into chunks of at most fragSize bytes. The TLS library's first write
	// contains the ClientHello record; splitting it is the core DPI bypass.
	fconn := &fragmentConn{Conn: rawConn, fragSize: fragSize}

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	start := time.Now()
	tlsConn := tls.Client(fconn, tlsCfg)
	err = tlsConn.HandshakeContext(ctx)
	lat := time.Since(start)
	tlsConn.Close()

	if err != nil {
		return 0, false
	}
	return lat, true
}

// fragmentConn wraps a net.Conn and splits every Write into chunks of at most
// fragSize bytes. This causes the TLS ClientHello to be sent across multiple
// TCP segments, which can evade DPI systems that match on a single packet.
type fragmentConn struct {
	net.Conn
	fragSize int
}

func (fc *fragmentConn) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		chunk := fc.fragSize
		if chunk > len(b) {
			chunk = len(b)
		}
		n, err := fc.Conn.Write(b[:chunk])
		total += n
		if err != nil {
			return total, err
		}
		b = b[chunk:]
	}
	return total, nil
}

// ProbeSNIFronting tests a list of SNI hostnames against a target IP and
// returns the first SNI that produces a valid HTTP response (200 OK). This
// identifies unblocked domain fronts through censored networks.
func ProbeSNIFronting(ctx context.Context, addr string, snis []string, timeout time.Duration) (workingSNI string, err error) {
	if len(snis) == 0 {
		snis = DefaultSNIList
	}

	type sniResult struct {
		sni     string
		latency time.Duration
	}

	var best *sniResult

	for _, sni := range snis {
		if ctx.Err() != nil {
			break
		}

		lat, ok := testSNI(ctx, addr, sni, timeout)
		if !ok {
			continue
		}

		if best == nil || lat < best.latency {
			best = &sniResult{sni: sni, latency: lat}
		}
	}

	if best == nil {
		return "", fmt.Errorf("no working SNI found for %s", addr)
	}
	return best.sni, nil
}

func testSNI(ctx context.Context, addr, sni string, timeout time.Duration) (time.Duration, bool) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: timeout}
	url := fmt.Sprintf("https://%s/cdn-cgi/trace", sni)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false
	}
	req.Host = sni

	start := time.Now()
	resp, err := client.Do(req)
	lat := time.Since(start)
	if err != nil {
		return 0, false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return lat, true
	}
	return 0, false
}

// ParseFragmentSizes converts a comma-separated string of integers into a
// slice, validating that each value is positive.
func ParseFragmentSizes(s string) ([]int, error) {
	if s == "" {
		return DefaultFragmentSizes, nil
	}
	var sizes []int
	for _, tok := range splitCSV(s) {
		var n int
		if _, err := fmt.Sscanf(tok, "%d", &n); err != nil || n <= 0 {
			return nil, fmt.Errorf("invalid fragment size: %q", tok)
		}
		if n > math.MaxUint16 {
			return nil, fmt.Errorf("fragment size too large: %d", n)
		}
		sizes = append(sizes, n)
	}
	if len(sizes) == 0 {
		return DefaultFragmentSizes, nil
	}
	return sizes, nil
}

func splitCSV(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			tok := s[start:i]
			// trim spaces
			for len(tok) > 0 && tok[0] == ' ' {
				tok = tok[1:]
			}
			for len(tok) > 0 && tok[len(tok)-1] == ' ' {
				tok = tok[:len(tok)-1]
			}
			if tok != "" {
				out = append(out, tok)
			}
			start = i + 1
		}
	}
	return out
}
