package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// ProbeConfig holds per-scan probe parameters.
type ProbeConfig struct {
	SNI        string
	Timeout    time.Duration
	Retries    int
	Mode       ScanMode
	TestTCP    bool
	TestTLS    bool
	TestHTTP   bool
	TestHTTP2  bool
	HTTPURL    string
	MaxLatency time.Duration
	ScanType   ScanType
	Script     string

	SpeedTest     bool
	DPIAnalysis   bool
	FragmentSizes []int
}

// ShouldTCP returns true if TCP probing is enabled by mode or explicit flag.
func (pc *ProbeConfig) ShouldTCP() bool {
	return pc.TestTCP || pc.Mode == ModeTCPOnly || pc.Mode == ModeFull
}

// ShouldTLS returns true if TLS probing is enabled.
func (pc *ProbeConfig) ShouldTLS() bool {
	return pc.TestTLS || pc.Mode == ModeTLS || pc.Mode == ModeHTTP || pc.Mode == ModeHTTP2 || pc.Mode == ModeFull
}

// ShouldHTTP returns true if HTTP/1.1 probing is enabled.
func (pc *ProbeConfig) ShouldHTTP() bool {
	return pc.TestHTTP || pc.Mode == ModeHTTP || pc.Mode == ModeFull
}

// ShouldHTTP2 returns true if HTTP/2 probing is enabled.
func (pc *ProbeConfig) ShouldHTTP2() bool {
	return pc.TestHTTP2 || pc.Mode == ModeHTTP2 || pc.Mode == ModeFull
}

// Probe runs all enabled tests against a single Target and returns a result.
// The function respects ctx for cancellation and applies per-probe retries.
func Probe(ctx context.Context, t Target, pc *ProbeConfig) ProbeResult {
	res := ProbeResult{
		IP:          t.IP,
		Port:        t.Port,
		SourceRange: t.SourceRange,
		ScanType:    string(pc.ScanType),
	}

	addr := net.JoinHostPort(t.IP, t.Port)
	start := time.Now()

	// TCP — dispatch based on scan type
	if pc.ShouldTCP() {
		switch pc.ScanType {
		case ScanSYN:
			ok, warning := ProbeSYN(ctx, addr, pc.Timeout)
			WarnSYNFallback(warning)
			if !ok {
				res.Error = "tcp/syn: port closed or unreachable"
				res.Latency = time.Since(start)
				return res
			}
			res.TCPSuccess = true
		case ScanFast:
			if err := ProbeFast(ctx, addr, pc.Timeout/2); err != nil {
				res.Error = fmt.Sprintf("tcp/fast: %v", err)
				res.Latency = time.Since(start)
				return res
			}
			res.TCPSuccess = true
		default: // ScanConnect
			if err := retry(ctx, pc.Retries, func() error {
				return probeTCP(ctx, addr, pc.Timeout)
			}); err != nil {
				res.Error = fmt.Sprintf("tcp: %v", err)
				res.Latency = time.Since(start)
				return res
			}
			res.TCPSuccess = true
		}
	}
	res.Latency = time.Since(start)

	if pc.MaxLatency > 0 && res.Latency > pc.MaxLatency {
		return res
	}

	isTLSPort := t.Port != "80"

	// TLS
	var tlsConn *tls.Conn
	if pc.ShouldTLS() && isTLSPort {
		var err error
		tlsConn, err = retryTLS(ctx, pc.Retries, addr, pc.SNI, pc.Timeout)
		if err != nil {
			res.Error = fmt.Sprintf("tls: %v", err)
			if !res.TCPSuccess {
				res.TCPSuccess = true
				res.Latency = time.Since(start)
			}
			return res
		}
		res.TLSSuccess = true
		res.TCPSuccess = true
		st := tlsConn.ConnectionState()
		res.TLSVersion = tlsVersionName(st.Version)
		res.TLSCipher = tls.CipherSuiteName(st.CipherSuite)
		if st.NegotiatedProtocol != "" {
			res.ALPN = st.NegotiatedProtocol
		}
	}

	// HTTP/1.1
	if pc.ShouldHTTP() && isTLSPort {
		hdrs, err := retryVal(ctx, pc.Retries, func() (http.Header, error) {
			return probeHTTP(ctx, addr, pc.SNI, pc.Timeout, pc.HTTPURL)
		})
		if err != nil {
			res.Error = fmt.Sprintf("http: %v", err)
		} else {
			res.HTTPSuccess = true
			extractHeaders(&res, hdrs)
		}
	}

	// HTTP/2
	if pc.ShouldHTTP2() && isTLSPort {
		hdrs, err := retryVal(ctx, pc.Retries, func() (http.Header, error) {
			return probeHTTP2(ctx, addr, pc.SNI, pc.Timeout, pc.HTTPURL)
		})
		if err != nil {
			res.Error = fmt.Sprintf("http2: %v", err)
		} else {
			res.HTTP2Success = true
			extractHeaders(&res, hdrs)
		}
	}

	// Close any lingering TLS conn.
	if tlsConn != nil {
		tlsConn.Close()
	}

	// Performance metrics: ICMP ping/jitter and HTTP speed.
	if pc.SpeedTest && res.TCPSuccess {
		res.PingMs, res.JitterMs, _ = ProbePing(ctx, t.IP, 5, pc.Timeout)
		res.DownloadMbps, res.UploadMbps, _ = ProbeSpeed(ctx, addr, pc.SNI, pc.Timeout)
	}

	// DPI fragment enumeration and SNI fronting.
	if pc.DPIAnalysis && res.TCPSuccess && isTLSPort {
		res.BestFragmentSize, _ = ProbeDPI(ctx, addr, pc.SNI, pc.Timeout, pc.FragmentSizes)
		res.SNIFront, _ = ProbeSNIFronting(ctx, addr, DefaultSNIList, pc.Timeout)
	}

	// Script probes run after standard probes succeed.
	if pc.Script == "cloudflare" && res.TCPSuccess {
		RunCloudflareScript(ctx, &res, pc.SNI, pc.Timeout)
	}

	return res
}

// --- low-level probes ---

func probeTCP(ctx context.Context, addr string, timeout time.Duration) error {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func probeTLS(ctx context.Context, addr, sni string, timeout time.Duration) (*tls.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func probeHTTP(ctx context.Context, addr, sni string, timeout time.Duration, httpURL string) (http.Header, error) {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, httpURL, nil)
	if err != nil {
		return nil, err
	}
	req.Host = sni
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.Header, nil
}

func probeHTTP2(ctx context.Context, addr, sni string, timeout time.Duration, httpURL string) (http.Header, error) {
	transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, _ string, cfg *tls.Config) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			rawConn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tlsCfg := &tls.Config{
				ServerName:         sni,
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2"},
			}
			tlsConn := tls.Client(rawConn, tlsCfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
		DisableCompression: true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, httpURL, nil)
	if err != nil {
		return nil, err
	}
	req.Host = sni
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.Header, nil
}

// --- helpers ---

func extractHeaders(res *ProbeResult, h http.Header) {
	if sv := h.Get("Server"); sv != "" {
		res.ServerHeader = sv
	}
	if ray := h.Get("CF-Ray"); ray != "" {
		res.CFRay = ray
	}
	if strings.Contains(strings.ToLower(res.ServerHeader), "cloudflare") {
		res.ServiceName = "cloudflare"
	}
}

func retry(ctx context.Context, n int, fn func() error) error {
	var err error
	for i := 0; i <= n; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err = fn(); err == nil {
			return nil
		}
	}
	return err
}

func retryTLS(ctx context.Context, n int, addr, sni string, timeout time.Duration) (*tls.Conn, error) {
	var conn *tls.Conn
	var err error
	for i := 0; i <= n; i++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		conn, err = probeTLS(ctx, addr, sni, timeout)
		if err == nil {
			return conn, nil
		}
	}
	return nil, err
}

func retryVal[T any](ctx context.Context, n int, fn func() (T, error)) (T, error) {
	var val T
	var err error
	for i := 0; i <= n; i++ {
		if ctx.Err() != nil {
			return val, ctx.Err()
		}
		val, err = fn()
		if err == nil {
			return val, nil
		}
	}
	return val, err
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
