package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeConfig_ShouldFlags(t *testing.T) {
	tests := []struct {
		name      string
		pc        ProbeConfig
		wantTCP   bool
		wantTLS   bool
		wantHTTP  bool
		wantHTTP2 bool
		wantHTTP3 bool
	}{
		{
			name:      "full mode enables all",
			pc:        ProbeConfig{Mode: ModeFull},
			wantTCP:   true,
			wantTLS:   true,
			wantHTTP:  true,
			wantHTTP2: true,
			wantHTTP3: true,
		},
		{
			name:    "tcp-only mode",
			pc:      ProbeConfig{Mode: ModeTCPOnly},
			wantTCP: true,
		},
		{
			name:    "tls mode enables tls only",
			pc:      ProbeConfig{Mode: ModeTLS},
			wantTLS: true,
		},
		{
			name:     "http mode enables tls+http",
			pc:       ProbeConfig{Mode: ModeHTTP},
			wantTLS:  true,
			wantHTTP: true,
		},
		{
			name:      "http2 mode enables tls+http2",
			pc:        ProbeConfig{Mode: ModeHTTP2},
			wantTLS:   true,
			wantHTTP2: true,
		},
		{
			name:      "http3 mode enables tls+http3",
			pc:        ProbeConfig{Mode: ModeHTTP3},
			wantTLS:   true,
			wantHTTP3: true,
		},
		{
			name:      "explicit test flags override mode",
			pc:        ProbeConfig{Mode: ModeTCPOnly, TestTLS: true, TestHTTP: true, TestHTTP2: true, TestHTTP3: true},
			wantTCP:   true,
			wantTLS:   true,
			wantHTTP:  true,
			wantHTTP2: true,
			wantHTTP3: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pc.ShouldTCP(); got != tt.wantTCP {
				t.Errorf("ShouldTCP() = %v, want %v", got, tt.wantTCP)
			}
			if got := tt.pc.ShouldTLS(); got != tt.wantTLS {
				t.Errorf("ShouldTLS() = %v, want %v", got, tt.wantTLS)
			}
			if got := tt.pc.ShouldHTTP(); got != tt.wantHTTP {
				t.Errorf("ShouldHTTP() = %v, want %v", got, tt.wantHTTP)
			}
			if got := tt.pc.ShouldHTTP2(); got != tt.wantHTTP2 {
				t.Errorf("ShouldHTTP2() = %v, want %v", got, tt.wantHTTP2)
			}
			if got := tt.pc.ShouldHTTP3(); got != tt.wantHTTP3 {
				t.Errorf("ShouldHTTP3() = %v, want %v", got, tt.wantHTTP3)
			}
		})
	}
}

func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		ver  uint16
		want string
	}{
		{tls.VersionTLS10, "TLS1.0"},
		{tls.VersionTLS11, "TLS1.1"},
		{tls.VersionTLS12, "TLS1.2"},
		{tls.VersionTLS13, "TLS1.3"},
		{0x9999, "0x9999"},
	}
	for _, tt := range tests {
		if got := tlsVersionName(tt.ver); got != tt.want {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", tt.ver, got, tt.want)
		}
	}
}

func TestExtractHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "cloudflare")
	h.Set("CF-Ray", "abc123-IAD")

	res := &ProbeResult{}
	extractHeaders(res, h)

	if res.ServerHeader != "cloudflare" {
		t.Errorf("ServerHeader = %q, want %q", res.ServerHeader, "cloudflare")
	}
	if res.CFRay != "abc123-IAD" {
		t.Errorf("CFRay = %q, want %q", res.CFRay, "abc123-IAD")
	}
	if res.ServiceName != "cloudflare" {
		t.Errorf("ServiceName = %q, want %q", res.ServiceName, "cloudflare")
	}
}

func TestExtractHeaders_NonCF(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx")

	res := &ProbeResult{}
	extractHeaders(res, h)

	if res.ServiceName != "" {
		t.Errorf("ServiceName = %q, want empty for non-CF", res.ServiceName)
	}
}

func TestRetry_SuccessFirst(t *testing.T) {
	calls := 0
	err := retry(context.Background(), 3, func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("called %d times, want 1", calls)
	}
}

func TestRetry_SuccessAfterFailures(t *testing.T) {
	calls := 0
	err := retry(context.Background(), 3, func() error {
		calls++
		if calls < 3 {
			return fmt.Errorf("fail %d", calls)
		}
		return nil
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if calls != 3 {
		t.Errorf("called %d times, want 3", calls)
	}
}

func TestRetry_AllFail(t *testing.T) {
	calls := 0
	err := retry(context.Background(), 2, func() error {
		calls++
		return fmt.Errorf("fail")
	})
	if err == nil {
		t.Error("expected error, got nil")
	}
	if calls != 3 { // initial + 2 retries
		t.Errorf("called %d times, want 3", calls)
	}
}

func TestRetry_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := retry(ctx, 5, func() error {
		t.Fatal("should not be called")
		return nil
	})
	if err == nil {
		t.Error("expected error from cancelled context")
	}
}

func TestRetryVal(t *testing.T) {
	calls := 0
	val, err := retryVal(context.Background(), 2, func() (string, error) {
		calls++
		if calls < 2 {
			return "", fmt.Errorf("fail")
		}
		return "ok", nil
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if val != "ok" {
		t.Errorf("val = %q, want %q", val, "ok")
	}
}

func TestProbeTCP_Success(t *testing.T) {
	// Start a local TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	err = probeTCP(context.Background(), ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Errorf("probeTCP failed: %v", err)
	}
}

func TestProbeTCP_Fail(t *testing.T) {
	err := probeTCP(context.Background(), "127.0.0.1:1", 200*time.Millisecond)
	if err == nil {
		t.Error("expected error connecting to closed port")
	}
}

func TestProbe_TCPOnly_LocalServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	target := Target{IP: "127.0.0.1", Port: port, SourceRange: "test"}
	pc := &ProbeConfig{
		Mode:     ModeTCPOnly,
		Timeout:  2 * time.Second,
		ScanType: ScanConnect,
	}

	res := Probe(context.Background(), target, pc)
	if !res.TCPSuccess {
		t.Errorf("TCPSuccess = false, want true (err: %s)", res.Error)
	}
	if res.TLSSuccess {
		t.Error("TLSSuccess should be false in tcp-only mode")
	}
}

func TestProbe_TCPFail_ClosedPort(t *testing.T) {
	target := Target{IP: "127.0.0.1", Port: "1", SourceRange: "test"}
	pc := &ProbeConfig{
		Mode:     ModeTCPOnly,
		Timeout:  200 * time.Millisecond,
		ScanType: ScanConnect,
		Retries:  0,
	}

	res := Probe(context.Background(), target, pc)
	if res.TCPSuccess {
		t.Error("TCPSuccess should be false for closed port")
	}
	if res.Error == "" {
		t.Error("Error should be set")
	}
}

func TestProbe_FastScan(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	target := Target{IP: "127.0.0.1", Port: port, SourceRange: "test"}
	pc := &ProbeConfig{
		Mode:     ModeTCPOnly,
		Timeout:  2 * time.Second,
		ScanType: ScanFast,
	}

	res := Probe(context.Background(), target, pc)
	if !res.TCPSuccess {
		t.Errorf("fast scan TCPSuccess = false (err: %s)", res.Error)
	}
	if res.ScanType != "fast" {
		t.Errorf("ScanType = %q, want %q", res.ScanType, "fast")
	}
}

func TestProbe_SYNScan_Fallback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	target := Target{IP: "127.0.0.1", Port: port, SourceRange: "test"}
	pc := &ProbeConfig{
		Mode:     ModeTCPOnly,
		Timeout:  2 * time.Second,
		ScanType: ScanSYN,
	}

	synWarned = false
	res := Probe(context.Background(), target, pc)
	if !res.TCPSuccess {
		t.Errorf("SYN fallback TCPSuccess = false (err: %s)", res.Error)
	}
}

func TestProbe_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	target := Target{IP: "127.0.0.1", Port: "443", SourceRange: "test"}
	pc := &ProbeConfig{
		Mode:     ModeTCPOnly,
		Timeout:  2 * time.Second,
		ScanType: ScanConnect,
	}

	res := Probe(ctx, target, pc)
	if res.TCPSuccess {
		t.Error("should fail with cancelled context")
	}
}

func TestProbe_HTTPMode_LocalHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-Ray", "test-ray-123")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	target := Target{IP: "127.0.0.1", Port: port, SourceRange: "local"}
	pc := &ProbeConfig{
		SNI:      "127.0.0.1",
		Mode:     ModeHTTP,
		Timeout:  5 * time.Second,
		ScanType: ScanConnect,
		HTTPURL:  srv.URL + "/test",
	}

	res := Probe(context.Background(), target, pc)
	if !res.TLSSuccess {
		t.Errorf("TLSSuccess = false (err: %s)", res.Error)
	}
	if !res.HTTPSuccess {
		t.Errorf("HTTPSuccess = false (err: %s)", res.Error)
	}
	if res.ServerHeader != "cloudflare" {
		t.Errorf("ServerHeader = %q, want %q", res.ServerHeader, "cloudflare")
	}
	if res.CFRay != "test-ray-123" {
		t.Errorf("CFRay = %q, want %q", res.CFRay, "test-ray-123")
	}
}

func TestProbe_HTTP2Mode_LocalHTTP2Server(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "h2-test")
		w.WriteHeader(http.StatusOK)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	target := Target{IP: "127.0.0.1", Port: port, SourceRange: "local"}
	pc := &ProbeConfig{
		SNI:      "127.0.0.1",
		Mode:     ModeHTTP2,
		Timeout:  5 * time.Second,
		ScanType: ScanConnect,
		HTTPURL:  srv.URL + "/",
	}

	res := Probe(context.Background(), target, pc)
	if !res.TLSSuccess {
		t.Fatalf("TLSSuccess = false (err: %s)", res.Error)
	}
	if !res.HTTP2Success {
		t.Fatalf("HTTP2Success = false (err: %s)", res.Error)
	}
	if res.ServerHeader != "h2-test" {
		t.Errorf("ServerHeader = %q, want %q", res.ServerHeader, "h2-test")
	}
}
