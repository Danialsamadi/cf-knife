package scanner

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProbePing_InvalidIP(t *testing.T) {
	_, _, err := ProbePing(context.Background(), "not-an-ip", 1, time.Second)
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestProbePing_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := ProbePing(ctx, "127.0.0.1", 5, time.Second)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestProbePing_DefaultCount(t *testing.T) {
	// count < 1 should default to 5; just verify no panic.
	// This will likely fail with "no ICMP replies" in CI without root,
	// but should not panic.
	_, _, _ = ProbePing(context.Background(), "127.0.0.1", 0, 200*time.Millisecond)
}

func TestProbePing_Localhost(t *testing.T) {
	// ICMP to localhost usually works on macOS (unprivileged UDP ICMP)
	// but may fail in CI without root on Linux. Use short test skip.
	ping, jitter, err := ProbePing(context.Background(), "127.0.0.1", 3, 2*time.Second)
	if err != nil {
		if strings.Contains(err.Error(), "root") || strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "listen") {
			t.Skipf("ICMP unavailable (needs root): %v", err)
		}
		if strings.Contains(err.Error(), "no ICMP replies") {
			t.Skipf("no ICMP replies from localhost: %v", err)
		}
		t.Fatalf("ProbePing error: %v", err)
	}
	if ping < 0 {
		t.Errorf("ping = %f, expected >= 0", ping)
	}
	if jitter < 0 {
		t.Errorf("jitter = %f, expected >= 0", jitter)
	}
}

func TestProbeSpeed_LocalHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(strings.Repeat("x", 4096)))
	}))
	defer srv.Close()

	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	addr := "127.0.0.1:" + port

	dl, ul, err := ProbeSpeed(context.Background(), addr, "127.0.0.1", 5*time.Second)
	if err != nil {
		t.Fatalf("ProbeSpeed error: %v", err)
	}
	if dl < 0 {
		t.Errorf("download = %f, expected >= 0", dl)
	}
	if ul < 0 {
		t.Errorf("upload = %f, expected >= 0", ul)
	}
}

func TestProbeSpeed_Unreachable(t *testing.T) {
	_, _, err := ProbeSpeed(context.Background(), "127.0.0.1:1", "example.com", 200*time.Millisecond)
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}

func TestProbeSpeed_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := ProbeSpeed(ctx, "127.0.0.1:443", "example.com", 2*time.Second)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestMeasureDownload_LocalServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("a", 8192)))
	}))
	defer srv.Close()

	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	addr := "127.0.0.1:" + port

	mbps, err := measureDownload(context.Background(), addr, "127.0.0.1", 5*time.Second)
	if err != nil {
		t.Fatalf("measureDownload error: %v", err)
	}
	if mbps < 0 {
		t.Errorf("download = %f, expected >= 0", mbps)
	}
}

func TestMeasureUpload_LocalServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	addr := "127.0.0.1:" + port

	mbps, err := measureUpload(context.Background(), addr, "127.0.0.1", 5*time.Second)
	if err != nil {
		t.Fatalf("measureUpload error: %v", err)
	}
	if mbps < 0 {
		t.Errorf("upload = %f, expected >= 0", mbps)
	}
}
