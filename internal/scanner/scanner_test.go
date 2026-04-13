package scanner

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestScanner_Run_Concurrency(t *testing.T) {
	// Start a local TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	var accepted atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			conn.Close()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	targets := make([]Target, 20)
	for i := range targets {
		targets[i] = Target{IP: "127.0.0.1", Port: port, SourceRange: "test"}
	}

	sc := &Scanner{
		Threads: 4,
		Config: &ProbeConfig{
			Mode:     ModeTCPOnly,
			Timeout:  2 * time.Second,
			ScanType: ScanConnect,
		},
		Progress: false,
	}

	sc.Run(context.Background(), targets)

	if len(sc.Results) != 20 {
		t.Errorf("got %d results, want 20", len(sc.Results))
	}

	successCount := 0
	for _, r := range sc.Results {
		if r.TCPSuccess {
			successCount++
		}
	}
	if successCount != 20 {
		t.Errorf("got %d successes, want 20", successCount)
	}
}

func TestScanner_Run_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	targets := make([]Target, 100)
	for i := range targets {
		targets[i] = Target{IP: "192.0.2.1", Port: "1", SourceRange: "test"}
	}

	sc := &Scanner{
		Threads: 2,
		Config: &ProbeConfig{
			Mode:     ModeTCPOnly,
			Timeout:  5 * time.Second,
			ScanType: ScanConnect,
			Retries:  0,
		},
		Progress: false,
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	sc.Run(ctx, targets)
	// Just verify it doesn't hang — the test passes if Run returns.
}

func TestScanner_Run_RateLimited(t *testing.T) {
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
	targets := make([]Target, 5)
	for i := range targets {
		targets[i] = Target{IP: "127.0.0.1", Port: port, SourceRange: "test"}
	}

	sc := &Scanner{
		Threads: 2,
		Config: &ProbeConfig{
			Mode:     ModeTCPOnly,
			Timeout:  2 * time.Second,
			ScanType: ScanConnect,
		},
		Rate:     100,
		Progress: false,
	}

	start := time.Now()
	sc.Run(context.Background(), targets)
	elapsed := time.Since(start)

	if len(sc.Results) != 5 {
		t.Errorf("got %d results, want 5", len(sc.Results))
	}

	// With rate=100, 5 targets should take ~50ms minimum; just verify it completes.
	if elapsed > 10*time.Second {
		t.Errorf("took %v, seems stuck", elapsed)
	}
}

func TestScanner_Run_EmptyTargets(t *testing.T) {
	sc := &Scanner{
		Threads: 4,
		Config: &ProbeConfig{
			Mode:     ModeTCPOnly,
			Timeout:  1 * time.Second,
			ScanType: ScanConnect,
		},
		Progress: false,
	}
	sc.Run(context.Background(), nil)
	if len(sc.Results) != 0 {
		t.Errorf("got %d results, want 0", len(sc.Results))
	}
}
