package scanner

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestBuildWGInitiation(t *testing.T) {
	msg := buildWGInitiation()

	if len(msg) != wgInitiationSize {
		t.Errorf("len = %d, want %d", len(msg), wgInitiationSize)
	}
	if msg[0] != wgMsgTypeInit {
		t.Errorf("type = %d, want %d", msg[0], wgMsgTypeInit)
	}
}

func TestBuildWGInitiation_Unique(t *testing.T) {
	a := buildWGInitiation()
	b := buildWGInitiation()

	same := true
	for i := 8; i < len(a); i++ {
		if a[i] != b[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("two consecutive initiations should differ in random payload")
	}
}

func TestExpandWARPRanges_Defaults(t *testing.T) {
	targets, err := ExpandWARPRanges(nil, 0)
	if err != nil {
		t.Fatalf("ExpandWARPRanges error: %v", err)
	}
	if len(targets) == 0 {
		t.Fatal("expected non-empty targets from default ranges")
	}

	for _, tgt := range targets[:5] {
		if tgt.Port != DefaultWARPPort {
			t.Errorf("port = %d, want %d", tgt.Port, DefaultWARPPort)
		}
		ip := net.ParseIP(tgt.IP)
		if ip == nil {
			t.Errorf("invalid IP: %s", tgt.IP)
		}
	}
}

func TestExpandWARPRanges_CustomPort(t *testing.T) {
	targets, err := ExpandWARPRanges([]string{"10.0.0.0/30"}, 9999)
	if err != nil {
		t.Fatalf("ExpandWARPRanges error: %v", err)
	}

	// /30 = 4 IPs (including network and broadcast for this implementation)
	if len(targets) < 2 {
		t.Fatalf("got %d targets, expected at least 2 from /30", len(targets))
	}

	for _, tgt := range targets {
		if tgt.Port != 9999 {
			t.Errorf("port = %d, want 9999", tgt.Port)
		}
	}
}

func TestExpandWARPRanges_InvalidCIDR(t *testing.T) {
	_, err := ExpandWARPRanges([]string{"not-a-cidr"}, 2408)
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestProbeWARPEndpoint_Unreachable(t *testing.T) {
	_, ok := ProbeWARPEndpoint(context.Background(), "127.0.0.1:1", 200*time.Millisecond)
	if ok {
		t.Error("expected unreachable for port 1")
	}
}

func TestProbeWARPEndpoint_LocalUDP(t *testing.T) {
	// Start a local UDP server that echoes back a reply.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 256)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()

	rtt, ok := ProbeWARPEndpoint(context.Background(), pc.LocalAddr().String(), 2*time.Second)
	if !ok {
		t.Error("expected reachable for local echo UDP server")
	}
	if rtt <= 0 {
		t.Errorf("rtt = %v, expected positive", rtt)
	}
}

func TestScanWARP_LocalUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 256)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()

	host, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	targets := []WARPTarget{
		{IP: host, Port: port},
	}

	results := ScanWARP(context.Background(), targets, 2*time.Second, 1)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if !results[0].Reachable {
		t.Error("expected reachable for local echo server")
	}
}

func TestScanWARP_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	targets := make([]WARPTarget, 10)
	for i := range targets {
		targets[i] = WARPTarget{IP: "192.0.2.1", Port: 2408}
	}

	results := ScanWARP(ctx, targets, 200*time.Millisecond, 2)
	// Should return without hanging; results may be partially empty.
	if len(results) != 10 {
		t.Errorf("got %d results, want 10 (even if empty)", len(results))
	}
}

func TestScanWARP_DefaultThreads(t *testing.T) {
	results := ScanWARP(context.Background(), nil, 100*time.Millisecond, 0)
	if len(results) != 0 {
		t.Errorf("got %d results, want 0 for nil targets", len(results))
	}
}
