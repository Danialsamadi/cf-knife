package scanner

import (
	"net"
	"testing"
)

func TestExpandEntry_BareIPv4(t *testing.T) {
	ips, src, err := expandEntry("1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src != "1.1.1.1" {
		t.Errorf("source range = %q, want %q", src, "1.1.1.1")
	}
	if len(ips) != 1 || ips[0].String() != "1.1.1.1" {
		t.Errorf("ips = %v, want [1.1.1.1]", ips)
	}
}

func TestExpandEntry_CIDR(t *testing.T) {
	ips, src, err := expandEntry("192.168.1.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src != "192.168.1.0/30" {
		t.Errorf("source range = %q, want %q", src, "192.168.1.0/30")
	}
	// /30 = 4 addresses
	if len(ips) != 4 {
		t.Errorf("got %d IPs, want 4", len(ips))
	}
}

func TestExpandEntry_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"bad IP", "not-an-ip"},
		{"bad CIDR", "10.0.0.0/99"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := expandEntry(tt.input)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestExpandCIDRs_PortMatrix(t *testing.T) {
	entries := []string{"10.0.0.0/30"}
	ports := []string{"443", "80"}
	targets, err := expandCIDRs(entries, ports, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 4 IPs × 2 ports = 8 targets
	if len(targets) != 8 {
		t.Errorf("got %d targets, want 8", len(targets))
	}
	for _, tgt := range targets {
		if tgt.SourceRange != "10.0.0.0/30" {
			t.Errorf("source range = %q, want %q", tgt.SourceRange, "10.0.0.0/30")
		}
	}
}

func TestExpandCIDRs_IPv4OnlyFilter(t *testing.T) {
	entries := []string{"::1"}
	ports := []string{"443"}
	targets, err := expandCIDRs(entries, ports, true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("expected 0 targets with ipv4-only filter on IPv6, got %d", len(targets))
	}
}

func TestExpandIPv4_SmallRange(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/31")
	ips := expandIPv4(ipNet)
	if len(ips) != 2 {
		t.Errorf("got %d IPs, want 2", len(ips))
	}
}
