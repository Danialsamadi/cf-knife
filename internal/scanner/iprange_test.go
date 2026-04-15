package scanner

import (
	"net"
	"os"
	"path/filepath"
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

func TestExpandEntry_BareIPv6(t *testing.T) {
	ips, src, err := expandEntry("::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src != "::1" {
		t.Errorf("source range = %q, want %q", src, "::1")
	}
	if len(ips) != 1 {
		t.Errorf("got %d IPs, want 1", len(ips))
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
	if len(ips) != 4 {
		t.Errorf("got %d IPs, want 4", len(ips))
	}
}

func TestExpandEntry_CIDR24(t *testing.T) {
	ips, src, err := expandEntry("10.0.0.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src != "10.0.0.0/24" {
		t.Errorf("source range = %q", src)
	}
	if len(ips) != 256 {
		t.Errorf("got %d IPs, want 256 for /24", len(ips))
	}
}

func TestExpandEntry_CIDR32(t *testing.T) {
	ips, _, err := expandEntry("10.0.0.1/32")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 {
		t.Errorf("got %d IPs, want 1 for /32", len(ips))
	}
}

func TestExpandEntry_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"bad IP", "not-an-ip"},
		{"bad CIDR", "10.0.0.0/99"},
		{"empty string", ""},
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
	targets, err := expandCIDRs(entries, ports, false, false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 8 {
		t.Errorf("got %d targets, want 8 (4 IPs × 2 ports)", len(targets))
	}
	for _, tgt := range targets {
		if tgt.SourceRange != "10.0.0.0/30" {
			t.Errorf("source range = %q, want %q", tgt.SourceRange, "10.0.0.0/30")
		}
	}
}

func TestExpandCIDRs_SingleIP(t *testing.T) {
	targets, err := expandCIDRs([]string{"8.8.8.8"}, []string{"53"}, false, false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 1 {
		t.Errorf("got %d targets, want 1", len(targets))
	}
	if targets[0].SourceRange != "8.8.8.8" {
		t.Errorf("source range = %q, want %q", targets[0].SourceRange, "8.8.8.8")
	}
}

func TestExpandCIDRs_IPv4OnlyFilter(t *testing.T) {
	entries := []string{"::1"}
	ports := []string{"443"}
	targets, err := expandCIDRs(entries, ports, true, false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("expected 0 targets with ipv4-only filter on IPv6, got %d", len(targets))
	}
}

func TestExpandCIDRs_IPv6OnlyFilter(t *testing.T) {
	entries := []string{"1.1.1.1"}
	ports := []string{"443"}
	targets, err := expandCIDRs(entries, ports, false, true, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("expected 0 targets with ipv6-only filter on IPv4, got %d", len(targets))
	}
}

func TestExpandCIDRs_MixedEntries(t *testing.T) {
	entries := []string{"10.0.0.0/31", "192.168.1.1"}
	ports := []string{"443"}
	targets, err := expandCIDRs(entries, ports, false, false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2 from /31 + 1 bare = 3
	if len(targets) != 3 {
		t.Errorf("got %d targets, want 3", len(targets))
	}
}

func TestExpandIPv4_SmallRange(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/31")
	ips := expandIPv4(ipNet)
	if len(ips) != 2 {
		t.Errorf("got %d IPs, want 2", len(ips))
	}
}

func TestExpandIPv4_Host(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.1/32")
	ips := expandIPv4(ipNet)
	if len(ips) != 1 {
		t.Errorf("got %d IPs, want 1", len(ips))
	}
}

func TestExpandIPv6_Small(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("::0/127")
	ips := expandIPv6(ipNet)
	if len(ips) != 2 {
		t.Errorf("got %d IPs, want 2 for /127", len(ips))
	}
}

func TestReadLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test_ranges.txt")
	content := "# comment line\n\n1.1.1.0/24\n  \n10.0.0.1\n# another comment\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	lines, err := readLinesFromFile(path)
	if err != nil {
		t.Fatalf("readLinesFromFile: %v", err)
	}
	if len(lines) != 2 {
		t.Errorf("got %d lines, want 2 (comments and blanks stripped)", len(lines))
	}
	if lines[0] != "1.1.1.0/24" {
		t.Errorf("line[0] = %q, want %q", lines[0], "1.1.1.0/24")
	}
	if lines[1] != "10.0.0.1" {
		t.Errorf("line[1] = %q, want %q", lines[1], "10.0.0.1")
	}
}

func TestReadLinesFromFile_NotExist(t *testing.T) {
	_, err := readLinesFromFile("/nonexistent/path/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
