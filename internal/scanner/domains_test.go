package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParseHostScheme(t *testing.T) {
	tests := []struct {
		in, wantHost, wantScheme string
	}{
		{"example.com", "example.com", "https"},
		{"https://example.com/path", "example.com", "https"},
		{"http://foo.bar:8080/x", "foo.bar:8080", "http"},
	}
	for _, tt := range tests {
		h, s := parseHostScheme(tt.in)
		if h != tt.wantHost || s != tt.wantScheme {
			t.Errorf("parseHostScheme(%q) = (%q,%q), want (%q,%q)", tt.in, h, s, tt.wantHost, tt.wantScheme)
		}
	}
}

func TestLoadDomainTargets_localhost(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "d.txt")
	if err := os.WriteFile(p, []byte("127.0.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	targets, err := LoadDomainTargets(ctx, p, DomainLoadOptions{Ports: []string{"443"}, CFAllPorts: false})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(targets))
	}
	if targets[0].Hostname != "127.0.0.1" {
		t.Errorf("Hostname = %q", targets[0].Hostname)
	}
	if targets[0].Port != "443" {
		t.Errorf("Port = %q", targets[0].Port)
	}
}

func TestSchemeForPort(t *testing.T) {
	if schemeForPort("80") != "http" {
		t.Error("80")
	}
	if schemeForPort("443") != "https" {
		t.Error("443")
	}
}
