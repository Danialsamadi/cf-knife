package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestConfig_Validate(t *testing.T) {
	base := func() *Config {
		return &Config{
			Ports:     []string{"443"},
			Threads:   200,
			Timing:    3,
			Mode:      "full",
			ScanType:  "connect",
			OutputFmt: "txt",
		}
	}

	tests := []struct {
		name    string
		modify  func(c *Config)
		wantErr bool
	}{
		{"valid defaults", func(c *Config) {}, false},
		{"threads min boundary", func(c *Config) { c.Threads = 1 }, false},
		{"threads max boundary", func(c *Config) { c.Threads = 10000 }, false},
		{"threads too low", func(c *Config) { c.Threads = 0 }, true},
		{"threads too high", func(c *Config) { c.Threads = 10001 }, true},
		{"timing min boundary", func(c *Config) { c.Timing = 0 }, false},
		{"timing max boundary", func(c *Config) { c.Timing = 5 }, false},
		{"timing too high", func(c *Config) { c.Timing = 6 }, true},
		{"timing negative", func(c *Config) { c.Timing = -1 }, true},
		{"mode tcp-only", func(c *Config) { c.Mode = "tcp-only" }, false},
		{"mode tls", func(c *Config) { c.Mode = "tls" }, false},
		{"mode http", func(c *Config) { c.Mode = "http" }, false},
		{"mode http2", func(c *Config) { c.Mode = "http2" }, false},
		{"bad mode", func(c *Config) { c.Mode = "invalid" }, true},
		{"scan-type fast", func(c *Config) { c.ScanType = "fast" }, false},
		{"scan-type syn", func(c *Config) { c.ScanType = "syn" }, false},
		{"bad scan-type", func(c *Config) { c.ScanType = "nope" }, true},
		{"output-format json", func(c *Config) { c.OutputFmt = "json" }, false},
		{"output-format csv", func(c *Config) { c.OutputFmt = "csv" }, false},
		{"bad output-format", func(c *Config) { c.OutputFmt = "xml" }, true},
		{"ipv4+ipv6 exclusive", func(c *Config) { c.IPv4Only = true; c.IPv6Only = true }, true},
		{"ipv4 only ok", func(c *Config) { c.IPv4Only = true }, false},
		{"ipv6 only ok", func(c *Config) { c.IPv6Only = true }, false},
		{"bad script", func(c *Config) { c.Script = "nmap" }, true},
		{"valid cloudflare script", func(c *Config) { c.Script = "cloudflare" }, false},
		{"empty script is valid", func(c *Config) { c.Script = "" }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base()
			tt.modify(c)
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-config.json")

	original := &Config{
		Ports:     []string{"443", "80"},
		SNI:       "example.com",
		Threads:   100,
		Mode:      "full",
		ScanType:  "connect",
		OutputFmt: "txt",
		Shuffle:   true,
		Verbose:   true,
	}

	if err := original.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}

	var loaded Config
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(loaded.Ports) != 2 || loaded.Ports[0] != "443" || loaded.Ports[1] != "80" {
		t.Errorf("Ports = %v, want [443 80]", loaded.Ports)
	}
	if loaded.SNI != "example.com" {
		t.Errorf("SNI = %q, want %q", loaded.SNI, "example.com")
	}
	if loaded.Threads != 100 {
		t.Errorf("Threads = %d, want 100", loaded.Threads)
	}
	if !loaded.Shuffle {
		t.Error("Shuffle should be true")
	}
	if !loaded.Verbose {
		t.Error("Verbose should be true")
	}
}

func TestConfig_SaveInvalidPath(t *testing.T) {
	c := &Config{Ports: []string{"443"}}
	err := c.Save("/nonexistent/dir/config.json")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestSplitTrim(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"443,80,8443", 3},
		{" 443 , 80 ", 2},
		{"443", 1},
		{"", 0},
		{",,,", 0},
		{" , , ", 0},
	}
	for _, tt := range tests {
		got := splitTrim(tt.input)
		if len(got) != tt.want {
			t.Errorf("splitTrim(%q) = %d items, want %d", tt.input, len(got), tt.want)
		}
	}
}
