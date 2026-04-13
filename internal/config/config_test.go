package config

import (
	"testing"
)

func TestConfig_Validate(t *testing.T) {
	base := func() *Config {
		return &Config{
			Ports:    []string{"443"},
			Threads:  200,
			Timing:   3,
			Mode:     "full",
			ScanType: "connect",
			OutputFmt: "txt",
		}
	}

	tests := []struct {
		name    string
		modify  func(c *Config)
		wantErr bool
	}{
		{"valid defaults", func(c *Config) {}, false},
		{"threads too low", func(c *Config) { c.Threads = 0 }, true},
		{"threads too high", func(c *Config) { c.Threads = 3000 }, true},
		{"timing too high", func(c *Config) { c.Timing = 6 }, true},
		{"bad mode", func(c *Config) { c.Mode = "invalid" }, true},
		{"bad scan-type", func(c *Config) { c.ScanType = "nope" }, true},
		{"bad output-format", func(c *Config) { c.OutputFmt = "xml" }, true},
		{"ipv4+ipv6 exclusive", func(c *Config) { c.IPv4Only = true; c.IPv6Only = true }, true},
		{"bad script", func(c *Config) { c.Script = "nmap" }, true},
		{"valid cloudflare script", func(c *Config) { c.Script = "cloudflare" }, false},
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
