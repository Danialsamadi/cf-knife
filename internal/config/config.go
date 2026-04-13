package config

import "time"

// Config holds all runtime configuration derived from flags, config file, and defaults.
type Config struct {
	Ports      []string      `json:"ports" mapstructure:"ports"`
	SNI        string        `json:"sni" mapstructure:"sni"`
	Threads    int           `json:"threads" mapstructure:"threads"`
	Timeout    time.Duration `json:"timeout" mapstructure:"timeout"`
	Retries    int           `json:"retries" mapstructure:"retries"`
	Mode       string        `json:"mode" mapstructure:"mode"`
	TestTCP    bool          `json:"test_tcp" mapstructure:"test-tcp"`
	TestTLS    bool          `json:"test_tls" mapstructure:"test-tls"`
	TestHTTP   bool          `json:"test_http" mapstructure:"test-http"`
	TestHTTP2  bool          `json:"test_http2" mapstructure:"test-http2"`
	HTTPURL    string        `json:"http_url" mapstructure:"http-url"`
	InputFile  string        `json:"input_file" mapstructure:"input-file"`
	IPs        string        `json:"ips" mapstructure:"ips"`
	IPv4Only   bool          `json:"ipv4_only" mapstructure:"ipv4-only"`
	IPv6Only   bool          `json:"ipv6_only" mapstructure:"ipv6-only"`
	MaxLatency time.Duration `json:"max_latency" mapstructure:"max-latency"`
	Output     string        `json:"output" mapstructure:"output"`
	OutputFmt  string        `json:"output_format" mapstructure:"output-format"`
	ScanType   string        `json:"scan_type" mapstructure:"scan-type"`
	Rate       int           `json:"rate" mapstructure:"rate"`
	Timing     int           `json:"timing" mapstructure:"timing"`
	Script     string        `json:"script" mapstructure:"script"`
	Shuffle    bool          `json:"shuffle" mapstructure:"shuffle"`
	RateLimit  int           `json:"rate_limit" mapstructure:"rate-limit"`
	ConfigFile string        `json:"-" mapstructure:"config"`
	SaveConfig bool          `json:"-" mapstructure:"save-config"`
	Verbose    bool          `json:"verbose" mapstructure:"verbose"`
	Progress   bool          `json:"progress" mapstructure:"progress"`
}
