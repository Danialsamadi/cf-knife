package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all runtime configuration derived from flags, config file, and defaults.
type Config struct {
	Ports      []string      `json:"ports" mapstructure:"ports"`
	SNI        string        `json:"sni" mapstructure:"sni"`
	SNIs       []string      `json:"snis"`
	Threads    int           `json:"threads" mapstructure:"threads"`
	Timeout    time.Duration `json:"timeout" mapstructure:"timeout"`
	Retries    int           `json:"retries" mapstructure:"retries"`
	Mode       string        `json:"mode" mapstructure:"mode"`
	TestTCP    bool          `json:"test_tcp" mapstructure:"test-tcp"`
	TestTLS    bool          `json:"test_tls" mapstructure:"test-tls"`
	TestHTTP   bool          `json:"test_http" mapstructure:"test-http"`
	TestHTTP2  bool          `json:"test_http2" mapstructure:"test-http2"`
	TestHTTP3  bool          `json:"test_http3" mapstructure:"test-http3"`
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

	SpeedTest     bool   `json:"speed_test" mapstructure:"speed-test"`
	DPIAnalysis   bool   `json:"dpi" mapstructure:"dpi"`
	FragmentSizes string `json:"fragment_sizes" mapstructure:"fragment-sizes"`
	WARPScan      bool   `json:"warp" mapstructure:"warp"`
	WARPPort      int    `json:"warp_port" mapstructure:"warp-port"`

	SamplePerSubnet int  `json:"sample_per_subnet" mapstructure:"sample"`
	HTTPFragment    bool `json:"http_fragment" mapstructure:"http-fragment"`

	FastlyRanges bool   `json:"fastly_ranges" mapstructure:"fastly-ranges"`
	CertCheck    bool   `json:"cert_check" mapstructure:"cert-check"`
	SmartRetry   bool   `json:"smart_retry" mapstructure:"smart-retry"`
	Resume       bool   `json:"resume" mapstructure:"resume"`
	DBPath       string `json:"db_path" mapstructure:"db"`

	DomainFile    string `json:"domain_file" mapstructure:"domain-file"`
	CFAllPorts    bool   `json:"cf_all_ports" mapstructure:"cf-all-ports"`
	SitePreflight bool   `json:"site_preflight" mapstructure:"site-preflight"`
}

// Load reads a Config from Viper, which should already have flag bindings and
// any config file merged in by the caller.
func Load(v *viper.Viper) (*Config, error) {
	// Parse the comma-separated port string into a slice.
	portStr := v.GetString("port")
	ports := splitTrim(portStr)
	if len(ports) == 0 {
		return nil, fmt.Errorf("at least one port is required")
	}

	sniStr := v.GetString("sni")
	snis := splitTrim(sniStr)
	if len(snis) == 0 {
		snis = []string{"www.cloudflare.com"}
	}

	cfg := &Config{
		Ports:      ports,
		SNI:        snis[0],
		SNIs:       snis,
		Threads:    v.GetInt("threads"),
		Timeout:    v.GetDuration("timeout"),
		Retries:    v.GetInt("retries"),
		Mode:       v.GetString("mode"),
		TestTCP:    v.GetBool("test-tcp"),
		TestTLS:    v.GetBool("test-tls"),
		TestHTTP:   v.GetBool("test-http"),
		TestHTTP2:  v.GetBool("test-http2"),
		TestHTTP3:  v.GetBool("test-http3"),
		HTTPURL:    v.GetString("http-url"),
		InputFile:  v.GetString("input-file"),
		IPs:        v.GetString("ips"),
		IPv4Only:   v.GetBool("ipv4-only"),
		IPv6Only:   v.GetBool("ipv6-only"),
		MaxLatency: v.GetDuration("max-latency"),
		Output:     v.GetString("output"),
		OutputFmt:  v.GetString("output-format"),
		ScanType:   v.GetString("scan-type"),
		Rate:       v.GetInt("rate"),
		Timing:     v.GetInt("timing"),
		Script:     v.GetString("script"),
		Shuffle:    v.GetBool("shuffle"),
		RateLimit:  v.GetInt("rate-limit"),
		ConfigFile: v.GetString("config"),
		SaveConfig: v.GetBool("save-config"),
		Verbose:    v.GetBool("verbose"),
		Progress:   v.GetBool("progress"),

		SpeedTest:     v.GetBool("speed-test"),
		DPIAnalysis:   v.GetBool("dpi"),
		FragmentSizes: v.GetString("fragment-sizes"),
		WARPScan:      v.GetBool("warp"),
		WARPPort:      v.GetInt("warp-port"),

		SamplePerSubnet: v.GetInt("sample"),
		HTTPFragment:    v.GetBool("http-fragment"),

		FastlyRanges: v.GetBool("fastly-ranges"),
		CertCheck:    v.GetBool("cert-check"),
		SmartRetry:   v.GetBool("smart-retry"),
		Resume:       v.GetBool("resume"),
		DBPath:       v.GetString("db"),

		DomainFile:    v.GetString("domain-file"),
		CFAllPorts:    v.GetBool("cf-all-ports"),
		SitePreflight: v.GetBool("site-preflight"),
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks semantic constraints that flag parsing alone cannot enforce.
func (c *Config) Validate() error {
	if c.Threads < 1 || c.Threads > 10000 {
		return fmt.Errorf("--threads must be between 1 and 10000, got %d", c.Threads)
	}
	if c.Timing < 0 || c.Timing > 5 {
		return fmt.Errorf("--timing must be between 0 and 5, got %d", c.Timing)
	}

	validModes := map[string]bool{"tcp-only": true, "tls": true, "http": true, "http2": true, "http3": true, "full": true}
	if !validModes[c.Mode] {
		return fmt.Errorf("--mode must be one of tcp-only|tls|http|http2|http3|full, got %q", c.Mode)
	}

	validScans := map[string]bool{"connect": true, "fast": true, "syn": true}
	if !validScans[c.ScanType] {
		return fmt.Errorf("--scan-type must be one of connect|fast|syn, got %q", c.ScanType)
	}

	validFmts := map[string]bool{"txt": true, "json": true, "csv": true}
	if !validFmts[c.OutputFmt] {
		return fmt.Errorf("--output-format must be one of txt|json|csv, got %q", c.OutputFmt)
	}

	if c.IPv4Only && c.IPv6Only {
		return fmt.Errorf("--ipv4-only and --ipv6-only are mutually exclusive")
	}

	validScripts := map[string]bool{"": true, "cloudflare": true, "fastly": true}
	if !validScripts[c.Script] {
		return fmt.Errorf("--script must be 'cloudflare', 'fastly', or empty, got %q", c.Script)
	}

	return nil
}

// Save writes the current config as pretty-printed JSON to the given path.
func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}
	return nil
}

func splitTrim(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
