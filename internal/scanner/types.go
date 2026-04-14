package scanner

import "time"

// Target represents a single IP+port job for the worker pool.
type Target struct {
	IP          string
	Port        string
	SourceRange string // CIDR or "single" that this IP was expanded from
}

// ProbeResult holds the outcome of all enabled probes for one target.
type ProbeResult struct {
	IP          string        `json:"ip"`
	Port        string        `json:"port"`
	SourceRange string        `json:"source_range"`
	Latency     time.Duration `json:"latency_ms"`

	TCPSuccess   bool `json:"tcp_success"`
	TLSSuccess   bool `json:"tls_success"`
	HTTPSuccess  bool `json:"http_success"`
	HTTP2Success bool `json:"http2_success"`

	ScanType string `json:"scan_type"`

	// Service/version info populated by probes and scripts.
	ServerHeader string `json:"server_header,omitempty"`
	TLSVersion   string `json:"tls_version,omitempty"`
	TLSCipher    string `json:"tls_cipher,omitempty"`
	ALPN         string `json:"alpn,omitempty"`
	CFRay        string `json:"cf_ray,omitempty"`
	ServiceName  string `json:"service_name,omitempty"`

	// Performance metrics (--speed-test).
	PingMs       float64 `json:"ping_ms,omitempty"`
	JitterMs     float64 `json:"jitter_ms,omitempty"`
	DownloadMbps float64 `json:"download_mbps,omitempty"`
	UploadMbps   float64 `json:"upload_mbps,omitempty"`

	// DPI analysis (--dpi).
	BestFragmentSize int    `json:"best_fragment_size,omitempty"`
	SNIFront         string `json:"sni_front,omitempty"`

	Error string `json:"error,omitempty"`
}

// WARPTarget represents a single WARP UDP endpoint to probe.
type WARPTarget struct {
	IP   string
	Port int
}

// WARPResult holds the outcome of a WARP UDP endpoint probe.
type WARPResult struct {
	Endpoint  string        `json:"endpoint"`
	RTT       time.Duration `json:"rtt_ms"`
	Reachable bool          `json:"reachable"`
}

// ScanMode controls which probes are executed.
type ScanMode string

const (
	ModeTCPOnly ScanMode = "tcp-only"
	ModeTLS     ScanMode = "tls"
	ModeHTTP    ScanMode = "http"
	ModeHTTP2   ScanMode = "http2"
	ModeFull    ScanMode = "full"
)

// ScanType selects the underlying scan engine.
type ScanType string

const (
	ScanConnect ScanType = "connect"
	ScanFast    ScanType = "fast"
	ScanSYN     ScanType = "syn"
)

// Scanner coordinates the concurrent probing of targets.
type Scanner struct {
	Threads   int
	Config    *ProbeConfig
	Rate      int // global ops/sec; 0 = unlimited
	RateLimit int // per-worker ops/sec; 0 = unlimited
	Progress  bool
	Verbose   bool

	Results []ProbeResult
}
