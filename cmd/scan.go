package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan Cloudflare (or custom) IP ranges",
	Long: `Probe IPs across multiple ports with TCP, TLS, HTTP/1.1, and HTTP/2
checks. Supports official Cloudflare ranges, custom files, and inline CIDRs.`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	f := scanCmd.Flags()
	f.StringP("port", "p", "443,80,8443,2053,2083", "comma-separated ports")
	f.String("sni", "www.cloudflare.com", "SNI hostname for TLS handshake")
	f.IntP("threads", "t", 200, "number of concurrent workers (1-2000)")
	f.Duration("timeout", 3_000_000_000, "per-probe timeout") // 3s
	f.Int("retries", 2, "number of retries per probe")
	f.String("mode", "full", "probe mode: tcp-only|tls|http|http2|full")
	f.Bool("test-tcp", false, "force TCP test regardless of mode")
	f.Bool("test-tls", false, "force TLS test regardless of mode")
	f.Bool("test-http", false, "force HTTP/1.1 test regardless of mode")
	f.Bool("test-http2", false, "force HTTP/2 test regardless of mode")
	f.String("http-url", "https://www.cloudflare.com/cdn-cgi/trace", "URL for HTTP probe")
	f.StringP("input-file", "i", "", "file with IPs/CIDRs (one per line)")
	f.String("ips", "", "comma-separated IPs or CIDRs")
	f.Bool("ipv4-only", false, "scan IPv4 addresses only")
	f.Bool("ipv6-only", false, "scan IPv6 addresses only")
	f.Duration("max-latency", 800_000_000, "discard results above this latency") // 800ms
	f.StringP("output", "o", "clean_ips.txt", "base output filename")
	f.String("output-format", "txt", "output format: txt|json|csv")
	f.String("scan-type", "connect", "scan engine: connect|fast|syn")
	f.Int("rate", 0, "global packets/connections per second (0=unlimited)")
	f.Int("timing", 3, "nmap-style timing template 0-5")
	f.String("script", "", "run a script: cloudflare")
	f.Bool("shuffle", false, "randomize target order")
	f.Int("rate-limit", 0, "per-worker requests/sec (legacy compat)")
	f.String("config", "", "path to JSON config file")
	f.Bool("save-config", false, "save current flags to config file")
	f.Bool("verbose", false, "verbose logging")
	f.Bool("progress", true, "show progress bar")
}

func runScan(cmd *cobra.Command, args []string) error {
	fmt.Println("cf-knife scan: not yet implemented (skeleton)")
	return nil
}
