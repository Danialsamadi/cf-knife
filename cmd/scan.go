package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"cf-knife/internal/config"
	"cf-knife/internal/output"
	"cf-knife/internal/scanner"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	f.IntP("threads", "t", 200, "number of concurrent workers (1-10000)")
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

	f.Bool("speed-test", false, "enable ICMP ping, jitter, and HTTP speed measurement")
	f.Bool("dpi", false, "enumerate DPI fragment sizes and find best SNI front")
	f.String("fragment-sizes", "10,50,100,200,500", "comma-separated fragment sizes for DPI testing")
	f.Bool("warp", false, "scan for reachable Cloudflare WARP UDP endpoints")
	f.Int("warp-port", 2408, "UDP port for WARP probing")
}

func runScan(cmd *cobra.Command, args []string) error {
	v := viper.New()
	if err := v.BindPFlags(cmd.Flags()); err != nil {
		return fmt.Errorf("bind flags: %w", err)
	}

	if cfgPath := v.GetString("config"); cfgPath != "" {
		v.SetConfigFile(cfgPath)
		if err := v.MergeInConfig(); err != nil {
			return fmt.Errorf("read config file %q: %w", cfgPath, err)
		}
	}

	cfg, err := config.Load(v)
	if err != nil {
		return err
	}

	// Apply timing preset for flags the user didn't explicitly set.
	cfg.ApplyTiming(func(name string) bool {
		return cmd.Flags().Changed(name)
	})

	if cfg.SaveConfig {
		savePath := "cf-knife-config.json"
		if cfg.ConfigFile != "" {
			savePath = cfg.ConfigFile
		}
		if err := cfg.Save(savePath); err != nil {
			return err
		}
		fmt.Printf("config saved to %s\n", savePath)
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Load targets.
	if cfg.Verbose {
		fmt.Println("loading targets...")
	}
	targets, err := scanner.LoadTargets(ctx, cfg.IPs, cfg.InputFile, cfg.Ports,
		cfg.IPv4Only, cfg.IPv6Only, cfg.Shuffle)
	if err != nil {
		return err
	}
	fmt.Printf("loaded %d targets (%d IPs × %d ports)\n",
		len(targets), len(targets)/maxInt(len(cfg.Ports), 1), len(cfg.Ports))

	// Parse DPI fragment sizes if needed.
	var fragSizes []int
	if cfg.DPIAnalysis {
		var parseErr error
		fragSizes, parseErr = scanner.ParseFragmentSizes(cfg.FragmentSizes)
		if parseErr != nil {
			return fmt.Errorf("parse --fragment-sizes: %w", parseErr)
		}
	}

	pc := &scanner.ProbeConfig{
		SNI:           cfg.SNI,
		Timeout:       cfg.Timeout,
		Retries:       cfg.Retries,
		Mode:          scanner.ScanMode(cfg.Mode),
		TestTCP:       cfg.TestTCP,
		TestTLS:       cfg.TestTLS,
		TestHTTP:      cfg.TestHTTP,
		TestHTTP2:     cfg.TestHTTP2,
		HTTPURL:       cfg.HTTPURL,
		MaxLatency:    cfg.MaxLatency,
		ScanType:      scanner.ScanType(cfg.ScanType),
		Script:        cfg.Script,
		SpeedTest:     cfg.SpeedTest,
		DPIAnalysis:   cfg.DPIAnalysis,
		FragmentSizes: fragSizes,
	}

	sc := &scanner.Scanner{
		Threads:   cfg.Threads,
		Config:    pc,
		Rate:      cfg.Rate,
		RateLimit: cfg.RateLimit,
		Progress:  cfg.Progress,
		Verbose:   cfg.Verbose,
	}

	// WARP scan runs as a separate path (UDP-based, not TCP probes).
	if cfg.WARPScan {
		fmt.Println("scanning WARP endpoints...")
		warpStart := time.Now()

		warpTargets, warpErr := scanner.ExpandWARPRanges(nil, cfg.WARPPort)
		if warpErr != nil {
			return fmt.Errorf("expand WARP ranges: %w", warpErr)
		}
		fmt.Printf("  %d WARP endpoints to probe on port %d\n", len(warpTargets), cfg.WARPPort)

		warpResults := scanner.ScanWARP(ctx, warpTargets, cfg.Timeout, cfg.Threads)
		warpElapsed := time.Since(warpStart)

		var reachable []scanner.WARPResult
		for _, wr := range warpResults {
			if wr.Reachable {
				reachable = append(reachable, wr)
			}
		}

		ext := filepath.Ext(cfg.Output)
		base := strings.TrimSuffix(cfg.Output, ext)
		ts := time.Now().Format("20060102-150405")
		warpPath := base + "-warp-" + ts + ext

		if warpWriteErr := output.WriteWARP(reachable, warpPath, warpElapsed); warpWriteErr != nil {
			return fmt.Errorf("write WARP output: %w", warpWriteErr)
		}
		fmt.Printf("  %d reachable WARP endpoints saved to %s (%.1fs)\n",
			len(reachable), warpPath, warpElapsed.Seconds())
	}

	fmt.Println("scanning...")
	start := time.Now()
	sc.Run(ctx, targets)
	elapsed := time.Since(start)

	interrupted := ctx.Err() != nil

	// From here on, ignore further signals so the save phase always completes.
	stop()
	signal.Reset(os.Interrupt)
	if interrupted {
		fmt.Println("\n  Interrupted — saving partial results...")
	}

	// Filter: keep results where any probe succeeded and latency is within limit.
	var clean []scanner.ProbeResult
	for _, r := range sc.Results {
		anyOK := r.TCPSuccess || r.TLSSuccess || r.HTTPSuccess || r.HTTP2Success
		if anyOK && r.Latency <= cfg.MaxLatency {
			clean = append(clean, r)
		}
	}

	// Append timestamp to output filename: result.txt → result-20260413-151200.txt
	ext := filepath.Ext(cfg.Output)
	base := strings.TrimSuffix(cfg.Output, ext)
	ts := time.Now().Format("20060102-150405")
	outPath := base + "-" + ts + ext

	if err := output.Write(clean, outPath, cfg.OutputFmt, elapsed); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	fmt.Printf("  %d clean results saved to %s\n", len(clean), outPath)
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
