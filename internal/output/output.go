package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cf-knife/internal/scanner"
)

// Write persists results to the requested format and always writes a
// clean_list.txt companion. It also prints a colored summary to stdout.
func Write(results []scanner.ProbeResult, basePath, format string, elapsed time.Duration) error {
	sort.Slice(results, func(i, j int) bool {
		return results[i].Latency < results[j].Latency
	})

	// Always write clean_list.txt (ip:port only).
	dir := filepath.Dir(basePath)
	listPath := filepath.Join(dir, "clean_list.txt")
	if err := writeCleanList(results, listPath); err != nil {
		return fmt.Errorf("write clean_list: %w", err)
	}

	var err error
	switch format {
	case "json":
		err = writeJSON(results, basePath)
	case "csv":
		err = writeCSV(results, basePath)
	default:
		err = writeTXT(results, basePath)
	}
	if err != nil {
		return err
	}

	printSummary(results, basePath, listPath, elapsed)
	return nil
}

func writeCleanList(results []scanner.ProbeResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, r := range results {
		if r.SNI != "" {
			fmt.Fprintf(f, "%s:%s#%s\n", r.IP, r.Port, r.SNI)
		} else {
			fmt.Fprintf(f, "%s:%s\n", r.IP, r.Port)
		}
	}
	return nil
}

func writeTXT(results []scanner.ProbeResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, r := range results {
		line := fmt.Sprintf("%s:%s | sni=%s | latency=%dms | range=%s | tcp=%s tls=%s https=%s http2=%s http3=%s | service=%s",
			r.IP, r.Port,
			nvl(r.SNI, "-"),
			r.Latency.Milliseconds(),
			r.SourceRange,
			boolOK(r.TCPSuccess), boolOK(r.TLSSuccess),
			boolOK(r.HTTPSuccess), boolOK(r.HTTP2Success), boolOK(r.HTTP3Success),
			nvl(r.ServiceName, "-"),
		)
		if r.PingMs > 0 {
			line += fmt.Sprintf(" | ping=%.1fms jitter=%.1fms", r.PingMs, r.JitterMs)
		}
		if r.DownloadMbps > 0 || r.UploadMbps > 0 {
			line += fmt.Sprintf(" | dl=%.2fMbps ul=%.2fMbps", r.DownloadMbps, r.UploadMbps)
		}
		if r.BestFragmentSize > 0 {
			line += fmt.Sprintf(" | frag=%d", r.BestFragmentSize)
		}
		if r.SNIFront != "" {
			line += fmt.Sprintf(" | sni_front=%s", r.SNIFront)
		}
		if r.CertIssuer != "" {
			line += fmt.Sprintf(" | cert_issuer=%s", r.CertIssuer)
		}
		if r.CertMITM {
			line += " | MITM_DETECTED"
		}
		fmt.Fprintln(f, line)
	}
	return nil
}

func writeJSON(results []scanner.ProbeResult, path string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func writeCSV(results []scanner.ProbeResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{"ip", "port", "sni", "latency_ms", "source_range", "tcp", "tls", "https", "http2", "http3",
		"scan_type", "server", "tls_version", "tls_cipher", "alpn", "cf_ray", "service",
		"ping_ms", "jitter_ms", "download_mbps", "upload_mbps",
		"best_fragment", "sni_front",
		"cert_issuer", "cert_subject", "cert_expiry", "cert_mitm",
		"error"}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, r := range results {
		row := []string{
			r.IP, r.Port, r.SNI,
			fmt.Sprintf("%d", r.Latency.Milliseconds()),
			r.SourceRange,
			boolStr(r.TCPSuccess), boolStr(r.TLSSuccess),
			boolStr(r.HTTPSuccess), boolStr(r.HTTP2Success), boolStr(r.HTTP3Success),
			r.ScanType, r.ServerHeader, r.TLSVersion, r.TLSCipher,
			r.ALPN, r.CFRay, r.ServiceName,
			fmtFloat(r.PingMs), fmtFloat(r.JitterMs),
			fmtFloat(r.DownloadMbps), fmtFloat(r.UploadMbps),
			fmtInt(r.BestFragmentSize), r.SNIFront,
			r.CertIssuer, r.CertSubject, r.CertExpiry, boolStr(r.CertMITM),
			r.Error,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// printSummary renders a colored table to stdout.
func printSummary(results []scanner.ProbeResult, mainPath, listPath string, elapsed time.Duration) {
	const (
		reset  = "\033[0m"
		bold   = "\033[1m"
		green  = "\033[32m"
		red    = "\033[31m"
		yellow = "\033[33m"
		cyan   = "\033[36m"
	)

	fmt.Printf("\n%s%s=== cf-knife scan results ===%s\n\n", bold, cyan, reset)

	// Header
	fmt.Printf("%s%-40s %-6s %-22s %8s  %-20s  %-4s %-4s %-5s %-5s %-5s  %s%s\n",
		bold,
		"IP", "PORT", "SNI", "LATENCY", "RANGE", "TCP", "TLS", "HTTPS", "HTTP2", "HTTP3", "SERVICE",
		reset,
	)
	fmt.Println(strings.Repeat("─", 145))

	limit := len(results)
	if limit > 50 {
		limit = 50
	}
	for _, r := range results[:limit] {
		fmt.Printf("%-40s %-6s %-22s %6dms  %-20s  %s %s %s %s %s  %s\n",
			r.IP, r.Port,
			truncate(nvl(r.SNI, "-"), 22),
			r.Latency.Milliseconds(),
			truncate(r.SourceRange, 20),
			colorBool(r.TCPSuccess, green, red, reset),
			colorBool(r.TLSSuccess, green, red, reset),
			colorBool(r.HTTPSuccess, green, red, reset),
			colorBool(r.HTTP2Success, green, red, reset),
			colorBool(r.HTTP3Success, green, red, reset),
			nvl(r.ServiceName, "-"),
		)
	}
	if len(results) > 50 {
		fmt.Printf("  ... and %d more\n", len(results)-50)
	}

	fmt.Println(strings.Repeat("─", 135))
	fmt.Printf("\n%sStats:%s  %d clean results  |  elapsed %s  |  %.0f targets/sec\n",
		bold, reset,
		len(results), elapsed.Round(time.Millisecond),
		float64(len(results))/maxF(elapsed.Seconds(), 0.001),
	)
	fmt.Printf("%sFiles:%s  %s  |  %s\n\n",
		bold, reset,
		mainPath, listPath,
	)

	_ = yellow // reserved for warnings
}

func colorBool(ok bool, cGreen, cRed, cReset string) string {
	if ok {
		return cGreen + " ok " + cReset
	}
	return cRed + "fail" + cReset
}

func boolOK(b bool) string {
	if b {
		return "ok"
	}
	return "fail"
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func nvl(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func fmtFloat(v float64) string {
	if v == 0 {
		return ""
	}
	return fmt.Sprintf("%.2f", v)
}

func fmtInt(v int) string {
	if v == 0 {
		return ""
	}
	return fmt.Sprintf("%d", v)
}

// WriteWARP saves reachable WARP endpoint results to a file and prints a summary.
func WriteWARP(results []scanner.WARPResult, path string, elapsed time.Duration) error {
	sort.Slice(results, func(i, j int) bool {
		return results[i].RTT < results[j].RTT
	})

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, r := range results {
		fmt.Fprintf(f, "%s | rtt=%dms\n", r.Endpoint, r.RTT.Milliseconds())
	}

	printWARPSummary(results, path, elapsed)
	return nil
}

func printWARPSummary(results []scanner.WARPResult, path string, elapsed time.Duration) {
	const (
		reset = "\033[0m"
		bold  = "\033[1m"
		cyan  = "\033[36m"
		green = "\033[32m"
	)

	fmt.Printf("\n%s%s=== WARP scan results ===%s\n\n", bold, cyan, reset)
	fmt.Printf("%s%-30s %10s%s\n", bold, "ENDPOINT", "RTT", reset)
	fmt.Println(strings.Repeat("-", 45))

	limit := len(results)
	if limit > 30 {
		limit = 30
	}
	for _, r := range results[:limit] {
		fmt.Printf("%s%-30s%s %8dms\n", green, r.Endpoint, reset, r.RTT.Milliseconds())
	}
	if len(results) > 30 {
		fmt.Printf("  ... and %d more\n", len(results)-30)
	}

	fmt.Println(strings.Repeat("-", 45))
	fmt.Printf("\n%sStats:%s  %d reachable endpoints  |  elapsed %s\n",
		bold, reset, len(results), elapsed.Round(time.Millisecond))
	fmt.Printf("%sFile:%s  %s\n\n", bold, reset, path)
}
