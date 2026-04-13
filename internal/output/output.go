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
		fmt.Fprintf(f, "%s:%s\n", r.IP, r.Port)
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
		fmt.Fprintf(f, "%s:%s | latency=%dms | range=%s | tcp=%s tls=%s http=%s http2=%s | service=%s\n",
			r.IP, r.Port,
			r.Latency.Milliseconds(),
			r.SourceRange,
			boolOK(r.TCPSuccess), boolOK(r.TLSSuccess),
			boolOK(r.HTTPSuccess), boolOK(r.HTTP2Success),
			nvl(r.ServiceName, "-"),
		)
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

	header := []string{"ip", "port", "latency_ms", "source_range", "tcp", "tls", "http", "http2",
		"scan_type", "server", "tls_version", "tls_cipher", "alpn", "cf_ray", "service", "error"}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, r := range results {
		row := []string{
			r.IP, r.Port,
			fmt.Sprintf("%d", r.Latency.Milliseconds()),
			r.SourceRange,
			boolStr(r.TCPSuccess), boolStr(r.TLSSuccess),
			boolStr(r.HTTPSuccess), boolStr(r.HTTP2Success),
			r.ScanType, r.ServerHeader, r.TLSVersion, r.TLSCipher,
			r.ALPN, r.CFRay, r.ServiceName, r.Error,
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
	fmt.Printf("%s%-40s %-6s %8s  %-20s  %-4s %-4s %-5s %-6s  %s%s\n",
		bold,
		"IP", "PORT", "LATENCY", "RANGE", "TCP", "TLS", "HTTP", "HTTP2", "SERVICE",
		reset,
	)
	fmt.Println(strings.Repeat("─", 110))

	limit := len(results)
	if limit > 50 {
		limit = 50
	}
	for _, r := range results[:limit] {
		fmt.Printf("%-40s %-6s %6dms  %-20s  %s %s %s %s  %s\n",
			r.IP, r.Port,
			r.Latency.Milliseconds(),
			truncate(r.SourceRange, 20),
			colorBool(r.TCPSuccess, green, red, reset),
			colorBool(r.TLSSuccess, green, red, reset),
			colorBool(r.HTTPSuccess, green, red, reset),
			colorBool(r.HTTP2Success, green, red, reset),
			nvl(r.ServiceName, "-"),
		)
	}
	if len(results) > 50 {
		fmt.Printf("  ... and %d more\n", len(results)-50)
	}

	fmt.Println(strings.Repeat("─", 110))
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
