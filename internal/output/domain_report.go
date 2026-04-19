package output

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cf-knife/internal/scanner"
)

// WriteDomainReports writes two supplementary report files for domain-mode scans:
//   - reachable_TIMESTAMP.txt  — OPEN results sorted by latency
//   - full_log_TIMESTAMP.txt   — all results with OPEN/DEAD tags sorted by label
func WriteDomainReports(clean []scanner.ProbeResult, all []scanner.ProbeResult, basePath string, elapsed time.Duration) error {
	dir := filepath.Dir(basePath)
	ext := filepath.Ext(basePath)
	base := strings.TrimSuffix(filepath.Base(basePath), ext)
	// Extract timestamp suffix already embedded in basePath (e.g. "out-20260419-143000.txt")
	ts := time.Now().Format("20060102-150405")
	// Reuse the timestamp from basePath when possible to keep filenames in sync.
	if idx := strings.LastIndex(base, "-"); idx != -1 {
		ts = base[idx+1:]
	}

	reachablePath := filepath.Join(dir, "reachable-"+ts+".txt")
	fullLogPath := filepath.Join(dir, "full_log-"+ts+".txt")

	var dead []scanner.ProbeResult
	for _, r := range all {
		anyOK := r.TCPSuccess || r.TLSSuccess || r.HTTPSuccess || r.HTTP2Success || r.HTTP3Success
		if !anyOK {
			dead = append(dead, r)
		}
	}

	if err := writeReachableReport(reachablePath, clean, dead, len(all), elapsed); err != nil {
		return fmt.Errorf("write reachable report: %w", err)
	}
	if err := writeFullLogReport(fullLogPath, clean, dead); err != nil {
		return fmt.Errorf("write full log report: %w", err)
	}

	fmt.Printf("  domain reports: %s  |  %s\n", reachablePath, fullLogPath)
	return nil
}

func writeReachableReport(path string, open, dead []scanner.ProbeResult, total int, elapsed time.Duration) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "Reachability Report — OPEN SITES")
	fmt.Fprintf(w, "Generated        : %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Total tested     : %d / %d\n", len(open)+len(dead), total)
	fmt.Fprintf(w, "Open (reachable) : %d\n", len(open))
	fmt.Fprintf(w, "Closed / Dead    : %d\n", len(dead))
	fmt.Fprintf(w, "Elapsed          : %s\n", elapsed.Round(time.Millisecond))
	fmt.Fprintln(w, "============================================================================================")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%-4s  %8s  %5s  %-22s  %-30s  %s\n", "#", "Latency", "HTTP", "IP : Port", "Label", "Hostname")
	fmt.Fprintln(w, "--------------------------------------------------------------------------------------------")

	sorted := make([]scanner.ProbeResult, len(open))
	copy(sorted, open)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Latency < sorted[j].Latency })

	for i, r := range sorted {
		ipPort := r.IP + ":" + r.Port
		status := ""
		if r.HTTPStatus != 0 {
			status = fmt.Sprintf("%d", r.HTTPStatus)
		}
		fmt.Fprintf(w, "%-4d  %6dms  %5s  %-22s  %-30s  %s\n",
			i+1, r.Latency.Milliseconds(), status, ipPort,
			truncate(r.Label, 30), nvl(r.Hostname, r.IP))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "============================================================================================")
	fmt.Fprintln(w, "CLOSED / UNREACHABLE (DNS/TCP/TLS/HTTP Errors)")
	fmt.Fprintln(w, "============================================================================================")

	deadSorted := make([]scanner.ProbeResult, len(dead))
	copy(deadSorted, dead)
	sort.Slice(deadSorted, func(i, j int) bool { return deadSorted[i].Label < deadSorted[j].Label })

	for _, r := range deadSorted {
		ipPort := r.IP + ":" + r.Port
		fmt.Fprintf(w, "  %-30s  %-22s  [%s]\n", truncate(r.Label, 30), ipPort, r.Error)
	}

	return w.Flush()
}

func writeFullLogReport(path string, open, dead []scanner.ProbeResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "Reachability Report — FULL LOG")
	fmt.Fprintf(w, "Generated : %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintln(w, "============================================================================================")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%-6s  %8s  %-15s  %-22s  %-30s  %s\n", "Tag", "Latency", "HTTP/Err", "IP : Port", "Label", "Hostname")
	fmt.Fprintln(w, "--------------------------------------------------------------------------------------------")

	all := make([]scanner.ProbeResult, 0, len(open)+len(dead))
	all = append(all, open...)
	all = append(all, dead...)
	sort.Slice(all, func(i, j int) bool { return all[i].Label < all[j].Label })

	for _, r := range all {
		tag := "OPEN"
		statStr := ""
		if r.HTTPStatus != 0 {
			statStr = fmt.Sprintf("%d", r.HTTPStatus)
		}
		if r.Error != "" {
			tag = "DEAD"
			statStr = r.Error
		}
		ipPort := r.IP + ":" + r.Port
		fmt.Fprintf(w, "%-6s  %6dms  %-15s  %-22s  %-30s  %s\n",
			tag, r.Latency.Milliseconds(), truncate(statStr, 15),
			ipPort, truncate(r.Label, 30), nvl(r.Hostname, r.IP))
	}

	return w.Flush()
}
