package scanner

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadDomainCache reads a cache file written by SaveDomainCache and returns targets.
// Each line is "label | host" (comment lines starting with # are skipped).
// Returns nil, nil if the file does not exist.
func LoadDomainCache(path string) ([]Target, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Target
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lbl := ""
		host := line
		if idx := strings.Index(line, "|"); idx != -1 {
			lbl = strings.TrimSpace(line[:idx])
			host = strings.TrimSpace(line[idx+1:])
		}
		if host == "" {
			continue
		}
		out = append(out, Target{
			Hostname:    host,
			SNI:         host,
			SourceRange: "cache",
			Label:       lbl,
		})
	}
	return out, sc.Err()
}

// SaveDomainCache writes successful domain scan results to a cache file.
// Only results where HTTP or TLS succeeded and Hostname is set are saved.
func SaveDomainCache(path string, results []ProbeResult) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create cache file: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "# Auto-saved cache of last passed domains")
	for _, r := range results {
		if r.Hostname == "" {
			continue
		}
		if r.HTTPSuccess || r.HTTP2Success || r.TLSSuccess {
			fmt.Fprintf(w, "%s | %s\n", r.Label, r.Hostname)
		}
	}
	return w.Flush()
}

// DeduplicateDomainTargets returns prioritized ++ main with duplicates removed.
// Dedup key is Hostname+Port so cache entries can override stale main-list IPs.
func DeduplicateDomainTargets(prioritized, main []Target) []Target {
	seen := make(map[string]struct{})
	var out []Target
	for _, t := range prioritized {
		key := t.Hostname + ":" + t.Port
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, t)
		}
	}
	for _, t := range main {
		key := t.Hostname + ":" + t.Port
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}
