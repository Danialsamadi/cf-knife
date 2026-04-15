package scanner

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	cfIPv4URL = "https://www.cloudflare.com/ips-v4/"
	cfIPv6URL = "https://www.cloudflare.com/ips-v6/"
)

const fastlyIPListURL = "https://api.fastly.com/public-ip-list"

// LoadTargets resolves all three input modes into a flat slice of Targets.
// Priority: --ips > --input-file > official ranges (Cloudflare or Fastly).
// When samplePerSubnet > 0, only that many random IPs are kept from each CIDR.
func LoadTargets(ctx context.Context, ips, inputFile string, ports []string, ipv4Only, ipv6Only, shuffle, fastlyRanges bool, samplePerSubnet int) ([]Target, error) {
	var cidrs []string

	switch {
	case ips != "":
		for _, entry := range strings.Split(ips, ",") {
			entry = strings.TrimSpace(entry)
			if entry != "" {
				cidrs = append(cidrs, entry)
			}
		}
	case inputFile != "":
		lines, err := readLinesFromFile(inputFile)
		if err != nil {
			return nil, fmt.Errorf("read input file: %w", err)
		}
		cidrs = lines
	case fastlyRanges:
		fetched, err := fetchFastlyRanges(ctx, ipv4Only, ipv6Only)
		if err != nil {
			return nil, fmt.Errorf("fetch fastly ranges: %w", err)
		}
		cidrs = fetched
	default:
		fetched, err := fetchCloudflareRanges(ctx, ipv4Only, ipv6Only)
		if err != nil {
			return nil, fmt.Errorf("fetch cloudflare ranges: %w", err)
		}
		cidrs = fetched
	}

	targets, err := expandCIDRs(cidrs, ports, ipv4Only, ipv6Only, samplePerSubnet)
	if err != nil {
		return nil, err
	}

	if shuffle {
		rand.Shuffle(len(targets), func(i, j int) {
			targets[i], targets[j] = targets[j], targets[i]
		})
	}

	return targets, nil
}

func fetchCloudflareRanges(ctx context.Context, ipv4Only, ipv6Only bool) ([]string, error) {
	var urls []string
	if !ipv6Only {
		urls = append(urls, cfIPv4URL)
	}
	if !ipv4Only {
		urls = append(urls, cfIPv6URL)
	}

	var all []string
	client := &http.Client{Timeout: 15 * time.Second}

	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, fmt.Errorf("create request for %s: %w", u, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", u, err)
		}
		lines, err := readLines(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read body from %s: %w", u, err)
		}
		all = append(all, lines...)
	}

	if len(all) == 0 {
		return nil, fmt.Errorf("no CIDR ranges found from Cloudflare")
	}
	return all, nil
}

func fetchFastlyRanges(ctx context.Context, ipv4Only, ipv6Only bool) ([]string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fastlyIPListURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", fastlyIPListURL, err)
	}
	defer resp.Body.Close()

	var payload struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode fastly ip list: %w", err)
	}

	var all []string
	if !ipv6Only {
		all = append(all, payload.Addresses...)
	}
	if !ipv4Only {
		all = append(all, payload.IPv6Addresses...)
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no CIDR ranges found from Fastly")
	}
	return all, nil
}

func readLinesFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readLines(f)
}

func readLines(r io.Reader) ([]string, error) {
	var lines []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}

// expandCIDRs converts a mix of bare IPs and CIDRs into per-port Targets,
// recording the original source range for each.
// When sampleN > 0, at most sampleN IPs are randomly selected per CIDR entry.
func expandCIDRs(entries []string, ports []string, ipv4Only, ipv6Only bool, sampleN int) ([]Target, error) {
	var targets []Target

	for _, entry := range entries {
		ips, sourceRange, err := expandEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("expand %q: %w", entry, err)
		}

		// Apply address-family filter before sampling.
		filtered := ips[:0]
		for _, ip := range ips {
			if ipv4Only && ip.To4() == nil {
				continue
			}
			if ipv6Only && ip.To4() != nil {
				continue
			}
			filtered = append(filtered, ip)
		}

		if sampleN > 0 && len(filtered) > sampleN {
			rand.Shuffle(len(filtered), func(i, j int) {
				filtered[i], filtered[j] = filtered[j], filtered[i]
			})
			filtered = filtered[:sampleN]
		}

		for _, ip := range filtered {
			ipStr := ip.String()
			for _, port := range ports {
				targets = append(targets, Target{
					IP:          ipStr,
					Port:        port,
					SourceRange: sourceRange,
				})
			}
		}
	}
	return targets, nil
}

// expandEntry expands a single entry (bare IP or CIDR) into a list of IPs.
// Returns the canonical source range string.
func expandEntry(entry string) ([]net.IP, string, error) {
	// Try parsing as CIDR first.
	if strings.Contains(entry, "/") {
		ip, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, "", fmt.Errorf("invalid CIDR %q: %w", entry, err)
		}
		sourceRange := ipNet.String()
		ips := expandNetwork(ip, ipNet)
		return ips, sourceRange, nil
	}

	// Bare IP.
	ip := net.ParseIP(entry)
	if ip == nil {
		return nil, "", fmt.Errorf("invalid IP %q", entry)
	}
	return []net.IP{ip}, entry, nil
}

// expandNetwork enumerates all host addresses in a network.
// For IPv4 networks larger than /16 we cap at 65536 IPs to avoid OOM on huge
// ranges (e.g. /12); callers scanning /12 should use rate limiting and random
// sampling at the worker level.  IPv6 ranges are capped at the same limit.
const maxHostsPerRange = 1 << 20 // ~1M IPs — generous but bounded

func expandNetwork(ip net.IP, ipNet *net.IPNet) []net.IP {
	if ip.To4() != nil {
		return expandIPv4(ipNet)
	}
	return expandIPv6(ipNet)
}

func expandIPv4(ipNet *net.IPNet) []net.IP {
	ones, bits := ipNet.Mask.Size()
	count := 1 << uint(bits-ones)
	if count > maxHostsPerRange {
		count = maxHostsPerRange
	}

	start := binary.BigEndian.Uint32(ipNet.IP.To4())
	ips := make([]net.IP, 0, count)
	for i := 0; i < count; i++ {
		ipVal := start + uint32(i)
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, ipVal)
		ips = append(ips, ip)
	}
	return ips
}

func expandIPv6(ipNet *net.IPNet) []net.IP {
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	total := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	max := big.NewInt(int64(maxHostsPerRange))
	if total.Cmp(max) > 0 {
		total.Set(max)
	}

	startInt := new(big.Int).SetBytes(ipNet.IP.To16())
	ips := make([]net.IP, 0, int(total.Int64()))
	for i := int64(0); i < total.Int64(); i++ {
		cur := new(big.Int).Add(startInt, big.NewInt(i))
		b := cur.Bytes()
		ip := make(net.IP, 16)
		copy(ip[16-len(b):], b)
		ips = append(ips, ip)
	}
	return ips
}
