// Domain list loading for DPI-bypass style scans (DNS → dial IP, SNI = hostname).
// Parser patterns adapted from cloudflare-site-scanner/engine/target.go (see ATTRIBUTION.md).

package scanner

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
)

// CFHTTPSPorts and CFHTTPPorts are Cloudflare-proxied edge ports (HTTP vs HTTPS stacks).
var (
	CFHTTPSPorts = []int{443, 2053, 2083, 2087, 2096, 8443}
	CFHTTPPorts  = []int{80, 8080, 8880, 2052, 2082, 2086, 2095}
)

// DomainLoadOptions configures LoadDomainTargets.
type DomainLoadOptions struct {
	Ports      []string // used when CFAllPorts is false (e.g. "443", "80")
	CFAllPorts bool     // expand each host across all 13 CF ports
	Shuffle    bool
	IPv4Only   bool // when resolving, prefer IPv4
	IPv6Only   bool // when resolving, prefer IPv6
}

type domainEntry struct {
	label string
	host  string
}

// LoadDomainTargets reads a text file of domains (one per line), resolves each
// hostname to an IP, and emits Targets with Hostname/SNI set for dial-by-IP probes.
func LoadDomainTargets(ctx context.Context, path string, opt DomainLoadOptions) ([]Target, error) {
	entries, err := parseDomainFile(path)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no domains in %s", path)
	}
	if !opt.CFAllPorts && len(opt.Ports) == 0 {
		return nil, fmt.Errorf("domain load: Ports required when CFAllPorts is false")
	}

	var out []Target
	if opt.CFAllPorts {
		seen := make(map[string]struct{})
		for _, e := range entries {
			if _, ok := seen[e.host]; ok {
				continue
			}
			seen[e.host] = struct{}{}
			ip, err := resolveHost(ctx, e.host, opt.IPv4Only, opt.IPv6Only)
			if err != nil {
				return nil, fmt.Errorf("resolve %q: %w", e.host, err)
			}
			for _, p := range CFHTTPSPorts {
				out = append(out, Target{
					IP:          ip,
					Port:        strconv.Itoa(p),
					SourceRange: "domain",
					Hostname:    e.host,
					SNI:         e.host,
				})
			}
			for _, p := range CFHTTPPorts {
				out = append(out, Target{
					IP:          ip,
					Port:        strconv.Itoa(p),
					SourceRange: "domain",
					Hostname:    e.host,
					SNI:         e.host,
				})
			}
		}
	} else {
		for _, e := range entries {
			ip, err := resolveHost(ctx, e.host, opt.IPv4Only, opt.IPv6Only)
			if err != nil {
				return nil, fmt.Errorf("resolve %q: %w", e.host, err)
			}
			for _, ps := range opt.Ports {
				ps = strings.TrimSpace(ps)
				out = append(out, Target{
					IP:          ip,
					Port:        ps,
					SourceRange: "domain",
					Hostname:    e.host,
					SNI:         e.host,
				})
			}
		}
	}

	if opt.Shuffle {
		rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	}

	return out, nil
}

func parseDomainFile(path string) ([]domainEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []domainEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lbl := ""
		val := line
		if idx := strings.Index(line, "|"); idx != -1 {
			lbl = strings.TrimSpace(line[:idx])
			val = strings.TrimSpace(line[idx+1:])
		}
		val = strings.Trim(val, "'\"")

		host, _ := parseHostScheme(val)
		if host == "" {
			continue
		}
		out = append(out, domainEntry{label: lbl, host: host})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseHostScheme(val string) (host, scheme string) {
	if strings.HasPrefix(val, "http://") {
		scheme = "http"
		host = strings.TrimPrefix(val, "http://")
		host = strings.SplitN(host, "/", 2)[0]
		return host, scheme
	}
	if strings.HasPrefix(val, "https://") {
		scheme = "https"
		host = strings.TrimPrefix(val, "https://")
		host = strings.SplitN(host, "/", 2)[0]
		return host, scheme
	}
	return val, "https"
}

func resolveHost(ctx context.Context, host string, ipv4Only, ipv6Only bool) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no addresses for %q", host)
	}
	if ipv6Only {
		for _, s := range ips {
			if net.ParseIP(s).To16() != nil && net.ParseIP(s).To4() == nil {
				return s, nil
			}
		}
		return ips[0], nil
	}
	if ipv4Only {
		for _, s := range ips {
			if net.ParseIP(s).To4() != nil {
				return s, nil
			}
		}
	}
	for _, s := range ips {
		if net.ParseIP(s).To4() != nil {
			return s, nil
		}
	}
	return ips[0], nil
}
