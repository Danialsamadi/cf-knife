package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// DNSCheckResult holds the outcome of a DNS poison detection check.
type DNSCheckResult struct {
	SystemIP string // IP returned by the system resolver
	CleanIP  string // IP returned by DoH (the "real" answer)
	Poisoned bool
	// Reason is one of: "" (clean), "IP_MISMATCH", "DNS_HIJACK", "DOH_UNAVAILABLE"
	Reason string
}

// CheckDNSPoisoning resolves host via the system resolver and via Cloudflare+Google
// DoH, then compares the results. If the system IP is absent from both DoH answers
// the DNS is considered poisoned.
func CheckDNSPoisoning(ctx context.Context, host string, timeout time.Duration) DNSCheckResult {
	dnsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// System resolution.
	sysIPs, sysErr := net.DefaultResolver.LookupHost(dnsCtx, host)
	systemIP := ""
	if sysErr == nil && len(sysIPs) > 0 {
		// Prefer IPv4.
		for _, s := range sysIPs {
			if net.ParseIP(s).To4() != nil {
				systemIP = s
				break
			}
		}
		if systemIP == "" {
			systemIP = sysIPs[0]
		}
	}

	// DoH resolution — dial by hardcoded IP to bypass DNS poisoning of the resolver
	// hostname itself. InsecureSkipVerify is intentional: we only use these IPs for
	// comparison, not for establishing trust.
	cfIPs, _ := resolveDoH(ctx, "1.1.1.1", "cloudflare-dns.com", "/dns-query", host, timeout)
	gIPs, _ := resolveDoH(ctx, "8.8.8.8", "dns.google", "/resolve", host, timeout)

	dohIPs := union(cfIPs, gIPs)
	cleanIP := ""
	if len(dohIPs) > 0 {
		cleanIP = dohIPs[0]
	}

	// --- Classify ---

	// Both DoH sources unavailable → inconclusive.
	if len(dohIPs) == 0 {
		return DNSCheckResult{
			SystemIP: systemIP,
			Poisoned: false,
			Reason:   "DOH_UNAVAILABLE",
		}
	}

	// System DNS failed but DoH succeeded → DNS hijack / block.
	if sysErr != nil || systemIP == "" {
		return DNSCheckResult{
			SystemIP: systemIP,
			CleanIP:  cleanIP,
			Poisoned: true,
			Reason:   "DNS_HIJACK",
		}
	}

	// System IP not found in DoH results → mismatch / poisoning.
	if !contains(dohIPs, systemIP) {
		return DNSCheckResult{
			SystemIP: systemIP,
			CleanIP:  cleanIP,
			Poisoned: true,
			Reason:   "IP_MISMATCH",
		}
	}

	return DNSCheckResult{
		SystemIP: systemIP,
		CleanIP:  systemIP,
		Poisoned: false,
	}
}

// resolveDoH dials dialIP:443 directly (bypassing DNS for the resolver hostname)
// and queries the JSON DoH path. InsecureSkipVerify is intentional — the result
// is only used for IP comparison, not for establishing trust.
func resolveDoH(ctx context.Context, dialIP, serverName, path, host string, timeout time.Duration) ([]string, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, //nolint:gosec
		},
		DialContext: func(dctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(dctx, network, dialIP+":443")
		},
	}
	client := &http.Client{Transport: transport, Timeout: timeout}

	url := fmt.Sprintf("https://%s%s?name=%s&type=A", serverName, path, host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var payload struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	var ips []string
	for _, a := range payload.Answer {
		if a.Type == 1 && a.Data != "" { // type 1 = A record
			ips = append(ips, a.Data)
		}
	}
	return ips, nil
}

func union(a, b []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range append(a, b...) {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
