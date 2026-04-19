// Pre-flight DNS/TCP/TLS checks for domain-based targets (dial resolved IP, SNI = hostname).
// Adapted from cloudflare-site-scanner/engine/probe.go (see ATTRIBUTION.md).

package scanner

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"time"
)

// PreflightResult holds the outcome of PreFlightLayerCheck.
type PreflightResult struct {
	Status     string // PASSED, DNS_FAILED, TCP_FAILED, TLS_FAILED, FATAL_ERR, PARSE_ERR
	ResolvedIP string
}

// PreFlightLayerCheck resolves host, dials the resolved IP:port for TCP, then TLS with SNI=host.
func PreFlightLayerCheck(ctx context.Context, host string, port int, scheme string, timeout time.Duration) PreflightResult {
	if host == "" {
		return PreflightResult{Status: "PARSE_ERR"}
	}
	portStr := strconv.Itoa(port)

	var resolvedIP string
	if ip := net.ParseIP(host); ip != nil {
		resolvedIP = ip.String()
	} else {
		dnsCtx, dnsCancel := context.WithTimeout(ctx, timeout)
		defer dnsCancel()
		ips, err := net.DefaultResolver.LookupHost(dnsCtx, host)
		if err != nil || len(ips) == 0 {
			return PreflightResult{Status: "DNS_FAILED"}
		}
		resolvedIP = ips[0]
	}

	tcpAddr := net.JoinHostPort(resolvedIP, portStr)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", tcpAddr)
	if err != nil {
		return PreflightResult{Status: "TCP_FAILED", ResolvedIP: resolvedIP}
	}
	conn.Close()

	if scheme == "https" {
		tlsDialer := &net.Dialer{Timeout: timeout}
		tlsConn, err := tls.DialWithDialer(tlsDialer, "tcp", tcpAddr, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})
		if err != nil {
			if IsSocketExhaustion(err) {
				return PreflightResult{Status: "FATAL_ERR", ResolvedIP: resolvedIP}
			}
			return PreflightResult{Status: "TLS_FAILED", ResolvedIP: resolvedIP}
		}
		tlsConn.Close()
	}

	return PreflightResult{Status: "PASSED", ResolvedIP: resolvedIP}
}

// schemeForPort returns "https" or "http" for preflight TLS decision.
func schemeForPort(portStr string) string {
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return "https"
	}
	for _, hp := range CFHTTPPorts {
		if p == hp {
			return "http"
		}
	}
	return "https"
}
