package scanner

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"time"
)

// SYN scanning requires raw sockets and libpcap on Linux/macOS.
// On Windows (or when not running as root), we fall back to connect().
//
// A full gopacket/pcap implementation is a significant additional dependency
// that requires CGO and libpcap-dev. This file provides:
//   1. A fast-connect scan (ScanFast) — aggressive timeouts, no retries.
//   2. A SYN stub that detects capability and falls back gracefully.
//
// To build with real SYN support in the future, add a synscan_linux.go or
// synscan_unix.go behind a build tag that imports gopacket/pcap.

// ProbeFast performs a fast connect scan with aggressive settings:
// short timeout, no retries, and an immediate close on success.
func ProbeFast(ctx context.Context, addr string, timeout time.Duration) error {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// ProbeSYN attempts a SYN-only scan. On platforms where raw sockets are not
// available (Windows, unprivileged Unix), it falls back to a connect scan
// and returns a warning via the second return value.
func ProbeSYN(ctx context.Context, addr string, timeout time.Duration) (bool, string) {
	if !canRawSocket() {
		// Fallback to connect.
		err := ProbeFast(ctx, addr, timeout)
		return err == nil, "syn: fallback to connect (raw sockets unavailable)"
	}

	// Stub: real SYN implementation would craft a TCP SYN packet via
	// gopacket, send it on a raw socket, and listen for SYN-ACK.
	// For now, fall back to connect even on capable platforms.
	err := ProbeFast(ctx, addr, timeout)
	warning := ""
	if runtime.GOOS != "windows" {
		warning = "syn: using connect fallback (gopacket not linked)"
	}
	return err == nil, warning
}

// canRawSocket returns true on Linux/macOS where raw sockets are possible
// (actual use still requires root/CAP_NET_RAW).
func canRawSocket() bool {
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd":
		return true
	default:
		return false
	}
}

// HostDiscovery performs a quick TCP ping on a common port to check if the
// host is reachable before running full probes. Returns true if the host
// responds within the timeout.
func HostDiscovery(ctx context.Context, ip string, timeout time.Duration) bool {
	// Try port 80 first, then 443 — both are almost always open on CF edges.
	for _, port := range []string{"80", "443"} {
		addr := net.JoinHostPort(ip, port)
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return true
		}
		if ctx.Err() != nil {
			return false
		}
	}
	return false
}

// warnOnce guards the one-time SYN fallback warning.
var synWarned bool

// WarnSYNFallback prints a one-time notice when SYN scan falls back.
func WarnSYNFallback(warning string) {
	if warning != "" && !synWarned {
		synWarned = true
		fmt.Printf("  [!] %s\n", warning)
	}
}
