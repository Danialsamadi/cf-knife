//go:build windows
// +build windows

package scanner

import (
	"context"
	"fmt"
	"math"
	"net"
	"time"
)

// ProbePing on Windows uses repeated TCP connect RTTs as an ICMP substitute,
// since raw ICMP sockets require administrator privileges and the x/net/icmp
// package can crash unprivileged processes on some Windows versions.
func ProbePing(ctx context.Context, ip string, count int, timeout time.Duration) (pingMs, jitterMs float64, err error) {
	if count < 1 {
		count = 5
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return -1, -1, fmt.Errorf("invalid IP: %s", ip)
	}

	addr := net.JoinHostPort(ip, "443")
	var rtts []float64

	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			return -1, -1, ctx.Err()
		}

		start := time.Now()
		conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", addr)
		rtt := time.Since(start)
		if err != nil {
			continue
		}
		conn.Close()
		rtts = append(rtts, float64(rtt.Microseconds())/1000.0)
	}

	if len(rtts) == 0 {
		return -1, -1, fmt.Errorf("no TCP replies from %s", ip)
	}

	var sum float64
	for _, r := range rtts {
		sum += r
	}
	avg := sum / float64(len(rtts))

	var sqDiffSum float64
	for _, r := range rtts {
		d := r - avg
		sqDiffSum += d * d
	}
	jitter := math.Sqrt(sqDiffSum / float64(len(rtts)))

	return math.Round(avg*100) / 100, math.Round(jitter*100) / 100, nil
}
