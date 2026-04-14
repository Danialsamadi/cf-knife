//go:build !windows
// +build !windows

package scanner

import (
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ProbePing sends ICMP echo requests and returns the average RTT (ping) and
// the standard deviation of RTTs (jitter). Requires raw socket privileges on
// Linux (root or CAP_NET_RAW); falls back to unprivileged UDP ICMP on macOS.
func ProbePing(ctx context.Context, ip string, count int, timeout time.Duration) (pingMs, jitterMs float64, err error) {
	if count < 1 {
		count = 5
	}

	dst := &net.IPAddr{IP: net.ParseIP(ip)}
	if dst.IP == nil {
		return -1, -1, fmt.Errorf("invalid IP: %s", ip)
	}

	network := "ip4:icmp"
	conn, err := icmp.ListenPacket(network, "0.0.0.0")
	if err != nil {
		network = "udp4"
		conn, err = icmp.ListenPacket(network, "0.0.0.0")
		if err != nil {
			return -1, -1, fmt.Errorf("icmp listen: %w (try running as root)", err)
		}
	}
	defer conn.Close()

	id := os.Getpid() & 0xffff
	var rtts []float64

	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			return -1, -1, ctx.Err()
		}

		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   id,
				Seq:  i,
				Data: []byte("cf-knife-ping"),
			},
		}
		wb, err := msg.Marshal(nil)
		if err != nil {
			continue
		}

		conn.SetDeadline(time.Now().Add(timeout))
		start := time.Now()

		if _, err := conn.WriteTo(wb, dst); err != nil {
			continue
		}

		rb := make([]byte, 1500)
		n, _, err := conn.ReadFrom(rb)
		if err != nil {
			continue
		}

		rtt := time.Since(start)

		proto := 1 // ICMPv4
		if network == "udp4" {
			proto = 58
		}
		rm, err := icmp.ParseMessage(proto, rb[:n])
		if err != nil {
			rtts = append(rtts, float64(rtt.Microseconds())/1000.0)
			continue
		}

		if rm.Type == ipv4.ICMPTypeEchoReply {
			rtts = append(rtts, float64(rtt.Microseconds())/1000.0)
		}
	}

	if len(rtts) == 0 {
		return -1, -1, fmt.Errorf("no ICMP replies from %s", ip)
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
