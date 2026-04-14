package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ProbePing sends ICMP echo requests and returns the average RTT (ping) and
// the standard deviation of RTTs (jitter). Returns -1 for both if ICMP is
// unavailable (e.g. no root privileges on Linux).
func ProbePing(ctx context.Context, ip string, count int, timeout time.Duration) (pingMs, jitterMs float64, err error) {
	if count < 1 {
		count = 5
	}

	// Attempt privileged raw socket first, then fall back to unprivileged
	// UDP-based ICMP (works on macOS and some Linux sysctl configs).
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

	dst := &net.IPAddr{IP: net.ParseIP(ip)}
	if dst.IP == nil {
		return -1, -1, fmt.Errorf("invalid IP: %s", ip)
	}

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
			proto = 58 // parsed differently by the library for UDP
		}
		rm, err := icmp.ParseMessage(proto, rb[:n])
		if err != nil {
			// Still count the RTT if we got a response, even if parsing fails.
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

// ProbeSpeed measures download and upload throughput through a Cloudflare edge
// node. Download fetches a known URL via HTTP GET; upload sends random data via
// HTTP POST to the same endpoint.
func ProbeSpeed(ctx context.Context, addr, sni string, timeout time.Duration) (downloadMbps, uploadMbps float64, err error) {
	dlMbps, err := measureDownload(ctx, addr, sni, timeout)
	if err != nil {
		dlMbps = 0
	}

	ulMbps, err2 := measureUpload(ctx, addr, sni, timeout)
	if err2 != nil {
		ulMbps = 0
	}

	if err != nil && err2 != nil {
		return 0, 0, fmt.Errorf("speed test failed: dl=%v, ul=%v", err, err2)
	}

	return dlMbps, ulMbps, nil
}

func measureDownload(ctx context.Context, addr, sni string, timeout time.Duration) (float64, error) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	dlURL := fmt.Sprintf("https://%s/cdn-cgi/trace", sni)
	client := &http.Client{Transport: transport, Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return 0, err
	}
	req.Host = sni

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	elapsed := time.Since(start).Seconds()

	if elapsed == 0 || n == 0 {
		return 0, nil
	}

	mbps := (float64(n) * 8) / (elapsed * 1_000_000)
	return math.Round(mbps*100) / 100, nil
}

func measureUpload(ctx context.Context, addr, sni string, timeout time.Duration) (float64, error) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	const payloadSize = 1 << 20 // 1 MB
	payload := make([]byte, payloadSize)
	rand.Read(payload)

	ulURL := fmt.Sprintf("https://%s/cdn-cgi/trace", sni)
	client := &http.Client{Transport: transport, Timeout: timeout}

	pr, pw := io.Pipe()
	go func() {
		pw.Write(payload)
		pw.Close()
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ulURL, pr)
	if err != nil {
		return 0, err
	}
	req.Host = sni
	req.ContentLength = payloadSize

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	elapsed := time.Since(start).Seconds()

	if elapsed == 0 {
		return 0, nil
	}

	mbps := (float64(payloadSize) * 8) / (elapsed * 1_000_000)
	return math.Round(mbps*100) / 100, nil
}
