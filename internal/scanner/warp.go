package scanner

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Default WARP CIDR ranges. These are Cloudflare's well-known WARP
// endpoint ranges used by the 1.1.1.1 app and WARP client.
var DefaultWARPRanges = []string{
	"162.159.192.0/24",
	"162.159.193.0/24",
	"162.159.195.0/24",
	"162.159.204.0/24",
	"188.114.96.0/24",
	"188.114.97.0/24",
	"188.114.98.0/24",
	"188.114.99.0/24",
}

const DefaultWARPPort = 2408

const wgMsgTypeInit = 1
const wgInitiationSize = 148

func buildWGInitiation() []byte {
	msg := make([]byte, wgInitiationSize)
	msg[0] = wgMsgTypeInit
	binary.LittleEndian.PutUint32(msg[4:8],
		uint32(time.Now().UnixNano()&0xFFFFFFFF))
	rand.Read(msg[8:])
	return msg
}

// ProbeWARPEndpoint sends a WireGuard handshake initiation to a UDP endpoint
// and waits for any response. Returns RTT and reachability.
func ProbeWARPEndpoint(ctx context.Context, endpoint string, timeout time.Duration) (rtt time.Duration, ok bool) {
	conn, err := net.DialTimeout("udp", endpoint, timeout)
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	msg := buildWGInitiation()
	start := time.Now()

	if _, err := conn.Write(msg); err != nil {
		return 0, false
	}

	buf := make([]byte, 256)
	_, err = conn.Read(buf)
	rtt = time.Since(start)

	if err != nil {
		return 0, false
	}
	return rtt, true
}

// ScanWARP probes WARP UDP endpoints concurrently.
func ScanWARP(ctx context.Context, targets []WARPTarget, timeout time.Duration, threads int) []WARPResult {
	if threads < 1 {
		threads = 50
	}

	results := make([]WARPResult, len(targets))
	jobs := make(chan int, threads)
	var completed atomic.Int64
	total := int64(len(targets))
	start := time.Now()

	var wg sync.WaitGroup
	for w := 0; w < threads; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				t := targets[idx]
				endpoint := fmt.Sprintf("%s:%d", t.IP, t.Port)
				rtt, ok := ProbeWARPEndpoint(ctx, endpoint, timeout)

				results[idx] = WARPResult{
					Endpoint:  endpoint,
					RTT:       rtt,
					Reachable: ok,
				}

				n := completed.Add(1)
				if n%100 == 0 || n == total {
					elapsed := time.Since(start).Seconds()
					fmt.Printf("  WARP: %d/%d probed | %.0f/s\n", n, total, float64(n)/elapsed)
				}
			}
		}()
	}

	for i := range targets {
		if ctx.Err() != nil {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	return results
}

// ExpandWARPRanges converts CIDRs into a flat list of WARPTarget structs.
func ExpandWARPRanges(cidrList []string, port int) ([]WARPTarget, error) {
	if len(cidrList) == 0 {
		cidrList = DefaultWARPRanges
	}
	if port <= 0 {
		port = DefaultWARPPort
	}

	var targets []WARPTarget
	for _, entry := range cidrList {
		ips, _, err := expandEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("expand WARP range %q: %w", entry, err)
		}
		for _, ip := range ips {
			if ip.To4() == nil {
				continue
			}
			targets = append(targets, WARPTarget{IP: ip.String(), Port: port})
		}
	}
	return targets, nil
}
