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
	"time"
)

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
