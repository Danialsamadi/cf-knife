package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// RunCloudflareScript performs Cloudflare-specific probes on an already
// successful target and enriches the ProbeResult in place.
func RunCloudflareScript(ctx context.Context, r *ProbeResult, sni string, timeout time.Duration) {
	addr := net.JoinHostPort(r.IP, r.Port)

	// Fetch /cdn-cgi/trace which returns key=value pairs like:
	//   fl=...\n h=...\n ip=...\n ...  colo=...\n
	traceURL := fmt.Sprintf("https://%s/cdn-cgi/trace", sni)
	body, hdrs, err := fetchBody(ctx, addr, sni, timeout, traceURL)
	if err == nil {
		parseCDNCGITrace(r, body)
		if ray := hdrs.Get("CF-Ray"); ray != "" {
			r.CFRay = ray
		}
	}

	// Additional Server header check (idempotent if already set).
	if r.ServerHeader == "" {
		if sv := hdrs.Get("Server"); sv != "" {
			r.ServerHeader = sv
		}
	}

	if strings.Contains(strings.ToLower(r.ServerHeader), "cloudflare") {
		r.ServiceName = "cloudflare"
	}
}

func parseCDNCGITrace(r *ProbeResult, body string) {
	for _, line := range strings.Split(body, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch key {
		case "colo":
			if r.ServiceName == "" {
				r.ServiceName = "cloudflare"
			}
			r.ServiceName = "cloudflare/" + val
		case "h":
			// hostname echoed back — confirms the edge processed the request
		}
	}
}

func fetchBody(ctx context.Context, addr, sni string, timeout time.Duration, url string) (string, http.Header, error) {
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

	client := &http.Client{Transport: transport, Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, err
	}
	req.Host = sni
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", resp.Header, err
	}
	return string(b), resp.Header, nil
}
