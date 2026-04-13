# cf-knife

A high-performance Cloudflare IP scanner written in pure Go. Single static binary, fully cross-platform, with layered network probing and real-time progress reporting.

## Overview

cf-knife probes IP addresses across multiple ports using a layered approach: TCP connect, TLS handshake, HTTP/1.1, and HTTP/2. It is purpose-built for scanning Cloudflare IP ranges at scale, with nmap-style timing templates, configurable concurrency, and multiple output formats.

Key capabilities:

- Three input modes: official Cloudflare ranges (auto-fetched), file-based input, or inline CIDRs
- Multi-port matrix scanning (every IP tested against every specified port)
- Layered probes: TCP, TLS, HTTP/1.1, HTTP/2
- Scan engines: `connect` (default), `fast` (aggressive timeouts), `syn` (stub with fallback)
- Rate control: global throughput cap and per-worker rate limiting
- Timing templates 0-5 (paranoid to insane), modeled after nmap's `-T` flag
- Cloudflare fingerprinting via `/cdn-cgi/trace` (colo codes, CF-Ray)
- Output formats: txt, json, csv, plus a `clean_list.txt` for direct proxy-config use
- Real-time progress bar with live stats (TCP/TLS/HTTP/H2 counters, scan rate)
- Graceful shutdown on Ctrl-C with partial result saving
- Timestamped output files to prevent overwrites between runs

## Build

Requires Go 1.23 or later.

```bash
go build -o cf-knife .
```

Cross-compilation examples:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o cf-knife-linux-amd64 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o cf-knife-linux-arm64 .
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o cf-knife-darwin-arm64 .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o cf-knife.exe .
```

## Quick Start

Scan a single IP on two ports with default settings:

```bash
./cf-knife scan --ips 1.1.1.1 --port 443,80
```

Scan a CIDR range from a file with aggressive timing:

```bash
./cf-knife scan -i Cloudflare-IP.txt -p 443,80,8443,2053,2083 --timing 4 -o result.txt
```

## Command Reference

cf-knife has one subcommand: `scan`.

```
./cf-knife scan [flags]
```

### Input Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ips` | | _(none)_ | Comma-separated IPs or CIDR ranges to scan. Example: `1.1.1.0/24,104.16.0.0/20` |
| `--input-file` | `-i` | _(none)_ | Path to a file containing IPs or CIDRs, one per line. Lines starting with `#` and blank lines are ignored. |
| `--ipv4-only` | | `false` | Only scan IPv4 addresses. |
| `--ipv6-only` | | `false` | Only scan IPv6 addresses. |
| `--shuffle` | | `false` | Randomize target order before scanning. Useful for distributing load across ranges. |

If neither `--ips` nor `--input-file` is provided, cf-knife fetches the official Cloudflare IP ranges automatically.

### Probe Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port` | `-p` | `443,80,8443,2053,2083` | Comma-separated list of ports to scan on each IP. |
| `--mode` | | `full` | Probe mode. Controls which protocol layers are tested. Values: `tcp-only`, `tls`, `http`, `http2`, `full`. |
| `--test-tcp` | | `false` | Force TCP test regardless of mode. |
| `--test-tls` | | `false` | Force TLS test regardless of mode. |
| `--test-http` | | `false` | Force HTTP/1.1 test regardless of mode. |
| `--test-http2` | | `false` | Force HTTP/2 test regardless of mode. |
| `--sni` | | `www.cloudflare.com` | Server Name Indication hostname used during TLS handshake. |
| `--http-url` | | `https://www.cloudflare.com/cdn-cgi/trace` | URL fetched during HTTP/HTTP2 probes. |
| `--scan-type` | | `connect` | Scan engine. `connect` uses standard TCP dial. `fast` uses aggressive timeouts. `syn` is a stub that falls back to connect (requires future gopacket implementation). |
| `--script` | | _(none)_ | Run a detection script. Currently supports `cloudflare` which fetches `/cdn-cgi/trace` to identify colo codes, CF-Ray headers, and service names. |

### Performance Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--threads` | `-t` | `200` | Number of concurrent worker goroutines. Range: 1-10000. Higher values increase throughput but also resource usage. |
| `--timeout` | | `3s` | Per-probe timeout. Applied to each individual network operation (TCP dial, TLS handshake, HTTP request). |
| `--retries` | | `2` | Number of retry attempts per failed probe. |
| `--rate` | | `0` | Global operations per second across all workers. Set to 0 for unlimited. |
| `--rate-limit` | | `0` | Per-worker operations per second. Set to 0 for unlimited. |
| `--timing` | | `3` | Nmap-style timing template (0-5). Sets threads, timeout, max-latency, and rate as a group. Explicitly set flags override the template values. |
| `--max-latency` | | `800ms` | Discard results with TCP latency above this threshold. Results that pass at least one probe but exceed this latency are filtered out. |

### Timing Templates

The `--timing` flag provides predefined profiles. Any flag set explicitly on the command line overrides its timing template value.

| Level | Name | Threads | Timeout | Max Latency | Rate |
|-------|------|---------|---------|-------------|------|
| 0 | Paranoid | 1 | 10s | 5s | 1/s |
| 1 | Sneaky | 5 | 8s | 3s | 10/s |
| 2 | Polite | 50 | 5s | 2s | 100/s |
| 3 | Normal | 200 | 3s | 800ms | Unlimited |
| 4 | Aggressive | 2000 | 2s | 500ms | Unlimited |
| 5 | Insane | 8000 | 1s | 300ms | Unlimited |

### Output Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | `clean_ips.txt` | Base output filename. A timestamp is appended automatically (e.g., `clean_ips-20260413-163902.txt`). |
| `--output-format` | | `txt` | Output format. Values: `txt`, `json`, `csv`. |
| `--verbose` | | `false` | Print detailed progress to stdout (target counts every 500 completions). |
| `--progress` | | `true` | Show a real-time progress bar with live scan statistics. |

### Configuration Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | _(none)_ | Path to a JSON configuration file. CLI flags override file values. |
| `--save-config` | `false` | Save the current flag values to a JSON configuration file and exit. |

## Example Commands

### 1. Basic scan of a single IP

Scan 1.1.1.1 on ports 443 and 80 with all protocol layers:

```bash
./cf-knife scan --ips 1.1.1.1 --port 443,80
```

This runs TCP, TLS, HTTP/1.1, and HTTP/2 probes on both ports using default timing (level 3: 200 threads, 3s timeout).

### 2. Scan from a file with aggressive timing

Load IP ranges from a file, scan five common Cloudflare ports, and use aggressive timing for faster results:

```bash
./cf-knife scan \
  -i Cloudflare-IP.txt \
  -p 443,80,8443,2053,2083 \
  --timing 4 \
  -o result.txt \
  --shuffle
```

- `-i Cloudflare-IP.txt` -- read CIDRs from file (one per line)
- `-p 443,80,8443,2053,2083` -- test five ports per IP
- `--timing 4` -- aggressive preset (2000 threads, 2s timeout, 500ms max latency)
- `-o result.txt` -- output saved as `result-20260413-163902.txt` (timestamp appended)
- `--shuffle` -- randomize target order to distribute load

### 3. TCP-only scan for fast reachability check

Skip TLS/HTTP probes and only test TCP connectivity. Useful for quickly finding reachable IPs:

```bash
./cf-knife scan \
  --ips 104.16.0.0/20 \
  -p 443,80 \
  --mode tcp-only \
  --timing 4 \
  -o result.txt
```

### 4. Full scan with Cloudflare fingerprinting

Detect Cloudflare colo codes, CF-Ray headers, and service names:

```bash
./cf-knife scan \
  --ips 1.0.0.0/24 \
  -p 443 \
  --script cloudflare \
  -o cloudflare-scan.txt
```

### 5. Rate-limited scan

Cap global throughput to 5000 connections per second to stay within ISP limits:

```bash
./cf-knife scan \
  -i Cloudflare-IP.txt \
  -p 443 \
  --rate 5000 \
  --threads 500 \
  -o result.txt
```

### 6. JSON output for programmatic use

```bash
./cf-knife scan \
  --ips 104.16.0.0/24 \
  -p 443,80 \
  --output-format json \
  -o scan-results.json
```

### 7. Save and reuse configuration

Save a scan profile to a JSON file:

```bash
./cf-knife scan \
  --ips 1.1.1.0/24 \
  --threads 500 \
  --timing 4 \
  --save-config \
  --config my-profile.json
```

Reuse it later (CLI flags still override file values):

```bash
./cf-knife scan --config my-profile.json
```

## Output Format

### Detailed results (txt)

Each line contains the IP, port, latency, source range, per-protocol status, and service name:

```
1.0.0.113:443 | latency=33ms | range=1.0.0.0/24 | tcp=ok tls=ok http=ok http2=ok | service=cloudflare
1.0.0.54:443  | latency=33ms | range=1.0.0.0/24 | tcp=ok tls=fail http=fail http2=fail | service=-
```

### Clean list (clean_list.txt)

A companion file generated on every run, containing only `ip:port` pairs for direct use in proxy configurations:

```
1.0.0.113:443
1.0.0.54:443
1.0.0.118:443
```

### Terminal summary

After each scan, a colored summary table is printed to the terminal showing the top results sorted by latency, along with aggregate statistics and file paths.

## Live Scan Statistics

During a scan, real-time statistics are printed above the progress bar every 3 seconds:

```
  1134/2048 scanned | TCP:1134 TLS:890 HTTP:456 H2:312 | err:120 | 378/s
```

After completion (or interruption), a final summary is printed:

```
  Scan complete in 5.199s -- 2048 targets scanned
  TCP: 1928  TLS: 890  HTTP: 456  H2: 312  Errors: 120
```

## Graceful Shutdown

Pressing Ctrl-C (SIGINT) or sending SIGTERM during a scan triggers graceful shutdown:

1. Active workers finish their current probe and stop accepting new targets.
2. The progress bar and stats goroutine are stopped.
3. All results collected so far are filtered and saved to disk.
4. A second Ctrl-C during the save phase is ignored to ensure the file write completes.

This means you can interrupt a long-running scan at any time and still get usable partial results.

## Tips for High-Volume Scanning

- Start with `--timing 2` (polite) to stay within ISP rate limits, then increase.
- Use `--rate 10000` to cap global throughput regardless of thread count.
- `--scan-type fast` halves the TCP timeout for quicker sweeps.
- `--mode tcp-only` skips TLS/HTTP probes entirely for maximum speed.
- Large CIDR ranges (e.g., /12) are capped at approximately 1M IPs per range to prevent excessive memory usage. Use `--shuffle` for random sampling across ranges.
- On Linux with root, a future gopacket-backed `--scan-type syn` will provide stateless SYN scanning.

## SYN Scan Note

The SYN scan type (`--scan-type syn`) is currently a stub that falls back to connect. A full implementation would require gopacket with libpcap (`libpcap-dev` on Debian/Ubuntu), CGO, and root/CAP_NET_RAW. The fallback is transparent and prints a one-time warning.

## Responsible Use

This tool is intended for authorized network testing only. Scanning IP ranges you do not own or have permission to test may violate your ISP's terms of service, local laws, or the Computer Fraud and Abuse Act (or equivalents in your jurisdiction). Always obtain written authorization before scanning third-party infrastructure.

## License

MIT
