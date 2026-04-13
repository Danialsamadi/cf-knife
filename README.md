# cf-knife

The ultimate Swiss-Army-knife Cloudflare IP scanner.  Single static binary, pure Go, fully cross-platform.

## Features

- **Three input modes**: official Cloudflare ranges (auto-fetched), `--input-file`, or `--ips` (inline CIDRs/IPs)
- **Multi-port matrix**: test every IP against every specified port
- **Layered probes**: TCP connect → TLS handshake → HTTP/1.1 → HTTP/2
- **Scan types**: `connect` (default, portable), `fast` (aggressive timeouts), `syn` (raw-socket stub with documented fallback)
- **Rate control**: global `--rate` (token-bucket) and per-worker `--rate-limit`
- **Timing templates**: `--timing 0-5` (paranoid → insane), like nmap's `-T`
- **Cloudflare script**: `--script cloudflare` fetches `/cdn-cgi/trace` to detect colo codes, CF-Ray, etc.
- **Multiple output formats**: txt, json, csv — plus a `clean_list.txt` for direct proxy-config use
- **Colored terminal summary** sorted by latency with throughput stats
- **Signal handling**: graceful shutdown on Ctrl-C

## Build

Requires Go 1.23+.

```bash
# Native build
go build -o cf-knife .

# Linux AMD64 static binary
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o cf-knife-linux-amd64 .

# Linux ARM64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o cf-knife-linux-arm64 .

# macOS ARM64 (Apple Silicon)
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o cf-knife-darwin-arm64 .

# Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o cf-knife.exe .
```

### SYN scan note

The SYN scan type (`--scan-type syn`) is currently a stub that falls back to connect.  A full implementation would require `gopacket` + libpcap (`libpcap-dev` on Debian/Ubuntu), CGO, and root/CAP_NET_RAW.  The fallback is transparent and prints a one-time warning.

## Usage

### Scan default Cloudflare ranges

```bash
cf-knife scan
```

### Scan specific IPs / CIDRs

```bash
cf-knife scan --ips 1.1.1.1,104.16.0.0/12 --port 443,80,8443,2053,2083 --threads 100
```

### Scan from a file

```bash
cf-knife scan -i my_ranges.txt --port 443,2053 --output today_clean.txt
```

Lines starting with `#` and blank lines are ignored.

### Fast scan with rate limiting

```bash
cf-knife scan --ips 104.16.0.0/20 --scan-type fast --rate 50000 --threads 500
```

### Cloudflare fingerprinting script

```bash
cf-knife scan --ips 104.16.0.0/24 --script cloudflare
```

### Aggressive timing

```bash
cf-knife scan --timing 5 --ips 1.1.1.0/24
```

### JSON output

```bash
cf-knife scan --ips 1.1.1.1 --output-format json --output results.json
```

### Save / load config

```bash
# Save current flags to a config file
cf-knife scan --ips 1.1.1.0/24 --threads 500 --save-config --config my.json

# Load config (CLI flags override file values)
cf-knife scan --config my.json
```

## Output

### clean_ips.txt (default)

```
104.16.124.96:443 | latency=142ms | range=104.16.0.0/13 | tcp=ok tls=ok http=ok http2=ok | service=cloudflare
```

### clean_list.txt (always generated)

```
104.16.124.96:443
104.16.124.96:80
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --port` | `443,80,8443,2053,2083` | Comma-separated ports |
| `--sni` | `www.cloudflare.com` | SNI for TLS handshake |
| `-t, --threads` | `200` | Workers (1-2000) |
| `--timeout` | `3s` | Per-probe timeout |
| `--retries` | `2` | Retries per probe |
| `--mode` | `full` | `tcp-only\|tls\|http\|http2\|full` |
| `--test-tcp/tls/http/http2` | `false` | Force individual tests |
| `--http-url` | CF cdn-cgi/trace | URL for HTTP probe |
| `-i, --input-file` | | File with IPs/CIDRs |
| `--ips` | | Inline IPs/CIDRs |
| `--ipv4-only / --ipv6-only` | `false` | Address family filter |
| `--max-latency` | `800ms` | Discard slow results |
| `-o, --output` | `clean_ips.txt` | Output filename |
| `--output-format` | `txt` | `txt\|json\|csv` |
| `--scan-type` | `connect` | `connect\|fast\|syn` |
| `--rate` | `0` | Global ops/sec (0=unlimited) |
| `--rate-limit` | `0` | Per-worker ops/sec |
| `--timing` | `3` | Timing template 0-5 |
| `--script` | | `cloudflare` |
| `--shuffle` | `false` | Randomize target order |
| `--config` | | JSON config file path |
| `--save-config` | `false` | Persist flags to config |
| `--verbose` | `false` | Verbose logging |
| `--progress` | `true` | Show progress bar |

## Tips for high-volume scanning

- Start with `--timing 2` (polite) to stay within ISP rate limits, then increase.
- Use `--rate 10000` to cap global throughput regardless of thread count.
- `--scan-type fast` halves the TCP timeout for quicker sweeps.
- On Linux with root, a future gopacket-backed `--scan-type syn` will provide stateless SYN scanning.
- Large CIDR ranges (e.g. `/12`) are capped at ~1M IPs per range to prevent OOM.  Use `--shuffle` for random sampling across ranges.

## Responsible use

This tool is intended for **authorized network testing only**.  Scanning IP ranges you do not own or have permission to test may violate your ISP's terms of service, local laws, or the Computer Fraud and Abuse Act (or equivalents in your jurisdiction).  Always obtain written authorization before scanning third-party infrastructure.

## License

MIT
