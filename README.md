# cf-knife

**Languages:** [فارسی (Persian) — README.fa.md](README.fa.md)

A high-performance CDN IP scanner written in pure Go. Single static binary, fully cross-platform, with layered network probing, real-time progress reporting, and advanced analysis capabilities.

## Overview

cf-knife probes IP addresses across multiple ports using a layered approach: TCP connect, TLS handshake, HTTP/1.1, and HTTP/2. It is purpose-built for scanning Cloudflare and Fastly IP ranges at scale, with nmap-style timing templates, configurable concurrency, and multiple output formats.

### Core Features

- **Domain-based scanning**: Feed a list of hostnames (`--domain-file`); each is resolved via DNS and dialed by IP with SNI/Host = original hostname — DPI-bypass semantics without touching raw IPs. Supports bare hostnames, full URLs, `label | host` prefixes, and CIDR blocks
- **HTTPS → HTTP fallback**: When preflight fails on an HTTPS port, automatically retries on port 80 with HTTP — keeps domain targets alive even under partial censorship
- **Browser-like probes**: Domain-mode scans use HTTP `GET` (not `HEAD`) and send real `User-Agent`, `Accept`, `Accept-Language`, `Accept-Encoding` headers for accurate server behavior
- **HTTP status code capture**: Actual HTTP response code (200, 301, 403…) stored in results and included in all output formats
- **Label field**: `label | host` lines in domain files carry the label through to results and all output files
- **Domain scan cache** (`--domain-cache`): Successful results are saved after each run; on the next run, cached targets are loaded first for faster re-checks
- **Domain reports**: After every domain-mode scan, two report files are written automatically — `reachable-*.txt` (OPEN results sorted by latency) and `full_log-*.txt` (all targets with OPEN/DEAD tags)
- **Multi-CDN support**: Cloudflare and Fastly edge fingerprinting with auto-fetched IP ranges
- **Layered probes**: TCP, TLS, HTTP/1.1 (labeled HTTPS), HTTP/2, HTTP/3 (QUIC) -- run any combination per target
- **Multi-SNI matrix scan**: Comma-separated `--sni` hostnames expand into separate targets (each IP×port is probed once per SNI)
- **Subnet sampling**: `--sample N` randomly keeps up to *N* addresses per CIDR before scanning (useful for huge ranges)
- **HTTP fragment probe**: Optional `--http-fragment` sends the HTTP probe payload in small chunks with delays (app-layer DPI / filtering experiments)
- **Scan engines**: `connect` (default), `fast` (aggressive timeouts), `syn` (stub with fallback)
- **Performance metrics**: Real ping/jitter (ICMP or TCP-based) and download/upload speed testing
- **DPI bypass analysis**: TLS ClientHello fragmentation and SNI fronting enumeration
- **WARP endpoint scanner**: Dedicated WireGuard/UDP scanner for Cloudflare WARP endpoints
- **DNS poison detection** (`--dns-check`): Compares system resolver answer against Cloudflare (`1.1.1.1`) and Google (`8.8.8.8`) DoH — dials by IP to bypass poisoning of the resolver itself, detects IP_MISMATCH and DNS_HIJACK
- **TLS certificate validation**: Anti-MITM detection by inspecting the certificate chain
- **Smart retry logic**: Automatically relaxes thresholds when strict settings yield zero results
- **Persistent SQLite queue**: Scan state survives app restarts with `--resume`
- **Rate control**: Global throughput cap and per-worker rate limiting
- **Timing templates 0-5**: Paranoid to insane, modeled after nmap's `-T` flag
- **Output formats**: txt, json, csv, plus a `clean_list.txt` for direct proxy-config use
- **Real-time progress bar** with live stats (TCP/TLS/HTTP/H2 counters, scan rate)
- **Graceful shutdown** on Ctrl-C with partial result saving
- **Cross-platform**: Linux, macOS, Windows -- prebuilt binaries on every release

## Installation

### Download prebuilt binaries

Grab the latest release from [GitHub Releases](https://github.com/Danialsamadi/cf-knife/releases):

| Platform | Binary |
|----------|--------|
| Linux amd64 | `cf-knife-linux-amd64` |
| Linux arm64 | `cf-knife-linux-arm64` |
| Linux 386 | `cf-knife-linux-386` |
| macOS amd64 | `cf-knife-darwin-amd64` |
| macOS arm64 (Apple Silicon) | `cf-knife-darwin-arm64` |
| Windows amd64 | `cf-knife-windows-amd64.exe` |

**Linux / macOS** — make the binary executable after download:

```bash
chmod +x cf-knife-*
```

**Windows** — no `chmod`. From the folder that contains the `.exe`, run (adjust the filename if you renamed it):

```powershell
.\cf-knife-windows-amd64.exe scan --help
```

### Build from source

Requires Go 1.25 or later.

**Linux / macOS:**

```bash
go build -o cf-knife .
```

**Windows (PowerShell or CMD):**

```powershell
go build -o cf-knife.exe .
```

Cross-compilation examples:

```bash
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o cf-knife-linux-amd64 .
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o cf-knife-linux-arm64 .
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o cf-knife-darwin-arm64 .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o cf-knife.exe .
```

## Quick Start

Use **`./cf-knife`** on Linux and macOS, and **`.\cf-knife.exe`** on Windows (or `.\cf-knife-windows-amd64.exe` if you kept the release name). Flags are identical on every platform.

**Line breaks:** bash examples use `\` at the end of a line. On **PowerShell**, use a trailing backtick `` ` `` instead; on **CMD**, use `^`.

### Linux / macOS

Scan a single IP on two ports:

```bash
./cf-knife scan --ips 1.1.1.1 --port 443,80
```

Scan a CIDR range from a file with aggressive timing:

```bash
./cf-knife scan -i ips.txt -p 443,80,8443 --timing 4 -o result.txt
```

Scan Fastly edge nodes instead of Cloudflare:

```bash
./cf-knife scan --fastly-ranges --script fastly -p 443
```

Same IPs, multiple TLS server names (each `--sni` becomes its own target):

```bash
./cf-knife scan --ips 1.1.1.1,1.0.0.1 -p 443 \
  --sni "www.cloudflare.com,example.com" \
  -o multi-sni.txt
```

Sample a few random hosts per CIDR instead of expanding the whole range:

```bash
./cf-knife scan --ips 104.16.0.0/16 -p 443 --sample 200 --timing 4 -o sampled.txt
```

HTTP/HTTPS probe using fragmented request writes (compare with a normal run without the flag):

```bash
./cf-knife scan --ips 1.1.1.1 -p 443 --mode http --http-fragment -o http-frag.txt
```

### Windows (PowerShell)

```powershell
.\cf-knife.exe scan --ips 1.1.1.1 --port 443,80
```

```powershell
.\cf-knife.exe scan -i ips.txt -p 443,80,8443 --timing 4 -o result.txt
```

```powershell
.\cf-knife.exe scan --fastly-ranges --script fastly -p 443
```

```powershell
.\cf-knife.exe scan --ips 1.1.1.1,1.0.0.1 -p 443 `
  --sni "www.cloudflare.com,example.com" `
  -o multi-sni.txt
```

```powershell
.\cf-knife.exe scan --ips 104.16.0.0/16 -p 443 --sample 200 --timing 4 -o sampled.txt
```

```powershell
.\cf-knife.exe scan --ips 1.1.1.1 -p 443 --mode http --http-fragment -o http-frag.txt
```

---

## Command Reference

cf-knife has one subcommand: `scan`.

```
# Linux / macOS
./cf-knife scan [flags]

# Windows (PowerShell / CMD)
.\cf-knife.exe scan [flags]
```

### Input Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ips` | | _(none)_ | Comma-separated IPs or CIDR ranges. Example: `1.1.1.0/24,104.16.0.0/20` |
| `--input-file` | `-i` | _(none)_ | Path to a file with IPs or CIDRs, one per line. Lines starting with `#` are ignored. |
| `--ipv4-only` | | `false` | Only scan IPv4 addresses. |
| `--ipv6-only` | | `false` | Only scan IPv6 addresses. |
| `--shuffle` | | `false` | Randomize target order before scanning. |
| `--sample` | | `0` | Randomly sample up to *N* IPs per CIDR subnet (`0` = expand every address in range). |
| `--fastly-ranges` | | `false` | Use Fastly edge IP ranges instead of Cloudflare (fetched from `api.fastly.com`). |
| `--domain-file` | | _(none)_ | Path to a file of hostnames to scan. Supports bare hostnames, `https://` / `http://` URLs, `label \| host` prefixes, and CIDR blocks (e.g. `104.18.2.0/24`). Each host is resolved via DNS; probes dial the resolved IP with SNI and `Host` set to the original hostname (DPI-bypass). Mutually exclusive with `--ips`, `--input-file`, `--fastly-ranges`, `--warp`. |
| `--cf-all-ports` | | `false` | When using `--domain-file`, expand each hostname across all 13 Cloudflare edge ports (6 HTTPS + 7 HTTP) instead of `--port`. |
| `--site-preflight` | | `true` | Run a DNS → TCP → TLS pre-flight check for each domain target before main probes. If the HTTPS preflight fails, automatically retries on port 80 with HTTP (anti-censorship fallback). Backs off 500 ms on socket exhaustion. |
| `--domain-cache` | | `domain-cache.txt` | Cache file for domain scan results. Successful targets are saved after each run; on the next run, cached hosts are loaded first (deduplicated with the main list). |

If none of `--ips`, `--input-file`, `--domain-file`, or `--fastly-ranges` is provided, cf-knife fetches official Cloudflare IP ranges automatically.

### Probe Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port` | `-p` | `443,80,8443,2053,2083` | Comma-separated list of ports to scan on each IP. |
| `--mode` | | `full` | Probe mode: `tcp-only`, `tls`, `http`, `http2`, `http3`, `full`. |
| `--test-tcp` | | `false` | Force TCP test regardless of mode. |
| `--test-tls` | | `false` | Force TLS test regardless of mode. |
| `--test-http` | | `false` | Force HTTP/1.1 test regardless of mode. |
| `--test-http2` | | `false` | Force HTTP/2 test regardless of mode. |
| `--test-http3` | | `false` | Force HTTP/3 (QUIC) test regardless of mode. |
| `--sni` | | `www.cloudflare.com` | SNI hostname(s) for TLS. Comma-separated values run a **matrix scan**: each IP×port is tested with every listed hostname. |
| `--http-url` | | `https://www.cloudflare.com/cdn-cgi/trace` | URL fetched during HTTP/HTTP2 probes. |
| `--scan-type` | | `connect` | Scan engine: `connect`, `fast`, `syn`. |
| `--script` | | _(none)_ | Run a detection script: `cloudflare` or `fastly`. |

### Performance Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--threads` | `-t` | `200` | Number of concurrent workers (1-10000). |
| `--timeout` | | `3s` | Per-probe timeout for each network operation. |
| `--retries` | | `2` | Retry attempts per failed probe. |
| `--rate` | | `0` | Global ops/sec across all workers (0 = unlimited). |
| `--rate-limit` | | `0` | Per-worker ops/sec (0 = unlimited). |
| `--timing` | | `3` | Nmap-style timing template (0-5). Explicitly set flags override template values. |
| `--max-latency` | | `800ms` | Discard results above this latency threshold. |

### Timing Templates

| Level | Name | Threads | Timeout | Max Latency | Rate |
|-------|------|---------|---------|-------------|------|
| 0 | Paranoid | 1 | 10s | 5s | 1/s |
| 1 | Sneaky | 5 | 8s | 3s | 10/s |
| 2 | Polite | 50 | 5s | 2s | 100/s |
| 3 | Normal | 200 | 3s | 800ms | Unlimited |
| 4 | Aggressive | 2000 | 2s | 500ms | Unlimited |
| 5 | Insane | 8000 | 1s | 300ms | Unlimited |

### Analysis Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--speed-test` | `false` | Measure ICMP ping, jitter, and HTTP download/upload speed per target. |
| `--dpi` | `false` | Enumerate DPI fragment sizes and find the best SNI front per target. |
| `--fragment-sizes` | `10,50,100,200,500` | Comma-separated fragment sizes (bytes) for DPI testing. |
| `--http-fragment` | `false` | Use chunked HTTP requests (small writes with delays) instead of a normal HEAD for HTTP/HTTPS probes. |
| `--cert-check` | `false` | Validate TLS certificates against known CDN issuers and flag MITM. |
| `--dns-check` | `false` | Compare system DNS answer against Cloudflare+Google DoH (dialed by IP) to detect poisoning. Adds `dns=` field to every result. Only meaningful with `--domain-file`. |
| `--smart-retry` | `false` | Auto-relax `max-latency` (2x) and `timeout` (1.5x) if no results pass filters. |
| `--warp` | `false` | Scan for reachable Cloudflare WARP UDP endpoints. |
| `--warp-port` | `2408` | UDP port for WARP probing. |

### Persistence Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--db` | `cf-knife.db` | Path to the SQLite database file for persistent scan state. |
| `--resume` | `false` | Resume the last interrupted scan from the SQLite queue. |

### Output Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | `clean_ips.txt` | Base output filename. A timestamp is appended automatically. |
| `--output-format` | | `txt` | Output format: `txt`, `json`, `csv`. |
| `--verbose` | | `false` | Print detailed progress to stdout. |
| `--progress` | | `true` | Show a real-time progress bar with live stats. |

### Configuration Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | _(none)_ | Path to a JSON configuration file. CLI flags override file values. |
| `--save-config` | `false` | Save current flags to a JSON config file and exit. |

### Reference examples (copy-paste)

Multi-SNI (matrix):

```bash
./cf-knife scan --ips 1.0.0.0/28 -p 443 --sni "a.example.com,b.example.com" -o out.txt
```

```powershell
.\cf-knife.exe scan --ips 1.0.0.0/28 -p 443 --sni "a.example.com,b.example.com" -o out.txt
```

Subnet sampling:

```bash
./cf-knife scan -i ranges.txt -p 443 --sample 25 -o out.txt
```

```powershell
.\cf-knife.exe scan -i ranges.txt -p 443 --sample 25 -o out.txt
```

HTTP fragment probe (requires HTTP layer, e.g. `--mode http` or `full`):

```bash
./cf-knife scan --ips 8.8.8.8 -p 443 --mode full --http-fragment -o out.txt
```

```powershell
.\cf-knife.exe scan --ips 8.8.8.8 -p 443 --mode full --http-fragment -o out.txt
```

---

## Examples

Throughout this section, **`./cf-knife`** means your built or downloaded binary on Linux/macOS. On Windows, run the same flags with **`.\cf-knife.exe`** (or your release `.exe` name). Multi-line **bash** commands use `\`; in **PowerShell** use `` ` `` at the end of each continued line, or put the command on one line.

### 1. Basic scan of a single IP

```bash
./cf-knife scan --ips 1.1.1.1 --port 443,80
```

```powershell
.\cf-knife.exe scan --ips 1.1.1.1 --port 443,80
```

Runs TCP, TLS, HTTP/1.1, HTTP/2, and HTTP/3 probes on both ports using default timing (level 3: 200 threads, 3s timeout).

### 2. Scan from a file with aggressive timing

```bash
./cf-knife scan \
  -i Cloudflare-IP.txt \
  -p 443,80,8443,2053,2083 \
  --timing 4 \
  -o result.txt \
  --shuffle
```

```powershell
.\cf-knife.exe scan `
  -i Cloudflare-IP.txt `
  -p 443,80,8443,2053,2083 `
  --timing 4 `
  -o result.txt `
  --shuffle
```

- Loads CIDRs from file, tests 5 ports per IP
- 2000 threads, 2s timeout, 500ms max latency
- Output saved as `result-20260413-163902.txt`
- `--shuffle` randomizes target order to distribute load

### 3. TCP-only fast reachability check

```bash
./cf-knife scan \
  --ips 104.16.0.0/20 \
  -p 443 \
  --mode tcp-only \
  --timing 5
```

Skips TLS/HTTP probes entirely for maximum speed. Insane timing: 8000 threads, 1s timeout.

### 4. Cloudflare fingerprinting with colo detection

```bash
./cf-knife scan \
  --ips 1.0.0.0/24 \
  -p 443 \
  --script cloudflare \
  -o cloudflare-scan.txt
```

Fetches `/cdn-cgi/trace` to identify Cloudflare colo codes (e.g., `cloudflare/LAX`), CF-Ray headers, and server info.

### 5. Fastly edge node scanning

```bash
./cf-knife scan \
  --fastly-ranges \
  --script fastly \
  --sni www.fastly.com \
  -p 443 \
  -o fastly-results.txt
```

- `--fastly-ranges` auto-fetches Fastly public IP ranges from `api.fastly.com/public-ip-list`
- `--script fastly` parses `X-Served-By` (POP ID), `X-Cache`, and `Via` headers
- Identifies Fastly POP locations (e.g., `fastly/cache-lax-123`)

### 6. Performance metrics with speed test

```bash
./cf-knife scan \
  --ips 1.1.1.1,1.0.0.1 \
  -p 443 \
  --speed-test \
  -o speed-results.txt
```

For each target that passes TCP, measures:
- **Ping**: ICMP echo RTT (Linux/macOS) or TCP connect RTT (Windows)
- **Jitter**: Standard deviation of RTTs
- **Download**: HTTP GET throughput in Mbps
- **Upload**: HTTP POST throughput in Mbps

Output includes columns like: `ping=12.3ms jitter=2.1ms | dl=45.67Mbps ul=12.34Mbps`

### 7. DPI bypass analysis

```bash
./cf-knife scan \
  --ips 1.1.1.1 \
  -p 443 \
  --dpi \
  --fragment-sizes "10,50,100,200,500,1000" \
  -o dpi-results.txt
```

For each target:
- **Fragment enumeration**: Splits the TLS ClientHello into chunks of each size and finds which fragment size produces the lowest-latency handshake (bypassing DPI)
- **SNI fronting**: Tests 10 well-known Cloudflare-served domains to find one that works through censored networks

Output includes: `frag=100 | sni_front=discord.com`

### 8. TLS certificate validation (anti-MITM)

```bash
./cf-knife scan \
  --ips 1.0.0.0/24 \
  -p 443 \
  --cert-check \
  --script cloudflare \
  --output-format csv \
  -o cert-audit.csv
```

After TLS handshake, inspects the certificate chain:
- Extracts issuer organization, subject CN, and expiry
- Validates against known CDN issuers (DigiCert, Google Trust, Let's Encrypt, GlobalSign, etc.)
- Flags `cert_mitm=true` if the issuer doesn't match the expected provider

CSV output includes columns: `cert_issuer`, `cert_subject`, `cert_expiry`, `cert_mitm`

### 9. Smart retry with relaxed thresholds

```bash
./cf-knife scan \
  --ips 104.16.0.0/24 \
  -p 443 \
  --max-latency 200ms \
  --smart-retry \
  -o results.txt
```

If the strict 200ms latency filter yields zero results but targets were alive:
- Round 1: Doubles max-latency to 400ms, increases timeout by 50%
- Round 2: Doubles again to 800ms if still zero
- Only re-scans targets that were TCP-alive but filtered out

```
  0 results passed filters; retrying with relaxed thresholds (max-latency: 200ms -> 400ms, round 1/2)
  re-scanning 47 alive targets...
```

### 10. WARP endpoint scanning

```bash
./cf-knife scan \
  --warp \
  --warp-port 2408 \
  -t 100 \
  -o warp.txt
```

Probes Cloudflare WARP UDP endpoints (WireGuard handshake initiation):
- Scans 8 default WARP CIDR ranges (~2048 endpoints)
- Reports reachable endpoints sorted by RTT
- Output saved as `warp-20260413-163902.txt`

### 11. Resumable scan with persistent queue

Start a large scan that persists state to SQLite:

```bash
./cf-knife scan \
  -i Cloudflare-IP.txt \
  -p 443,80,8443 \
  --timing 4 \
  --db my-scan.db \
  -o results.txt
```

If the scan is interrupted (Ctrl-C, crash, power loss), resume exactly where it left off:

```bash
./cf-knife scan \
  --resume \
  --db my-scan.db \
  -p 443,80,8443 \
  --timing 4 \
  -o results.txt
```

```
  resuming scan #1: 15234 pending targets
  scanning...
```

The SQLite database (`my-scan.db`) stores:
- Scan configuration (as JSON)
- Each target's status (`pending` or `done`)
- Completed probe results for later retrieval

### 12. Rate-limited scan

```bash
./cf-knife scan \
  -i Cloudflare-IP.txt \
  -p 443 \
  --rate 5000 \
  --threads 500 \
  -o result.txt
```

Caps global throughput to 5000 connections/sec regardless of thread count.

### 13. JSON output for programmatic use

```bash
./cf-knife scan \
  --ips 104.16.0.0/24 \
  -p 443,80 \
  --output-format json \
  -o scan-results.json
```

Each result is a JSON object with all probe fields:

```json
{
  "ip": "104.16.0.1",
  "port": "443",
  "latency_ms": 33000000,
  "tcp_success": true,
  "tls_success": true,
  "http_success": true,
  "http2_success": true,
  "http3_success": true,
  "tls_version": "TLS1.3",
  "tls_cipher": "TLS_AES_128_GCM_SHA256",
  "alpn": "h2",
  "service_name": "cloudflare/LAX",
  "cert_issuer": "DigiCert Inc",
  "cert_mitm": false
}
```

### 14. CSV output for spreadsheets

```bash
./cf-knife scan \
  --ips 1.0.0.0/24 \
  -p 443 \
  --cert-check \
  --speed-test \
  --output-format csv \
  -o full-audit.csv
```

CSV header includes all fields:

```
ip,port,sni,label,latency_ms,http_status,source_range,tcp,tls,https,http2,http3,
scan_type,server,tls_version,tls_cipher,alpn,cf_ray,service,ping_ms,jitter_ms,
download_mbps,upload_mbps,best_fragment,sni_front,cert_issuer,cert_subject,cert_expiry,
cert_mitm,error
```

`label` and `http_status` are populated for domain-mode scans.

### 15. Save and reuse configuration

Save a scan profile:

```bash
./cf-knife scan \
  --ips 1.1.1.0/24 \
  --threads 500 \
  --timing 4 \
  --cert-check \
  --smart-retry \
  --save-config \
  --config my-profile.json
```

Reuse it later (CLI flags still override file values):

```bash
./cf-knife scan --config my-profile.json
```

### 16. Full kitchen-sink scan

```bash
./cf-knife scan \
  -i Cloudflare-IP.txt \
  -p 443,80,8443,2053,2083 \
  --timing 4 \
  --script cloudflare \
  --speed-test \
  --dpi \
  --cert-check \
  --smart-retry \
  --db scan-state.db \
  --shuffle \
  --output-format csv \
  -o full-scan.csv
```

This runs everything: TCP/TLS/HTTP/H2/H3 probes, Cloudflare fingerprinting, speed testing, DPI analysis, certificate validation, smart retry, and persistent state -- all in one pass.

### 17. Multi-SNI matrix scan

Test each IP and port against several hostnames. Target count is *addresses × ports × SNIs*.

```bash
./cf-knife scan \
  --ips 104.16.0.0/25 \
  -p 443,8443 \
  --sni "www.cloudflare.com,cf-ns.com,www.example.com" \
  --timing 4 \
  -o sni-matrix.txt
```

Console line when loading (128 addresses × 2 ports × 3 SNIs = 768 targets):

```
loaded 768 targets (128 IPs × 2 ports × 3 SNIs)
```

### 18. Subnet sampling (`--sample`)

Useful when an input CIDR is too large for a full sweep; keeps up to *N* random IPs **per CIDR line** before ports are applied.

```bash
./cf-knife scan \
  -i cloudflare-ranges.txt \
  -p 443 \
  --sample 100 \
  --shuffle \
  -o spot-check.txt
```

Single-line equivalent for one big range:

```bash
./cf-knife scan --ips 104.16.0.0/14 -p 443 --sample 500 --rate 2000 -o sampled.txt
```

### 19. HTTP fragment probe (`--http-fragment`)

Runs the HTTP/HTTPS probe with small chunked writes and delays instead of a single HEAD. Combine with `--mode http` if you only need HTTP/1.1, or `--mode full` for the full stack.

```bash
./cf-knife scan \
  --ips 1.1.1.1 \
  -p 443 \
  --mode full \
  --http-fragment \
  --http-url "https://www.cloudflare.com/cdn-cgi/trace" \
  -o fragment-probe.txt
```

Combined workflow (matrix + sampling + fragment) in one run:

```bash
./cf-knife scan \
  --ips 104.16.0.0/20 \
  -p 443 \
  --sni "www.cloudflare.com,www.example.com" \
  --sample 50 \
  --http-fragment \
  -o matrix-scan.txt
```

### 20. Domain-based scan (`--domain-file`)

Create a `domains.txt` file — mix of formats all supported in one file:

```
# plain hostnames
example.com
myapp.workers.dev

# optional label prefix (label | host)
vpn-node | cf-node.example.com
my-app   | https://another.site.dev

# CIDR blocks expand to individual IP targets
104.18.2.0/24
labeled-range | 104.18.4.0/30
```

**Basic domain scan** — DNS → dial resolved IP, SNI = hostname:

```bash
./cf-knife scan \
  --domain-file domains.txt \
  -p 443 \
  --mode full \
  -o domain-scan.txt
```

```powershell
.\cf-knife.exe scan `
  --domain-file domains.txt `
  -p 443 `
  --mode full `
  -o domain-scan.txt
```

After the scan, three output files are written automatically:
- `domain-scan-TIMESTAMP.txt` — main results with label and http_status fields
- `reachable-TIMESTAMP.txt` — OPEN results sorted by latency
- `full_log-TIMESTAMP.txt` — all targets with OPEN/DEAD tags

**All 13 Cloudflare edge ports** in one pass:

```bash
./cf-knife scan \
  --domain-file domains.txt \
  --cf-all-ports \
  --timing 3 \
  -o domain-all-ports.txt
```

**With result cache** — successful targets saved after first run; loaded first on second run:

```bash
# First run — populates domain-cache.txt
./cf-knife scan \
  --domain-file domains.txt \
  -p 443 \
  --domain-cache domain-cache.txt \
  -o domain-scan.txt

# Subsequent runs — cached hosts checked first
./cf-knife scan \
  --domain-file domains.txt \
  -p 443 \
  --domain-cache domain-cache.txt \
  -o domain-scan.txt
```

**HTTPS → HTTP fallback** — enabled by default; no flag needed. If a domain fails HTTPS preflight, cf-knife automatically retries on port 80 with HTTP:

```
  preflight: TLS_FAILED → retrying on port 80 with http...
  [PASS] example.com resolved to 104.18.1.1 via HTTP fallback
```

**Disable pre-flight** (faster, skips DNS/TCP/TLS validation):

```bash
./cf-knife scan \
  --domain-file domains.txt \
  -p 443 \
  --site-preflight=false \
  -o domain-no-preflight.txt
```

**Full domain audit** — DPI analysis, certificate check, CSV output:

```bash
./cf-knife scan \
  --domain-file domains.txt \
  --cf-all-ports \
  --dpi \
  --cert-check \
  --script cloudflare \
  --domain-cache domain-cache.txt \
  --output-format csv \
  -o domain-audit.csv
```

```powershell
.\cf-knife.exe scan `
  --domain-file domains.txt `
  --cf-all-ports `
  --dpi `
  --cert-check `
  --script cloudflare `
  --domain-cache domain-cache.txt `
  --output-format csv `
  -o domain-audit.csv
```

### 21. Quick feature verification

A set of targeted commands for verifying each domain-mode feature individually.

**CIDR block in domain file** — expands to 6 host IPs (skips network + broadcast):

```bash
echo "104.18.0.0/29" > cidr.txt
./cf-knife scan \
  --domain-file cidr.txt \
  -p 443 --mode tls \
  --site-preflight=false \
  --verbose \
  -o cidr-out.txt
```

**Label field in results** — verify `label=` appears in txt output:

```bash
cat > /tmp/labeled.txt << 'EOF'
Cloudflare Main | cloudflare.com
Google CDN      | google.com
Example Site    | example.com
EOF

./cf-knife scan \
  --domain-file /tmp/labeled.txt \
  -p 443 --mode http --verbose \
  -o /tmp/labeled-out.txt

cat /tmp/labeled-out-*.txt
```

Each result line should contain `label=Cloudflare Main`, `label=Google CDN`, etc.

**HTTP status code in CSV output** — verify `label` and `http_status` columns:

```bash
./cf-knife scan \
  --domain-file /tmp/labeled.txt \
  -p 443 --mode http \
  --output-format csv \
  -o /tmp/labels.csv

head -3 /tmp/labels-*.csv
```

Expected CSV header: `ip,port,sni,label,latency_ms,http_status,...`

**Domain cache: two-run workflow** — first run creates cache, second run loads it:

```bash
# Run 1 — builds cache
./cf-knife scan \
  --domain-file /tmp/labeled.txt \
  -p 443 --mode http \
  --domain-cache /tmp/dc.txt \
  -o /tmp/run1.txt

# Run 2 — prints "loaded N cached targets from /tmp/dc.txt"
./cf-knife scan \
  --domain-file /tmp/labeled.txt \
  -p 443 --mode http \
  --domain-cache /tmp/dc.txt \
  --verbose \
  -o /tmp/run2.txt
```

**Verify all output files are created** — main results + reachable + full_log + cache:

```bash
./cf-knife scan \
  --domain-file /tmp/labeled.txt \
  -p 443 --mode http \
  --domain-cache /tmp/dc2.txt \
  -o /tmp/report.txt

ls /tmp/report-*.txt /tmp/reachable-*.txt /tmp/full_log-*.txt /tmp/dc2.txt
```

**All 13 Cloudflare ports** — expands each hostname across 6 HTTPS + 7 HTTP ports:

```bash
./cf-knife scan \
  --domain-file /tmp/labeled.txt \
  --cf-all-ports \
  --mode http \
  -t 500 \
  -o /tmp/all-ports.txt
```

**JSON output** — machine-readable with label + http_status fields:

```bash
./cf-knife scan \
  --domain-file /tmp/labeled.txt \
  -p 443 --mode http \
  --output-format json \
  -o /tmp/out.json

cat /tmp/out-*.json | python3 -m json.tool | head -40
```

**Preflight + HTTPS→HTTP fallback** — watch stderr for fallback messages:

```bash
./cf-knife scan \
  --domain-file /tmp/labeled.txt \
  -p 443 --mode http \
  --site-preflight \
  --timeout 5s \
  --verbose \
  -o /tmp/preflight.txt
```

**Smart retry + high concurrency stress test**:

```bash
./cf-knife scan \
  --domain-file domains.txt \
  -p 443 --mode full \
  -t 300 \
  --smart-retry \
  --max-latency 2s \
  --verbose \
  -o /tmp/stress.txt
```

**Disable preflight** (faster, skips DNS/TCP/TLS validation before probing) — note: use `=false`, not `--no-site-preflight`:

```bash
./cf-knife scan \
  --domain-file domains.txt \
  -p 443 --mode http \
  --site-preflight=false \
  -o /tmp/fast.txt
```

### 22. DNS poison detection (`--dns-check`)

Compares your system resolver against Cloudflare DoH (`1.1.1.1`) and Google DoH (`8.8.8.8`), dialing both by IP to avoid poisoning of the resolver hostname itself.

```bash
echo "cloudflare.com" > /tmp/dns-test.txt
./cf-knife scan \
  --domain-file /tmp/dns-test.txt \
  -p 443 --mode http \
  --dns-check \
  --site-preflight=false \
  -o /tmp/dns-out.txt

cat /tmp/dns-out-*.txt
```

The `dns=` field in every result line shows one of:

| Value | Meaning |
|-------|---------|
| `dns=clean` | System IP matches DoH — no poisoning detected |
| `dns=POISONED:IP_MISMATCH(sys=X real=Y)` | System returned a different IP than DoH |
| `dns=POISONED:DNS_HIJACK(real=Y)` | System DNS fails but DoH resolves — DNS blocked/hijacked |
| `dns=DOH_UNAVAILABLE` | Both DoH endpoints unreachable — result is inconclusive |

**CSV output** — includes 4 extra columns: `dns_poisoned`, `dns_system_ip`, `dns_clean_ip`, `dns_poison_reason`:

```bash
./cf-knife scan \
  --domain-file /tmp/dns-test.txt \
  -p 443 --mode http \
  --dns-check --site-preflight=false \
  --output-format csv \
  -o /tmp/dns-out.csv

head -2 /tmp/dns-out-*.csv
```

**Combined with cert-check** — catches both DNS-level and TLS-level interception in one pass:

```bash
./cf-knife scan \
  --domain-file domains.txt \
  -p 443 --mode http \
  --dns-check \
  --cert-check \
  --site-preflight=false \
  -o /tmp/full-check.txt
```

---

## Output Format

### Detailed results (txt)

Each line contains all available data for a target:

```
1.0.0.113:443 | sni=www.cloudflare.com | latency=33ms | range=1.0.0.0/24 | tcp=ok tls=ok https=ok http2=ok http3=ok | service=cloudflare/LAX | http_status=200
example.com:443 | sni=example.com | latency=45ms | range=domain | tcp=ok tls=ok https=ok http2=ok http3=fail | service=cloudflare/SIN | label=my-site | http_status=200
1.0.0.200:443 | sni=- | latency=89ms | range=1.0.0.0/24 | tcp=ok tls=ok https=fail http2=fail http3=fail | service=- | cert_issuer=Unknown CA | MITM_DETECTED
```

Domain-mode lines include `label=` and `http_status=` when available.

### Domain reports (domain-mode only)

When scanning with `--domain-file`, two extra files are written automatically alongside the main output:

**`reachable-TIMESTAMP.txt`** — OPEN results sorted by latency:

```
Reachability Report — OPEN SITES
Generated        : 2026-04-19 14:30:00
Total tested     : 120 / 500
Open (reachable) : 45
Closed / Dead    : 75
==========================================================================================
#     Latency   HTTP  IP : Port               Label                          Hostname
------------------------------------------------------------------------------------------
1      142ms    200   104.18.1.1:443          my-app                         example.com
2      178ms    200   104.18.2.5:443          vpn-node                       cf-node.example.com
...
CLOSED / UNREACHABLE
  dead-site                      :0                     [DNS_FAILED]
```

**`full_log-TIMESTAMP.txt`** — all results with OPEN/DEAD tags, sorted by label:

```
Tag     Latency  HTTP/Err         IP : Port               Label                          Hostname
OPEN     142ms   200              104.18.1.1:443          my-app                         example.com
DEAD       0ms   DNS_FAILED       :0                      dead-site                      dead-site.io
```

### Clean list (clean_list.txt)

Generated on every run -- `ip:port` pairs for direct proxy use:

```
1.0.0.113:443
1.0.0.54:443
1.0.0.118:443
```

### Terminal summary

A colored table printed after each scan showing top results by latency:

```
=== cf-knife scan results ===

IP                                       PORT   LATENCY  RANGE                 TCP  TLS  HTTPS HTTP2 HTTP3  SERVICE
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
1.0.0.113                                443      33ms  1.0.0.0/24              ok   ok   ok    ok    ok    cloudflare/LAX
1.0.0.54                                 443      45ms  1.0.0.0/24              ok   ok   ok    ok   fail   cloudflare/SIN
...

Stats:  128 clean results  |  elapsed 5.199s  |  24 targets/sec
Files:  result-20260413-163902.txt  |  clean_list.txt
```

---

## Live Scan Statistics

During a scan, real-time statistics are printed every 3 seconds:

```
  1134/2048 scanned | TCP:1134 TLS:890 HTTP:456 H2:312 H3:104 | err:120 | 378/s
```

After completion:

```
  Scan complete in 5.199s -- 2048 targets scanned
  TCP: 1928  TLS: 890  HTTP: 456  H2: 312  H3: 104  Errors: 120
```

---

## Graceful Shutdown

Pressing Ctrl-C during a scan triggers graceful shutdown:

1. Active workers finish their current probe and stop accepting new targets.
2. The progress bar and stats goroutine are stopped.
3. All results collected so far are filtered and saved to disk.
4. If using `--db`, completed results are already persisted. Use `--resume` to continue.
5. A second Ctrl-C during the save phase is ignored to ensure the file write completes.

---

## Platform Notes

### Windows
- **Ping**: Uses TCP connect RTT instead of ICMP (raw sockets require administrator privileges on Windows).
- **Progress bar**: Displays text-based stats instead of the graphical progress bar (compatibility).
- **ANSI colors**: Automatically enabled via Windows Virtual Terminal Processing.
- **Run from terminal**: Always run `cf-knife.exe` from PowerShell or CMD -- double-clicking closes instantly.

### Linux
- **Ping**: Uses ICMP echo requests. Requires root or `CAP_NET_RAW` capability.
- **SYN scan**: The `--scan-type syn` flag is a stub that falls back to connect scan with a warning.

### macOS
- **Ping**: Uses unprivileged UDP-based ICMP (no root required).

---

## Tips for High-Volume Scanning

- Start with `--timing 2` (polite) to stay within ISP rate limits, then increase.
- Use `--rate 10000` to cap global throughput regardless of thread count.
- `--scan-type fast` halves the TCP timeout for quicker sweeps.
- `--mode tcp-only` skips TLS/HTTP probes entirely for maximum speed.
- `--smart-retry` prevents wasted scans when initial thresholds are too strict.
- `--db scan.db` ensures you never lose progress on large scans. Resume with `--resume`.
- Large CIDR ranges (/12) are capped at ~1M IPs per range. Use `--shuffle` for random sampling.
- Use `--sample N` to randomly cap hosts per CIDR: `./cf-knife scan --ips 104.24.0.0/13 -p 443 --sample 300 -o t.txt` (Windows: `.\cf-knife.exe scan ...` with the same flags)
- Compare TLS/HTTP behavior across hostnames: `./cf-knife scan --ips 1.1.1.1 -p 443 --sni "h1.com,h2.com" -o m.txt`
- Combine `--cert-check` with `--script cloudflare` to detect MITM proxies in your network.

---

## Responsible Use

This tool is intended for authorized network testing only. Scanning IP ranges you do not own or have permission to test may violate your ISP's terms of service, local laws, or the Computer Fraud and Abuse Act (or equivalents in your jurisdiction). Always obtain written authorization before scanning third-party infrastructure.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
