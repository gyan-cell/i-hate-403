# i-hate-403

**Because 403 is just a suggestion.**

> **[!] AUTHORIZED USE ONLY.** This tool is intended for security professionals conducting authorized penetration testing or bug bounty research. Using it against targets without explicit written permission is illegal and unethical. The authors accept no liability for misuse.

---

A production-grade 403/401 bypass tool built in Go. It goes beyond status-code guessing by capturing a **calibrated baseline** before anything fires — then scores every result with a heuristic confidence engine so you know which bypasses are real.

## What makes it different

| Feature | nomore403 | 400OK | **i-hate-403** |
|---------|-----------|-------|----------------|
| Baseline calibration | No | Partial | Yes Full (status + length + hash + fingerprint) |
| Soft-404 detection | No | No | Yes |
| Fragment-stripping detection | No | No | Yes |
| Confidence scoring | No | No | Yes HIGH/MEDIUM/LOW/INTERESTING |
| Concurrent per-technique | No | No | Yes Worker pool per technique |
| Deduplication | No | Partial | Yes By status+length+body hash |
| Overlong UTF-8 (2+3 byte) | No | No | Yes |
| IIS %uXXXX encoding | No | No | Yes |
| Raw request file (Burp/ZAP) | No | No | Yes |
| JSON/CSV output | No | No | Yes |
| Rate limiting | No | No | Yes |
| Exponential backoff | No | No | Yes |
| Graceful Ctrl+C (partial flush) | No | No | Yes |
| `--quick` time-boxed preset | No | No | Yes |

## Install

```bash
git clone https://github.com/gyan-cell/i-hate-403
cd i-hate-403
make build          # produces ./i-hate-403
# or
make install        # installs to $GOPATH/bin
```

**Requirements:** Go 1.21+

## Quick start

```bash
# Single target
./i-hate-403 -u https://target.tld/admin

# Quick mode (4 techniques, fast engagement)
./i-hate-403 -u https://target.tld/admin --quick

# Specific techniques
./i-hate-403 -u https://target.tld/admin -k headers,midpaths,endpaths

# Through Burp proxy, skip TLS, save JSON
./i-hate-403 -u https://target.tld/admin \
  --proxy http://127.0.0.1:8080 \
  --insecure \
  -o results.json

# From a Burp raw request file
./i-hate-403 --request-file request.txt

# Batch targets
./i-hate-403 -l targets.txt --unique --status 200,302

# Rate limited (5 req/s), 20 threads
./i-hate-403 -u https://target.tld/admin --rate-limit 5 -t 20

# Start Web UI on default port (http://127.0.0.1:8080)
./i-hate-403 --web

# Start Web UI on custom port
./i-hate-403 --web --web-addr 127.0.0.1:9090
```

## Techniques

| Name | Description |
|------|-------------|
| `verbs` | 24 HTTP method variants including WebDAV and invented methods |
| `verbs-case` | Case permutations of GET, POST, PUT, etc. |
| `headers` | IP spoofing (X-Forwarded-For, X-Real-IP, etc.), host override, scheme override, method override |
| `endpaths` | 30+ path suffix variants (`/`, `//`, `/.`, `..;/`, `.json`, `%20`, `%00`, …) |
| `midpaths` | Inject `./`, `../`, `..;/`, `//`, `%2e/` at each path segment boundary |
| `double-encoding` | Double/triple percent-encode `/` and `.` to bypass single-decode filters |
| `unicode` | 2-byte overlong (%C0%AF), 3-byte overlong (%E0%80%AF), IIS %uXXXX, full-width chars |
| `path-case` | UPPER, Title, and aLtErNaTiNg case variants per segment |
| `http-versions` | Force HTTP/1.0, HTTP/1.1, HTTP/2 via curl |
| `custom-position` | Inject payloads at a custom marker position (`§`) in the URL |
| `raw-request` | Replay and mutate a raw Burp/ZAP request file |

## Scoring

Every response is scored against the calibrated baseline:

| Confidence | Meaning |
|-----------|---------|
| **HIGH** | Status changed from blocked → success, body changed, length outside tolerance |
| **MEDIUM** | Status changed, body differs from baseline |
| **LOW** | Status changed but body looks like baseline (likely soft-block) |
| **INTERESTING** | Status unchanged but content length/type shifted significantly |
| **NONE** | No meaningful difference from baseline — filtered from output by default |

## Flags

```
  -u, --url string           Target URL
  -l, --list string          File of target URLs (one per line)
      --request-file string  Burp/ZAP raw HTTP request file
  -k, --technique string     Techniques to run: 'all' or comma-separated (default "all")
      --bypass-ip strings    IPs for header-based bypasses (default: loopback + RFC1918)
  -p, --marker string        Custom position marker (default "§")
  -o, --output string        Output file (.json / .csv / .txt)
      --unique               Collapse identical (status+length+hash) results
      --status ints          Filter to specific status codes
  -t, --threads int          Workers per technique (default 10)
      --timeout duration     Per-request timeout (default 10s)
      --proxy string         HTTP/SOCKS proxy (e.g. http://127.0.0.1:8080)
      --insecure             Skip TLS verification
      --user-agent string    Custom User-Agent
  -v, --verbose              Show all results including NONE
      --rate-limit float     Max requests/sec (0 = unlimited)
      --quick                Fast preset: headers+midpaths+endpaths+verbs
      --no-scope             Disable automatic scope restriction
      --web                  Start the web UI server
      --web-addr string      Web UI server address (default "127.0.0.1:8080")
```

## Architecture

```
cmd/i-hate-403/main.go          CLI entry point (cobra)
internal/
  calibrate/                    Baseline capture, soft-404 / fragment detection, WAF fingerprinting
  bypass/                       Technique interface + registry + all technique implementations
    engine.go                   Concurrent worker pool per technique, Ctrl+C safe
    types.go                    Technique, Target, Payload, Result, Registry
    endpaths.go, midpaths.go    Path manipulation techniques
    headers.go, verbs.go        Header and method techniques
    double_encoding.go          Double/triple encoding
    unicode.go                  Overlong UTF-8, IIS unicode
    path_case.go                Case variants
    http_versions.go            HTTP/1.0, 1.1, 2 via curl
    custom_position.go          Marker-based position injection
    raw_request.go              Burp/ZAP raw request replay
  http/                         Custom http.Client (retry, backoff, proxy, TLS, raw URL)
  score/                        Heuristic confidence scoring + deduplication
  report/                       Terminal (colorized + tabwriter), JSON, CSV output
web/                            Embedded web UI with SSE streaming
```

## Development

```bash
make test          # run all tests
make vet           # go vet
make lint          # golangci-lint (requires install)
make tidy          # go mod tidy
make clean         # remove binary
```

## License

MIT — see [LICENSE](LICENSE).

---

*Built for security professionals, not script kiddies. Use responsibly.*
# i-hate-403
