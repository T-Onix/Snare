# 🕸️ SNARE

<p align="center">
  <img src="image.png" alt="SNARE Banner" width="100%">
</p>

<p align="center">
  <strong>Automated Web Technology Fingerprinting & CVE Discovery Engine</strong>
</p>

<p align="center">
  <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go" alt="Go"></a>
  <a href="https://github.com/t-onix/snare/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-GNU-green?style=for-the-badge" alt="License"></a>
</p>

---

**SNARE** is a high-performance reconnaissance tool built in Go, designed specifically for security researchers and bug bounty hunters. It automatically probes target domains to identify running technologies, web servers, and framework versions, then cross-references them against multi-source CVE vulnerability databases (CIRCL, OSV, and NVD) to highlight potential attack surfaces and public PoCs.

### Visual Preview

```text
╭──────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ TARGET:  [https://example-vulnerable-host.com](https://example-vulnerable-host.com)                      │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Tech: OpenSSL v1.0.1e                                                                                    │
│   └─ [HIGH 7.5] [🔥 PoC AVAILABLE] CVE-2014-0160 -> Heartbleed: Out-of-bounds read in TLS heartbeat      │
│                                                     extension leading to memory disclosure               │
│ Tech: Apache HTTP Server v2.4.49                                                                         │
│   ├─ [CRITICAL 9.8] [🔥 PoC AVAILABLE] CVE-2021-41773 -> Path traversal and remote code execution in     │
│   │                                                      Apache HTTP Server 2.4.49                       │
│   └─ [HIGH 7.5] CVE-2017-9798 -> OptionsBleed: Memory disclosure in OPTIONS HTTP method                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### Features

- Smart Probe & HTTP Transport
    Accepts bare domain names, standard HTTP/HTTPS URLs, or IP addresses
    Performs automatic protocol fallback (tries HTTPS first with SSL verification disabled, falling back to HTTP if needed)
    Operates asynchronously using a concurrent worker pool for maximum speed

- Technology Fingerprinting Engine
    Leverages projectdiscovery/wappalyzergo for high-speed pattern matching
    Analyzes HTTP response headers, cookies, HTML bodies, and meta tags
    Extracts exact version numbers when exposed

- Zero-Overhead Surgical CVE Filtering (-sc)
      Pre-loads specific CVE definitions at startup (e.g., -sc 'CVE-2021-41773,CVE-2014-0160') and evaluates detected technologies purely in memory with zero per-host API latency

- Multi-Source CVE Intelligence & PoC Detection
    Correlates versions against CIRCL Vulnerability-Lookup, Google OSV, and NIST NVD with local disk caching and rate-limit guards
    Automatically flags CVEs with known public exploits ([🔥 PoC AVAILABLE]) across Exploit-DB, PacketStorm, Metasploit, and GitHub

- Manual Technology Queries: Accepts manual tech:version entries directly to search CVEs without sending network traffic to a host

### Installation

- Go Install (Recommended)

```bash
go install github.com/t-onix/snare@latest
```

- Build from Source

```bash
git clone https://github.com/t-onix/snare.git
cd snare
go mod tidy
go install .
```

### Usage

```
SNARE - Web Technology Fingerprinting & CVE Discovery Engine

Usage:
  snare [flags]

Flags:
  -c int
    	Number of concurrent target workers (default 10)
  -d string
    	Single target domain or URL
  -f string
    	File containing list of targets
  -json
    	Output results as structured JSON lines
  -k	Skip TLS certificate verification (use only when required)
  -no-banner
    	Disable startup ASCII banner
  -o string
    	File to save results
  -rt int
    	Number of retries for failed target requests (default 2)
  -sc string
    	Comma-separated list of specific CVEs to scan for (e.g. 'CVE-2021-41773,CVE-2014-0160')
  -specific-cves string
    	Comma-separated list of specific CVEs to scan for
  -t string
    	Manual technology & version lookup (e.g. nextjs:1.2.3 or apache:2.4.49)
  -update
    	Update SNARE to the latest version via go install
  -vo
    	Only display targets with version-matched CVEs (shorthand)
  -vuln-only
    	Only display targets with version-matched CVEs
```

### Examples

- Single Target Scan

```bash
snare -d example.com
Or
echo target.com | snare
```

- Multi-threaded Scan from File & Save Output

```bash
snare -f hosts -c 25 -o results
```

- Pipeline Integration

```bash
subfinder -d target.com -silent | httprobe | snare -c 30 -o results
```

- Manual Technology Lookup

```bash
snare -t "nextjs:1.2.3,apache:2.4.49,openssl:1.0.1f"
```

- JSON Output Format

```bash
snare -d example.com -json | jq
```

- JSON Output structure:

```json
{
  "target": "https://example.com",
  "timestamp": "2026-11-02T14:20:00Z",
  "technologies": [
    {
      "tech": {
        "name": "Apache",
        "version": "2.4.49"
      },
      "cves": [
        {
          "id": "CVE-2021-41773",
          "severity": "CRITICAL",
          "cvss": 9.8,
          "has_poc": true,
          "summary": "Path traversal and remote code execution in Apache HTTP Server 2.4.49",
          "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
          ]
        }
      ],
      "cve_status": "matched"
    }
  ]
}
```

- Environment Variables
    NVD_API_KEY: Optional NIST NVD API key to increase NVD fallback rate limits during large scans.
    SNARE_CACHE_DIR: Optional custom directory path for persistent CVE lookup caching.

### Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue or submit a pull request
