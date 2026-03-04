# ReconX

**Automated Reconnaissance & Intelligence Gathering Tool**

```
╔══════════════════════════════════════════════════════════════╗
║   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗      ║
║   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝      ║
║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝       ║
║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗       ║
║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗      ║
║   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝    ║
╚══════════════════════════════════════════════════════════════╝
```

A high-performance CLI reconnaissance tool that accepts **domains, IP addresses, CIDR ranges, or target files** as input. For domains it aggregates subdomain data from **11 sources**, performs HTTP probing via [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx), port scanning with [Nmap](https://nmap.org), SMB/Windows enumeration with [enum4linux](https://github.com/CiscoCXSecurity/enum4linux), and protocol enumeration with [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec). For IP/CIDR targets it **skips enumeration entirely** and jumps straight to nmap + enum4linux + CME. All results are presented in rich, color-coded terminal output with per-domain file exports.

## Features

| Category | Details |
|----------|---------|
| **Multi-Source Enumeration** | 11 data sources — Atlas (crt.sh), Sphinx (Certspotter), Oracle (AlienVault OTX), Radar (HackerTarget), Torrent (Wayback Machine), Venom (VT + ThreatMiner + Anubis + RapidDNS), VirusTotal (VT v3 subdomains), Shodan, Censys, SecurityTrails, URLScan.io |
| **HTTPX HTTP Probing** | ProjectDiscovery httpx integration — status codes, titles, technologies (Wappalyzer), favicon hashes, CDN detection, server headers, FQDNs from response bodies |
| **Nmap Port Scanning** | Nmap integration — `-sCV --top-ports 1000 -T3` service/version detection on all discovered IP addresses with `.nmap`, `.xml`, `.gnmap` output |
| **Enum4linux Enumeration** | enum4linux integration — `-a` full SMB/Windows enumeration (shares, users, groups, password policy, null sessions) on all discovered IPs after nmap |
| **CrackMapExec Protocol Enum** | CME/NetExec integration — protocol-based enumeration (SMB, SSH, RDP, WinRM, MSSQL, LDAP, etc.) grouped by open ports from nmap |
| **Multi-Target Input** | Accepts domain names, single IPs (`10.10.0.5`), CIDR ranges (`10.10.0.0/24`), or target files (`targets.txt`) — IPs/CIDRs skip enumeration and go straight to nmap + enum4linux + CME |
| **Infrastructure Classification** | Cloudflare, AWS, Azure, Akamai detection via CNAME patterns, IP ranges, and httpx CDN/server data |
| **Certificate Transparency** | CT log triage with age classification — stale (1–2yr), aged (2yr+), no date |
| **Subdomain Takeover** | 11+ provider fingerprints (Azure, AWS S3, GitHub Pages, Heroku, Shopify, Fastly, etc.) |
| **Tech Stack Profiling** | 15+ technology signatures — Spring Boot Actuator, Tomcat, Jenkins, Grafana, WordPress, Laravel, Django, etc. with CRITICAL/High/Medium/Low/Info severity |
| **Pattern Collapse** | Groups repetitive subdomains into wildcard patterns (e.g., `app-*.example.com`) |
| **Concurrent Execution** | ThreadPoolExecutor with configurable worker count (default: 50) — optimized timeouts for fast enumeration |
| **Structured Export** | JSON export + 25+ per-domain output files (alive hosts, IPs, tech, takeover, httpx data, nmap results, enum4linux users/shares, CME protocols, etc.) |
| **Rich Terminal Output** | ANSI-colored box-drawn summary matching professional security tooling |

## Quick Start

### Prerequisites

- Python 3.8+
- [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx) (recommended, for HTTP probing)
- [Nmap](https://nmap.org) (recommended, for port scanning)
- [enum4linux](https://github.com/CiscoCXSecurity/enum4linux) (optional, for SMB/Windows enumeration)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) or [NetExec](https://github.com/Pennyw0rth/NetExec) (optional, for protocol enumeration)

### Install

```bash
git clone https://github.com/securiben/reconx.git
cd reconx

# Install Python dependencies
pip install -r requirements.txt

# (Recommended) Install ProjectDiscovery httpx
# Option A: Go install
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Option B: Download binary
# https://github.com/projectdiscovery/httpx/releases

# (Recommended) Install Nmap
# Debian/Ubuntu: sudo apt install nmap
# Windows: https://nmap.org/download.html
# macOS: brew install nmap

# (Optional) Install enum4linux
sudo apt install enum4linux
# Or: https://github.com/CiscoCXSecurity/enum4linux

# (Optional) Install CrackMapExec / NetExec
pip install crackmapexec
# Or: https://github.com/byt3bl33d3r/CrackMapExec
```

### Configure API Keys (Optional)

API keys are optional but significantly increase coverage. Copy `.env.example` to `.env` and fill in your keys:

```bash
cp .env.example .env
```

Get free API keys from:
| Service | Free Tier | URL |
|---------|-----------|-----|
| VirusTotal | 500 req/day | https://www.virustotal.com/gui/my-apikey |
| VirusTotal (domain_siblings) | Same key as above | https://www.virustotal.com/gui/my-apikey |
| Shodan | 100 req/month | https://account.shodan.io/ |
| Censys | 250 req/month | https://search.censys.io/account/api |
| SecurityTrails | 50 req/month | https://securitytrails.com/corp/api |
| URLScan.io | 1000 req/day | https://urlscan.io/user/signup |
| Certspotter | Higher limits | https://sslmate.com/certspotter/ |

### Run

```bash
# Domain → full recon pipeline (enum → httpx → nmap)
python main.py target.com

# Single IP → direct scan (nmap + CME, skips enumeration)
python main.py 10.10.0.5

# CIDR range → direct scan on all hosts in range
python main.py 10.10.0.0/24

# Target file → reads IPs/domains from file (one per line)
python main.py targets.txt

# Demo mode (simulated data, no API keys needed)
python main.py example.com --demo

# Custom output
python main.py target.com -o results.json

# High concurrency with longer timeout
python main.py target.com -c 100 -t 15
```

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `target` | Target: domain, IP address, CIDR range, or file of targets | Required |
| `-o, --output` | Output JSON filename | `<domain>/<domain>.json` |
| `--demo` | Run with simulated data | `false` |
| `--no-redact` | Show full subdomain names | `false` |
| `-v, --verbose` | Verbose output | `false` |
| `-c, --concurrency` | Max concurrent workers | `50` |
| `-t, --timeout` | Per-request timeout (seconds) | `10` |
| `--no-banner` | Skip ASCII banner | `false` |
| `--collapse-threshold` | Min entries for pattern collapse | `5` |

## Output Structure

Each scan creates a domain-specific folder with categorized output files:

```
<domain>/
├── <domain>.json              # Full scan results (JSON)
├── scan_summary.json          # Metadata + summary
├── all_subdomains.txt         # All unique subdomains
├── alive_subdomains.txt       # HTTP-alive subdomains only
├── ip_addresses.txt           # All discovered IPs
├── ip_subdomain_map.txt       # IP → subdomain mapping
├── takeover_vulnerable.txt    # Subdomain takeover vulns
├── dangling_cnames.txt        # Dangling CNAME records
├── tech_detected.txt          # Tech detections by severity
├── flagged_interesting.txt    # Interesting/flagged subdomains
├── ct_aged.txt                # Aged CT entries (2yr+)
├── ct_stale.txt               # Stale CT entries (1-2yr)
├── collapsed_patterns.txt     # Collapsed pattern groups
├── infrastructure.txt         # Cloud provider classification
├── sources_stats.txt          # Per-source statistics
├── httpx_probe.txt            # Full httpx results per host
├── httpx_technologies.txt     # Wappalyzer tech detection
├── httpx_cdn.txt              # CDN-backed subdomains
├── httpx_favicon.txt          # Favicon hash mapping
├── httpx_servers.txt          # Server header distribution
├── httpx_titles.txt           # HTTP page titles
├── httpx_redirects.txt        # Redirect chains
├── nmap_scan.nmap             # Nmap normal output
├── nmap_scan.xml              # Nmap XML output
├── nmap_scan.gnmap            # Nmap greppable output
├── nmap_summary.txt           # Nmap human-readable summary
├── nmap_summary.json          # Nmap structured JSON results
├── enum4linux_summary.txt     # Enum4linux human-readable summary
├── enum4linux_summary.json    # Enum4linux structured JSON results
├── enum4linux_users.txt       # All discovered usernames
├── enum4linux_shares.txt      # All discovered SMB shares
├── enum4linux_null_sessions.txt # Hosts allowing null sessions
├── enum4linux_<ip>.txt        # Raw per-host enum4linux output
├── cme_summary.txt            # CME human-readable summary
├── cme_summary.json           # CME structured JSON results
└── cme_<protocol>_targets.txt # Per-protocol target IP lists
```

## Architecture

```
reconx/
├── main.py                      # CLI entry point & argument parser
├── .env                         # API keys (git-ignored)
├── .env.example                 # API key template
├── requirements.txt             # Python dependencies
└── recon/
    ├── config.py                # Configuration, .env loader, source definitions
    ├── models.py                # Data models (Subdomain, TechMatch, CTEntry, etc.)
    ├── utils.py                 # DNS resolution, IP classification, pattern matching, input detection
    ├── engine.py                # Multi-phase pipeline orchestrator + direct-target mode
    ├── sources/                 # 11 data source modules
    │   ├── base.py              # Abstract base class
    │   ├── atlas.py             # crt.sh Certificate Transparency
    │   ├── sphinx.py            # Certspotter CT logs
    │   ├── oracle.py            # AlienVault OTX passive DNS
    │   ├── radar.py             # HackerTarget hostsearch
    │   ├── torrent.py           # Wayback Machine CDX index
    │   ├── venom.py             # VT + Anubis + ThreatMiner + RapidDNS
    │   ├── vt_siblings.py       # VT v3 subdomains API
    │   ├── shodan_source.py     # Shodan DNS + SSL cert search
    │   ├── censys_source.py     # Censys certificate + host search
    │   ├── sectrails_source.py  # SecurityTrails subdomain enumeration
    │   └── urlscan_source.py    # URLScan.io web intelligence
    ├── scanner/                 # Analysis modules
    │   ├── infrastructure.py    # Cloud provider classification (DNS + IP ranges)
    │   ├── ct_logs.py           # CT log triage (stale/aged/fresh)
    │   ├── takeover.py          # Subdomain takeover detection
    │   ├── tech_profiler.py     # Technology stack profiling (15+ signatures)
    │   ├── httpx_probe.py       # ProjectDiscovery httpx CLI wrapper
    │   ├── nmap_scan.py         # Nmap port & service scanner wrapper
    │   ├── enum4linux_scan.py   # Enum4linux SMB/Windows enumeration wrapper
    │   └── cme_scan.py          # CrackMapExec protocol enumeration wrapper
    └── output/                  # Output rendering
        ├── terminal.py          # ANSI terminal renderer (box-drawn)
        ├── json_export.py       # Structured JSON export
        └── file_export.py       # Per-domain file exporter (25+ files)
```

## Pipeline Phases

### Domain Mode

When the input is a domain name, the engine executes an 11-phase pipeline:

| Phase | Name | Description |
|-------|------|-------------|
| 1 | **Sources** | Concurrent subdomain enumeration from all 11 sources |
| 2 | **Dedup** | Normalize, deduplicate, and aggregate all discovered subdomains |
| 3 | **CT Logs** | Query crt.sh for certificate transparency entries + age triage |
| 4 | **Infrastructure** | DNS CNAME/A resolution → cloud provider classification |
| 5 | **HTTPX Probe** | HTTP probing via ProjectDiscovery httpx (status, title, tech, CDN, favicon) |
| 5b | **Infra Reconcile** | Update infrastructure stats from httpx CDN/server data |
| 6 | **Collapse** | Group repetitive subdomains into wildcard patterns |
| 7 | **Takeover** | Check for subdomain takeover vulnerabilities (11+ providers) |
| 8 | **Tech Profile** | Technology stack detection on alive subdomains (15+ signatures) |
| 9 | **Nmap** | Port & service scanning on all discovered IP addresses (-sCV --top-ports 1000) |
| 9b | **Enum4linux** | SMB/Windows enumeration on all discovered IPs (shares, users, groups, null sessions) |
| 9c | **CME** | CrackMapExec protocol enumeration grouped by open ports from nmap |
| 10 | **Statistics** | Compute final stats (timing, counts, DB stats) |
| 11 | **Output** | Terminal rendering + JSON export + per-domain file export |

### Direct Mode (IP / CIDR / File of IPs)

When the input is an IP address, CIDR range, or a file containing only IPs/CIDRs, all subdomain enumeration phases are **skipped**. The engine runs only:

| Phase | Name | Description |
|-------|------|-------------|
| 1 | **Nmap** | Port & service scanning on all target IPs (`-sCV --top-ports 1000`) |
| 2 | **Enum4linux** | SMB/Windows enumeration on all target IPs (`enum4linux -a`) |
| 3 | **CME** | CrackMapExec protocol enumeration grouped by open ports from nmap |
| 4 | **Output** | Terminal rendering + JSON export + per-target file export |

## Subdomain Takeover Detection

| Provider | CNAME Patterns | Detection Method |
|----------|---------------|------------------|
| Microsoft Azure | `.azurewebsites.net`, `.cloudapp.azure.com`, `.trafficmanager.net` | NXDOMAIN + HTTP fingerprint |
| AWS S3 | `.s3.amazonaws.com` | NoSuchBucket response |
| GitHub Pages | `.github.io` | HTTP fingerprint |
| Heroku | `.herokuapp.com` | HTTP fingerprint |
| Shopify | `.myshopify.com` | HTTP fingerprint |
| Fastly | `.fastly.net` | HTTP fingerprint |
| Pantheon | `.pantheonsite.io` | HTTP fingerprint |
| WordPress.com | `.wordpress.com` | HTTP fingerprint |
| Tumblr | `.tumblr.com` | HTTP fingerprint |
| Ghost | `.ghost.io` | HTTP fingerprint |
| Surge.sh | `.surge.sh` | HTTP fingerprint |

## Tech Signatures

| Technology | Severity | Key Indicators |
|-----------|----------|----------------|
| Spring Boot Actuator | **CRITICAL** | `/actuator`, `/env`, `/heapdump` exposure |
| Apache Tomcat | HIGH | `/manager`, `/host-manager`, `tomcat-users.xml` |
| Spring Boot | HIGH | Whitelabel Error Page, SpEL injection |
| Jenkins | HIGH | Script console, unauthenticated access |
| Grafana | HIGH | Dashboard access, default credentials |
| WordPress | MEDIUM | `/wp-admin`, `/xmlrpc.php`, plugin vulns |
| Laravel | MEDIUM | `/telescope`, `.env` exposure, debug mode |
| Django | MEDIUM | `/admin`, debug mode, settings exposure |
| Shopify | MEDIUM | CDN patterns, open admin |
| Postmark | MEDIUM | Email injection vectors |
| Nginx | LOW | Version disclosure, misconfigurations |
| Apache HTTP | LOW | `/server-status`, version disclosure |
| Express.js | LOW | Debug mode, verbose errors |
| ASP.NET | LOW | ViewState deserialization, verbose errors |
| React | INFO | Exposed source maps |

## Example Output

```
┌─ Summary ──────────────────────────────────────────────────────────────────────
│ Infrastructure: 0 AWS | 0 Azure | 24 Cloudflare | 0 Akamai | 758 Other | 8 CT-only
│ CT Triage: 42 stale (1-2yr) | 128 aged (2yr+) | 3 no date
│ Collapsed: 156 entries → 12 pattern groups (threshold: 5+)
│ Takeover: 2 dangling CNAME(s)
│ Flagged: 47 interesting subdomain(s)
│ httpx: 782/790 alive | 751 2xx 31 4xx | 26 CDN | 782 tech | 7 favicons
│     Servers: nginx(754), cloudflare(24), Microsoft-HTTPAPI(1), ESF(1), GitHub.com(1)
│ Tech: 3 medium (Laravel(2), WordPress(1))
│     blog.target.com  ← WordPress [Body] – CMS – check /wp-admin, /xmlrpc.php
│     app.target.com   ← Laravel [Body] – PHP framework – check /telescope, debug mode
│ Nmap: 12/15 hosts up | 47 open ports | 8 services (124.3s)
│     Services: http(12), ssh(8), https(7), smtp(3), mysql(2)
│     Top ports: 80(12), 443(7), 22(8), 25(3), 3306(2)
│ Enum4linux: 5/15 hosts | 12 shares | 8 users | 3 groups (45.2s)
│     !! 2 host(s) allow null sessions (anonymous access)
│     Shares: ADMIN$, C$, IPC$, Public, Data, Backup
│     Users: Administrator, guest, svc-backup, jsmith
│ CME: 4 protocols | 18 hosts responded (32.1s)
│     Protocols: smb(8), ssh(5), rdp(3), mssql(2)
│     !! 3 host(s) SMB signing disabled (relay targets)
│ Time: 229.5s | Total: 790 unique | TakeoverDB: 11 services | TechDB: 15 signatures
│ Sources: Atlas 191 | Sphinx 40 | Oracle 7 | Radar 50 | Torrent 40 | Venom 85 | ...
└──────────────────────────────────────────────────────────────────────────────────
```

## License

MIT License
