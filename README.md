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

A high-performance CLI reconnaissance tool that aggregates subdomain data from **12 sources**, performs **recursive subdomain enumeration** via VirusTotal domain_siblings, HTTP probing via [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx), runs automated vulnerability scanning with [ProjectDiscovery nuclei](https://github.com/projectdiscovery/nuclei), classifies cloud infrastructure, detects subdomain takeover vulnerabilities, and profiles technology stacks — all presented in a rich, color-coded terminal output with per-domain file exports.

## Features

| Category | Details |
|----------|---------|
| **Multi-Source Enumeration** | 12 data sources — Atlas (crt.sh), Sphinx (Certspotter), Oracle (AlienVault OTX), Radar (HackerTarget), Torrent (Wayback Machine), Venom (VT + ThreatMiner + Anubis + RapidDNS), VirusTotal (VT domain siblings), Sonar (DNS brute-force), Shodan, Censys, SecurityTrails, URLScan.io |
| **Recursive Enumeration** | VirusTotal v2 domain_siblings recursive discovery — queries each discovered subdomain to find sibling domains, expanding coverage beyond initial enumeration |
| **HTTPX HTTP Probing** | ProjectDiscovery httpx integration — status codes, titles, technologies (Wappalyzer), favicon hashes, CDN detection, server headers, FQDNs from response bodies |
| **Nuclei Vulnerability Scanning** | ProjectDiscovery nuclei integration — automated vuln scanning with dynamic tag selection based on detected tech stack (WordPress → `wordpress,wp-plugin`, Laravel → `laravel`, Spring → `spring,springboot`, etc.) |
| **Nmap Port Scanning** | Nmap integration — `-sCV --top-ports 1000 -T3` service/version detection on all discovered IP addresses with `.nmap`, `.xml`, `.gnmap` output |
| **Infrastructure Classification** | Cloudflare, AWS, Azure, Akamai detection via CNAME patterns, IP ranges, and httpx CDN/server data |
| **Certificate Transparency** | CT log triage with age classification — stale (1–2yr), aged (2yr+), no date |
| **Subdomain Takeover** | 11+ provider fingerprints (Azure, AWS S3, GitHub Pages, Heroku, Shopify, Fastly, etc.) |
| **Tech Stack Profiling** | 15+ technology signatures — Spring Boot Actuator, Tomcat, Jenkins, Grafana, WordPress, Laravel, Django, etc. with CRITICAL/High/Medium/Low/Info severity |
| **Pattern Collapse** | Groups repetitive subdomains into wildcard patterns (e.g., `app-*.example.com`) |
| **Concurrent Execution** | ThreadPoolExecutor with configurable worker count (default: 50) |
| **Structured Export** | JSON export + 25+ per-domain output files (alive hosts, IPs, tech, takeover, httpx data, nuclei findings, etc.) |
| **Rich Terminal Output** | ANSI-colored box-drawn summary matching professional security tooling |

## Quick Start

### Prerequisites

- Python 3.8+
- [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx) (recommended, for HTTP probing)
- [ProjectDiscovery nuclei](https://github.com/projectdiscovery/nuclei) (recommended, for vulnerability scanning)

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

# (Recommended) Install ProjectDiscovery nuclei
# Option A: Go install
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Option B: Download binary
# https://github.com/projectdiscovery/nuclei/releases
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
# Real scan
python main.py target.com

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
| `domain` | Target domain to scan | Required |
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
├── nuclei_findings.txt        # All nuclei vulnerability findings
├── nuclei_critical.txt        # Critical severity findings only
├── nuclei_high.txt            # High severity findings only
└── nuclei_summary.json        # Nuclei scan statistics + findings
├── nmap_scan.nmap             # Nmap normal output
├── nmap_scan.xml              # Nmap XML output
├── nmap_scan.gnmap            # Nmap greppable output
├── nmap_summary.txt           # Nmap human-readable summary
└── nmap_summary.json          # Nmap structured JSON results
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
    ├── utils.py                 # DNS resolution, IP classification, pattern matching
    ├── engine.py                # 12-phase pipeline orchestrator
    ├── sources/                 # 12 data source modules
    │   ├── base.py              # Abstract base class
    │   ├── atlas.py             # crt.sh Certificate Transparency
    │   ├── sphinx.py            # Certspotter CT logs
    │   ├── oracle.py            # AlienVault OTX passive DNS
    │   ├── radar.py             # HackerTarget hostsearch
    │   ├── torrent.py           # Wayback Machine CDX index
    │   ├── venom.py             # VT + Anubis + ThreatMiner + RapidDNS
    │   ├── vt_siblings.py       # VT v2 domain_siblings (recursive)
    │   ├── sonar.py             # DNS brute-force (wordlist)
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
    │   ├── nuclei_scan.py       # ProjectDiscovery nuclei CLI wrapper (dynamic tags)
    │   └── nmap_scan.py         # Nmap port & service scanner wrapper
    └── output/                  # Output rendering
        ├── terminal.py          # ANSI terminal renderer (box-drawn)
        ├── json_export.py       # Structured JSON export
        └── file_export.py       # Per-domain file exporter (25+ files)
```

## Pipeline Phases

The engine executes a 12-phase pipeline:

| Phase | Name | Description |
|-------|------|-------------|
| 1 | **Sources** | Concurrent subdomain enumeration from all 12 sources |
| 2 | **Dedup** | Normalize, deduplicate, and aggregate all discovered subdomains |
| 2b | **Recursive** | VT domain_siblings recursive enumeration on all discovered subdomains |
| 3 | **CT Logs** | Query crt.sh for certificate transparency entries + age triage |
| 4 | **Infrastructure** | DNS CNAME/A resolution → cloud provider classification |
| 5 | **HTTPX Probe** | HTTP probing via ProjectDiscovery httpx (status, title, tech, CDN, favicon) |
| 5b | **Infra Reconcile** | Update infrastructure stats from httpx CDN/server data |
| 6 | **Collapse** | Group repetitive subdomains into wildcard patterns |
| 7 | **Takeover** | Check for subdomain takeover vulnerabilities (11+ providers) |
| 8 | **Tech Profile** | Technology stack detection on alive subdomains (15+ signatures) |
| 9 | **Nuclei** | Automated vulnerability scanning with dynamic tags based on detected tech |
| 9b | **Nmap** | Port & service scanning on all discovered IP addresses (-sCV --top-ports 1000) |
| 10 | **Statistics** | Compute final stats (timing, counts, DB stats) |
| 11 | **Output** | Terminal rendering + JSON export + per-domain file export |

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

## Nuclei Vulnerability Scanning

ReconX integrates [ProjectDiscovery nuclei](https://github.com/projectdiscovery/nuclei) for automated vulnerability scanning after subdomain discovery and tech profiling.

### Dynamic Tag Selection

Nuclei tags are **dynamically selected** based on technologies detected by httpx (Wappalyzer) and the built-in tech profiler. This ensures relevant templates are used without wasting time on irrelevant checks.

**Base tags** (always included):
```
vuln, cve, discovery, vkev, panel, xss
```

**Conditional tags** (added when tech is detected):

| Detected Technology | Extra Nuclei Tags |
|---|---|
| WordPress / wp-content / wp-includes | `wordpress`, `wp-plugin` |
| Laravel | `laravel` |
| Spring Boot / Spring Boot Actuator | `spring`, `springboot` |
| Apache Tomcat | `tomcat`, `apache` |
| Jenkins | `jenkins` |
| Grafana | `grafana` |
| Django | `django` |
| Jira | `jira`, `atlassian` |
| Confluence | `confluence`, `atlassian` |
| GitLab | `gitlab` |
| Nginx | `nginx` |
| Drupal | `drupal` |
| Magento | `magento` |
| phpMyAdmin | `phpmyadmin` |
| IIS / ASP.NET | `iis` |
| WebLogic | `weblogic`, `oracle` |
| Zimbra | `zimbra` |

### Example

If httpx detects WordPress and Nginx technologies on alive subdomains:
```
Tags: vuln, cve, discovery, vkev, panel, xss, wordpress, wp-plugin, nginx
```

If no specific tech is detected, only base tags are used — keeping scan time efficient.

### Nuclei Output Files

| File | Contents |
|------|----------|
| `nuclei_findings.txt` | All findings sorted by severity |
| `nuclei_critical.txt` | Critical severity findings with details + curl commands |
| `nuclei_high.txt` | High severity findings with details + references |
| `nuclei_summary.json` | Full stats + all findings in structured JSON |

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
│ Nuclei: 14 findings (3 high | 8 medium | 3 info) (87.2s)
│     Tech tags: wordpress, wp-plugin, laravel, nginx
│     [HIGH] WordPress XML-RPC Enabled → blog.target.com
│     [HIGH] Laravel Debug Mode → app.target.com
│     [MEDIUM] WordPress User Enumeration → blog.target.com
│     ... and 11 more finding(s)
│ Time: 229.5s | Total: 790 unique | TakeoverDB: 11 services | TechDB: 15 signatures
│ Sources: Atlas 191 | Sphinx 40 | Oracle 7 | Radar 50 | Torrent 40 | Venom 85 | ...
└──────────────────────────────────────────────────────────────────────────────────
```

## License

MIT License
