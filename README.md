# ReconX

**Automated Reconnaissance & Intelligence Gathering Tool**

Multi-source subdomain enumeration, HTTP probing, port scanning, vulnerability scanning, brute-force attacks, and protocol-level network intelligence — all in one command.

Built for **Kali Linux**. One target in, full recon out.

## What is ReconX?

ReconX is an **automation tool for reconnaissance and enumeration** used in **pentesting** and **security assessments**. It acts as a central orchestrator that combines multiple security tools into a single workflow, so users do not need to run each tool manually one by one.

In practice, ReconX helps collect target intelligence such as subdomains, live web services, open ports, running technologies, potential vulnerabilities, SMB/Windows exposure, and weak or default credentials across multiple protocols.

Its main goal is to make the recon phase faster, more consistent, and easier to repeat for domain targets, single IPs, CIDR ranges, or target lists.

---

## Tools Used

ReconX mengintegrasikan **13 external tools** ke dalam satu alur kerja otomatis:

| # | Tool | Fungsi di ReconX | Modul / Protokol |
|---|------|-----------------|------------------|
| 1 | **Nmap** | Port scanning & service/version detection | TCP top-1000, `-sCV`, custom `--script` |
| 2 | **Naabu** | Fast port discovery (optional pre-scan) | `-rate 3000 -c 50 -top-ports 1000` |
| 3 | **httpx** | HTTP probing — status code, title, tech, CDN, favicon | ProjectDiscovery |
| 4 | **Nuclei** | Template-based vulnerability scanning | Severity: critical, high, medium, low |
| 5 | **Katana** | Web crawling — endpoint & parameter discovery | ProjectDiscovery |
| 6 | **Feroxbuster** | Directory & file brute-forcing | Wordlist-based |
| 7 | **WPScan** | WordPress vulnerability scanner | Theme, plugin, user enum + WPVulnDB API |
| 8 | **enum4linux** | SMB/Windows enumeration | Shares, users, groups, null sessions, OS info |
| 9 | **NetExec** (CrackMapExec) | Multi-protocol enumeration | SMB, SSH, RDP, MSSQL, WinRM — signing, guest, NULL |
| 10 | **smbclient** | SMB share listing | Anonymous access verification |
| 11 | **Metasploit** (`msfconsole`) | Login brute-force & enumeration | SMB login, SSH login, FTP login, PostgreSQL login, MongoDB login, SNMP login, SNMP enum |
| 12 | **Crowbar** | RDP & VNC brute-force | Common/default credential testing |
| 13 | **Hydra** | SMB brute-force | Fast network login cracker |

### Metasploit Modules Detail

| Auxiliary Module | Target Service | Deskripsi |
|-----------------|----------------|-----------|
| `auxiliary/scanner/smb/smb_login` | SMB (445) | Blank/anonymous credential testing |
| `auxiliary/scanner/ssh/ssh_login` | SSH (22) | Common credential brute-force |
| `auxiliary/scanner/ftp/anonymous` | FTP (21) | Anonymous FTP access check |
| `auxiliary/scanner/ftp/ftp_login` | FTP (21) | FTP credential brute-force |
| `auxiliary/scanner/postgres/postgres_login` | PostgreSQL (5432) | Anonymous/blank password testing |
| `auxiliary/scanner/mongodb/mongodb_login` | MongoDB (27017) | Default credential testing |
| `auxiliary/scanner/snmp/snmp_login` | SNMP (161) | Community string brute-force |
| `auxiliary/scanner/snmp/snmp_enum` | SNMP (161) | SNMP information enumeration |

### Data Sources (Subdomain Enumeration)

| # | Source | Tipe | API Key |
|---|--------|------|---------|
| 1 | **crt.sh** | Certificate Transparency | — |
| 2 | **Certspotter** | Certificate Transparency | — |
| 3 | **AlienVault OTX** | Passive DNS | — |
| 4 | **HackerTarget** | Host search | — |
| 5 | **Wayback Machine** | CDX index | — |
| 6 | **VirusTotal** | Subdomain API | Optional |
| 7 | **Anubis** | Subdomain DB | — |
| 8 | **ThreatMiner** | Threat intel | — |
| 9 | **RapidDNS** | DNS database | — |
| 10 | **Shodan** | DNS + SSL cert | Optional |
| 11 | **Censys** | Certificate + host search | Optional |
| 12 | **SecurityTrails** | Subdomain enum | Optional |
| 13 | **URLScan.io** | Web intelligence | Optional |
| 14 | **Chaos** | ProjectDiscovery dataset | Optional |
| 15 | **CommonCrawl** | Web crawl index | — |
| 16 | **FOFA** | Cyberspace search | Optional |
| 17 | **ZoomEye** | Cyberspace search | Optional |
| 18 | **ASN Expansion** | ASN-based IP range | — |

---

## Features

### Reconnaissance & Enumeration

| Module | Description |
|--------|-------------|
| **Subdomain Enumeration** | 16 concurrent sources (crt.sh, Certspotter, AlienVault OTX, HackerTarget, Wayback, VirusTotal, Anubis, ThreatMiner, RapidDNS, Shodan, Censys, SecurityTrails, URLScan, Chaos, CommonCrawl, FOFA, ZoomEye, ASN Expansion) |
| **CT Log Triage** | Certificate Transparency age classification: stale (1-2yr), aged (2yr+), fresh |
| **Infrastructure** | Cloud provider detection (AWS, Azure, Cloudflare, Akamai, GCP, etc.) via DNS + IP CIDR |
| **HTTPX Probe** | ProjectDiscovery httpx — status codes, titles, technologies, CDN, favicons, redirects, server headers |
| **Tech Profiling** | 15+ technology signatures with severity-tagged findings (Spring Boot, Jenkins, WordPress, etc.) |
| **Subdomain Takeover** | 11+ cloud provider takeover detection via CNAME + HTTP fingerprinting |
| **Pattern Collapse** | Wildcard grouping for repetitive subdomains (e.g. `*.cdn.target.com`) |

### Scanning & Vulnerability Detection

| Module | Tool | Description |
|--------|------|-------------|
| **Port Scan** | Nmap | `-sCV --top-ports 1000` with service/version detection, custom `--script` support |
| **Fast Port Discovery** | Naabu | Optional pre-scan (`--naabu`) — discovers open ports first, then nmap only scans hosts with open ports |
| **Vuln Scan** | Nuclei | Template-based vulnerability scanning (critical/high/medium/low severity) |
| **Web Crawl** | Katana | ProjectDiscovery web crawler — endpoint & parameter discovery |
| **Dir Brute** | Feroxbuster | Directory/file brute-forcing with wordlists |
| **WordPress** | WPScan | Theme, plugin, user enumeration + API-powered vulnerability detection |

### SMB & Windows

| Module | Tool | Description |
|--------|------|-------------|
| **SMB Enum** | enum4linux | Shares, users, groups, null sessions, OS info |
| **Protocol Intel** | NetExec (CME) | SMB signing, guest login, NULL sessions, MSSQL, SSH, RDP, WinRM |
| **SMB Client** | smbclient | Native share listing & anonymous access verification |
| **SMB Brute** | Hydra | SMB brute-force with common credentials |
| **MSF SMB Brute** | Metasploit | `smb_login` — blank/anonymous credential testing |

### Login Brute-Force

| Module | Tool | Description |
|--------|------|-------------|
| **RDP Brute** | Crowbar | RDP brute-force with common credentials |
| **VNC Brute** | Crowbar | VNC brute-force with default passwords |
| **SSH Login** | Metasploit | `ssh_login` — common credential testing |
| **FTP Login** | Metasploit | `ftp_login` — anonymous + common credential testing |
| **PostgreSQL Login** | Metasploit | `postgres_login` — anonymous/blank password testing |
| **MongoDB Login** | Metasploit | `mongodb_login` — default credential testing |
| **SNMP Login** | Metasploit | `snmp_login` — community string brute-force |
| **SNMP Enum** | Metasploit | `snmp_enum` — SNMP information enumeration |

### Output & Reporting

| Feature | Description |
|---------|-------------|
| **JSON Export** | Full structured scan results |
| **File Export** | Per-domain folder with 30+ categorized text files |
| **Terminal UI** | ANSI box-drawn summary with color-coded severity |
| **Multi-target** | Domain, single IP, CIDR range, file of targets, or comma-separated files |

---

## Quick Start

### Prerequisites

- **Kali Linux** (VM, bare-metal, or WSL)
- Python 3.10+
- External tools (auto-installed if missing):
  `nmap` `naabu` `httpx` `nuclei` `katana` `feroxbuster` `enum4linux` `crackmapexec`/`netexec` `msfconsole` `crowbar` `hydra` `wpscan` `smbclient`

### Install

```bash
git clone https://github.com/youruser/reconx.git
cd reconx
pip install -r requirements.txt

# Optional: API keys for premium sources
cp .env.example .env
# Edit .env → add keys for Shodan, Censys, SecurityTrails, WPScan, FOFA, ZoomEye, etc.
```

### Run

```bash
# Domain → full recon pipeline (subdomain enum → httpx → nmap → vuln scan → brute)
python main.py target.com

# Single IP → direct scan (nmap + nuclei + brute-force, skips enumeration)
python main.py 10.10.0.5

# CIDR range → direct scan on all hosts
python main.py 10.10.0.0/24

# Target file → reads IPs/domains from file (one per line)
python main.py targets.txt

# Multiple files (comma-separated)
python main.py 'a.txt,"file 2.txt",c.txt'

# Skip host discovery (for hosts that block ICMP)
python main.py 10.10.0.5 --Pn

# Use naabu for fast port discovery before nmap (great for large IP sets)
python main.py targets.txt --naabu

# Combine naabu with nmap options
python main.py 10.10.0.0/24 --naabu --Pn --script=vuln

# Run nmap with NSE vuln scripts
python main.py 10.10.0.5 --script=vuln

# Custom output + high concurrency
python main.py target.com -o results.json -c 100 -t 15
```

---

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `target` | Target: domain, IP, CIDR range, or file of targets | *required* |
| `-o, --output` | Output JSON filename | `<domain>/<domain>.json` |
| `--Pn` | Nmap: skip host discovery (treat all hosts as online) | `false` |
| `--naabu` | Use naabu for fast port discovery before nmap service detection | `false` |
| `--script <name>` | Nmap: run NSE script (e.g. `--script=vuln`) | — |
| `--no-redact` | Show full subdomain names (don't redact) | `false` |
| `-v, --verbose` | Verbose output | `false` |
| `-c, --concurrency` | Max concurrent workers | `50` |
| `-t, --timeout` | Per-request timeout (seconds) | `10` |
| `--no-banner` | Skip ASCII banner | `false` |
| `--collapse-threshold` | Min entries to collapse into pattern group | `5` |

---

## Architecture

```
reconx/
├── main.py                        # CLI entry point & argument parser
├── config.py                      # Configuration, .env loader, source definitions
├── models.py                      # Data models (Subdomain, TechMatch, CTEntry, ScanResult, etc.)
├── utils.py                       # DNS resolution, IP classification, pattern matching, input detection
├── engine.py                      # Multi-phase pipeline orchestrator + direct-target mode
├── requirements.txt               # Python dependencies
├── .env                           # API keys (git-ignored)
├── .env.example                   # API key template
│
├── sources/                       # 16 data source modules
│   ├── base.py                    # Abstract base class
│   ├── atlas.py                   # Crt.sh Certificate Transparency
│   ├── sphinx.py                  # Certspotter CT logs
│   ├── oracle.py                  # AlienVault OTX passive DNS
│   ├── radar.py                   # HackerTarget hostsearch
│   ├── torrent.py                 # Wayback Machine CDX index
│   ├── venom.py                   # VT + Anubis + ThreatMiner + RapidDNS
│   ├── vt_siblings.py             # VirusTotal v3 subdomains API
│   ├── shodan_source.py           # Shodan DNS + SSL cert search
│   ├── censys_source.py           # Censys certificate + host search
│   ├── sectrails_source.py        # SecurityTrails subdomain enumeration
│   ├── urlscan_source.py          # URLScan.io web intelligence
│   ├── chaos_source.py            # ProjectDiscovery Chaos dataset
│   ├── commoncrawl_source.py      # CommonCrawl index search
│   ├── fofa_source.py             # FOFA cyberspace search
│   ├── zoomeye_source.py          # ZoomEye cyberspace search
│   └── asn_source.py              # ASN-based IP range expansion
│
├── scanner/                       # 26 scanner modules
│   ├── infrastructure.py          # Cloud provider classification (DNS + IP ranges)
│   ├── ct_logs.py                 # CT log triage (stale/aged/fresh)
│   ├── takeover.py                # Subdomain takeover detection (11+ providers)
│   ├── tech_profiler.py           # Technology stack profiling (15+ signatures)
│   ├── httpx_probe.py             # ProjectDiscovery httpx CLI wrapper
│   ├── nmap_scan.py               # Nmap port & service scanner (+ custom --script)
│   ├── naabu_scan.py              # Naabu fast port scanner (pre-scan for nmap)
│   ├── nuclei_scan.py             # ProjectDiscovery Nuclei vuln scanner
│   ├── katana_scan.py             # ProjectDiscovery Katana web crawler
│   ├── feroxbuster_scan.py        # Feroxbuster directory brute-forcer
│   ├── wpscan.py                  # WPScan WordPress scanner
│   ├── enum4linux_scan.py         # Enum4linux SMB/Windows enumeration
│   ├── cme_scan.py                # NetExec/CrackMapExec protocol enumeration
│   ├── smbclient_scan.py          # smbclient share listing
│   ├── smb_brute.py               # Hydra SMB brute-force
│   ├── msf_smb_brute.py           # Metasploit smb_login brute-force
│   ├── rdp_brute.py               # Crowbar RDP brute-force
│   ├── vnc_brute.py               # Crowbar VNC brute-force
│   ├── ssh_login.py               # Metasploit ssh_login brute-force
│   ├── ftp_login.py               # Metasploit ftp_login brute-force
│   ├── postgres_login.py          # Metasploit postgres_login brute-force
│   ├── mongodb_login.py           # Metasploit mongodb_login brute-force
│   ├── snmp_login.py              # Metasploit snmp_login community brute-force
│   └── snmp_enum.py               # Metasploit snmp_enum information gathering
│
├── output/                        # Output rendering
│   ├── terminal.py                # ANSI terminal renderer (box-drawn)
│   ├── json_export.py             # Structured JSON export
│   └── file_export.py             # Per-domain file exporter (30+ files)
│
└── wordlists/                     # Built-in credential wordlists
    ├── enum-pass.txt              # Common passwords
    ├── ftp-user-enum.txt          # FTP usernames
    ├── mongodb-userpass-enum.txt  # MongoDB credentials
    └── ssh-user-enum.txt          # SSH usernames
```

---

## Pipeline Phases

### Domain Mode

When the input is a domain name, the engine runs a multi-phase pipeline:

| Phase | Name | Description |
|-------|------|-------------|
| 1 | **Sources** | Concurrent subdomain enumeration from 16 sources |
| 2 | **Dedup** | Normalize, deduplicate, and aggregate all discovered subdomains |
| 3 | **CT Logs** | Certificate Transparency entries + age triage |
| 4 | **Infrastructure** | DNS CNAME/A resolution → cloud provider classification |
| 5 | **HTTPX Probe** | HTTP probing (status, title, tech, CDN, favicon, redirect) |
| 5b | **Infra Reconcile** | Update infrastructure stats from httpx CDN/server data |
| 6 | **Collapse** | Group repetitive subdomains into wildcard patterns |
| 7 | **Takeover** | Subdomain takeover detection (11+ cloud providers) |
| 8 | **Tech Profile** | Technology stack detection on alive subdomains (15+ signatures) |
| 9 | **Nmap** | Port & service scanning (`-sCV --top-ports 1000`, optional `--script`) |
| 9a | **Naabu** | Optional fast port discovery pre-scan (with `--naabu` flag) |
| 10 | **Post-Nmap** | Enum4linux, CME, SMBClient, Nuclei, Katana, Feroxbuster, WPScan |
| 11 | **Brute-Force** | MSF SMB, RDP, VNC, SMB, SSH, FTP, PostgreSQL, MongoDB, SNMP brute-force |
| 12 | **Statistics** | Compute final stats (timing, counts, DB stats) |
| 13 | **Output** | Terminal rendering + JSON export + per-domain file export |

### Direct Mode (IP / CIDR / File)

When the input is an IP address, CIDR range, or file of IPs, subdomain enumeration is **skipped**:

| Phase | Name | Description |
|-------|------|-------------|
| 1 | **Nmap** | Port & service scanning on all target IPs |
| 2 | **Post-Nmap** | Enum4linux, CME, SMBClient, Nuclei, Katana, Feroxbuster, WPScan |
| 3 | **Brute-Force** | All login brute-force modules based on discovered open ports |
| 4 | **Output** | Terminal rendering + JSON export + per-target file export |

---

## Output Structure

Each scan creates a domain/target folder with categorized output files:

```
<target>/
├── <target>.json                # Full scan results (JSON)
├── scan_summary.json            # Metadata + summary
│
├── all_subdomains.txt           # All unique subdomains (domain mode)
├── alive_subdomains.txt         # HTTP-alive subdomains only
├── ip_addresses.txt             # All discovered IPs
├── ip_subdomain_map.txt         # IP → subdomain mapping
│
├── takeover_vulnerable.txt      # Subdomain takeover vulns
├── dangling_cnames.txt          # Dangling CNAME records
├── tech_detected.txt            # Tech detections by severity
├── flagged_interesting.txt      # Interesting/flagged subdomains
├── ct_aged.txt                  # Aged CT entries (2yr+)
├── ct_stale.txt                 # Stale CT entries (1-2yr)
├── collapsed_patterns.txt       # Collapsed pattern groups
├── infrastructure.txt           # Cloud provider classification
├── sources_stats.txt            # Per-source statistics
│
├── httpx_probe.txt              # Full httpx results per host
├── httpx_technologies.txt       # Wappalyzer tech detection
├── httpx_cdn.txt                # CDN-backed subdomains
├── httpx_favicon.txt            # Favicon hash mapping
├── httpx_servers.txt            # Server header distribution
├── httpx_titles.txt             # HTTP page titles
├── httpx_redirects.txt          # Redirect chains
│
├── nmap_scan.txt                # Nmap scan output
├── nmap_summary.txt             # Nmap human-readable summary
├── nmap_summary.json            # Nmap structured JSON results
│
├── nuclei_scan.txt              # Nuclei vulnerability findings
├── katana_results.txt           # Katana crawl results
├── feroxbuster_results.txt      # Feroxbuster findings
├── wpscan_results.txt           # WPScan WordPress findings
│
├── enum4linux_summary.txt       # Enum4linux summary
├── enum4linux_<ip>.txt          # Raw per-host enum4linux output
├── cme_summary.txt              # CME/NetExec summary
├── smbclient_results.txt        # SMBClient share listing
│
├── rdp_brute_results.txt        # RDP brute-force results
├── vnc_brute_results.txt        # VNC brute-force results
├── smb_brute_results.txt        # SMB brute-force results
├── msf_smb_brute_results.txt    # MSF SMB brute-force results
├── ssh_login_results.txt        # SSH login results
├── ftp_login_results.txt        # FTP login results
├── postgres_login_results.txt   # PostgreSQL login results
├── mongodb_login_results.txt    # MongoDB login results
├── snmp_login_results.txt       # SNMP login results
└── snmp_enum_results.txt        # SNMP enumeration results
```

---

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

---

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

---

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
│ Nuclei: 9 findings | 2 critical | 3 high | 4 medium (87.2s)
│ Enum4linux: 5/15 hosts | 12 shares | 8 users | 3 groups (45.2s)
│     !! 2 host(s) allow null sessions (anonymous access)
│ CME: 4 protocols | 18 hosts responded (32.1s)
│     Protocols: smb(8), ssh(5), rdp(3), mssql(2)
│     !! 3 host(s) SMB signing disabled (relay targets)
│ RDP Brute: 1/3 cracked | VNC Brute: 0/2 | SMB Brute: 2/8
│ SSH Login: 1/5 cracked | FTP Login: 3/4 anon | PostgreSQL: 1/2 anon
│ SNMP: 4/6 default community | MongoDB: 0/1
│ Time: 429.5s | Total: 790 unique | TakeoverDB: 11 services | TechDB: 15 signatures
│ Sources: Crt.sh 191 | Sphinx 40 | Oracle 7 | Radar 50 | Torrent 40 | Venom 85 | ...
└──────────────────────────────────────────────────────────────────────────────────
```

---

## License

MIT License
