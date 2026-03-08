"""
HTTPX Probe Scanner for ReconX.
Uses ProjectDiscovery's httpx CLI tool for comprehensive HTTP probing.
Auto-installs httpx if not found.

Features:
  - Status code, page title, redirect location
  - Technology detection (Wappalyzer-based via -td)
  - Favicon hash (for service fingerprinting)
  - CDN detection & CDN provider name
  - CPE (Common Platform Enumeration)
  - Web probe (which protocol responded)
  - Extracted FQDNs from response body
  - Server header
  - Content type, content length
  - Response time
  - Body hash (mmh3)

Requires: httpx from ProjectDiscovery installed in PATH
  Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  Or:      https://github.com/projectdiscovery/httpx/releases
"""

import os
import json
import shutil
import subprocess
import tempfile
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field

from ..config import ScannerConfig


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class HttpxResult:
    """Parsed result from a single httpx JSON line."""
    input: str = ""
    url: str = ""
    scheme: str = ""
    host: str = ""
    port: str = ""
    path: str = ""
    status_code: int = 0
    title: str = ""
    location: str = ""
    content_type: str = ""
    content_length: int = 0
    server: str = ""
    technologies: List[str] = field(default_factory=list)
    favicon_hash: str = ""
    cdn: bool = False
    cdn_name: str = ""
    cpe: Dict = field(default_factory=dict)
    webprobe: str = ""
    extracted_fqdns: List[str] = field(default_factory=list)
    body_hash: str = ""
    response_time: str = ""
    method: str = "GET"
    lines: int = 0
    words: int = 0
    tls_grab: Dict = field(default_factory=dict)
    a_records: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    final_url: str = ""
    failed: bool = False
    error: str = ""

    # Raw JSON for any extra fields
    raw: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "input": self.input,
            "url": self.url,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "status_code": self.status_code,
            "title": self.title,
            "location": self.location,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "server": self.server,
            "technologies": self.technologies,
            "favicon_hash": self.favicon_hash,
            "cdn": self.cdn,
            "cdn_name": self.cdn_name,
            "webprobe": self.webprobe,
            "extracted_fqdns": self.extracted_fqdns,
            "body_hash": self.body_hash,
            "response_time": self.response_time,
            "lines": self.lines,
            "words": self.words,
            "a_records": self.a_records,
            "cnames": self.cnames,
            "final_url": self.final_url,
        }
        if self.cpe:
            d["cpe"] = self.cpe
        if self.tls_grab:
            d["tls"] = self.tls_grab
        return d

    @classmethod
    def from_json(cls, data: dict) -> "HttpxResult":
        """Parse a single httpx JSON output line into HttpxResult."""
        r = cls()
        r.raw = data
        r.input = data.get("input", "")
        r.url = data.get("url", "")
        r.scheme = data.get("scheme", "")
        r.host = data.get("host", "")
        r.port = str(data.get("port", ""))
        r.path = data.get("path", "")
        r.status_code = data.get("status_code", data.get("status-code", 0))
        r.title = data.get("title", "")
        r.location = data.get("location", "")
        r.content_type = data.get("content_type", data.get("content-type", ""))
        r.content_length = data.get("content_length", data.get("content-length", 0))
        r.server = data.get("webserver", data.get("server", ""))
        r.method = data.get("method", "GET")

        # Technologies (td flag)
        techs = data.get("tech", data.get("technologies", []))
        r.technologies = techs if isinstance(techs, list) else []

        # Favicon hash
        fav = data.get("favicon", "")
        if isinstance(fav, dict):
            r.favicon_hash = str(fav.get("hash", fav.get("mmh3", "")))
        else:
            r.favicon_hash = str(fav) if fav else ""

        # CDN
        r.cdn = bool(data.get("cdn", False))
        r.cdn_name = data.get("cdn_name", data.get("cdn-name", ""))

        # CPE
        cpe = data.get("cpe", {})
        r.cpe = cpe if isinstance(cpe, dict) else {}

        # Web probe
        r.webprobe = data.get("webprobe", data.get("scheme", ""))

        # Extracted FQDNs
        fqdns = data.get("extracted_fqdn", data.get("extracted-fqdn", []))
        r.extracted_fqdns = fqdns if isinstance(fqdns, list) else []

        # Body hash
        bhash = data.get("body_sha256", data.get("hash", ""))
        if isinstance(bhash, dict):
            r.body_hash = bhash.get("body_sha256", bhash.get("body_md5", ""))
        else:
            r.body_hash = str(bhash) if bhash else ""

        # Response time
        r.response_time = data.get("response_time", data.get("response-time", ""))

        # Lines / words
        r.lines = data.get("lines", data.get("line_count", 0))
        r.words = data.get("words", data.get("word_count", 0))

        # TLS
        tls = data.get("tls-grab", data.get("tls", {}))
        r.tls_grab = tls if isinstance(tls, dict) else {}

        # DNS records
        a_recs = data.get("a", [])
        r.a_records = a_recs if isinstance(a_recs, list) else []
        cname_recs = data.get("cname", data.get("cnames", []))
        r.cnames = cname_recs if isinstance(cname_recs, list) else []

        # Final URL (after redirects)
        r.final_url = data.get("final_url", data.get("final-url", r.url))

        # Failure
        r.failed = bool(data.get("failed", False))
        r.error = data.get("error", "")

        return r


class HttpxProbe:
    """
    HTTP Prober using ProjectDiscovery's httpx.

    Runs httpx CLI against a list of subdomains and collects
    rich metadata including status codes, titles, technologies,
    favicon hashes, CDN detection, etc.
    """

    HTTPX_FLAGS = [
        "-sc",          # status code
        "-title",       # page title
        "-location",    # redirect location
        "-td",          # technology detection (Wappalyzer)
        "-favicon",     # favicon hash
        "-cdn",         # CDN detection + CDN name
        "-server",      # server header
        "-ct",          # content type
        "-cl",          # content length
        "-rt",          # response time
        "-lc",          # line count
        "-wc",          # word count
        "-efqdn",       # extract FQDNs from response
        "-json",        # JSON output (NDJSON)
        "-silent",      # quiet mode
        "-follow-redirects",  # follow HTTP redirects
        "-random-agent",      # randomize User-Agent
    ]

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.httpx_path = self._find_httpx()
        self.available = self.httpx_path is not None
        self.results: Dict[str, HttpxResult] = {}
        self.alive_count = 0
        self.total_probed = 0
        self.new_fqdns: List[str] = []  # FQDNs discovered from response bodies
        self.all_technologies: Dict[str, List[str]] = {}  # subdomain → [techs]

    def _find_httpx(self) -> Optional[str]:
        """Find the ProjectDiscovery httpx binary in PATH or common install locations."""
        candidates = []

        # Check PATH first
        found = shutil.which("httpx")
        if found:
            candidates.append(found)

        # Check common Go / pdtm binary locations (PD paths first)
        common_paths = [
            os.path.expanduser("~/.pdtm/go/bin/httpx"),
            os.path.expanduser("~/go/bin/httpx"),
            os.path.expanduser("~/go/bin/httpx.exe"),
            os.path.expanduser("~/.local/bin/httpx"),
            "/usr/local/bin/httpx",
            "/usr/bin/httpx",
        ]
        # Windows-specific
        if os.name == "nt":
            common_paths.extend([
                os.path.join(os.environ.get("GOPATH", ""), "bin", "httpx.exe"),
                os.path.join(os.environ.get("USERPROFILE", ""), "go", "bin", "httpx.exe"),
            ])

        for path in common_paths:
            if path and os.path.isfile(path) and path not in candidates:
                candidates.append(path)

        # Verify each candidate is ProjectDiscovery's httpx (not Python httpx)
        for path in candidates:
            if self._is_projectdiscovery_httpx(path):
                return path

        # Auto-install httpx if not found
        from .auto_install import ensure_tool
        if ensure_tool("httpx"):
            found = shutil.which("httpx")
            if found and self._is_projectdiscovery_httpx(found):
                return found

        return None

    def _is_projectdiscovery_httpx(self, path: str) -> bool:
        """
        Verify that a httpx binary is the ProjectDiscovery version.
        The Python httpx package also installs a CLI binary, so we need
        to distinguish between the two.
        """
        try:
            proc = subprocess.run(
                [path, "-version"],
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )
            output = (proc.stdout + proc.stderr).lower()
            # ProjectDiscovery httpx shows "Current Version: x.x.x"
            # or "httpx version x.x.x" or contains "projectdiscovery"
            if any(kw in output for kw in [
                "projectdiscovery", "current version",
                "httpx version", "pd-", "nuclei",
            ]):
                return True
            # Python httpx shows "httpx, version X.X.X" (from encode/httpx)
            if "encode" in output or "python" in output:
                return False
            # If it mentions flags like -silent, -json etc., it's PD's httpx
            help_proc = subprocess.run(
                [path, "-h"],
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )
            help_output = (help_proc.stdout + help_proc.stderr).lower()
            if any(kw in help_output for kw in ["-silent", "-tech-detect", "-favicon"]):
                return True
            return False
        except Exception:
            return False

    def probe(self, hostnames: List[str]) -> Dict[str, HttpxResult]:
        """
        Run httpx against a list of hostnames.
        Returns dict mapping hostname → HttpxResult.
        """
        if not self.available:
            return {}

        if not hostnames:
            return {}

        self.total_probed = len(hostnames)

        # Write hostnames to temp file
        tmpdir = tempfile.mkdtemp(prefix="reconx_httpx_")
        input_file = os.path.join(tmpdir, "targets.txt")
        output_file = os.path.join(tmpdir, "results.json")

        try:
            with open(input_file, "w", encoding="utf-8") as f:
                f.write("\n".join(hostnames))

            # Build httpx command
            cmd = [
                self.httpx_path,
                "-l", input_file,
                "-o", output_file,
                "-t", str(min(self.config.concurrency, 100)),  # threads
                "-timeout", str(self.config.timeout),
                "-retries", "1",
                "-rate-limit", "150",   # requests per second cap
            ] + self.HTTPX_FLAGS

            # Run httpx
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(300, len(hostnames) * 2),  # generous timeout
                encoding="utf-8",
                errors="replace",
            )

            # Parse output (NDJSON - one JSON object per line)
            if os.path.isfile(output_file):
                self._parse_results(output_file)
            elif proc.stdout:
                # Some httpx versions write to stdout with -json
                self._parse_results_text(proc.stdout)

        except subprocess.TimeoutExpired:
            # Try to parse whatever was written before timeout
            if os.path.isfile(output_file):
                self._parse_results(output_file)
        except FileNotFoundError:
            self.available = False
        except Exception:
            pass
        finally:
            # Cleanup temp files
            try:
                if os.path.isfile(input_file):
                    os.remove(input_file)
                if os.path.isfile(output_file):
                    os.remove(output_file)
                os.rmdir(tmpdir)
            except Exception:
                pass

        self.alive_count = len(self.results)
        return self.results

    def _parse_results(self, filepath: str):
        """Parse httpx NDJSON output file."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        result = HttpxResult.from_json(data)
                        hostname = result.input or result.host
                        if hostname:
                            hostname = hostname.lower().strip()
                            # Keep the best result (prefer HTTPS, higher status)
                            if hostname not in self.results or result.scheme == "https":
                                self.results[hostname] = result

                            # Collect technologies
                            if result.technologies:
                                self.all_technologies[hostname] = result.technologies

                            # Collect new FQDNs
                            for fqdn in result.extracted_fqdns:
                                if fqdn.lower().strip() not in self.new_fqdns:
                                    self.new_fqdns.append(fqdn.lower().strip())

                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass

    def _parse_results_text(self, text: str):
        """Parse httpx JSON from stdout text."""
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                result = HttpxResult.from_json(data)
                hostname = result.input or result.host
                if hostname:
                    hostname = hostname.lower().strip()
                    if hostname not in self.results or result.scheme == "https":
                        self.results[hostname] = result
                    if result.technologies:
                        self.all_technologies[hostname] = result.technologies
                    for fqdn in result.extracted_fqdns:
                        if fqdn.lower().strip() not in self.new_fqdns:
                            self.new_fqdns.append(fqdn.lower().strip())
            except (json.JSONDecodeError, Exception):
                continue

    def enrich_subdomains(self, subdomains: list) -> Tuple[int, int, List[str]]:
        """
        Enrich Subdomain objects with httpx probe data.
        
        Returns (alive_count, new_fqdn_count, new_fqdns_found).
        """
        alive = 0
        for sub in subdomains:
            hostname = sub.hostname.lower().strip()
            if hostname in self.results:
                r = self.results[hostname]
                sub.is_alive = True
                sub.http_status = r.status_code
                sub.http_title = getattr(sub, "http_title", "") or r.title
                sub.http_server = getattr(sub, "http_server", "") or r.server
                sub.http_content_type = getattr(sub, "http_content_type", "") or r.content_type
                sub.http_url = r.url
                sub.http_scheme = r.scheme
                sub.http_location = r.location
                sub.http_favicon_hash = r.favicon_hash
                sub.http_technologies = r.technologies
                sub.http_cdn = r.cdn
                sub.http_cdn_name = r.cdn_name
                sub.http_body_hash = r.body_hash
                sub.http_response_time = r.response_time
                sub.http_content_length = r.content_length
                sub.http_lines = r.lines
                sub.http_words = r.words
                sub.http_final_url = r.final_url
                sub.http_cpe = r.cpe
                sub.http_tls = r.tls_grab

                # Merge technologies into the existing list
                for tech in r.technologies:
                    if tech not in sub.technologies:
                        sub.technologies.append(tech)

                alive += 1

        self.alive_count = alive
        return alive, len(self.new_fqdns), self.new_fqdns

    def get_stats(self) -> dict:
        """Get probe statistics."""
        status_dist = {}
        status_codes = {}   # individual status codes: {200: 30, 301: 4, ...}
        cdn_count = 0
        tech_count = 0
        server_dist = {}
        favicon_hashes = {}

        for hostname, r in self.results.items():
            # Status code distribution
            sc = r.status_code
            sc_range = f"{sc // 100}xx"
            status_dist[sc_range] = status_dist.get(sc_range, 0) + 1
            if sc:
                status_codes[sc] = status_codes.get(sc, 0) + 1

            # CDN
            if r.cdn:
                cdn_count += 1

            # Technologies
            if r.technologies:
                tech_count += 1

            # Server header
            if r.server:
                srv = r.server.split("/")[0].strip()
                server_dist[srv] = server_dist.get(srv, 0) + 1

            # Favicon hashes (for identifying known services)
            if r.favicon_hash and r.favicon_hash != "0":
                favicon_hashes[r.favicon_hash] = favicon_hashes.get(r.favicon_hash, 0) + 1

        return {
            "total_probed": self.total_probed,
            "alive": self.alive_count,
            "status_distribution": status_dist,
            "status_codes": status_codes,
            "cdn_detected": cdn_count,
            "tech_detected": tech_count,
            "server_distribution": server_dist,
            "unique_favicon_hashes": len(favicon_hashes),
            "new_fqdns_discovered": len(self.new_fqdns),
        }


# ─── Favicon Fingerprint Database ────────────────────────────────────────────
# Known favicon hashes for identifying specific services/products.
# Format: mmh3_hash → service_name

KNOWN_FAVICONS = {
    "116323821": "Spring Boot",
    "-297069493": "Jenkins",
    "81586820": "Grafana",
    "-1293039886": "GitLab",
    "-162429179": "Fortinet VPN",
    "-305179312": "Atlassian Jira",
    "538414708": "Confluence",
    "-1395014541": "Kibana",
    "-1368015753": "SonarQube",
    "-1737044845": "phpMyAdmin",
    "88733723": "RabbitMQ",
    "247100307": "Apache Tomcat",
    "-266008933": "Harbor",
    "1485257654": "Kubernetes Dashboard",
    "-335242539": "Prometheus",
    "-978627938": "Netdata",
    "1060632504": "Portainer",
    "1369405752": "Traefik",
    "-74973177": "Weblogic",
    "681395560": "Zabbix",
    "-1322419031": "Bitbucket",
    "-1016466899": "Nexus Repository",
    "2047368528": "ArgoCD",
    "552737561": "MinIO",
    "-1190899346": "pgAdmin",
    "803527991": "Airflow",
    "-674048714": "Superset",
    "478779807": "Rancher",
    "773779547": "Vault",
    "-1556749020": "AWX/Tower",
    "1820793827": "Graylog",
}


def identify_favicon(hash_value: str) -> Optional[str]:
    """Identify a service by its favicon hash."""
    return KNOWN_FAVICONS.get(str(hash_value))
