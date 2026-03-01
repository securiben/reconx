"""
Configuration module for ReconX.
Holds API keys, timeouts, thresholds, and source configurations.
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


def _load_dotenv():
    """Load .env file from project root if it exists."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip()
                    if value and key:
                        os.environ.setdefault(key, value)


# Load .env on import
_load_dotenv()


@dataclass
class SourceConfig:
    """Configuration for a single data source."""
    name: str
    enabled: bool = True
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    description: str = ""
    timeout: int = 60
    max_retries: int = 3
    rate_limit: float = 1.0  # requests per second


@dataclass
class ScannerConfig:
    """Configuration for scanner modules."""
    # Subdomain takeover
    takeover_fingerprints_path: str = "fingerprints.json"
    takeover_providers: List[str] = field(default_factory=lambda: [
        "Microsoft Azure", "AWS S3", "GitHub Pages", "Heroku",
        "Shopify", "Fastly", "Pantheon", "Tumblr", "WordPress.com",
        "Ghost", "Surge.sh", "Bitbucket", "Ghost",
    ])

    # Tech profiling
    tech_signatures_path: str = "signatures.json"
    sensitive_endpoints: List[str] = field(default_factory=lambda: [
        "/env", "/heapdump", "/mappings", "/actuator",
        "/actuator/env", "/actuator/health", "/actuator/info",
        "/manager", "/host-manager", "/status",
        "/wp-admin", "/wp-login.php",
    ])

    # Infrastructure
    ct_log_servers: List[str] = field(default_factory=lambda: [
        "https://crt.sh",
        "https://transparencyreport.google.com",
    ])

    # Thresholds
    collapse_threshold: int = 5
    stale_days: int = 365       # 1 year
    aged_days: int = 730        # 2 years
    concurrency: int = 50       # max concurrent workers
    timeout: int = 10           # per-request timeout in seconds


@dataclass
class ReconConfig:
    """Master configuration for the tool."""
    target_domain: str = ""
    output_file: Optional[str] = None
    output_format: str = "json"
    verbose: bool = False
    demo_mode: bool = False  # Use simulated data for demo

    # Source configs - Real free APIs, no keys required (except optional VirusTotal)
    sources: Dict[str, SourceConfig] = field(default_factory=lambda: {
        "atlas": SourceConfig(
            name="Atlas",
            description="querying crt.sh certificate transparency",
        ),
        "sphinx": SourceConfig(
            name="Sphinx",
            description="querying Certspotter CT logs",
            api_key=os.getenv("CERTSPOTTER_API_KEY"),
        ),
        "oracle": SourceConfig(
            name="Oracle",
            description="querying AlienVault OTX passive DNS",
            api_key=os.getenv("OTX_API_KEY"),
        ),
        "radar": SourceConfig(
            name="Radar",
            description="querying HackerTarget hostsearch",
        ),
        "torrent": SourceConfig(
            name="Torrent",
            description="querying RapidDNS passive DNS",
        ),
        "venom": SourceConfig(
            name="Venom",
            description="querying VirusTotal passive DNS",
            api_key=os.getenv("VT_API_KEY"),
        ),
        "sonar": SourceConfig(
            name="Sonar",
            description="DNS brute-force via wordlist",
        ),
        "shodan": SourceConfig(
            name="Shodan",
            description="querying Shodan internet scanning",
            api_key=os.getenv("SHODAN_API_KEY"),
        ),
        "censys": SourceConfig(
            name="Censys",
            description="querying Censys certificate search",
            api_key=os.getenv("CENSYS_API_KEY"),
        ),
        "sectrails": SourceConfig(
            name="SecTrails",
            description="querying SecurityTrails DNS intelligence",
            api_key=os.getenv("SECURITYTRAILS_API_KEY"),
        ),
        "urlscan": SourceConfig(
            name="URLScan",
            description="querying URLScan.io web intelligence",
            api_key=os.getenv("URLSCAN_API_KEY"),
        ),
    })

    scanner: ScannerConfig = field(default_factory=ScannerConfig)

    def get_output_filename(self) -> str:
        """Generate output filename based on target domain."""
        if self.output_file:
            return self.output_file
        safe_domain = self.target_domain.replace(".", "_").replace("/", "_")
        # Place JSON output inside domain results folder
        domain_dir = os.path.join(".", self.target_domain)
        os.makedirs(domain_dir, exist_ok=True)
        return os.path.join(domain_dir, f"{safe_domain}.json")
