"""
Data models for ReconX.
Defines all the data structures used across modules.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum
from datetime import datetime


# ─── Enums ───────────────────────────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class InfraProvider(Enum):
    AWS = "AWS"
    AZURE = "Azure"
    CLOUDFLARE = "Cloudflare"
    AKAMAI = "Akamai"
    OTHER = "Other"
    CT_ONLY = "CT-only"


class TakeoverStatus(Enum):
    VULNERABLE = "VULNERABLE"
    DANGLING = "dangling"
    NOT_VULNERABLE = "not vulnerable"


# ─── Subdomain Models ────────────────────────────────────────────────────────

@dataclass
class Subdomain:
    """Represents a discovered subdomain."""
    hostname: str
    ip_addresses: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    provider: Optional[InfraProvider] = None
    source: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_alive: bool = False
    http_status: Optional[int] = None
    technologies: List[str] = field(default_factory=list)
    interesting: bool = False
    interesting_reason: str = ""

    # ── httpx-enriched fields ──────────────────────────────────────────
    http_url: str = ""
    http_scheme: str = ""
    http_title: str = ""
    http_server: str = ""
    http_content_type: str = ""
    http_location: str = ""         # redirect location
    http_favicon_hash: str = ""
    http_technologies: List[str] = field(default_factory=list)
    http_cdn: bool = False
    http_cdn_name: str = ""
    http_body_hash: str = ""
    http_response_time: str = ""
    http_content_length: int = 0
    http_lines: int = 0
    http_words: int = 0
    http_final_url: str = ""
    http_cpe: Dict = field(default_factory=dict)
    http_tls: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "hostname": self.hostname,
            "ip_addresses": self.ip_addresses,
            "cnames": self.cnames,
            "provider": self.provider.value if self.provider else None,
            "source": self.source,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "is_alive": self.is_alive,
            "http_status": self.http_status,
            "technologies": self.technologies,
            "interesting": self.interesting,
            "interesting_reason": self.interesting_reason,
        }
        # Conditionally include httpx data if probed
        if self.http_url:
            d.update({
                "http_url": self.http_url,
                "http_scheme": self.http_scheme,
                "http_title": self.http_title,
                "http_server": self.http_server,
                "http_content_type": self.http_content_type,
                "http_location": self.http_location,
                "http_favicon_hash": self.http_favicon_hash,
                "http_technologies": self.http_technologies,
                "http_cdn": self.http_cdn,
                "http_cdn_name": self.http_cdn_name,
                "http_body_hash": self.http_body_hash,
                "http_response_time": self.http_response_time,
                "http_content_length": self.http_content_length,
                "http_final_url": self.http_final_url,
            })
            if self.http_cpe:
                d["http_cpe"] = self.http_cpe
            if self.http_tls:
                d["http_tls"] = self.http_tls
        return d


# ─── Takeover Models ─────────────────────────────────────────────────────────

@dataclass
class TakeoverResult:
    """Result of a subdomain takeover check."""
    subdomain: str
    status: TakeoverStatus
    provider: str = ""
    cname: str = ""
    evidence: str = ""
    match_type: str = "CNAME-Match"

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "status": self.status.value,
            "provider": self.provider,
            "cname": self.cname,
            "evidence": self.evidence,
            "match_type": self.match_type,
        }


# ─── Tech Detection Models ───────────────────────────────────────────────────

@dataclass
class TechSignature:
    """Defines a technology signature for detection."""
    name: str
    category: str  # e.g., "framework", "server", "cms", "cdn"
    severity: Severity = Severity.INFO
    match_location: str = "Body"  # Body, Header, URL
    indicators: List[str] = field(default_factory=list)
    description: str = ""
    endpoints_to_check: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "severity": self.severity.value,
            "match_location": self.match_location,
            "indicators": self.indicators,
            "description": self.description,
            "endpoints_to_check": self.endpoints_to_check,
        }


@dataclass
class TechMatch:
    """A confirmed technology match on a subdomain."""
    subdomain: str
    tech: TechSignature
    evidence: str = ""
    match_location: str = "Body"

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "tech_name": self.tech.name,
            "severity": self.tech.severity.value,
            "evidence": self.evidence,
            "match_location": self.match_location,
            "description": self.tech.description,
        }


# ─── CT Log Models ───────────────────────────────────────────────────────────

@dataclass
class CTEntry:
    """A Certificate Transparency log entry."""
    subdomain: str
    issuer: str = ""
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    serial: str = ""
    source: str = "crt.sh"

    @property
    def age_category(self) -> str:
        """Classify CT entry age: stale (1-2yr), aged (2yr+), or no date."""
        if not self.not_before:
            return "no_date"
        now = datetime.utcnow()
        age_days = (now - self.not_before).days
        if age_days > 730:
            return "aged"
        elif age_days > 365:
            return "stale"
        else:
            return "fresh"

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "issuer": self.issuer,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "serial": self.serial,
            "source": self.source,
            "age_category": self.age_category,
        }


# ─── Infrastructure Classification ───────────────────────────────────────────

@dataclass
class InfraStats:
    """Infrastructure classification statistics."""
    aws: int = 0
    azure: int = 0
    cloudflare: int = 0
    akamai: int = 0
    other: int = 0
    ct_only: int = 0

    def to_dict(self) -> dict:
        return {
            "aws": self.aws,
            "azure": self.azure,
            "cloudflare": self.cloudflare,
            "akamai": self.akamai,
            "other": self.other,
            "ct_only": self.ct_only,
        }


# ─── Collapsed Entries ────────────────────────────────────────────────────────

@dataclass
class CollapseStats:
    """Statistics for pattern-collapsed entries."""
    total_entries: int = 0
    pattern_groups: int = 0
    threshold: int = 5

    def to_dict(self) -> dict:
        return {
            "total_entries": self.total_entries,
            "pattern_groups": self.pattern_groups,
            "threshold": self.threshold,
        }


# ─── Source Stats ─────────────────────────────────────────────────────────────

@dataclass
class SourceStats:
    """Statistics per data source."""
    name: str
    count: int = 0
    subdomains: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "count": self.count,
        }


# ─── Master Scan Result ──────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Master result container for an entire scan."""
    target_domain: str
    scan_time: float = 0.0
    total_unique: int = 0

    # Infrastructure
    infra: InfraStats = field(default_factory=InfraStats)

    # CT Triage
    ct_stale: int = 0    # 1-2yr
    ct_aged: int = 0     # 2yr+
    ct_no_date: int = 0

    # Collapse
    collapse: CollapseStats = field(default_factory=CollapseStats)

    # Takeover
    takeover_results: List[TakeoverResult] = field(default_factory=list)
    vulnerable_count: int = 0
    dangling_count: int = 0
    not_vulnerable_count: int = 0
    takeover_provider: str = "Microsoft Azure"

    # Flagged
    flagged_interesting: int = 0

    # Tech
    tech_matches: List[TechMatch] = field(default_factory=list)
    tech_severity_summary: Dict[str, List] = field(default_factory=dict)

    # Database stats
    takeover_db_services: int = 0
    tech_db_signatures: int = 0

    # Sources
    source_stats: Dict[str, SourceStats] = field(default_factory=dict)

    # All subdomains discovered
    subdomains: List[Subdomain] = field(default_factory=list)

    # CT entries
    ct_entries: List[CTEntry] = field(default_factory=list)

    # HTTPX probe stats
    httpx_stats: Dict = field(default_factory=dict)
    httpx_available: bool = False

    # Nuclei vulnerability scanner
    nuclei_results: List = field(default_factory=list)
    nuclei_stats: Dict = field(default_factory=dict)
    nuclei_available: bool = False

    # Nmap port scanner
    nmap_results: Dict = field(default_factory=dict)
    nmap_stats: Dict = field(default_factory=dict)
    nmap_available: bool = False

    # Enum4linux SMB enumeration
    enum4linux_results: Dict = field(default_factory=dict)
    enum4linux_stats: Dict = field(default_factory=dict)
    enum4linux_available: bool = False

    # CrackMapExec protocol enumeration
    cme_results: Dict = field(default_factory=dict)
    cme_stats: Dict = field(default_factory=dict)
    cme_available: bool = False

    # Metasploit SMB brute-force
    msf_results: Dict = field(default_factory=dict)
    msf_stats: Dict = field(default_factory=dict)
    msf_available: bool = False

    # RDP brute-force (netexec)
    rdp_results: Dict = field(default_factory=dict)
    rdp_stats: Dict = field(default_factory=dict)
    rdp_available: bool = False

    # WPScan WordPress scanner
    wpscan_results: Dict = field(default_factory=dict)
    wpscan_stats: Dict = field(default_factory=dict)
    wpscan_available: bool = False

    # SMBClient null session detection
    smbclient_results: Dict = field(default_factory=dict)
    smbclient_stats: Dict = field(default_factory=dict)
    smbclient_available: bool = False

    def to_dict(self) -> dict:
        d = {
            "target_domain": self.target_domain,
            "scan_time": self.scan_time,
            "total_unique": self.total_unique,
            "infrastructure": self.infra.to_dict(),
            "ct_triage": {
                "stale_1_2yr": self.ct_stale,
                "aged_2yr_plus": self.ct_aged,
                "no_date": self.ct_no_date,
            },
            "collapsed": self.collapse.to_dict(),
            "takeover": {
                "vulnerable_count": self.vulnerable_count,
                "dangling_count": self.dangling_count,
                "not_vulnerable_count": self.not_vulnerable_count,
                "provider": self.takeover_provider,
                "results": [r.to_dict() for r in self.takeover_results],
            },
            "flagged_interesting": self.flagged_interesting,
            "tech": {
                "matches": [m.to_dict() for m in self.tech_matches],
                "severity_summary": {
                    k: [{"name": t.tech.name, "count": 1} for t in v]
                    for k, v in self.tech_severity_summary.items()
                },
            },
            "databases": {
                "takeover_db_services": self.takeover_db_services,
                "tech_db_signatures": self.tech_db_signatures,
            },
            "sources": {k: v.to_dict() for k, v in self.source_stats.items()},
            "subdomains": [s.to_dict() for s in self.subdomains],
        }
        if self.httpx_stats:
            d["httpx"] = self.httpx_stats
        if self.nuclei_results:
            d["nuclei"] = {
                "stats": self.nuclei_stats,
                "findings": [
                    r.to_dict() if hasattr(r, 'to_dict') else r
                    for r in self.nuclei_results
                ],
            }
        if self.nmap_results:
            d["nmap"] = {
                "stats": self.nmap_stats,
                "hosts": {
                    ip: h.to_dict() if hasattr(h, 'to_dict') else h
                    for ip, h in self.nmap_results.items()
                },
            }
        if self.enum4linux_results:
            d["enum4linux"] = {
                "stats": self.enum4linux_stats,
                "hosts": {
                    ip: h.to_dict() if hasattr(h, 'to_dict') else h
                    for ip, h in self.enum4linux_results.items()
                },
            }
        if self.cme_results:
            d["cme"] = {
                "stats": self.cme_stats,
                "protocols": {
                    proto: r.to_dict() if hasattr(r, 'to_dict') else r
                    for proto, r in self.cme_results.items()
                },
            }
        if self.msf_results:
            d["msf_smb_brute"] = {
                "stats": self.msf_stats,
                "hosts": {
                    ip: r.to_dict() if hasattr(r, 'to_dict') else r
                    for ip, r in self.msf_results.items()
                },
            }
        if self.rdp_results:
            d["rdp_brute"] = {
                "stats": self.rdp_stats,
                "hosts": {
                    ip: r.to_dict() if hasattr(r, 'to_dict') else r
                    for ip, r in self.rdp_results.items()
                },
            }
        if self.wpscan_results:
            d["wpscan"] = {
                "stats": self.wpscan_stats,
                "targets": {
                    url: r.to_dict() if hasattr(r, 'to_dict') else r
                    for url, r in self.wpscan_results.items()
                },
            }
        if self.smbclient_results:
            d["smbclient"] = {
                "stats": self.smbclient_stats,
                "hosts": {
                    ip: r.to_dict() if hasattr(r, 'to_dict') else r
                    for ip, r in self.smbclient_results.items()
                },
            }
        return d
