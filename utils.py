"""
Utility functions for ReconX.
DNS resolution, HTTP probing, pattern matching, etc.
"""

import re
import socket
import hashlib
import random
import string
from typing import List, Optional, Tuple
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ─── DNS Utilities ────────────────────────────────────────────────────────────

def resolve_cname(hostname: str, timeout: int = 5) -> List[str]:
    """Resolve CNAME records for a hostname."""
    cnames = []
    if HAS_DNSPYTHON:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            answers = resolver.resolve(hostname, "CNAME")
            for rdata in answers:
                cnames.append(str(rdata.target).rstrip("."))
        except Exception:
            pass
    else:
        # Fallback: use socket
        try:
            result = socket.getfqdn(hostname)
            if result != hostname:
                cnames.append(result)
        except Exception:
            pass
    return cnames


def resolve_a(hostname: str, timeout: int = 5) -> List[str]:
    """Resolve A records for a hostname."""
    ips = []
    if HAS_DNSPYTHON:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            answers = resolver.resolve(hostname, "A")
            for rdata in answers:
                ips.append(str(rdata.address))
        except Exception:
            pass
    else:
        try:
            ips = [info[4][0] for info in socket.getaddrinfo(hostname, None, socket.AF_INET)]
        except Exception:
            pass
    return list(set(ips))


def check_http(url: str, timeout: int = 10) -> Tuple[Optional[int], str]:
    """Make an HTTP GET and return (status_code, body_snippet)."""
    if not HAS_REQUESTS:
        return None, ""
    try:
        import urllib3
        import warnings
        # Suppress TLS warnings for verify=False probes
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        warnings.filterwarnings(
            "ignore",
            message="Unverified HTTPS request is being made.*",
            category=urllib3.exceptions.InsecureRequestWarning,
        )
        # Some requests distributions expose urllib3 via requests.packages
        try:
            import requests as _r
            _r.packages.urllib3.disable_warnings(
                _r.packages.urllib3.exceptions.InsecureRequestWarning
            )
        except Exception:
            pass
    except Exception:
        pass
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
        return resp.status_code, resp.text[:4096]
    except Exception:
        return None, ""


# ─── Infrastructure Classification ───────────────────────────────────────────

# IP ranges / CNAME patterns for provider classification
PROVIDER_PATTERNS = {
    "AWS": {
        "cname": [
            r"\.amazonaws\.com$",
            r"\.aws\.com$",
            r"\.elasticbeanstalk\.com$",
            r"\.s3\.amazonaws\.com$",
            r"\.cloudfront\.net$",
            r"\.elb\.amazonaws\.com$",
        ],
        "ip_ranges": [],  # Would load from AWS IP ranges JSON
    },
    "Azure": {
        "cname": [
            r"\.azure\.com$",
            r"\.azurewebsites\.net$",
            r"\.azure-api\.net$",
            r"\.azurefd\.net$",
            r"\.blob\.core\.windows\.net$",
            r"\.cloudapp\.azure\.com$",
            r"\.azureedge\.net$",
            r"\.trafficmanager\.net$",
            r"\.azure-mobile\.net$",
        ],
    },
    "Cloudflare": {
        "cname": [
            r"\.cdn\.cloudflare\.net$",
            r"\.cloudflare\.com$",
        ],
        "ip_ranges": [
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
            "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
            "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
            "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        ],
    },
    "Akamai": {
        "cname": [
            r"\.akamaized\.net$",
            r"\.akamai\.net$",
            r"\.edgesuite\.net$",
            r"\.edgekey\.net$",
            r"\.akamaiedge\.net$",
        ],
    },
}


def classify_provider(hostname: str, cnames: List[str], ips: List[str]) -> str:
    """Classify which infrastructure provider a subdomain belongs to."""
    import ipaddress

    all_cnames = cnames + [hostname]
    for provider, patterns in PROVIDER_PATTERNS.items():
        for cname in all_cnames:
            for pattern in patterns.get("cname", []):
                if re.search(pattern, cname, re.IGNORECASE):
                    return provider

    # Check IP ranges for Cloudflare (and others with defined ranges)
    for ip_str in ips:
        try:
            ip_addr = ipaddress.ip_address(ip_str)
            for provider, patterns in PROVIDER_PATTERNS.items():
                for cidr in patterns.get("ip_ranges", []):
                    try:
                        if ip_addr in ipaddress.ip_network(cidr, strict=False):
                            return provider
                    except ValueError:
                        continue
        except ValueError:
            continue

    return "Other"


# ─── Pattern Collapse ────────────────────────────────────────────────────────

def collapse_subdomains(hostnames: List[str], threshold: int = 5) -> Tuple[int, int]:
    """
    Collapse subdomains into pattern groups.
    Detects patterns like:
      - app-01.example.com, app-02.example.com -> app-*.example.com
      - us-east-api.example.com, eu-west-api.example.com -> *-api.example.com
      - staging1.api.example.com, staging2.api.example.com -> staging*.api.example.com
      - foo.cdn.example.com, bar.cdn.example.com -> *.cdn.example.com
    Returns (total_collapsed_entries, pattern_groups_count).
    """
    patterns = {}
    for hostname in hostnames:
        parts = hostname.split(".")
        if len(parts) < 2:
            continue

        # Strategy 1: Replace numeric sequences in first label
        pat1 = re.sub(r'\d+', '*', parts[0])
        pat1 = re.sub(r'\*+', '*', pat1)
        key1 = pat1 + "." + ".".join(parts[1:])

        # Strategy 2: Wildcard the entire first label (group by parent domain)
        if len(parts) >= 3:
            key2 = "*." + ".".join(parts[1:])
        else:
            key2 = None

        # Strategy 3: Replace hex-like hashes (8+ hex chars)
        pat3 = re.sub(r'[0-9a-f]{8,}', '*', parts[0], flags=re.IGNORECASE)
        key3 = pat3 + "." + ".".join(parts[1:]) if pat3 != parts[0] else None

        # Strategy 4: Replace UUID patterns
        pat4 = re.sub(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '*', hostname, flags=re.IGNORECASE
        )
        key4 = pat4 if pat4 != hostname else None

        # Add to all applicable patterns
        for key in [key1, key2, key3, key4]:
            if key and key != hostname:
                if key not in patterns:
                    patterns[key] = set()
                patterns[key].add(hostname)

    # Filter: only keep patterns that meet threshold
    # Remove patterns that are strict subsets of larger patterns
    collapsed_entries = 0
    pattern_groups = 0
    counted_hostnames = set()

    # Sort by size descending so larger groups take priority
    sorted_patterns = sorted(patterns.items(), key=lambda x: -len(x[1]))

    for pattern, members in sorted_patterns:
        # Only count members not already counted by a larger group
        new_members = members - counted_hostnames
        if len(members) >= threshold and new_members:
            collapsed_entries += len(members)
            pattern_groups += 1
            counted_hostnames.update(members)

    return collapsed_entries, pattern_groups


# ─── Interesting Subdomain Detection ─────────────────────────────────────────

INTERESTING_PATTERNS = [
    r"(admin|panel|dashboard|console|portal)",
    r"(api|graphql|rest|swagger|openapi)",
    r"(dev|staging|stage|test|qa|uat|sandbox|demo)",
    r"(vpn|remote|internal|intranet|corp)",
    r"(jenkins|gitlab|github|bitbucket|ci|cd|deploy)",
    r"(jira|confluence|slack|teams)",
    r"(mail|smtp|imap|pop3|exchange|webmail)",
    r"(ftp|sftp|ssh|rdp|vnc)",
    r"(db|database|mysql|postgres|mongo|redis|elastic)",
    r"(backup|bak|old|legacy|archive)",
    r"(auth|login|sso|oauth|saml|keycloak)",
    r"(monitor|grafana|prometheus|kibana|nagios|zabbix)",
    r"(storage|s3|blob|cdn|static|assets|media)",
    r"(gateway|proxy|lb|loadbalancer|haproxy|nginx)",
    r"(secret|private|hidden|internal)",
]

INTERESTING_COMPILED = [re.compile(p, re.IGNORECASE) for p in INTERESTING_PATTERNS]


def is_interesting_subdomain(hostname: str) -> Tuple[bool, str]:
    """Check if a subdomain appears interesting for security analysis."""
    for pattern in INTERESTING_COMPILED:
        match = pattern.search(hostname)
        if match:
            return True, f"Matches pattern: {match.group()}"
    return False, ""


# ─── Demo Data Generation ────────────────────────────────────────────────────

def generate_random_subdomain(domain: str) -> str:
    """Generate a random-looking subdomain for demo mode."""
    prefixes = [
        "app", "api", "dev", "staging", "test", "admin", "portal",
        "mail", "vpn", "cdn", "static", "media", "blog", "shop",
        "auth", "sso", "gateway", "proxy", "monitor", "grafana",
        "jenkins", "gitlab", "jira", "confluence", "db", "redis",
        "elastic", "kibana", "backup", "legacy", "internal", "corp",
        "dashboard", "console", "panel", "mgmt", "ops", "infra",
    ]
    prefix = random.choice(prefixes)
    if random.random() > 0.6:
        prefix += f"-{random.randint(1, 99):02d}"
    if random.random() > 0.7:
        prefix = f"{random.choice(['us', 'eu', 'ap', 'prod', 'stg'])}-{prefix}"
    return f"{prefix}.{domain}"


def generate_demo_hash() -> str:
    """Generate a random hash-like string for redacted display."""
    return hashlib.md5(
        "".join(random.choices(string.ascii_lowercase, k=16)).encode()
    ).hexdigest()[:12]
