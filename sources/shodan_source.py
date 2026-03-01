"""
Shodan - Internet-wide scanning intelligence.
Queries Shodan API for subdomain discovery via DNS dataset.
Requires SHODAN_API_KEY.
"""

import random
from typing import List
from .base import BaseSource

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class ShodanSource(BaseSource):
    """
    Shodan data source — discovers subdomains from Shodan's DNS dataset.
    Uses /dns/domain/{domain} endpoint.
    Fallback: Shodan search for SSL certificate common names.
    """
    SOURCE_DESC = "querying Shodan internet scanning"

    def fetch(self, domain: str) -> List[str]:
        if not HAS_REQUESTS or not self.config.api_key:
            return []

        subdomains = set()
        headers = {"User-Agent": "ReconX/1.0"}

        # Primary: DNS domain endpoint
        try:
            url = f"https://api.shodan.io/dns/domain/{domain}"
            params = {"key": self.config.api_key}
            resp = requests.get(url, params=params, headers=headers, timeout=self.config.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for record in data.get("subdomains", []):
                    name = f"{record}.{domain}".lower().strip()
                    if name.endswith(f".{domain}") or name == domain:
                        subdomains.add(name)
                # Also grab data[].subdomain from the detailed records
                for entry in data.get("data", []):
                    sub = entry.get("subdomain", "")
                    if sub:
                        name = f"{sub}.{domain}".lower().strip()
                        subdomains.add(name)
        except Exception:
            pass

        # Secondary: Search SSL certificates
        try:
            url = "https://api.shodan.io/shodan/host/search"
            params = {
                "key": self.config.api_key,
                "query": f"ssl.cert.subject.cn:*.{domain}",
                "minify": "true",
            }
            resp = requests.get(url, params=params, headers=headers, timeout=self.config.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for match in data.get("matches", []):
                    # Extract hostnames from SSL cert
                    ssl_info = match.get("ssl", {})
                    cert = ssl_info.get("cert", {})
                    cn = cert.get("subject", {}).get("CN", "")
                    if cn and not cn.startswith("*"):
                        cn = cn.lower().strip()
                        if cn.endswith(f".{domain}") or cn == domain:
                            subdomains.add(cn)
                    # Subject alternative names
                    for ext in cert.get("extensions", []):
                        if ext.get("name") == "subjectAltName":
                            for san in ext.get("data", "").split(","):
                                san = san.strip().replace("DNS:", "").lower().strip()
                                if san and not san.startswith("*") and (san.endswith(f".{domain}") or san == domain):
                                    subdomains.add(san)
                    # Also check hostnames array
                    for hostname in match.get("hostnames", []):
                        hostname = hostname.lower().strip()
                        if hostname.endswith(f".{domain}") or hostname == domain:
                            subdomains.add(hostname)
        except Exception:
            pass

        return list(subdomains)

    def fetch_demo(self, domain: str) -> List[str]:
        target_count = random.randint(120, 200)
        return self._generate_demo_subdomains(domain, target_count)
