"""
Oracle - AlienVault OTX passive DNS intelligence.
Queries AlienVault OTX API for subdomain discovery.
Free, no API key required.
"""

import random
from typing import List
from .base import BaseSource

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class OracleSource(BaseSource):
    """
    Oracle data source - AlienVault OTX passive DNS.
    Discovers subdomains from AlienVault OTX threat intelligence platform.
    """
    SOURCE_DESC = "querying AlienVault OTX passive DNS"

    def fetch(self, domain: str) -> List[str]:
        """Fetch subdomains from AlienVault OTX passive DNS."""
        if not HAS_REQUESTS:
            return []

        subdomains = set()

        # Primary: AlienVault OTX passive DNS
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            headers = {"User-Agent": "ReconX/1.0", "Accept": "application/json"}
            if self.config.api_key:
                headers["X-OTX-API-KEY"] = self.config.api_key
            resp = requests.get(url, timeout=self.config.timeout, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get("passive_dns", []):
                    hostname = entry.get("hostname", "").strip().lower()
                    if hostname and (hostname.endswith(f".{domain}") or hostname == domain):
                        subdomains.add(hostname)
            elif resp.status_code == 429:
                # Rate limited, try URL list endpoint as fallback
                import time
                time.sleep(0.5)
                url2 = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
                resp2 = requests.get(url2, timeout=self.config.timeout, headers=headers)
                if resp2.status_code == 200:
                    data2 = resp2.json()
                    for entry in data2.get("url_list", []):
                        hostname = entry.get("hostname", "").strip().lower()
                        if hostname and (hostname.endswith(f".{domain}") or hostname == domain):
                            subdomains.add(hostname)
        except Exception:
            pass

        # Fallback: URLScan.io
        if not subdomains:
            try:
                url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
                resp = requests.get(url, timeout=self.config.timeout, headers={"User-Agent": "ReconX/1.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    for result in data.get("results", []):
                        page = result.get("page", {})
                        d = page.get("domain", "").strip().lower()
                        if d and (d.endswith(f".{domain}") or d == domain):
                            subdomains.add(d)
            except Exception:
                pass

        return list(subdomains)

    def fetch_demo(self, domain: str) -> List[str]:
        """Generate Oracle demo data (~164 subdomains)."""
        target_count = random.randint(150, 180)
        return self._generate_demo_subdomains(domain, target_count)
