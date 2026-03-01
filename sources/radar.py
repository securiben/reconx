"""
Radar - HackerTarget host search intelligence.
Queries HackerTarget API for subdomain discovery.
Free, no API key required (rate limited).
"""

import random
from typing import List
from .base import BaseSource

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class RadarSource(BaseSource):
    """
    Radar data source - HackerTarget hostsearch.
    Discovers subdomains via HackerTarget's free host search API.
    """
    SOURCE_DESC = "querying HackerTarget hostsearch"

    def fetch(self, domain: str) -> List[str]:
        """Fetch subdomains from HackerTarget hostsearch."""
        if not HAS_REQUESTS:
            return []

        subdomains = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            resp = requests.get(
                url, timeout=self.config.timeout,
                headers={"User-Agent": "ReconX/1.0"},
            )
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.strip().split("\n"):
                    if "," in line:
                        hostname = line.split(",")[0].strip().lower()
                        if hostname and (hostname.endswith(f".{domain}") or hostname == domain):
                            subdomains.add(hostname)
        except Exception:
            pass

        return list(subdomains)

    def fetch_demo(self, domain: str) -> List[str]:
        """Generate Radar demo data (~51 subdomains)."""
        target_count = random.randint(45, 60)
        return self._generate_demo_subdomains(domain, target_count)
