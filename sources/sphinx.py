"""
Sphinx - Certspotter Certificate Transparency.
Queries Certspotter API for subdomain discovery via CT logs.
Free tier available, no API key required for basic usage.
"""

import random
from typing import List
from .base import BaseSource

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class SphinxSource(BaseSource):
    """
    Sphinx data source - Certspotter CT log intelligence.
    Discovers subdomains from Certspotter certificate transparency API.
    """
    SOURCE_DESC = "querying Certspotter CT logs"

    def fetch(self, domain: str) -> List[str]:
        """Fetch subdomains from Certspotter CT logs."""
        if not HAS_REQUESTS:
            return []

        subdomains = set()
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            headers = {"User-Agent": "ReconX/1.0"}
            # Use API token if available for higher rate limits
            if self.config.api_key:
                headers["Authorization"] = f"Bearer {self.config.api_key}"
            resp = requests.get(url, timeout=self.config.timeout, headers=headers)
            if resp.status_code == 200:
                for entry in resp.json():
                    for name in entry.get("dns_names", []):
                        name = name.strip().lower()
                        if name.startswith("*."):
                            name = name[2:]
                        if name and (name.endswith(f".{domain}") or name == domain):
                            subdomains.add(name)
        except Exception:
            pass

        return list(subdomains)

    def fetch_demo(self, domain: str) -> List[str]:
        """Generate Sphinx demo data (~492 subdomains)."""
        target_count = random.randint(470, 510)
        return self._generate_demo_subdomains(domain, target_count)
