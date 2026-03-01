"""
Atlas - crt.sh Certificate Transparency.
Queries crt.sh for subdomain discovery via CT logs.
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


class AtlasSource(BaseSource):
    """
    Atlas data source - crt.sh Certificate Transparency.
    Discovers subdomains from CT logs via the crt.sh public API.
    """
    SOURCE_DESC = "querying crt.sh certificate transparency"

    def fetch(self, domain: str) -> List[str]:
        """Fetch subdomains from crt.sh Certificate Transparency."""
        if not HAS_REQUESTS:
            return []

        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(
                url, timeout=max(self.config.timeout, 60),
                headers={"User-Agent": "ReconX/1.0"},
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name.startswith("*."):
                            name = name[2:]
                        if name and (name.endswith(f".{domain}") or name == domain):
                            subdomains.add(name)
        except Exception:
            pass

        return list(subdomains)

    def fetch_demo(self, domain: str) -> List[str]:
        """Generate Atlas demo data (~928 subdomains)."""
        target_count = random.randint(900, 960)
        return self._generate_demo_subdomains(domain, target_count)
