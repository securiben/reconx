"""
Chaos - ProjectDiscovery CHAOS subdomain discovery.
Queries the Chaos dataset for known subdomains.
Requires CHAOS_API_KEY.
"""

import random
from typing import List
from .base import BaseSource

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class ChaosSource(BaseSource):
    """
    Chaos data source — ProjectDiscovery CHAOS.
    Discovers subdomains from the Chaos dataset (DNS records collected
    by ProjectDiscovery's internet-wide scanning).
    """
    SOURCE_DESC = "querying ProjectDiscovery Chaos"

    def fetch(self, domain: str) -> List[str]:
        if not HAS_REQUESTS or not self.config.api_key:
            return []

        subdomains = set()
        try:
            url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
            headers = {
                "Authorization": self.config.api_key,
                "User-Agent": "ReconX/1.0",
            }
            resp = requests.get(url, headers=headers, timeout=self.config.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for sub in data.get("subdomains", []):
                    sub = str(sub).strip().lower()
                    if sub == "":
                        subdomains.add(domain)
                    else:
                        name = f"{sub}.{domain}"
                        if name.endswith(f".{domain}") or name == domain:
                            subdomains.add(name)
        except Exception:
            pass

        return list(subdomains)

    def fetch_demo(self, domain: str) -> List[str]:
        target_count = random.randint(60, 120)
        return self._generate_demo_subdomains(domain, target_count)
