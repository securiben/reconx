"""
VirusTotal Subdomain Discovery for ReconX.
Uses VT v3 API /domains/{domain}/subdomains endpoint for reliable
subdomain enumeration with pagination support.

API: https://www.virustotal.com/api/v3/domains/{domain}/subdomains
Auth: x-apikey header

Requires: VT_DOMAIN_API_KEY or VT_API_KEY in .env
  Get free key at: https://www.virustotal.com/gui/my-apikey
"""

import time
import random
from typing import List
from .base import BaseSource

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class VTSiblingsSource(BaseSource):
    """
    VirusTotal subdomain enumeration source (v3 API).
    Queries VT v3 /domains/{domain}/subdomains with pagination
    for fast subdomain discovery.
    """
    SOURCE_DESC = "querying VirusTotal subdomains (v3 API)"

    VT_V3_BASE = "https://www.virustotal.com/api/v3"

    def fetch(self, domain: str) -> List[str]:
        """Fetch subdomains for the root domain via VT v3."""
        if not HAS_REQUESTS or not self.config.api_key:
            return []
        return self._fetch_subdomains_v3(domain, domain)

    def _fetch_subdomains_v3(self, target: str, root_domain: str,
                             max_pages: int = 3) -> List[str]:
        """
        Query VT v3 /domains/{target}/subdomains with pagination.

        Returns subdomains that belong to the root domain.
        """
        subdomains: List[str] = []
        headers = {
            "x-apikey": self.config.api_key,
            "User-Agent": "ReconX/1.0",
        }
        cursor = ""

        for page in range(max_pages):
            try:
                url = f"{self.VT_V3_BASE}/domains/{target}/subdomains"
                params = {"limit": 40}
                if cursor:
                    params["cursor"] = cursor

                resp = requests.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=self.config.timeout,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get("data", [])

                    for item in items:
                        name = item.get("id", "").strip().lower()
                        if name and (name.endswith(f".{root_domain}") or name == root_domain):
                            subdomains.append(name)

                    # Pagination
                    cursor = data.get("meta", {}).get("cursor", "")
                    if not cursor or not items:
                        break

                    # Brief rate limit pause between pages
                    time.sleep(0.1)

                elif resp.status_code == 429:
                    # Rate limited — stop paginating
                    break
                elif resp.status_code == 403:
                    # Invalid API key
                    break
                else:
                    break

            except Exception:
                break

        return subdomains

    def fetch_demo(self, domain: str) -> List[str]:
        """Generate VT siblings demo data."""
        target_count = random.randint(30, 60)
        return self._generate_demo_subdomains(domain, target_count)
