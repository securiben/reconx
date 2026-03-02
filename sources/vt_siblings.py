"""
VirusTotal Recursive Subdomain Discovery for ReconX.
Uses VT v3 API /domains/{domain}/subdomains endpoint for reliable
subdomain enumeration with pagination support.

API: https://www.virustotal.com/api/v3/domains/{domain}/subdomains
Auth: x-apikey header

Requires: VT_DOMAIN_API_KEY or VT_API_KEY in .env
  Get free key at: https://www.virustotal.com/gui/my-apikey
"""

import time
import random
import sys
from typing import List, Set
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
    for the root domain, then recursively discovers deeper
    subdomains from newly found hosts.
    """
    SOURCE_DESC = "querying VirusTotal subdomains (recursive)"

    VT_V3_BASE = "https://www.virustotal.com/api/v3"

    def fetch(self, domain: str) -> List[str]:
        """Fetch subdomains for the root domain via VT v3."""
        if not HAS_REQUESTS or not self.config.api_key:
            return []
        return self._fetch_subdomains_v3(domain, domain)

    def fetch_recursive(self, domain: str, hostnames: Set[str],
                        max_depth: int = 2, max_queries: int = 20) -> List[str]:
        """
        Recursively discover subdomains using VT v3 API.

        Strategy:
        - Depth 0: Query root domain's /subdomains endpoint (paginated)
        - Depth 1+: Query newly discovered multi-level subs for deeper subs
        - Only queries domains NOT already queried in Phase 1

        Args:
            domain: Root target domain (e.g., example.com).
            hostnames: Set of already-known subdomain hostnames.
            max_depth: Maximum recursion depth (default: 2).
            max_queries: Maximum total API queries (default: 20).

        Returns:
            List of newly discovered subdomains.
        """
        if not HAS_REQUESTS or not self.config.api_key:
            return []

        all_discovered: Set[str] = set()
        queried: Set[str] = set()
        query_count = 0

        # Phase 1 already queried the root domain via fetch(),
        # so start recursive with the root domain to get paginated results
        # (Phase 1 in venom.py may have limited pages)
        current_batch: Set[str] = set()
        current_batch.add(domain)

        # Also add known subdomains that have further sub-levels
        # e.g., if we know "dev.example.com", querying its /subdomains
        # might reveal "api.dev.example.com"
        for h in hostnames:
            h = h.lower().strip()
            # Only recurse on hosts that are direct subs (have potential for deeper subs)
            parts = h.replace(f".{domain}", "").split(".")
            if len(parts) >= 1 and h.endswith(f".{domain}"):
                current_batch.add(h)

        for depth in range(max_depth):
            next_batch: Set[str] = set()

            for hostname in sorted(current_batch):
                if query_count >= max_queries:
                    break
                if hostname in queried:
                    continue

                queried.add(hostname)
                query_count += 1

                subs = self._fetch_subdomains_v3(hostname, domain)
                for sub in subs:
                    if sub not in all_discovered and sub not in hostnames:
                        all_discovered.add(sub)
                        next_batch.add(sub)

                # VT free tier: 4 req/min → sleep ~16s between requests
                if query_count < max_queries and len(current_batch) > 1:
                    time.sleep(16)

            if not next_batch or query_count >= max_queries:
                break

            current_batch = next_batch

        return list(all_discovered)

    def _fetch_subdomains_v3(self, target: str, root_domain: str,
                             max_pages: int = 10) -> List[str]:
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

                    # Respect rate limits between pages
                    time.sleep(0.3)

                elif resp.status_code == 429:
                    # Rate limited — wait and stop paginating
                    time.sleep(15)
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
