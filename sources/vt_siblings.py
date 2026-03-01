"""
VirusTotal Domain Siblings - Recursive subdomain discovery.
Uses VT v2 API domain/report endpoint to extract domain_siblings
from each discovered subdomain, enabling recursive enumeration.

API: https://virustotal.com/vtapi/v2/domain/report?apikey=<KEY>&domain=<DOMAIN>
Field: domain_siblings → list of sibling domains

Requires: VT_DOMAIN_API_KEY in .env
  Get free key at: https://www.virustotal.com/gui/my-apikey
"""

import time
import random
from typing import List, Set
from .base import BaseSource

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class VTSiblingsSource(BaseSource):
    """
    VirusTotal domain_siblings source.
    Queries VT v2 domain/report for each subdomain to extract
    sibling domains, enabling recursive subdomain discovery.
    """
    SOURCE_DESC = "querying VirusTotal domain siblings (recursive)"

    VT_V2_URL = "https://virustotal.com/vtapi/v2/domain/report"

    def fetch(self, domain: str) -> List[str]:
        """Fetch domain_siblings for the root domain."""
        if not HAS_REQUESTS or not self.config.api_key:
            return []
        return self._fetch_siblings(domain, domain)

    def fetch_recursive(self, domain: str, hostnames: Set[str],
                        max_depth: int = 2, max_queries: int = 100) -> List[str]:
        """
        Recursively fetch domain_siblings for all known subdomains.

        Args:
            domain: Root target domain (e.g., example.com).
            hostnames: Set of already-known subdomain hostnames to recurse on.
            max_depth: Maximum recursion depth (default: 2).
            max_queries: Maximum total API queries to make (default: 100).

        Returns:
            List of newly discovered subdomains.
        """
        if not HAS_REQUESTS or not self.config.api_key:
            return []

        all_discovered: Set[str] = set()
        queried: Set[str] = set()
        query_count = 0

        # Start with all known hostnames as seeds
        current_batch = set(hostnames)
        # Always include the root domain
        current_batch.add(domain)

        for depth in range(max_depth):
            next_batch: Set[str] = set()

            for hostname in sorted(current_batch):
                if query_count >= max_queries:
                    break
                if hostname in queried:
                    continue

                queried.add(hostname)
                query_count += 1

                siblings = self._fetch_siblings(hostname, domain)
                for sib in siblings:
                    if sib not in all_discovered and sib not in hostnames:
                        all_discovered.add(sib)
                        next_batch.add(sib)

                # VT free tier: 4 req/min → sleep ~16s between requests
                # VT premium: higher limits → shorter sleep
                # Use a conservative 16s for free tier safety
                if query_count < max_queries and len(current_batch) > 1:
                    time.sleep(16)

            if not next_batch or query_count >= max_queries:
                break

            current_batch = next_batch

        return list(all_discovered)

    def _fetch_siblings(self, target: str, root_domain: str) -> List[str]:
        """
        Query VT v2 domain/report for a single target and extract
        domain_siblings that belong to the root domain.
        """
        subdomains = []
        try:
            params = {
                "apikey": self.config.api_key,
                "domain": target,
            }
            resp = requests.get(
                self.VT_V2_URL,
                params=params,
                timeout=self.config.timeout,
                headers={"User-Agent": "ReconX/1.0"},
            )

            if resp.status_code == 200:
                data = resp.json()
                # Extract domain_siblings
                siblings = data.get("domain_siblings", [])
                for sib in siblings:
                    name = str(sib).strip().lower()
                    if name and (name.endswith(f".{root_domain}") or name == root_domain):
                        subdomains.append(name)

                # Also extract subdomains field if present
                subs = data.get("subdomains", [])
                for sub in subs:
                    name = str(sub).strip().lower()
                    if not name.endswith(f".{root_domain}"):
                        name = f"{name}.{root_domain}"
                    subdomains.append(name)

            elif resp.status_code == 204:
                # Rate limited — VT returns 204 when quota exceeded
                pass
            elif resp.status_code == 403:
                # Invalid API key
                pass

        except Exception:
            pass

        return subdomains

    def fetch_demo(self, domain: str) -> List[str]:
        """Generate VT siblings demo data."""
        target_count = random.randint(30, 60)
        return self._generate_demo_subdomains(domain, target_count)
