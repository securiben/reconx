"""
FOFA - Cyberspace search engine subdomain discovery.
Queries FOFA API for host discovery.
Requires FOFA_EMAIL and FOFA_API_KEY.
"""

import os
import base64
import random
from typing import List
from .base import BaseSource

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class FOFASource(BaseSource):
    """
    FOFA data source — cyberspace search engine.
    Discovers subdomains through FOFA's indexed internet-wide scanning
    data using the domain= search query.
    """
    SOURCE_DESC = "querying FOFA cyberspace search"

    def fetch(self, domain: str) -> List[str]:
        if not HAS_REQUESTS or not self.config.api_key:
            return []

        email = os.getenv("FOFA_EMAIL", "")
        if not email:
            return []

        subdomains = set()
        try:
            query = f'domain="{domain}"'
            query_b64 = base64.b64encode(query.encode()).decode()
            url = (
                f"https://fofa.info/api/v1/search/all"
                f"?email={email}&key={self.config.api_key}"
                f"&qbase64={query_b64}&size=500&fields=host"
            )
            headers = {"User-Agent": "ReconX/1.0"}
            resp = requests.get(url, headers=headers, timeout=self.config.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("error") is False or "results" in data:
                    for row in data.get("results", []):
                        hostname = row[0] if isinstance(row, list) else str(row)
                        hostname = hostname.lower().strip()
                        # Remove protocol prefix if present
                        if "://" in hostname:
                            from urllib.parse import urlparse
                            hostname = urlparse(hostname).hostname or hostname
                        # Remove port suffix if present
                        if ":" in hostname:
                            hostname = hostname.split(":")[0]
                        if hostname and (hostname.endswith(f".{domain}")
                                         or hostname == domain):
                            subdomains.add(hostname)
        except Exception:
            pass

        return list(subdomains)

    def fetch_demo(self, domain: str) -> List[str]:
        target_count = random.randint(50, 100)
        return self._generate_demo_subdomains(domain, target_count)
