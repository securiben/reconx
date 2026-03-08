"""
Torrent - Wayback Machine CDX subdomain discovery.
Extracts subdomains from Internet Archive's URL index.
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


class TorrentSource(BaseSource):
    """
    Torrent data source - Wayback Machine CDX.
    Discovers subdomains from Internet Archive's CDX URL index.
    """
    SOURCE_DESC = "querying Wayback Machine CDX index"

    def fetch(self, domain: str) -> List[str]:
        """Fetch subdomains from Wayback Machine CDX API."""
        if not HAS_REQUESTS:
            return []

        subdomains = set()
        try:
            from urllib.parse import urlparse
            url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=5000"
            )
            resp = requests.get(
                url, timeout=self.config.timeout,
                headers={"User-Agent": "ReconX/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                for row in data[1:]:  # skip header row
                    try:
                        parsed = urlparse(row[0])
                        hostname = parsed.hostname
                        if hostname:
                            hostname = hostname.lower()
                            if hostname.endswith(f".{domain}") or hostname == domain:
                                subdomains.add(hostname)
                    except Exception:
                        pass
        except Exception:
            pass

        return list(subdomains)

    def fetch_demo(self, domain: str) -> List[str]:
        """Generate Torrent demo data (~101 subdomains)."""
        target_count = random.randint(90, 115)
        return self._generate_demo_subdomains(domain, target_count)
