"""
Common Crawl - Web archive subdomain discovery.
Extracts subdomains from Common Crawl's URL index.
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


class CommonCrawlSource(BaseSource):
    """
    Common Crawl data source.
    Discovers subdomains by querying Common Crawl's CDX index for
    URLs matching *.domain. Different dataset from Wayback Machine.
    """
    SOURCE_DESC = "querying Common Crawl index"

    def fetch(self, domain: str) -> List[str]:
        if not HAS_REQUESTS:
            return []

        subdomains = set()
        try:
            # Get latest available indexes
            resp = requests.get(
                "https://index.commoncrawl.org/collinfo.json",
                timeout=self.config.timeout,
                headers={"User-Agent": "ReconX/1.0"},
            )
            if resp.status_code != 200:
                return []

            indexes = resp.json()
            if not indexes:
                return []

            # Query the 2 most recent indexes for good coverage
            from urllib.parse import urlparse
            for idx_info in indexes[:2]:
                api_url = idx_info.get("cdx-api")
                if not api_url:
                    continue
                try:
                    search_url = (
                        f"{api_url}?url=*.{domain}"
                        f"&output=json&fl=url&limit=5000"
                    )
                    resp2 = requests.get(
                        search_url,
                        timeout=max(self.config.timeout, 30),
                        headers={"User-Agent": "ReconX/1.0"},
                    )
                    if resp2.status_code == 200:
                        import json as _json
                        for line in resp2.text.strip().split("\n"):
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                data = _json.loads(line)
                                url_str = data.get("url", "")
                                parsed = urlparse(url_str)
                                hostname = parsed.hostname
                                if hostname:
                                    hostname = hostname.lower()
                                    if (hostname.endswith(f".{domain}")
                                            or hostname == domain):
                                        subdomains.add(hostname)
                            except Exception:
                                pass
                except Exception:
                    pass
        except Exception:
            pass

        return list(subdomains)

    def fetch_demo(self, domain: str) -> List[str]:
        target_count = random.randint(40, 80)
        return self._generate_demo_subdomains(domain, target_count)
