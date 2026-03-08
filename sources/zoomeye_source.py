"""
ZoomEye - Cyberspace search engine subdomain discovery.
Queries ZoomEye API for domain/host data.
Requires ZOOMEYE_API_KEY.
"""

import random
from typing import List
from .base import BaseSource

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class ZoomEyeSource(BaseSource):
    """
    ZoomEye data source — cyberspace search engine.
    Discovers subdomains through ZoomEye's domain search and
    SSL certificate subject CN matching.
    """
    SOURCE_DESC = "querying ZoomEye cyberspace search"

    def fetch(self, domain: str) -> List[str]:
        if not HAS_REQUESTS or not self.config.api_key:
            return []

        subdomains = set()

        # ── Domain search endpoint ───────────────────────────────────
        try:
            url = "https://api.zoomeye.hk/domain/search"
            headers = {
                "API-KEY": self.config.api_key,
                "User-Agent": "ReconX/1.0",
            }
            params = {"q": domain, "type": "1", "page": 1}

            for page in range(1, 6):  # up to 5 pages
                params["page"] = page
                resp = requests.get(
                    url, headers=headers, params=params,
                    timeout=self.config.timeout,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    records = data.get("list", [])
                    if not records:
                        break
                    for rec in records:
                        name = rec.get("name", "").lower().strip()
                        if name and (name.endswith(f".{domain}")
                                     or name == domain):
                            subdomains.add(name)
                elif resp.status_code == 429:
                    break
                else:
                    break
        except Exception:
            pass

        # ── SSL certificate subject search ───────────────────────────
        try:
            url = "https://api.zoomeye.hk/host/search"
            headers = {
                "API-KEY": self.config.api_key,
                "User-Agent": "ReconX/1.0",
            }
            params = {
                "query": f'ssl.cert.subject.cn:"{domain}"',
                "page": 1,
            }
            resp = requests.get(
                url, headers=headers, params=params,
                timeout=self.config.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                for match in data.get("matches", []):
                    ssl_info = match.get("ssl", {})
                    cn = (ssl_info.get("cert", {})
                          .get("subject", {}).get("CN", ""))
                    if cn:
                        cn = cn.lower().strip()
                        if (not cn.startswith("*")
                                and (cn.endswith(f".{domain}")
                                     or cn == domain)):
                            subdomains.add(cn)
                    for h in match.get("rdns", []):
                        h = h.lower().strip()
                        if h.endswith(f".{domain}") or h == domain:
                            subdomains.add(h)
        except Exception:
            pass

        return list(subdomains)

    def fetch_demo(self, domain: str) -> List[str]:
        target_count = random.randint(30, 80)
        return self._generate_demo_subdomains(domain, target_count)
