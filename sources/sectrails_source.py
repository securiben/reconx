"""
SecurityTrails - Historical DNS & subdomain intelligence.
Queries SecurityTrails API for subdomain enumeration.
Requires SECURITYTRAILS_API_KEY.
"""

import random
from typing import List
from .base import BaseSource

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class SecurityTrailsSource(BaseSource):
    """
    SecurityTrails data source — discovers subdomains from
    SecurityTrails' massive DNS database.
    Uses /v1/domain/{domain}/subdomains endpoint.
    """
    SOURCE_DESC = "querying SecurityTrails DNS intelligence"

    def fetch(self, domain: str) -> List[str]:
        if not HAS_REQUESTS or not self.config.api_key:
            return []

        subdomains = set()
        headers = {
            "APIKEY": self.config.api_key,
            "User-Agent": "ReconX/1.0",
            "Accept": "application/json",
        }

        # Primary: Subdomains endpoint
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            params = {"children_only": "false", "include_inactive": "true"}
            resp = requests.get(url, headers=headers, params=params, timeout=self.config.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for sub in data.get("subdomains", []):
                    name = f"{sub}.{domain}".lower().strip()
                    if name.endswith(f".{domain}") or name == domain:
                        subdomains.add(name)

                # Handle pagination (endpoint_count > returned)
                endpoint_count = data.get("endpoint_count", 0)
                page = 2
                while len(subdomains) < endpoint_count and page <= 10:
                    try:
                        params2 = {
                            "children_only": "false",
                            "include_inactive": "true",
                            "page": page,
                        }
                        resp2 = requests.get(
                            url, headers=headers, params=params2,
                            timeout=self.config.timeout,
                        )
                        if resp2.status_code == 200:
                            data2 = resp2.json()
                            new_subs = data2.get("subdomains", [])
                            if not new_subs:
                                break
                            for sub in new_subs:
                                name = f"{sub}.{domain}".lower().strip()
                                subdomains.add(name)
                            page += 1
                        else:
                            break
                    except Exception:
                        break
        except Exception:
            pass

        # Secondary: Associated domains & historical DNS
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}"
            resp = requests.get(url, headers=headers, timeout=self.config.timeout)
            if resp.status_code == 200:
                data = resp.json()
                # Current DNS records may reveal related subdomains
                for record_type in ["a", "aaaa", "mx", "ns", "cname"]:
                    records = data.get("current_dns", {}).get(record_type, {})
                    for entry in records.get("values", []):
                        hostname = entry.get("hostname", "")
                        if hostname:
                            hostname = hostname.lower().strip().rstrip(".")
                            if hostname.endswith(f".{domain}") or hostname == domain:
                                subdomains.add(hostname)
        except Exception:
            pass

        # Tertiary: Search via DSL
        try:
            url = "https://api.securitytrails.com/v1/domains/list"
            payload = {
                "filter": {
                    "apex_domain": domain,
                },
            }
            resp = requests.post(
                url, json=payload, headers=headers,
                timeout=self.config.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                for record in data.get("records", []):
                    hostname = record.get("hostname", "").lower().strip()
                    if hostname and (hostname.endswith(f".{domain}") or hostname == domain):
                        subdomains.add(hostname)
        except Exception:
            pass

        return list(subdomains)

    def fetch_demo(self, domain: str) -> List[str]:
        target_count = random.randint(200, 400)
        return self._generate_demo_subdomains(domain, target_count)
