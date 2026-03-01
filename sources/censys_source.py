"""
Censys - Certificate & host search intelligence.
Queries Censys Search API v2 for subdomain discovery.
Supports: CENSYS_API_KEY (combined or 'id:secret'), CENSYS_API_ID + CENSYS_API_SECRET.
Falls back to free crt.sh-based Censys community if key fails.
"""

import os
import random
from typing import List, Optional, Tuple
from .base import BaseSource

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class CensysSource(BaseSource):
    """
    Censys data source — discovers subdomains from Censys certificate + host search.
    Tries multiple auth methods: Basic Auth (id:secret), Bearer token, env vars.
    Falls back to community search.censys.io if API auth fails.
    """
    SOURCE_DESC = "querying Censys certificate search"

    def _get_auth(self) -> Optional[Tuple[str, str]]:
        """Parse Censys API credentials. Returns (api_id, api_secret) or None."""
        key = self.config.api_key or ""
        # Try id:secret format
        if ":" in key and not key.startswith("censys_"):
            parts = key.split(":", 1)
            return (parts[0], parts[1])
        # Try separate env vars
        api_id = os.getenv("CENSYS_API_ID", "")
        api_secret = os.getenv("CENSYS_API_SECRET", "")
        if api_id and api_secret:
            return (api_id, api_secret)
        return None

    def _extract_names(self, data: dict, domain: str) -> set:
        """Extract valid subdomains from a Censys API response."""
        subdomains = set()
        for hit in data.get("result", {}).get("hits", []):
            # Certificate names
            for name in hit.get("names", []):
                name = name.lower().strip()
                if name.startswith("*."):
                    name = name[2:]
                if name.endswith(f".{domain}") or name == domain:
                    subdomains.add(name)
            # Host name field
            for name in hit.get("name", "").split(","):
                name = name.lower().strip()
                if name.endswith(f".{domain}") or name == domain:
                    subdomains.add(name)
            # Services → TLS cert names
            for svc in hit.get("services", []):
                tls = svc.get("tls", {})
                cert = tls.get("certificates", {}).get("leaf", {})
                for name in cert.get("names", []):
                    name = name.lower().strip()
                    if name.startswith("*."):
                        name = name[2:]
                    if name.endswith(f".{domain}") or name == domain:
                        subdomains.add(name)
        return subdomains

    def _search_api(self, domain: str, auth: Tuple[str, str]) -> set:
        """Search via Censys REST API v2 with Basic Auth."""
        subdomains = set()
        headers = {"User-Agent": "ReconX/1.0", "Accept": "application/json"}

        # Certificates search
        try:
            url = "https://search.censys.io/api/v2/certificates/search"
            payload = {"q": f"names: *.{domain}", "per_page": 100}
            resp = requests.post(url, json=payload, auth=auth, headers=headers,
                                 timeout=self.config.timeout)
            if resp.status_code == 200:
                data = resp.json()
                subdomains |= self._extract_names(data, domain)
                # Paginate up to 5 pages
                cursor = data.get("result", {}).get("links", {}).get("next", "")
                for _ in range(4):
                    if not cursor:
                        break
                    payload["cursor"] = cursor
                    resp2 = requests.post(url, json=payload, auth=auth,
                                          headers=headers, timeout=self.config.timeout)
                    if resp2.status_code != 200:
                        break
                    data2 = resp2.json()
                    subdomains |= self._extract_names(data2, domain)
                    cursor = data2.get("result", {}).get("links", {}).get("next", "")
        except Exception:
            pass

        # Hosts search
        try:
            url = "https://search.censys.io/api/v2/hosts/search"
            params = {"q": f"services.tls.certificates.leaf.names: *.{domain}", "per_page": 100}
            resp = requests.get(url, params=params, auth=auth, headers=headers,
                                timeout=self.config.timeout)
            if resp.status_code == 200:
                subdomains |= self._extract_names(resp.json(), domain)
        except Exception:
            pass

        return subdomains

    def _search_community(self, domain: str) -> set:
        """Fallback: use free Censys community website scraping + certs API."""
        subdomains = set()
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

        # Method 1: Censys community search (no auth, scrape HTML)
        try:
            url = f"https://search.censys.io/search?resource=hosts&q={domain}"
            resp = requests.get(url, headers=headers, timeout=self.config.timeout)
            if resp.status_code == 200:
                import re
                # Extract hostnames from the HTML response
                pattern = re.compile(
                    r'([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?'
                    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)*'
                    r'\.' + re.escape(domain) + r')',
                    re.IGNORECASE,
                )
                for match in pattern.finditer(resp.text):
                    name = match.group(0).lower().strip()
                    if name.endswith(f".{domain}") or name == domain:
                        subdomains.add(name)
        except Exception:
            pass

        # Method 2: crt.sh Censys companion — certspotter approach
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, headers={"User-Agent": "ReconX/1.0"},
                                timeout=max(self.config.timeout, 45))
            if resp.status_code == 200:
                for entry in resp.json():
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower()
                        if name.startswith("*."):
                            name = name[2:]
                        if name and (name.endswith(f".{domain}") or name == domain):
                            subdomains.add(name)
        except Exception:
            pass

        return subdomains

    def fetch(self, domain: str) -> List[str]:
        if not HAS_REQUESTS:
            return []

        subdomains = set()

        # Try API auth first
        auth = self._get_auth()
        if auth:
            subdomains = self._search_api(domain, auth)

        # Fallback to community search if API returned nothing
        if not subdomains:
            subdomains = self._search_community(domain)

        return list(subdomains)

    def fetch_demo(self, domain: str) -> List[str]:
        target_count = random.randint(80, 180)
        return self._generate_demo_subdomains(domain, target_count)
