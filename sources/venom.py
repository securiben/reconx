"""
Venom - Multi-source subdomain intelligence.
Queries Anubis, VirusTotal, ThreatMiner, and other free APIs.
Falls back through multiple providers if primary sources fail.
"""

import random
import time
from typing import List
from .base import BaseSource

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class VenomSource(BaseSource):
    """
    Venom data source - aggregates from multiple free subdomain APIs.
    Priority chain: Anubis → VirusTotal → ThreatMiner → AlienVault → crt.sh
    """
    SOURCE_DESC = "querying VirusTotal passive DNS"

    def fetch(self, domain: str) -> List[str]:
        """Fetch subdomains from multiple sources with fallbacks."""
        if not HAS_REQUESTS:
            return []

        subdomains = set()
        ua = {"User-Agent": "ReconX/1.0"}
        timeout = self.config.timeout

        # ── Source 1: Anubis (jldc.me) - free, no key ────────────────────
        try:
            url = f"https://jldc.me/anubis/subdomains/{domain}"
            resp = requests.get(url, timeout=timeout, headers=ua)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    for name in data:
                        name = str(name).strip().lower()
                        if name and (name.endswith(f".{domain}") or name == domain):
                            subdomains.add(name)
        except Exception:
            pass

        # ── Source 2: VirusTotal (API key optional, better with key) ─────
        if self.config.api_key:
            try:
                cursor = ""
                for _ in range(3):  # up to 3 pages (fast)
                    vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
                    headers = {"x-apikey": self.config.api_key, "User-Agent": "ReconX/1.0"}
                    params = {"limit": 40}
                    if cursor:
                        params["cursor"] = cursor
                    resp = requests.get(vt_url, headers=headers, params=params, timeout=timeout)
                    if resp.status_code == 200:
                        data = resp.json()
                        items = data.get("data", [])
                        for item in items:
                            name = item.get("id", "").strip().lower()
                            if name and (name.endswith(f".{domain}") or name == domain):
                                subdomains.add(name)
                        # Check for pagination cursor
                        cursor = data.get("meta", {}).get("cursor", "")
                        if not cursor or not items:
                            break
                        time.sleep(0.1)  # Brief VT rate limit pause
                    elif resp.status_code == 429:
                        # Rate limited, skip remaining pages
                        break
                    else:
                        break
            except Exception:
                pass

        # ── Source 3: ThreatMiner - free, no key ─────────────────────────
        try:
            url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
            resp = requests.get(url, timeout=timeout, headers=ua)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status_code") == "200":
                    for name in data.get("results", []):
                        name = str(name).strip().lower()
                        if name and (name.endswith(f".{domain}") or name == domain):
                            subdomains.add(name)
        except Exception:
            pass

        # ── Source 4: AlienVault OTX passive DNS (no key needed) ─────────
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            resp = requests.get(url, timeout=timeout, headers=ua)
            if resp.status_code == 200:
                data = resp.json()
                for record in data.get("passive_dns", []):
                    hostname = record.get("hostname", "").strip().lower()
                    if hostname and (hostname.endswith(f".{domain}") or hostname == domain):
                        subdomains.add(hostname)
        except Exception:
            pass

        # ── Source 5: RapidDNS - free, no key ────────────────────────────
        try:
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            resp = requests.get(url, timeout=timeout, headers=headers)
            if resp.status_code == 200:
                import re
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

        return list(subdomains)

    def fetch_demo(self, domain: str) -> List[str]:
        """Generate Venom demo data (~578 subdomains)."""
        target_count = random.randint(560, 600)
        return self._generate_demo_subdomains(domain, target_count)
