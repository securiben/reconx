"""
ASN Expansion - Discovers subdomains via ASN/netblock reverse lookups.
Resolves the target domain to IPs, finds the owning ASN,
then discovers additional subdomains via reverse DNS in those netblocks.
Free, no API key required.
"""

import random
import socket
from typing import List
from .base import BaseSource

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class ASNExpansionSource(BaseSource):
    """
    ASN Expansion data source.
    Discovers subdomains by:
    1. Resolving the target domain to seed IPs
    2. Looking up the ASN for those IPs via BGPView
    3. Running reverse IP lookups to find additional subdomains
       belonging to the same organization/netblock
    """
    SOURCE_DESC = "querying ASN/netblock expansion"

    def fetch(self, domain: str) -> List[str]:
        if not HAS_REQUESTS:
            return []

        subdomains = set()
        seed_ips = set()
        ua = {"User-Agent": "ReconX/1.0"}

        # 1. Resolve domain to seed IPs
        try:
            for info in socket.getaddrinfo(domain, None, socket.AF_INET):
                seed_ips.add(info[4][0])
        except Exception:
            pass

        if not seed_ips:
            return []

        # 2. Look up ASN info via BGPView
        seen_asns = set()
        for ip in list(seed_ips)[:3]:
            try:
                resp = requests.get(
                    f"https://api.bgpview.io/ip/{ip}",
                    timeout=self.config.timeout, headers=ua,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    for pfx in data.get("prefixes", []):
                        asn = pfx.get("asn", {}).get("asn")
                        if asn:
                            seen_asns.add(asn)
            except Exception:
                pass

        # 3. Reverse IP lookup on seed IPs via HackerTarget
        for ip in list(seed_ips)[:5]:
            try:
                resp = requests.get(
                    f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                    timeout=self.config.timeout, headers=ua,
                )
                if resp.status_code == 200 and "API count exceeded" not in resp.text:
                    for line in resp.text.strip().split("\n"):
                        hostname = line.strip().lower()
                        if hostname and (hostname.endswith(f".{domain}")
                                         or hostname == domain):
                            subdomains.add(hostname)
            except Exception:
                pass

        # 4. Query BGPView ASN peers for related description lookups
        for asn in list(seen_asns)[:2]:
            try:
                resp = requests.get(
                    f"https://api.bgpview.io/asn/{asn}/prefixes",
                    timeout=self.config.timeout, headers=ua,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    for pfx in data.get("ipv4_prefixes", [])[:10]:
                        prefix_ip = pfx.get("prefix", "").split("/")[0]
                        if prefix_ip and prefix_ip not in seed_ips:
                            # Reverse lookup a sample IP from each prefix
                            try:
                                resp2 = requests.get(
                                    f"https://api.hackertarget.com/reverseiplookup/?q={prefix_ip}",
                                    timeout=self.config.timeout, headers=ua,
                                )
                                if (resp2.status_code == 200
                                        and "API count exceeded" not in resp2.text):
                                    for line in resp2.text.strip().split("\n"):
                                        hostname = line.strip().lower()
                                        if hostname and (hostname.endswith(f".{domain}")
                                                         or hostname == domain):
                                            subdomains.add(hostname)
                            except Exception:
                                pass
            except Exception:
                pass

        return list(subdomains)

    def fetch_demo(self, domain: str) -> List[str]:
        target_count = random.randint(10, 30)
        return self._generate_demo_subdomains(domain, target_count)
