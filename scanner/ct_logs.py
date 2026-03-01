"""
Certificate Transparency Log Scanner.
Queries CT logs and triages entries by age.
"""

import random
from typing import List, Tuple
from datetime import datetime, timedelta

from ..models import CTEntry
from ..config import ScannerConfig

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class CTLogScanner:
    """
    Scans Certificate Transparency logs to discover subdomains
    and triage certificate entries by age.
    """

    def __init__(self, config: ScannerConfig):
        self.config = config

    def scan(self, domain: str) -> Tuple[List[CTEntry], List[str]]:
        """
        Query CT logs for the given domain.
        Returns (ct_entries, discovered_subdomains).
        """
        entries = []
        subdomains = set()

        if HAS_REQUESTS:
            try:
                # Query crt.sh — needs longer timeout (crt.sh is slow)
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                resp = requests.get(url, timeout=max(self.config.timeout, 60))
                if resp.status_code == 200:
                    for item in resp.json():
                        name = item.get("name_value", "")
                        # Handle wildcard and multi-line entries
                        for hostname in name.split("\n"):
                            hostname = hostname.strip().lstrip("*.")
                            if hostname and hostname.endswith(domain):
                                subdomains.add(hostname)
                                entry = CTEntry(
                                    subdomain=hostname,
                                    issuer=item.get("issuer_name", ""),
                                    serial=item.get("serial_number", ""),
                                    source="crt.sh",
                                )
                                # Parse dates
                                try:
                                    nb = item.get("not_before", "")
                                    if nb:
                                        entry.not_before = datetime.fromisoformat(
                                            nb.replace("Z", "+00:00").replace("+00:00", "")
                                        )
                                except Exception:
                                    pass
                                try:
                                    na = item.get("not_after", "")
                                    if na:
                                        entry.not_after = datetime.fromisoformat(
                                            na.replace("Z", "+00:00").replace("+00:00", "")
                                        )
                                except Exception:
                                    pass

                                entries.append(entry)
            except Exception:
                pass

        return entries, list(subdomains)

    def triage(self, entries: List[CTEntry]) -> Tuple[int, int, int]:
        """
        Triage CT entries by age.
        Returns (stale_count, aged_count, no_date_count).
        """
        stale = 0   # 1-2 years
        aged = 0    # 2+ years
        no_date = 0

        for entry in entries:
            cat = entry.age_category
            if cat == "stale":
                stale += 1
            elif cat == "aged":
                aged += 1
            elif cat == "no_date":
                no_date += 1

        return stale, aged, no_date

    def scan_demo(self, domain: str, total_subs: int) -> Tuple[List[CTEntry], int, int, int]:
        """Generate demo CT log data."""
        entries = []
        now = datetime.utcnow()

        # Generate varied entries
        for i in range(total_subs):
            entry = CTEntry(
                subdomain=f"sub-{i}.{domain}",
                issuer="Let's Encrypt Authority X3",
                source="crt.sh",
            )
            # Distribute ages: ~33% stale, ~38% aged, ~27% no_date
            roll = random.random()
            if roll < 0.33:
                # Stale: 1-2 years old
                days = random.randint(365, 730)
                entry.not_before = now - timedelta(days=days)
            elif roll < 0.71:
                # Aged: 2+ years
                days = random.randint(731, 2000)
                entry.not_before = now - timedelta(days=days)
            else:
                # No date
                entry.not_before = None

            entries.append(entry)

        stale, aged, no_date = self.triage(entries)
        return entries, stale, aged, no_date
