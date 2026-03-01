"""
Infrastructure Scanner - Classifies subdomains by cloud provider.
Identifies AWS, Azure, Cloudflare, Akamai, and other providers.
"""

import random
from typing import Dict, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models import InfraStats, Subdomain, InfraProvider
from ..utils import resolve_cname, resolve_a, classify_provider
from ..config import ScannerConfig


class InfrastructureScanner:
    """
    Classifies discovered subdomains into infrastructure providers
    based on CNAME records, IP address ranges, and known patterns.
    """

    def __init__(self, config: ScannerConfig):
        self.config = config

    def scan(self, subdomains: List[Subdomain]) -> InfraStats:
        """
        Classify all subdomains by infrastructure provider.
        Uses concurrent DNS resolution for speed.
        """
        stats = InfraStats()

        def classify_single(sub: Subdomain) -> Tuple[Subdomain, str]:
            cnames = resolve_cname(sub.hostname, timeout=self.config.timeout)
            ips = resolve_a(sub.hostname, timeout=self.config.timeout)
            sub.cnames = cnames
            sub.ip_addresses = ips
            # If no DNS data at all, this is a CT-only entry
            if not cnames and not ips:
                sub.is_alive = False
                return sub, "CT-only"
            sub.is_alive = True
            provider = classify_provider(sub.hostname, cnames, ips)
            return sub, provider

        with ThreadPoolExecutor(max_workers=self.config.concurrency) as executor:
            futures = {
                executor.submit(classify_single, sub): sub
                for sub in subdomains
            }
            for future in as_completed(futures):
                try:
                    sub, provider = future.result()
                    if provider == "AWS":
                        stats.aws += 1
                        sub.provider = InfraProvider.AWS
                    elif provider == "Azure":
                        stats.azure += 1
                        sub.provider = InfraProvider.AZURE
                    elif provider == "Cloudflare":
                        stats.cloudflare += 1
                        sub.provider = InfraProvider.CLOUDFLARE
                    elif provider == "Akamai":
                        stats.akamai += 1
                        sub.provider = InfraProvider.AKAMAI
                    elif provider == "CT-only":
                        stats.ct_only += 1
                        sub.provider = InfraProvider.CT_ONLY
                    else:
                        stats.other += 1
                        sub.provider = InfraProvider.OTHER
                except Exception:
                    stats.ct_only += 1

        return stats

    def scan_demo(self, total: int) -> InfraStats:
        """Generate demo infrastructure stats matching reference output."""
        stats = InfraStats()
        stats.aws = random.randint(10, 20)
        stats.azure = random.randint(2, 8)
        stats.cloudflare = random.randint(18, 30)
        stats.akamai = random.randint(1, 3)
        stats.other = random.randint(5, 12)
        assigned = stats.aws + stats.azure + stats.cloudflare + stats.akamai + stats.other
        stats.ct_only = max(0, total - assigned)
        return stats
