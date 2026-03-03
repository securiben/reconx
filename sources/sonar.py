"""
Sonar - DNS brute-force via wordlist.
Resolves common subdomain prefixes against target domain.
No API key required - uses local DNS resolution.
"""

import os
import random
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseSource

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class SonarSource(BaseSource):
    """
    Sonar data source - DNS brute-force.
    Resolves common subdomain prefixes via DNS to discover
    live subdomains using a built-in wordlist.
    """
    SOURCE_DESC = "DNS brute-force via wordlist"

    def __init__(self, config):
        super().__init__(config)
        self.wordlist_size = 0
        self.resolved_count = 0

    def _load_wordlist(self) -> List[str]:
        """Load the DNS brute-force wordlist."""
        wordlist_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "wordlist.txt"
        )
        if os.path.exists(wordlist_path):
            with open(wordlist_path, "r") as f:
                return [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
        return self._default_wordlist()

    def _default_wordlist(self) -> List[str]:
        """Built-in minimal wordlist if file not found."""
        return [
            "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
            "beta", "app", "portal", "blog", "shop", "store", "secure", "vpn",
            "remote", "cdn", "static", "media", "m", "mobile", "login", "auth",
            "sso", "id", "dashboard", "panel", "webmail", "smtp", "ns1", "ns2",
            "db", "mysql", "redis", "elastic", "jenkins", "gitlab", "jira",
            "wiki", "docs", "support", "status", "monitor", "grafana", "proxy",
            "gateway", "web", "prod", "internal", "vpn1", "backup", "old",
            "new", "legacy", "search", "graphql", "chat", "email", "cloud",
            "log", "sentry", "analytics", "cms", "wp", "demo", "sandbox", "lab",
            "data", "kafka", "vault", "registry", "k8s", "docker", "ci", "cd",
        ]

    def _resolve_hostname(self, hostname: str) -> str:
        """Try to resolve a hostname, return it if successful."""
        from ..utils import resolve_a
        try:
            ips = resolve_a(hostname, timeout=2)
            if ips:
                return hostname
        except Exception:
            pass
        return ""

    def fetch(self, domain: str) -> List[str]:
        """DNS brute-force via built-in wordlist."""
        wordlist = self._load_wordlist()
        self.wordlist_size = len(wordlist)
        found = []

        def check(word):
            hostname = f"{word}.{domain}"
            return self._resolve_hostname(hostname)

        max_workers = min(100, len(wordlist))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check, w): w for w in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        self.resolved_count = len(found)
        return found

    def fetch_demo(self, domain: str) -> List[str]:
        """Generate Sonar demo data (~56 subdomains)."""
        target_count = random.randint(50, 65)
        return self._generate_demo_subdomains(domain, target_count)
