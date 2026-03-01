"""
URLScan.io - Website scanning & subdomain intelligence.
Queries URLScan.io search API for subdomain discovery.
Can work without key (limited), much better with URLSCAN_API_KEY.
"""

import random
from typing import List
from .base import BaseSource

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class URLScanSource(BaseSource):
    """
    URLScan.io data source — discovers subdomains from URLScan's
    website scan database.
    Uses /api/v1/search endpoint to find scanned pages matching the domain.
    """
    SOURCE_DESC = "querying URLScan.io web intelligence"

    def fetch(self, domain: str) -> List[str]:
        if not HAS_REQUESTS:
            return []

        subdomains = set()
        headers = {"User-Agent": "ReconX/1.0"}
        if self.config.api_key:
            headers["API-Key"] = self.config.api_key

        # Search for scanned pages under this domain
        try:
            url = "https://urlscan.io/api/v1/search/"
            params = {
                "q": f"domain:{domain}",
                "size": 1000,
            }
            resp = requests.get(url, headers=headers, params=params, timeout=self.config.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    # Primary: page.domain
                    page_domain = page.get("domain", "").lower().strip()
                    if page_domain and (page_domain.endswith(f".{domain}") or page_domain == domain):
                        subdomains.add(page_domain)
                    # Also: task.domain
                    task_domain = result.get("task", {}).get("domain", "").lower().strip()
                    if task_domain and (task_domain.endswith(f".{domain}") or task_domain == domain):
                        subdomains.add(task_domain)

                # Paginate if has_more
                search_after = data.get("has_more", False)
                results_list = data.get("results", [])
                page_count = 1
                while search_after and results_list and page_count < 5:
                    try:
                        last = results_list[-1]
                        sort_val = last.get("sort", [])
                        if not sort_val:
                            break
                        params2 = {
                            "q": f"domain:{domain}",
                            "size": 1000,
                            "search_after": ",".join(str(s) for s in sort_val),
                        }
                        resp2 = requests.get(
                            url, headers=headers, params=params2,
                            timeout=self.config.timeout,
                        )
                        if resp2.status_code == 200:
                            data2 = resp2.json()
                            results_list = data2.get("results", [])
                            for result in results_list:
                                page = result.get("page", {})
                                page_domain = page.get("domain", "").lower().strip()
                                if page_domain and (page_domain.endswith(f".{domain}") or page_domain == domain):
                                    subdomains.add(page_domain)
                                task_domain = result.get("task", {}).get("domain", "").lower().strip()
                                if task_domain and (task_domain.endswith(f".{domain}") or task_domain == domain):
                                    subdomains.add(task_domain)
                            search_after = data2.get("has_more", False)
                            page_count += 1
                        else:
                            break
                    except Exception:
                        break
        except Exception:
            pass

        # Secondary: Search by hostname wildcard
        try:
            url2 = "https://urlscan.io/api/v1/search/"
            params2 = {
                "q": f"page.domain:*.{domain}",
                "size": 1000,
            }
            resp = requests.get(url2, headers=headers, params=params2, timeout=self.config.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    page_domain = page.get("domain", "").lower().strip()
                    if page_domain and (page_domain.endswith(f".{domain}") or page_domain == domain):
                        subdomains.add(page_domain)
        except Exception:
            pass

        return list(subdomains)

    def fetch_demo(self, domain: str) -> List[str]:
        target_count = random.randint(40, 100)
        return self._generate_demo_subdomains(domain, target_count)
