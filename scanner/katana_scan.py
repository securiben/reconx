"""
Katana Web Crawler for ReconX.
Uses ProjectDiscovery's katana CLI for JavaScript-aware web crawling
to discover URLs, endpoints, and hidden paths on HTTP/HTTPS targets.

For domain mode:
  katana -u <url> -jc -js-crawl -jsl -kf all -aff -td -d 5 -c 50 -p 20 -o katana_urls.txt

For domain list (multiple targets):
  katana -list targets.txt -jc -js-crawl -jsl -kf all -aff -td -d 5 -c 50 -p 20 -o katana_urls.txt

Requires: katana from ProjectDiscovery installed in PATH
  Install: go install github.com/projectdiscovery/katana/cmd/katana@latest
  Or:      https://github.com/projectdiscovery/katana/releases
"""

import os
import sys
import shutil
import subprocess
import tempfile
import time
import threading
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from collections import Counter, defaultdict
from urllib.parse import urlparse

from ..config import ScannerConfig
from ..utils import routed_path


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class KatanaURL:
    """A single URL discovered by katana."""
    url: str = ""
    source: str = ""          # where this URL was found (e.g. parent page)
    status_code: int = 0
    content_type: str = ""
    extension: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "source": self.source,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "extension": self.extension,
        }


@dataclass
class KatanaStats:
    """Aggregated katana crawl statistics."""
    total_urls: int = 0
    unique_endpoints: int = 0
    targets_crawled: int = 0
    js_files: int = 0
    api_endpoints: int = 0
    form_actions: int = 0
    scan_time: float = 0.0
    extensions: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "total_urls": self.total_urls,
            "unique_endpoints": self.unique_endpoints,
            "targets_crawled": self.targets_crawled,
            "js_files": self.js_files,
            "api_endpoints": self.api_endpoints,
            "form_actions": self.form_actions,
            "scan_time": self.scan_time,
            "extensions": self.extensions,
        }


class KatanaScanner:
    """
    Katana web crawler wrapper.

    Runs katana CLI against HTTP/HTTPS targets to discover
    URLs, endpoints, JavaScript files, and hidden paths.
    """

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.katana_path = self._find_katana()
        self.available = self.katana_path is not None
        self.results: List[str] = []          # raw URL list
        self.parsed: List[KatanaURL] = []     # parsed results
        self.stats = KatanaStats()

    def _find_katana(self) -> Optional[str]:
        """Find the katana binary in PATH or common install locations."""
        candidates = []

        found = shutil.which("katana")
        if found:
            candidates.append(found)

        common_paths = [
            os.path.expanduser("~/go/bin/katana"),
            os.path.expanduser("~/go/bin/katana.exe"),
            os.path.expanduser("~/.local/bin/katana"),
            "/usr/local/bin/katana",
            "/usr/bin/katana",
        ]
        if os.name == "nt":
            common_paths.extend([
                os.path.join(os.environ.get("GOPATH", ""), "bin", "katana.exe"),
                os.path.join(os.environ.get("USERPROFILE", ""), "go", "bin", "katana.exe"),
            ])

        for path in common_paths:
            if path and os.path.isfile(path) and path not in candidates:
                candidates.append(path)

        for path in candidates:
            if self._verify_katana(path):
                return path

        return None

    def ensure_available(self) -> bool:
        """Attempt auto-install if katana is not available. Returns True if now available."""
        if self.available:
            return True
        from .auto_install import ensure_tool
        if ensure_tool("katana"):
            found = shutil.which("katana")
            if found and self._verify_katana(found):
                self.katana_path = found
                self.available = True
                return True
        return False

    def _verify_katana(self, path: str) -> bool:
        """Verify that the binary is actually ProjectDiscovery katana."""
        try:
            proc = subprocess.run(
                [path, "-version"],
                capture_output=True,
                text=True,
                timeout=15,
                encoding="utf-8",
                errors="replace",
            )
            output = (proc.stdout + proc.stderr).lower()
            if any(kw in output for kw in [
                "projectdiscovery", "katana", "current version",
            ]):
                return True
            return False
        except Exception:
            return False

    @staticmethod
    def get_http_targets_from_nmap(nmap_results: dict) -> Set[str]:
        """
        Extract HTTP/HTTPS targets from nmap results.

        Args:
            nmap_results: Dict of ip → NmapHostResult.

        Returns:
            Set of URLs like http://ip:port or https://ip:port.
        """
        targets: Set[str] = set()
        for ip, host_result in nmap_results.items():
            ports = host_result.ports if hasattr(host_result, 'ports') else []
            for p in ports:
                svc = (p.service if hasattr(p, 'service') else (
                    p.get("service", "") if isinstance(p, dict) else "")) or ""
                svc = svc.lower()
                port_num = p.port if hasattr(p, 'port') else (
                    p.get("port", 80) if isinstance(p, dict) else 80)
                state = p.state if hasattr(p, 'state') else (
                    p.get("state", "") if isinstance(p, dict) else "")
                if state == "open" and svc in (
                    "http", "https", "http-proxy", "https-alt",
                    "http-alt", "ssl/http", "ssl/https",
                ):
                    scheme = "https" if ("https" in svc or "ssl" in svc or port_num == 443) else "http"
                    targets.add(f"{scheme}://{ip}:{port_num}")
        return targets

    @staticmethod
    def get_http_targets_from_httpx(httpx_results: dict) -> Set[str]:
        """
        Extract HTTP/HTTPS targets from httpx results.

        Args:
            httpx_results: Dict of hostname → HttpxResult.

        Returns:
            Set of alive URLs.
        """
        targets: Set[str] = set()
        for hostname, result in httpx_results.items():
            url = ""
            if hasattr(result, 'final_url') and result.final_url:
                url = result.final_url
            elif hasattr(result, 'url') and result.url:
                url = result.url
            elif hasattr(result, 'input') and result.input:
                url = result.input
            if url:
                targets.add(url)
            else:
                # Fallback: construct from hostname
                scheme = result.scheme if hasattr(result, 'scheme') and result.scheme else "https"
                targets.add(f"{scheme}://{hostname}")
        return targets

    def scan(self, targets: List[str],
             output_dir: str = ".") -> List[str]:
        """
        Run katana against HTTP/HTTPS targets.

        Args:
            targets: List of URLs to crawl.
            output_dir: Directory for katana_urls.txt output.

        Returns:
            List of discovered URLs.
        """
        if not self.available:
            return []

        if not targets:
            return []

        # Reset
        self.results = []
        self.parsed = []
        self.stats = KatanaStats()

        scan_start = time.time()
        self.stats.targets_crawled = len(targets)

        # Write targets to temp file
        tmpdir = tempfile.mkdtemp(prefix="reconx_katana_")
        input_file = os.path.join(tmpdir, "targets.txt")

        os.makedirs(output_dir, exist_ok=True)
        output_file = routed_path(output_dir, "katana_urls.txt")

        try:
            with open(input_file, "w", encoding="utf-8") as f:
                for t in targets:
                    f.write(t.strip() + "\n")

            # Build command
            cmd = [
                self.katana_path,
                "-list", input_file,
                "-jc",            # JavaScript crawling
                "-js-crawl",      # Crawl JavaScript files
                "-jsl",           # JavaScript link finding
                "-kf", "all",     # Known files/endpoints
                "-aff",           # Automatic form filling
                "-td",            # Tech detection
                "-d", "5",        # Depth
                "-c", "50",       # Concurrency
                "-p", "20",       # Parallelism
                "-e", "png,jpg,jpeg,gif,svg,ico,webp,css,woff,woff2,ttf,eot,otf,mp4,mp3,avi,mov,wmv",
                "-silent",
                "-o", output_file,
            ]

            timeout_secs = max(600, len(targets) * 60)

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # ── Live spinner progress ──
            spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            spinner_idx = [0]
            url_count = [0]
            bar_width = 30
            num_targets = len(targets)
            scan_label = f"katana crawling: \033[92m{num_targets}\033[0m targets"

            def _draw():
                si = spinner_chars[spinner_idx[0] % len(spinner_chars)]
                spinner_idx[0] += 1
                bar = "\033[92m━\033[0m" * bar_width
                sys.stdout.write(
                    f"\r\033[96m[{si}]\033[0m {scan_label} [{bar}] "
                    f"\033[92m{url_count[0]}\033[0m urls\033[K"
                )
                sys.stdout.flush()

            _draw()
            try:
                while proc.poll() is None:
                    time.sleep(0.15)
                    if os.path.isfile(output_file):
                        try:
                            url_count[0] = sum(1 for _ in open(output_file, encoding="utf-8", errors="replace"))
                        except Exception:
                            pass
                    _draw()
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            # Final count
            if os.path.isfile(output_file):
                try:
                    url_count[0] = sum(1 for _ in open(output_file, encoding="utf-8", errors="replace"))
                except Exception:
                    pass

            # Final status
            bar = "\033[92m━\033[0m" * bar_width
            sys.stdout.write(
                f"\r\033[92m[✓]\033[0m {scan_label} [{bar}] "
                f"\033[92m{url_count[0]}\033[0m urls\033[K\n"
            )
            sys.stdout.flush()

            # Parse results
            if os.path.isfile(output_file) and os.path.getsize(output_file) > 0:
                self._parse_results(output_file)
            elif os.path.isfile(output_file):
                try:
                    os.remove(output_file)
                except Exception:
                    pass

        except FileNotFoundError:
            self.available = False
        except Exception:
            pass
        finally:
            try:
                if os.path.isfile(input_file):
                    os.remove(input_file)
                if os.path.isdir(tmpdir):
                    os.rmdir(tmpdir)
            except Exception:
                pass

        scan_elapsed = time.time() - scan_start
        self._compute_stats(scan_elapsed)

        return self.results

    def _parse_results(self, filepath: str):
        """Parse katana output file (one URL per line)."""
        try:
            seen = set()
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    url = line.strip()
                    if not url:
                        continue
                    if url not in seen:
                        seen.add(url)
                        self.results.append(url)

                        ku = KatanaURL(url=url)
                        # Extract extension
                        try:
                            parsed = urlparse(url)
                            path = parsed.path
                            if "." in path.split("/")[-1]:
                                ku.extension = path.rsplit(".", 1)[-1].lower()[:10]
                        except Exception:
                            pass
                        self.parsed.append(ku)
        except Exception:
            pass

    def _compute_stats(self, scan_time: float):
        """Compute aggregated statistics."""
        self.stats.total_urls = len(self.results)
        self.stats.unique_endpoints = len(set(self.results))
        self.stats.scan_time = scan_time

        # Count by extension
        ext_counts: Dict[str, int] = Counter()
        api_keywords = ("/api/", "/api?", "/graphql", "/v1/", "/v2/", "/v3/",
                        "/rest/", "/json", "/xml", "/swagger", "/openapi")
        js_count = 0
        api_count = 0
        form_count = 0

        for ku in self.parsed:
            if ku.extension:
                ext_counts[ku.extension] += 1
            if ku.extension == "js":
                js_count += 1
            url_lower = ku.url.lower()
            if any(kw in url_lower for kw in api_keywords):
                api_count += 1
            if "action=" in url_lower or "form" in url_lower:
                form_count += 1

        self.stats.js_files = js_count
        self.stats.api_endpoints = api_count
        self.stats.form_actions = form_count
        self.stats.extensions = dict(ext_counts.most_common(20))

    def get_js_urls(self) -> List[str]:
        """Return all discovered JavaScript file URLs."""
        return [ku.url for ku in self.parsed if ku.extension == "js"]

    def get_api_endpoints(self) -> List[str]:
        """Return all discovered API-like endpoints."""
        api_keywords = ("/api/", "/api?", "/graphql", "/v1/", "/v2/", "/v3/",
                        "/rest/", "/json", "/xml", "/swagger", "/openapi")
        return [ku.url for ku in self.parsed
                if any(kw in ku.url.lower() for kw in api_keywords)]

    def get_urls_by_extension(self, ext: str) -> List[str]:
        """Return all URLs with the given file extension."""
        ext = ext.lower().lstrip(".")
        return [ku.url for ku in self.parsed if ku.extension == ext]
