"""
WPScan Scanner for ReconX.
Runs wpscan against targets identified as WordPress by nuclei results.

Detection: checks nuclei findings for WordPress indicators:
  - template_id contains 'wordpress' or 'wp-'
  - tags contain 'wordpress' or 'wp-plugin' or 'wp-theme'
  - template_name contains 'WordPress'

Command:
  wpscan --url <URL> \
    --api-token <TOKEN> \
    --enumerate vp,ap,vt,at,tt,cb,dbe \
    --plugins-detection mixed \
    --output wpscan_results.txt

Requires: wpscan installed in PATH
  Install: gem install wpscan
  Or:      https://github.com/wpscanteam/wpscan
"""

import os
import re
import sys
import json
import shutil
import subprocess
import time as _time
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field

from ..config import ScannerConfig


# ─── WordPress detection keywords ────────────────────────────────────────────

WP_TEMPLATE_KEYWORDS = [
    "wordpress", "wp-", "wp_",
]

WP_TAG_KEYWORDS = [
    "wordpress", "wp-plugin", "wp-theme", "wp-core",
]

WP_NAME_KEYWORDS = [
    "wordpress", "wp-content", "wp-includes", "wp-admin",
]

# ─── Default API token ───────────────────────────────────────────────────────

DEFAULT_API_TOKEN = "kWBU7sDaQRrEpjYX7UsNujZotvd6awLHGnEBKWbmJ3I"


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class WPScanVulnerability:
    """A single vulnerability found by WPScan."""
    title: str = ""
    vuln_type: str = ""            # e.g., "SSRF", "XSS", "SQLi", "RCE"
    fixed_in: str = ""
    references: List[str] = field(default_factory=list)
    cvss: str = ""
    cve: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "vuln_type": self.vuln_type,
            "fixed_in": self.fixed_in,
            "references": self.references,
            "cvss": self.cvss,
            "cve": self.cve,
        }


@dataclass
class WPScanPlugin:
    """A detected WordPress plugin."""
    slug: str = ""
    title: str = ""
    version: str = ""
    outdated: bool = False
    vulnerabilities: List[WPScanVulnerability] = field(default_factory=list)
    location: str = ""

    def to_dict(self) -> dict:
        return {
            "slug": self.slug,
            "title": self.title or self.slug,
            "version": self.version,
            "outdated": self.outdated,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "location": self.location,
        }


@dataclass
class WPScanTheme:
    """A detected WordPress theme."""
    slug: str = ""
    title: str = ""
    version: str = ""
    outdated: bool = False
    vulnerabilities: List[WPScanVulnerability] = field(default_factory=list)
    location: str = ""

    def to_dict(self) -> dict:
        return {
            "slug": self.slug,
            "title": self.title or self.slug,
            "version": self.version,
            "outdated": self.outdated,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "location": self.location,
        }


@dataclass
class WPScanUser:
    """A detected WordPress user."""
    id: int = 0
    username: str = ""
    display_name: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "display_name": self.display_name,
        }


@dataclass
class WPScanHostResult:
    """WPScan results for a single WordPress target."""
    url: str = ""
    wp_version: str = ""
    wp_version_status: str = ""    # "latest", "outdated", "insecure"
    main_theme: str = ""
    plugins: List[WPScanPlugin] = field(default_factory=list)
    themes: List[WPScanTheme] = field(default_factory=list)
    users: List[WPScanUser] = field(default_factory=list)
    vulnerabilities: List[WPScanVulnerability] = field(default_factory=list)
    interesting_findings: List[str] = field(default_factory=list)
    config_backups: List[str] = field(default_factory=list)
    db_exports: List[str] = field(default_factory=list)
    scan_time: float = 0.0
    error: str = ""

    @property
    def total_vulns(self) -> int:
        count = len(self.vulnerabilities)
        for p in self.plugins:
            count += len(p.vulnerabilities)
        for t in self.themes:
            count += len(t.vulnerabilities)
        return count

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "wp_version": self.wp_version,
            "wp_version_status": self.wp_version_status,
            "main_theme": self.main_theme,
            "plugins": [p.to_dict() for p in self.plugins],
            "themes": [t.to_dict() for t in self.themes],
            "users": [u.to_dict() for u in self.users],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "interesting_findings": self.interesting_findings,
            "config_backups": self.config_backups,
            "db_exports": self.db_exports,
            "total_vulns": self.total_vulns,
            "scan_time": self.scan_time,
            "error": self.error,
        }


@dataclass
class WPScanStats:
    """Aggregated WPScan statistics."""
    targets_scanned: int = 0
    targets_with_vulns: int = 0
    total_vulns: int = 0
    total_plugins: int = 0
    total_themes: int = 0
    total_users: int = 0
    outdated_plugins: int = 0
    outdated_themes: int = 0
    config_backups: int = 0
    db_exports: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "targets_scanned": self.targets_scanned,
            "targets_with_vulns": self.targets_with_vulns,
            "total_vulns": self.total_vulns,
            "total_plugins": self.total_plugins,
            "total_themes": self.total_themes,
            "total_users": self.total_users,
            "outdated_plugins": self.outdated_plugins,
            "outdated_themes": self.outdated_themes,
            "config_backups": self.config_backups,
            "db_exports": self.db_exports,
            "scan_time": self.scan_time,
        }


class WPScanner:
    """
    WPScan wrapper for ReconX.
    Runs wpscan CLI against WordPress targets detected by nuclei.
    """

    def __init__(self, config: ScannerConfig, api_token: str = ""):
        self.config = config
        self.api_token = api_token or DEFAULT_API_TOKEN
        self.wpscan_path = self._find_wpscan()
        self.available = self.wpscan_path is not None
        self.results: Dict[str, WPScanHostResult] = {}
        self.stats = WPScanStats()

    def _find_wpscan(self) -> Optional[str]:
        """Find the wpscan binary in PATH."""
        candidates = []

        found = shutil.which("wpscan")
        if found:
            candidates.append(found)

        # Common locations
        common_paths = [
            "/usr/local/bin/wpscan",
            "/usr/bin/wpscan",
            os.path.expanduser("~/.local/bin/wpscan"),
            os.path.expanduser("~/bin/wpscan"),
        ]
        if os.name == "nt":
            common_paths.extend([
                os.path.join(os.environ.get("GEM_HOME", ""), "bin", "wpscan"),
                os.path.join(os.environ.get("GEM_HOME", ""), "bin", "wpscan.bat"),
            ])

        for path in common_paths:
            if path and os.path.isfile(path) and path not in candidates:
                candidates.append(path)

        for path in candidates:
            if self._verify_wpscan(path):
                return path

        return None

    def _verify_wpscan(self, path: str) -> bool:
        """Verify the binary is actually wpscan."""
        try:
            proc = subprocess.run(
                [path, "--version"],
                capture_output=True,
                text=True,
                timeout=15,
                encoding="utf-8",
                errors="replace",
            )
            output = (proc.stdout + proc.stderr).lower()
            # wpscan version output contains version number
            if any(c.isdigit() for c in output):
                return True
            return False
        except Exception:
            return False

    @staticmethod
    def detect_wordpress_targets(nuclei_results: list) -> Set[str]:
        """
        Detect WordPress targets from nuclei findings.

        Checks template_id, tags, and template_name for WordPress indicators.
        Returns a set of URLs/hosts running WordPress.
        """
        wp_hosts: Set[str] = set()

        for finding in nuclei_results:
            is_wp = False

            # Get fields (handle both object and dict)
            template_id = (finding.template_id if hasattr(finding, 'template_id')
                           else finding.get('template_id', ''))
            template_name = (finding.template_name if hasattr(finding, 'template_name')
                             else finding.get('template_name', ''))
            tags = (finding.tags if hasattr(finding, 'tags')
                    else finding.get('tags', []))
            host = (finding.host if hasattr(finding, 'host')
                    else finding.get('host', ''))
            matched_at = (finding.matched_at if hasattr(finding, 'matched_at')
                          else finding.get('matched_at', host))

            if not host:
                continue

            # Check template_id
            tid_lower = template_id.lower()
            for kw in WP_TEMPLATE_KEYWORDS:
                if kw in tid_lower:
                    is_wp = True
                    break

            # Check tags
            if not is_wp and tags:
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(",")]
                for tag in tags:
                    tag_lower = tag.lower()
                    for kw in WP_TAG_KEYWORDS:
                        if kw in tag_lower:
                            is_wp = True
                            break
                    if is_wp:
                        break

            # Check template_name
            if not is_wp:
                name_lower = template_name.lower()
                for kw in WP_NAME_KEYWORDS:
                    if kw in name_lower:
                        is_wp = True
                        break

            # Check matched_at for wp-content/wp-includes paths
            if not is_wp and matched_at:
                matched_lower = matched_at.lower()
                for kw in ["wp-content", "wp-includes", "wp-admin", "wp-login", "xmlrpc.php"]:
                    if kw in matched_lower:
                        is_wp = True
                        break

            if is_wp:
                # Normalize host → base URL
                url = WPScanner._normalize_wp_url(host)
                if url:
                    wp_hosts.add(url)

        return wp_hosts

    @staticmethod
    def _normalize_wp_url(host: str) -> str:
        """
        Normalize a host/URL to a base WordPress URL.
        '192.168.1.1'       → 'http://192.168.1.1'
        'http://host/path'  → 'http://host'
        'https://host:8443' → 'https://host:8443'
        """
        host = host.strip()
        if not host:
            return ""

        # Already a URL with scheme
        if host.startswith("http://") or host.startswith("https://"):
            # Extract base: scheme + host + optional port
            from urllib.parse import urlparse
            parsed = urlparse(host)
            base = f"{parsed.scheme}://{parsed.netloc}"
            return base

        # Bare IP/hostname — assume http
        # Remove any path
        if "/" in host:
            host = host.split("/")[0]
        return f"http://{host}"

    def scan(self, wp_targets: List[str],
             output_dir: str = ".") -> Dict[str, WPScanHostResult]:
        """
        Run wpscan against detected WordPress targets.

        Args:
            wp_targets: List of WordPress URLs to scan.
            output_dir: Directory for wpscan output files.

        Returns:
            Dict mapping URL → WPScanHostResult.
        """
        if not self.available:
            return {}

        if not wp_targets:
            return {}

        # Reset
        self.results = {}
        self.stats = WPScanStats()

        scan_start = _time.time()
        os.makedirs(output_dir, exist_ok=True)

        print(
            f"\033[36m[>]\033[0m wpscan: scanning "
            f"\033[92m{len(wp_targets)}\033[0m WordPress target(s) ..."
        )

        for target_url in sorted(wp_targets):
            host_result = self._scan_target(target_url, output_dir)
            self.results[target_url] = host_result

        scan_elapsed = _time.time() - scan_start
        self._compute_stats(scan_elapsed)

        return self.results

    def _scan_target(self, url: str, output_dir: str) -> WPScanHostResult:
        """Run wpscan against a single WordPress target."""
        result = WPScanHostResult(url=url)
        target_start = _time.time()

        # Sanitize URL for filename
        safe_name = re.sub(r'[^\w\-.]', '_', url.replace("://", "_"))
        json_output = os.path.join(output_dir, f"wpscan_{safe_name}.json")
        txt_output = os.path.join(output_dir, f"wpscan_{safe_name}.txt")

        cmd = [
            self.wpscan_path,
            "--url", url,
            "--api-token", self.api_token,
            "--enumerate", "vp,ap,vt,at,tt,cb,dbe",
            "--plugins-detection", "mixed",
            "--format", "json",
            "-o", json_output,
            "--no-banner",
            "--random-user-agent",
        ]

        # Also produce human-readable output
        cmd_txt = [
            self.wpscan_path,
            "--url", url,
            "--api-token", self.api_token,
            "--enumerate", "vp,ap,vt,at,tt,cb,dbe",
            "--plugins-detection", "mixed",
            "-o", txt_output,
            "--no-banner",
            "--random-user-agent",
        ]

        print(
            f"\033[36m    [>]\033[0m wpscan: \033[96m{url}\033[0m ..."
        )

        try:
            # Run JSON scan
            timeout_secs = 600
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=sys.stderr,
                encoding="utf-8",
                errors="replace",
            )
            try:
                proc.wait(timeout=timeout_secs)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                result.error = "timeout"

            # Parse JSON output
            if os.path.isfile(json_output) and os.path.getsize(json_output) > 0:
                self._parse_json_result(json_output, result)

            # Run text-format scan for human-readable file
            try:
                proc_txt = subprocess.Popen(
                    cmd_txt,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    encoding="utf-8",
                    errors="replace",
                )
                proc_txt.wait(timeout=timeout_secs)
            except (subprocess.TimeoutExpired, Exception):
                if 'proc_txt' in dir():
                    try:
                        proc_txt.kill()
                        proc_txt.wait()
                    except Exception:
                        pass

        except FileNotFoundError:
            self.available = False
            result.error = "wpscan not found"
        except Exception as e:
            result.error = str(e)

        result.scan_time = _time.time() - target_start
        return result

    def _parse_json_result(self, filepath: str, result: WPScanHostResult):
        """Parse wpscan JSON output."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except (json.JSONDecodeError, Exception):
            return

        # WordPress version
        version_info = data.get("version", {})
        if version_info:
            result.wp_version = version_info.get("number", "")
            result.wp_version_status = version_info.get("status", "")
            # Version-level vulns
            for vuln_data in version_info.get("vulnerabilities", []):
                result.vulnerabilities.append(self._parse_vuln(vuln_data))

        # Main theme
        main_theme = data.get("main_theme", {})
        if main_theme:
            result.main_theme = main_theme.get("slug", "")
            theme = self._parse_theme(main_theme)
            result.themes.append(theme)

        # Plugins
        plugins = data.get("plugins", {})
        for slug, plugin_data in plugins.items():
            plugin = self._parse_plugin(slug, plugin_data)
            result.plugins.append(plugin)

        # Themes (additional)
        themes = data.get("themes", {})
        for slug, theme_data in themes.items():
            if slug != result.main_theme:  # Don't duplicate main theme
                theme = self._parse_theme_from_dict(slug, theme_data)
                result.themes.append(theme)

        # Users
        users = data.get("users", {})
        for username, user_data in users.items():
            user = WPScanUser(
                username=username,
                id=user_data.get("id", 0),
                display_name=user_data.get("display_name", username),
            )
            result.users.append(user)

        # Interesting findings
        for finding in data.get("interesting_findings", []):
            url = finding.get("url", "")
            finding_type = finding.get("type", "")
            if url:
                result.interesting_findings.append(
                    f"[{finding_type}] {url}" if finding_type else url
                )

        # Config backups
        config_backups = data.get("config_backups", {})
        for url in config_backups:
            result.config_backups.append(url)

        # DB exports
        db_exports = data.get("db_exports", {})
        for url in db_exports:
            result.db_exports.append(url)

    def _parse_vuln(self, data: dict) -> WPScanVulnerability:
        """Parse a single vulnerability from wpscan JSON."""
        vuln = WPScanVulnerability()
        vuln.title = data.get("title", "")
        vuln.vuln_type = data.get("vuln_type", "")
        vuln.fixed_in = data.get("fixed_in", "")
        vuln.cvss = str(data.get("cvss", {}).get("score", ""))

        refs = data.get("references", {})
        for ref_type, ref_list in refs.items():
            if isinstance(ref_list, list):
                for ref in ref_list:
                    vuln.references.append(f"[{ref_type}] {ref}")
            elif isinstance(ref_list, str):
                vuln.references.append(f"[{ref_type}] {ref_list}")

        # Extract CVE from references
        cves = refs.get("cve", [])
        if cves and isinstance(cves, list):
            vuln.cve = cves[0] if cves else ""

        return vuln

    def _parse_plugin(self, slug: str, data: dict) -> WPScanPlugin:
        """Parse a plugin from wpscan JSON."""
        plugin = WPScanPlugin()
        plugin.slug = slug
        plugin.title = data.get("title", slug)
        plugin.location = data.get("location", "")

        ver = data.get("version", {})
        if ver:
            plugin.version = ver.get("number", "")

        plugin.outdated = data.get("outdated", False)

        for vuln_data in data.get("vulnerabilities", []):
            plugin.vulnerabilities.append(self._parse_vuln(vuln_data))

        return plugin

    def _parse_theme(self, data: dict) -> WPScanTheme:
        """Parse main_theme object from wpscan JSON."""
        theme = WPScanTheme()
        theme.slug = data.get("slug", "")
        theme.title = data.get("style_name", theme.slug)
        theme.location = data.get("location", "")

        ver = data.get("version", {})
        if ver:
            theme.version = ver.get("number", "")

        theme.outdated = data.get("outdated", False)

        for vuln_data in data.get("vulnerabilities", []):
            theme.vulnerabilities.append(self._parse_vuln(vuln_data))

        return theme

    def _parse_theme_from_dict(self, slug: str, data: dict) -> WPScanTheme:
        """Parse a theme from the themes dict."""
        theme = WPScanTheme()
        theme.slug = slug
        theme.title = data.get("style_name", slug)
        theme.location = data.get("location", "")

        ver = data.get("version", {})
        if ver:
            theme.version = ver.get("number", "")

        theme.outdated = data.get("outdated", False)

        for vuln_data in data.get("vulnerabilities", []):
            theme.vulnerabilities.append(self._parse_vuln(vuln_data))

        return theme

    def _compute_stats(self, scan_time: float):
        """Compute aggregated WPScan statistics."""
        self.stats.scan_time = scan_time
        self.stats.targets_scanned = len(self.results)

        for url, host_result in self.results.items():
            if host_result.total_vulns > 0:
                self.stats.targets_with_vulns += 1
            self.stats.total_vulns += host_result.total_vulns
            self.stats.total_plugins += len(host_result.plugins)
            self.stats.total_themes += len(host_result.themes)
            self.stats.total_users += len(host_result.users)
            self.stats.outdated_plugins += sum(1 for p in host_result.plugins if p.outdated)
            self.stats.outdated_themes += sum(1 for t in host_result.themes if t.outdated)
            self.stats.config_backups += len(host_result.config_backups)
            self.stats.db_exports += len(host_result.db_exports)
