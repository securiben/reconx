"""
Nuclei Vulnerability Scanner for ReconX.
Uses ProjectDiscovery's nuclei CLI for automated vulnerability scanning
on discovered alive subdomains.

Dynamic tag selection based on detected technologies:
  - Base tags always: vuln, cve, discovery, vkev, panel, xss
  - WordPress detected → adds: wordpress, wp-plugin
  - Laravel detected  → adds: laravel
  - Spring Boot       → adds: spring
  - Tomcat            → adds: tomcat, apache
  - Jenkins           → adds: jenkins
  - Grafana           → adds: grafana
  - Django            → adds: django
  - Jira              → adds: jira, atlassian
  - GitLab            → adds: gitlab

Requires: nuclei from ProjectDiscovery installed in PATH
  Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  Or:      https://github.com/projectdiscovery/nuclei/releases
"""

import os
import json
import re
import sys
import shutil
import subprocess
import tempfile
import threading
import time
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import Counter, defaultdict

from ..config import ScannerConfig
from ..utils import routed_path


# ─── Severity Mapping ────────────────────────────────────────────────────────

NUCLEI_SEVERITY_COLORS = {
    "critical": "\033[1;91m",  # Bold red
    "high": "\033[91m",        # Red
    "medium": "\033[93m",      # Yellow
    "low": "\033[36m",         # Cyan
    "info": "\033[37m",        # White
    "unknown": "\033[90m",     # Gray
}

EXCLUDED_TEMPLATE_KEYWORDS = {
    "application-dos",
}

# ─── Base + conditional tag mapping ──────────────────────────────────────────

BASE_TAGS = [
    "vuln", "cve", "vkev", "panel",
    "xss",
]

# Detected tech name (lowercase substring) → extra nuclei tags to add
TECH_TAG_MAP = {
    "wordpress": ["wordpress", "wp-plugin"],
    "wp-content": ["wordpress", "wp-plugin"],
    "wp-includes": ["wordpress", "wp-plugin"],
    "laravel": ["laravel"],
    "spring boot actuator": ["spring", "springboot"],
    "spring boot": ["spring", "springboot"],
    "spring": ["spring"],
    "apache tomcat": ["tomcat", "apache"],
    "tomcat": ["tomcat", "apache"],
    "jenkins": ["jenkins"],
    "grafana": ["grafana"],
    "django": ["django"],
    "jira": ["jira", "atlassian"],
    "confluence": ["confluence", "atlassian"],
    "gitlab": ["gitlab"],
    "nginx": ["nginx"],
    "apache http": ["apache"],
    "drupal": ["drupal"],
    "magento": ["magento"],
    "phpmyadmin": ["phpmyadmin"],
    "struts": ["struts", "apache"],
    "iis": ["iis"],
    "asp.net": ["iis"],
    "coldfusion": ["coldfusion"],
    "oracle": ["oracle"],
    "weblogic": ["weblogic", "oracle"],
    "zimbra": ["zimbra"],
    "moodle": ["moodle"],
}


@dataclass
class NucleiResult:
    """Parsed result from a single nuclei finding."""
    template_id: str = ""
    template_name: str = ""
    severity: str = "info"
    host: str = ""
    matched_at: str = ""
    extracted_results: List[str] = field(default_factory=list)
    curl_command: str = ""
    matcher_name: str = ""
    description: str = ""
    reference: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    template_url: str = ""
    matcher_status: bool = True

    # Raw JSON
    raw: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "template_id": self.template_id,
            "template_name": self.template_name,
            "severity": self.severity,
            "host": self.host,
            "matched_at": self.matched_at,
            "description": self.description,
            "tags": self.tags,
            "reference": self.reference,
            "extracted_results": self.extracted_results,
            "matcher_name": self.matcher_name,
        }

    @classmethod
    def from_json(cls, data: dict) -> "NucleiResult":
        """Parse a single nuclei JSON output line."""
        r = cls()
        r.raw = data
        r.template_id = data.get("template-id", data.get("template_id", ""))
        info = data.get("info", {})
        r.template_name = info.get("name", r.template_id)
        r.severity = info.get("severity", "info").lower()
        r.description = info.get("description", "")
        r.reference = info.get("reference", [])
        if r.reference is None:
            r.reference = []
        r.tags = info.get("tags", [])
        if isinstance(r.tags, str):
            r.tags = [t.strip() for t in r.tags.split(",")]

        r.host = data.get("host", "")
        r.matched_at = data.get("matched-at", data.get("matched_at", r.host))
        r.extracted_results = data.get("extracted-results",
                                       data.get("extracted_results", []))
        if r.extracted_results is None:
            r.extracted_results = []
        r.curl_command = data.get("curl-command", "")
        r.matcher_name = data.get("matcher-name", data.get("matcher_name", ""))
        r.matcher_status = data.get("matcher-status",
                                    data.get("matcher_status", True))
        return r


@dataclass
class NucleiStats:
    """Aggregated nuclei scan statistics."""
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    templates_used: int = 0
    hosts_scanned: int = 0
    tags_used: List[str] = field(default_factory=list)
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_findings": self.total_findings,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
            "templates_used": self.templates_used,
            "hosts_scanned": self.hosts_scanned,
            "tags_used": self.tags_used,
            "scan_time": self.scan_time,
        }


class NucleiScanner:
    """
    Nuclei vulnerability scanner wrapper.

    Runs nuclei CLI against alive subdomains with dynamically
    selected tags based on detected technologies.
    """

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.nuclei_path = self._find_nuclei()
        self.available = self.nuclei_path is not None
        self.results: List[NucleiResult] = []
        self.stats = NucleiStats()
        self._templates_checked = False

    def _find_nuclei(self) -> Optional[str]:
        """Find the nuclei binary in PATH or common install locations."""
        candidates = []

        # Check PATH
        found = shutil.which("nuclei")
        if found:
            candidates.append(found)

        # Common Go binary locations
        common_paths = [
            os.path.expanduser("~/go/bin/nuclei"),
            os.path.expanduser("~/go/bin/nuclei.exe"),
            os.path.expanduser("~/.local/bin/nuclei"),
            "/usr/local/bin/nuclei",
            "/usr/bin/nuclei",
        ]
        if os.name == "nt":
            common_paths.extend([
                os.path.join(os.environ.get("GOPATH", ""), "bin", "nuclei.exe"),
                os.path.join(os.environ.get("USERPROFILE", ""), "go", "bin", "nuclei.exe"),
            ])

        for path in common_paths:
            if path and os.path.isfile(path) and path not in candidates:
                candidates.append(path)

        # Verify it's actually nuclei
        for path in candidates:
            if self._verify_nuclei(path):
                return path

        return None

    def ensure_available(self) -> bool:
        """Attempt auto-install if nuclei is not available. Returns True if now available."""
        if self.available:
            return True
        from .auto_install import ensure_tool
        if ensure_tool("nuclei"):
            found = shutil.which("nuclei")
            if found and self._verify_nuclei(found):
                self.nuclei_path = found
                self.available = True
                return True
        return False

    def _verify_nuclei(self, path: str) -> bool:
        """Verify that the binary is actually ProjectDiscovery nuclei."""
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
                "projectdiscovery", "nuclei", "current version",
            ]):
                return True
            return False
        except Exception:
            return False

    def _has_templates_dir(self) -> bool:
        """Return True if a nuclei templates directory already exists locally."""
        template_dirs = [
            os.path.expanduser("~/nuclei-templates"),
            os.path.expanduser("~/.local/nuclei-templates"),
            os.path.expanduser("~/.config/nuclei/templates"),
            os.path.expanduser("~/.nuclei-templates"),
        ]

        for path in template_dirs:
            if os.path.isdir(path):
                try:
                    if any(os.scandir(path)):
                        return True
                except Exception:
                    return True
        return False

    def _ensure_templates(self):
        """Ensure nuclei templates exist without forcing an update on every scan."""
        if self._templates_checked:
            return
        self._templates_checked = True

        # Avoid running a slow template update every time ReconX scans.
        # If templates already exist locally, use them as-is.
        if self._has_templates_dir():
            return

        try:
            subprocess.run(
                [self.nuclei_path, "-update-templates"],
                capture_output=True,
                text=True,
                timeout=180,
                encoding="utf-8",
                errors="replace",
            )
        except Exception:
            pass

    def build_tags(self, detected_techs: Set[str]) -> List[str]:
        """
        Build nuclei tag list based on detected technologies.

        Args:
            detected_techs: Set of technology names detected by httpx/tech profiler.

        Returns:
            List of nuclei tags to use.
        """
        tags = list(BASE_TAGS)

        # Check each detected tech against the tag map
        for tech in detected_techs:
            tech_lower = tech.lower().strip()
            for pattern, extra_tags in TECH_TAG_MAP.items():
                if pattern in tech_lower:
                    for tag in extra_tags:
                        if tag not in tags:
                            tags.append(tag)

        return tags

    def _is_excluded_finding(self,
                             template_id: str = "",
                             template_name: str = "",
                             tags: Optional[List[str]] = None) -> bool:
        """Return True when a finding should be hidden from output/results."""
        haystacks = [template_id or "", template_name or ""]
        if tags:
            haystacks.extend(tags)

        for value in haystacks:
            value_lower = str(value).strip().lower()
            if any(keyword in value_lower for keyword in EXCLUDED_TEMPLATE_KEYWORDS):
                return True
        return False

    def _filter_text_output_file(self, filepath: str):
        """Remove excluded findings from nuclei plain-text output file."""
        _ansi_re = re.compile(r'\033\[[0-9;]*m')
        try:
            if not os.path.isfile(filepath):
                return

            filtered_lines = []
            changed = False
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    # Strip ANSI codes only for keyword matching; keep original line
                    line_plain = _ansi_re.sub('', line).lower()
                    if any(keyword in line_plain for keyword in EXCLUDED_TEMPLATE_KEYWORDS):
                        changed = True
                        continue
                    filtered_lines.append(line)

            if changed:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.writelines(filtered_lines)
        except Exception:
            pass

    def scan(self, alive_hostnames: List[str],
             output_dir: str = ".") -> List[NucleiResult]:
        """
        Run nuclei against alive subdomains.
        Command: cat alive.txt | nuclei -s critical,high,medium,low -o nuclei_results.txt

        Args:
            alive_hostnames: List of alive subdomain hostnames / URLs.
            output_dir: Directory for nuclei_results.txt output.

        Returns:
            List of NucleiResult findings.
        """
        if not self.available:
            return []

        if not alive_hostnames:
            return []

        # Reset results (in case of re-run after Ctrl+C resume)
        self.results = []
        self.stats = NucleiStats()

        # Deduplicate while preserving order and normalize trailing slashes.
        normalized_targets = []
        seen_targets = set()
        for host in alive_hostnames:
            target = (host or "").strip().rstrip("/")
            if not target or target in seen_targets:
                continue
            seen_targets.add(target)
            normalized_targets.append(target)

        if not normalized_targets:
            return []

        import time as _time
        scan_start = _time.time()

        # Ensure nuclei templates are downloaded
        self._ensure_templates()

        self.stats.hosts_scanned = len(normalized_targets)

        # Write targets to temp file
        tmpdir = tempfile.mkdtemp(prefix="reconx_nuclei_")
        input_file = os.path.join(tmpdir, "targets.txt")
        jsonl_file = os.path.join(tmpdir, "results.jsonl")

        # Plain-text output in the domain results folder
        os.makedirs(output_dir, exist_ok=True)
        txt_output = routed_path(output_dir, "nuclei_results.txt")
        targets_output = routed_path(output_dir, "nuclei_targets.txt")

        try:
            with open(input_file, "w", encoding="utf-8") as f:
                for h in normalized_targets:
                    # Keep full URLs (scheme + host + port) for nuclei
                    f.write(h.rstrip("/") + "\n")

            with open(targets_output, "w", encoding="utf-8") as f:
                f.write("\n".join(normalized_targets) + "\n")

            # nuclei -l targets.txt ... -o nuclei_results.txt
            #
            # Tuning rationale:
            #   -bs  25        : hosts processed in parallel (lower = less pressure)
            #   -c   25        : template concurrency per host
            #   -rl  150       : rate-limit (requests/second)
            #   -timeout 15    : per-request timeout in seconds (default 10)
            #   -retries 3     : retry failed requests (default 1)
            #   -mhe 0         : disable max-host-errors (0 = never skip a host)
            #   -page-timeout 30 : headless page render timeout
            #   -no-mhe        : (fallback) explicitly disable host-error skipping
            #
            cmd = [
                self.nuclei_path,
                "-l", input_file,
                "-bs", "50",
                "-c", "30",
                # "-rl", "150",
                # "-timeout", "10",
                # "-retries", "2",
                "-s", "critical,high,medium,low,info",
                "-etags", "application-dos",
                "-je", jsonl_file,         # JSONL export for structured parsing
            ]

            # If a local custom templates folder exists, add it
            custom_tpl_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "prv8_nuclei_templates",
            )
            if os.path.isdir(custom_tpl_dir):
                cmd.extend(["-t", custom_tpl_dir])

            preview = ", ".join(normalized_targets[:5])
            if len(normalized_targets) > 5:
                preview += f", ... (+{len(normalized_targets) - 5} more)"
            print(
                f"\033[96m[*]\033[0m nuclei targets: \033[92m{len(normalized_targets)}\033[0m | "
                f"severity=all"
            )
            if preview:
                print(f"\033[90m    {preview}\033[0m")
            cmd_display = " ".join(cmd).replace(input_file, "targets.txt").replace(jsonl_file, "output.jsonl")
            print(
                f"\033[90m    cmd: {cmd_display}\033[0m"
            )

            # Run nuclei with live findings log
            timeout_secs = max(900, len(normalized_targets) * 15)
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            # Severity colors for log output
            sev_colors = {
                "critical": "\033[1;91m",
                "high": "\033[91m",
                "medium": "\033[93m",
                "low": "\033[36m",
                "info": "\033[37m",
            }
            # [template-id] [protocol] [severity] matched-url
            finding_re = re.compile(
                r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)'
            )
            findings = [0]
            found_lines = []   # colored finding lines collected from stdout
            ansi_re = re.compile(r'\033\[[0-9;]*m')
            lock = threading.Lock()
            bar_width = 30
            spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            spinner_idx = [0]
            progress_start = time.time()

            scan_label = f"nuclei: \033[92m{len(normalized_targets)}\033[0m targets"

            def _fmt_elapsed():
                """Format elapsed time as human-readable string."""
                elapsed = time.time() - progress_start
                if elapsed < 60:
                    return f"{elapsed:.0f}s"
                m, s = divmod(int(elapsed), 60)
                if m < 60:
                    return f"{m}m{s:02d}s"
                h, m = divmod(m, 60)
                return f"{h}h{m:02d}m"

            def _draw_status():
                si = spinner_chars[spinner_idx[0] % len(spinner_chars)]
                spinner_idx[0] += 1
                f_count = findings[0]
                bar = "\033[92m━\033[0m" * bar_width
                elapsed_str = _fmt_elapsed()
                sys.stdout.write(
                    f"\r\033[96m[{si}]\033[0m {scan_label} [{bar}] "
                    f"\033[92m{f_count}\033[0m findings "
                    f"\033[90m{elapsed_str}\033[0m\033[K"
                )
                sys.stdout.flush()

            def _reader():
                buf = ""
                while True:
                    chunk = proc.stdout.read(256)
                    if not chunk:
                        break
                    text = chunk.decode("utf-8", errors="replace")
                    buf += text
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        m = finding_re.search(line)
                        if m:
                            # Strip ANSI codes from captured group for exclusion check
                            tmpl = ansi_re.sub('', m.group(1))
                            if self._is_excluded_finding(template_id=tmpl, template_name=tmpl):
                                continue
                            with lock:
                                findings[0] += 1
                                found_lines.append(line.strip())  # keep ANSI for file
                                # Print raw nuclei output (original format)
                                sys.stdout.write(f"\r\033[K")
                                sys.stdout.write(f"    {line.strip()}\n")
                                _draw_status()

            reader_t = threading.Thread(target=_reader, daemon=True)
            reader_t.start()

            # Animate spinner while running
            _draw_status()
            while proc.poll() is None:
                time.sleep(0.15)
                with lock:
                    _draw_status()

            reader_t.join(timeout=5)

            # Write colored findings to file — skip entirely if no findings
            if found_lines:
                try:
                    with open(txt_output, "w", encoding="utf-8") as _f:
                        _f.write("\n".join(found_lines) + "\n")
                except Exception:
                    pass

            # Final state
            f_count = findings[0]
            elapsed_str = _fmt_elapsed()
            success = proc.returncode == 0
            if success:
                bar = "\033[92m━\033[0m" * bar_width
                sys.stdout.write(
                    f"\r\033[92m[✓]\033[0m {scan_label} [{bar}] "
                    f"\033[92m{f_count}\033[0m findings\033[K\n"
                )
            else:
                bar = "\033[91m━\033[0m" * bar_width
                sys.stdout.write(
                    f"\r\033[91m[✗]\033[0m {scan_label} [{bar}] "
                    f"\033[91m{f_count}\033[0m findings\033[K\n"
                )
            # Summary line with elapsed time
            print(
                f"\033[92m[+]\033[0m nuclei: "
                f"\033[92m{f_count}\033[0m findings on "
                f"\033[92m{len(normalized_targets)}\033[0m hosts "
                f"({elapsed_str})"
            )
            sys.stdout.flush()

            # Parse JSONL results for structured data
            if os.path.isfile(jsonl_file) and os.path.getsize(jsonl_file) > 0:
                self._parse_results(jsonl_file)
            elif os.path.isfile(txt_output) and os.path.getsize(txt_output) > 0:
                # Fallback: parse plain text output if JSONL unavailable
                self._parse_text_output(txt_output)

            self._filter_text_output_file(txt_output)

        except FileNotFoundError:
            self.available = False
        except Exception:
            pass
        finally:
            # Cleanup temp dir (keep txt_output in output_dir)
            try:
                for fp in [input_file, jsonl_file]:
                    if os.path.isfile(fp):
                        os.remove(fp)
                if os.path.isdir(tmpdir):
                    os.rmdir(tmpdir)
            except Exception:
                pass

        scan_elapsed = _time.time() - scan_start
        self._compute_stats(scan_elapsed)

        return self.results

    def _parse_results(self, filepath: str):
        """Parse nuclei JSON export file (JSON array from -je, or NDJSON)."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read().strip()
            if not content:
                return

            # Try JSON array first (nuclei -je produces [{...}, {...}, ...])
            try:
                items = json.loads(content)
                if isinstance(items, list):
                    for data in items:
                        if isinstance(data, dict):
                            result = NucleiResult.from_json(data)
                            if result.template_id and not self._is_excluded_finding(
                                    template_id=result.template_id,
                                    template_name=result.template_name,
                                    tags=result.tags):
                                self.results.append(result)
                    return
                elif isinstance(items, dict):
                    # Single JSON object
                    result = NucleiResult.from_json(items)
                    if result.template_id and not self._is_excluded_finding(
                            template_id=result.template_id,
                            template_name=result.template_name,
                            tags=result.tags):
                        self.results.append(result)
                    return
            except (json.JSONDecodeError, ValueError):
                pass

            # Fallback: NDJSON (one JSON object per line)
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if isinstance(data, dict):
                        result = NucleiResult.from_json(data)
                        if result.template_id and not self._is_excluded_finding(
                                template_id=result.template_id,
                                template_name=result.template_name,
                                tags=result.tags):
                            self.results.append(result)
                except (json.JSONDecodeError, ValueError):
                    continue
        except Exception:
            pass

    def _parse_results_text(self, text: str):
        """Parse nuclei JSON from stdout text."""
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                result = NucleiResult.from_json(data)
                if result.template_id and not self._is_excluded_finding(
                        template_id=result.template_id,
                        template_name=result.template_name,
                        tags=result.tags):
                    self.results.append(result)
            except (json.JSONDecodeError, Exception):
                continue

    def _parse_text_output(self, filepath: str):
        """
        Parse nuclei plain-text output as fallback.
        Nuclei format: [template-id] [protocol] [severity] host [extra...]
        File may contain ANSI color codes; strip them before parsing.
        """
        import re
        _ansi_re = re.compile(r'\033\[[0-9;]*m')
        pattern = re.compile(
            r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)'
        )
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = _ansi_re.sub('', line).strip()
                    if not line:
                        continue
                    m = pattern.search(line)
                    if m:
                        if self._is_excluded_finding(
                                template_id=m.group(1),
                                template_name=m.group(1)):
                            continue
                        r = NucleiResult()
                        r.template_id = m.group(1)
                        r.template_name = m.group(1)
                        # group(2) = protocol (http, tcp, javascript, etc.)
                        # group(3) = severity (critical, high, medium, low, info)
                        r.severity = m.group(3).lower()
                        r.host = m.group(4)
                        r.matched_at = m.group(4)
                        self.results.append(r)
        except Exception:
            pass

    def _compute_stats(self, scan_time: float):
        """Compute aggregated statistics."""
        self.stats.total_findings = len(self.results)
        self.stats.scan_time = scan_time

        sev_counts = Counter(r.severity for r in self.results)
        self.stats.critical = sev_counts.get("critical", 0)
        self.stats.high = sev_counts.get("high", 0)
        self.stats.medium = sev_counts.get("medium", 0)
        self.stats.low = sev_counts.get("low", 0)
        self.stats.info = sev_counts.get("info", 0)

        self.stats.templates_used = len(set(r.template_id for r in self.results))

    def get_findings_by_severity(self) -> Dict[str, List[NucleiResult]]:
        """Group findings by severity level."""
        groups = defaultdict(list)
        for r in self.results:
            groups[r.severity].append(r)
        return dict(groups)

    def get_findings_by_host(self) -> Dict[str, List[NucleiResult]]:
        """Group findings by target host."""
        groups = defaultdict(list)
        for r in self.results:
            groups[r.host].append(r)
        return dict(groups)
