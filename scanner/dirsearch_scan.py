"""
Dirsearch Web Directory/File Discovery for ReconX.
Uses dirsearch CLI for recursive directory brute-forcing on HTTP/HTTPS targets.

Usage:
  dirsearch -l <hosts_file> --recursive --full-url -o <output_file>

Requires: dirsearch installed in PATH
  Install: pip3 install dirsearch  |  or: apt install dirsearch
  Or:      git clone https://github.com/maurosoria/dirsearch.git --depth 1
"""

import os
import sys
import shutil
import subprocess
import tempfile
import time
import threading
from typing import List, Dict, Optional
from dataclasses import dataclass, field

from ..config import ScannerConfig
from ..utils import routed_path


@dataclass
class DirsearchStats:
    """Aggregated dirsearch scan statistics."""
    total_findings: int = 0
    targets_scanned: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_findings": self.total_findings,
            "targets_scanned": self.targets_scanned,
            "scan_time": self.scan_time,
        }


class DirsearchScanner:
    """
    Dirsearch directory brute-force wrapper.

    Runs dirsearch CLI against HTTP/HTTPS targets to discover
    directories, files, and hidden paths via recursive brute-forcing.
    """

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.dirsearch_path = self._find_dirsearch()
        self.available = self.dirsearch_path is not None
        self.results: List[str] = []
        self.stats = DirsearchStats()

    def _find_dirsearch(self) -> Optional[str]:
        """Find the dirsearch binary/script in PATH or common locations."""
        found = shutil.which("dirsearch")
        if found:
            return found

        common_paths = [
            "/usr/local/bin/dirsearch",
            "/usr/bin/dirsearch",
            os.path.expanduser("~/.local/bin/dirsearch"),
            os.path.expanduser("~/dirsearch/dirsearch.py"),
            "/opt/dirsearch/dirsearch.py",
        ]
        for path in common_paths:
            if os.path.isfile(path):
                return path

        # Auto-install
        from .auto_install import ensure_tool
        if ensure_tool("dirsearch"):
            found = shutil.which("dirsearch")
            if found:
                return found

        return None

    def scan(self, targets: List[str],
             output_dir: str = ".") -> List[str]:
        """
        Run dirsearch against HTTP/HTTPS targets.

        Args:
            targets: List of URLs to scan.
            output_dir: Directory for dirsearch_results.txt output.

        Returns:
            List of discovered URLs (full URLs).
        """
        if not self.available or not targets:
            return []

        self.results = []
        self.stats = DirsearchStats()

        scan_start = time.time()
        self.stats.targets_scanned = len(targets)

        tmpdir = tempfile.mkdtemp(prefix="reconx_dirsearch_")
        input_file = os.path.join(tmpdir, "targets.txt")
        raw_output = os.path.join(tmpdir, "dirsearch_raw.txt")

        os.makedirs(output_dir, exist_ok=True)
        output_file = routed_path(output_dir, "dirsearch_results.txt")

        try:
            with open(input_file, "w", encoding="utf-8") as f:
                for t in targets:
                    f.write(t.strip() + "\n")

            # Determine if dirsearch_path is a .py script
            is_py = self.dirsearch_path.endswith(".py")
            if is_py:
                cmd = [sys.executable, self.dirsearch_path]
            else:
                cmd = [self.dirsearch_path]

            cmd += [
                "-l", input_file,
                "--crawl",
                "--recursive",
                "--full-url",
                "-q",
                "-o", raw_output,
                "--format", "plain",
            ]

            timeout_secs = max(900, len(targets) * 180)

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # ── Live spinner progress ──
            spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            spinner_idx = [0]
            finding_count = [0]
            bar_width = 30
            num_targets = len(targets)
            scan_label = f"dirsearch fuzz: \033[92m{num_targets}\033[0m targets"

            def _draw():
                si = spinner_chars[spinner_idx[0] % len(spinner_chars)]
                spinner_idx[0] += 1
                bar = "\033[92m━\033[0m" * bar_width
                sys.stdout.write(
                    f"\r\033[96m[{si}]\033[0m {scan_label} [{bar}] "
                    f"\033[92m{finding_count[0]}\033[0m urls\033[K"
                )
                sys.stdout.flush()

            _draw()
            try:
                while proc.poll() is None:
                    time.sleep(0.15)
                    if os.path.isfile(raw_output):
                        try:
                            cnt = 0
                            with open(raw_output, "r", encoding="utf-8", errors="replace") as rf:
                                for ln in rf:
                                    if ln.strip() and not ln.startswith("#"):
                                        cnt += 1
                            finding_count[0] = cnt
                        except Exception:
                            pass
                    _draw()
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            # Final count
            if os.path.isfile(raw_output):
                try:
                    cnt = 0
                    with open(raw_output, "r", encoding="utf-8", errors="replace") as rf:
                        for ln in rf:
                            if ln.strip() and not ln.startswith("#"):
                                cnt += 1
                    finding_count[0] = cnt
                except Exception:
                    pass

            # Final status
            bar = "\033[92m━\033[0m" * bar_width
            sys.stdout.write(
                f"\r\033[92m[✓]\033[0m {scan_label} [{bar}] "
                f"\033[92m{finding_count[0]}\033[0m urls\033[K\n"
            )
            sys.stdout.flush()

            # Parse results from dirsearch output
            seen = set()
            if os.path.isfile(raw_output) and os.path.getsize(raw_output) > 0:
                with open(raw_output, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and line not in seen:
                            seen.add(line)
                            self.results.append(line)

            # Write cleaned results to output file
            if self.results:
                with open(output_file, "w", encoding="utf-8") as f:
                    for r in self.results:
                        f.write(r + "\n")

        except FileNotFoundError:
            self.available = False
        except Exception:
            pass
        finally:
            try:
                if os.path.isfile(input_file):
                    os.remove(input_file)
                if os.path.isfile(raw_output):
                    os.remove(raw_output)
                if os.path.isdir(tmpdir):
                    os.rmdir(tmpdir)
            except Exception:
                pass

        scan_elapsed = time.time() - scan_start
        self.stats.total_findings = len(self.results)
        self.stats.scan_time = scan_elapsed

        return self.results
