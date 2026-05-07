"""
Feroxbuster Web Directory/File Discovery for ReconX.
Uses feroxbuster CLI for fast, recursive directory brute-forcing on HTTP/HTTPS targets.

Usage:
  feroxbuster --stdin -w <wordlist> --output <output_file> -q --no-state --silent

Requires: feroxbuster installed in PATH
  Install: sudo apt install feroxbuster
  Or:      cargo install feroxbuster
  Or:      https://github.com/epi052/feroxbuster/releases
"""

import os
import sys
import shutil
import subprocess
import tempfile
import time
import threading
from typing import List, Optional
from dataclasses import dataclass

from ..config import ScannerConfig
from ..utils import routed_path


# ─── Default wordlist search paths ───────────────────────────────────────────

WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirb/big.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
]


@dataclass
class FeroxbusterStats:
    """Aggregated feroxbuster scan statistics."""
    total_findings: int = 0
    targets_scanned: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_findings": self.total_findings,
            "targets_scanned": self.targets_scanned,
            "scan_time": self.scan_time,
        }


class FeroxbusterScanner:
    """
    Feroxbuster directory brute-force wrapper.

    Runs feroxbuster CLI against HTTP/HTTPS targets to discover
    directories, files, and hidden paths via recursive brute-forcing.
    """

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.feroxbuster_path = self._find_feroxbuster()
        self.wordlist = self._find_wordlist()
        self.available = self.feroxbuster_path is not None and self.wordlist is not None
        self.results: List[str] = []
        self.stats = FeroxbusterStats()

    def _find_feroxbuster(self) -> Optional[str]:
        """Find the feroxbuster binary in PATH or common locations."""
        found = shutil.which("feroxbuster")
        if found:
            return found

        common_paths = [
            "/usr/local/bin/feroxbuster",
            "/usr/bin/feroxbuster",
            os.path.expanduser("~/.cargo/bin/feroxbuster"),
            os.path.expanduser("~/.local/bin/feroxbuster"),
        ]
        for path in common_paths:
            if os.path.isfile(path):
                return path

        # Auto-install
        from .auto_install import ensure_tool
        if ensure_tool("feroxbuster"):
            found = shutil.which("feroxbuster")
            if found:
                return found

        return None

    def _find_wordlist(self) -> Optional[str]:
        """Find a suitable wordlist for feroxbuster."""
        for path in WORDLIST_CANDIDATES:
            if os.path.isfile(path):
                return path
        return None

    def ensure_available(self) -> bool:
        """Attempt auto-install if feroxbuster is not available. Returns True if now available."""
        if self.available:
            return True
        from .auto_install import ensure_tool
        if ensure_tool("feroxbuster"):
            found = shutil.which("feroxbuster")
            if found:
                self.feroxbuster_path = found
                self.wordlist = self._find_wordlist()
                self.available = self.feroxbuster_path is not None and self.wordlist is not None
        return self.available

    def scan(self, targets: List[str],
             output_dir: str = ".") -> List[str]:
        """
        Run feroxbuster against HTTP/HTTPS targets.

        Args:
            targets: List of URLs to scan.
            output_dir: Directory for feroxbuster_results.txt output.

        Returns:
            List of discovered URLs (full URLs).
        """
        if not self.available or not targets:
            return []

        self.results = []
        self.stats = FeroxbusterStats()

        scan_start = time.time()
        self.stats.targets_scanned = len(targets)

        tmpdir = tempfile.mkdtemp(prefix="reconx_ferox_")
        input_file = os.path.join(tmpdir, "targets.txt")
        raw_output = os.path.join(tmpdir, "ferox_raw.txt")

        os.makedirs(output_dir, exist_ok=True)
        output_file = routed_path(output_dir, "feroxbuster_results.txt")

        try:
            with open(input_file, "w", encoding="utf-8") as f:
                for t in targets:
                    f.write(t.strip() + "\n")

            cmd = [
                self.feroxbuster_path,
                "--stdin",
                "-w", self.wordlist,
                "--output", raw_output,
                "--quiet",
                "--no-state",
                "--silent",
                "--depth", "3",
                "--threads", "50",
                "--timeout", "7",
                "--auto-tune",
            ]

            timeout_secs = max(900, len(targets) * 180)

            with open(input_file, "r", encoding="utf-8") as stdin_f:
                proc = subprocess.Popen(
                    cmd,
                    stdin=stdin_f,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

            # ── Live spinner progress ──
            spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            spinner_idx = [0]
            finding_count = [0]
            bar_width = 30
            num_targets = len(targets)
            scan_label = f"feroxbuster fuzz: \033[92m{num_targets}\033[0m targets"

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
                                    ln = ln.strip()
                                    if ln and not ln.startswith("#"):
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

            # Parse results from feroxbuster output
            # feroxbuster text format: "200      GET      10l       40w     312c http://example.com/path"
            seen = set()
            if os.path.isfile(raw_output) and os.path.getsize(raw_output) > 0:
                with open(raw_output, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        # Extract URL from feroxbuster output (last whitespace-separated token)
                        parts = line.split()
                        url = None
                        for part in reversed(parts):
                            if part.startswith("http://") or part.startswith("https://"):
                                url = part
                                break
                        if url and url not in seen:
                            seen.add(url)
                            self.results.append(url)

            # Write cleaned results to output file (only if non-empty)
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
