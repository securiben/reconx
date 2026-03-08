"""
Chameleon Web Content Discovery for ReconX.
Uses chameleon CLI for web content/directory discovery on HTTP/HTTPS targets.

Usage:
  chameleon -L <hosts_file> -a

Requires: chameleon installed in PATH
  Install: curl -sL https://raw.githubusercontent.com/iustin24/chameleon/master/install.sh | bash
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
class ChameleonStats:
    """Aggregated chameleon scan statistics."""
    total_findings: int = 0
    targets_scanned: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_findings": self.total_findings,
            "targets_scanned": self.targets_scanned,
            "scan_time": self.scan_time,
        }


class ChameleonScanner:
    """
    Chameleon web content discovery wrapper.

    Runs chameleon CLI against HTTP/HTTPS targets to discover
    directories, files, and hidden content.
    """

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.chameleon_path = self._find_chameleon(allow_install=False)
        self.available = self.chameleon_path is not None
        self.results: List[str] = []
        self.stats = ChameleonStats()

    def _find_chameleon(self, allow_install: bool = True) -> Optional[str]:
        """Find the chameleon binary in PATH or common install locations."""
        found = shutil.which("chameleon")
        if found:
            return found

        common_paths = [
            "/usr/local/bin/chameleon",
            "/usr/bin/chameleon",
            os.path.expanduser("~/.local/bin/chameleon"),
            os.path.expanduser("~/go/bin/chameleon"),
            os.path.join(os.getcwd(), "chameleon"),
        ]
        for path in common_paths:
            if os.path.isfile(path):
                return path

        if allow_install:
            from .auto_install import ensure_tool
            if ensure_tool("chameleon"):
                found = shutil.which("chameleon")
                if found:
                    return found
                for path in common_paths:
                    if os.path.isfile(path):
                        return path

        return None

    def scan(self, targets: List[str],
             output_dir: str = ".") -> List[str]:
        """
        Run chameleon against HTTP/HTTPS targets.

        Args:
            targets: List of URLs to scan.
            output_dir: Directory for chameleon_results.txt output.

        Returns:
            List of discovered paths/URLs.
        """
        if not targets:
            return []

        if not self.available:
            self.chameleon_path = self._find_chameleon(allow_install=True)
            self.available = self.chameleon_path is not None

        if not self.available:
            return []

        self.results = []
        self.stats = ChameleonStats()

        scan_start = time.time()
        self.stats.targets_scanned = len(targets)

        tmpdir = tempfile.mkdtemp(prefix="reconx_chameleon_")
        input_file = os.path.join(tmpdir, "targets.txt")

        os.makedirs(output_dir, exist_ok=True)
        output_file = routed_path(output_dir, "chameleon_results.txt")

        try:
            with open(input_file, "w", encoding="utf-8") as f:
                for t in targets:
                    f.write(t.strip() + "\n")

            cmd = [
                self.chameleon_path,
                "-L", input_file,
                "-a",
            ]

            timeout_secs = max(600, len(targets) * 120)

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )

            # ── Live spinner progress ──
            spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            spinner_idx = [0]
            finding_count = [0]
            bar_width = 30
            num_targets = len(targets)
            scan_label = f"chameleon scan: \033[92m{num_targets}\033[0m targets"
            seen = set()
            lock = threading.Lock()

            def _draw():
                si = spinner_chars[spinner_idx[0] % len(spinner_chars)]
                spinner_idx[0] += 1
                bar = "\033[92m━\033[0m" * bar_width
                sys.stdout.write(
                    f"\r\033[96m[{si}]\033[0m {scan_label} [{bar}] "
                    f"\033[92m{finding_count[0]}\033[0m urls\033[K"
                )
                sys.stdout.flush()

            def _reader():
                for raw_line in proc.stdout:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if line:
                        with lock:
                            if line not in seen:
                                seen.add(line)
                                self.results.append(line)
                                finding_count[0] = len(self.results)

            reader_t = threading.Thread(target=_reader, daemon=True)
            reader_t.start()

            _draw()
            try:
                while proc.poll() is None:
                    time.sleep(0.15)
                    _draw()
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            reader_t.join(timeout=10)

            # Final status
            bar = "\033[92m━\033[0m" * bar_width
            sys.stdout.write(
                f"\r\033[92m[✓]\033[0m {scan_label} [{bar}] "
                f"\033[92m{finding_count[0]}\033[0m urls\033[K\n"
            )
            sys.stdout.flush()

            # Write results to output file
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
                if os.path.isdir(tmpdir):
                    os.rmdir(tmpdir)
            except Exception:
                pass

        scan_elapsed = time.time() - scan_start
        self.stats.total_findings = len(self.results)
        self.stats.scan_time = scan_elapsed

        return self.results
