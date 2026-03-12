"""
Naabu Fast Port Scanner for ReconX.
Uses ProjectDiscovery's naabu CLI tool for fast port discovery.
Can be used as a full replacement for nmap (--naabu flag).

When used with --naabu flag:
  - naabu replaces nmap entirely (nmap is skipped)
  - naabu results are converted to nmap-compatible format
  - downstream scanners (enum4linux, smbclient, vnc, snmp, ssh, nuclei)
    still work because they see the same nmap_results structure

Command: naabu -l <targets> -rate 3000 -retries 3 -warm-up-time 0
                -c 50 -top-ports 1000 -silent -o <output>

Requires: naabu from ProjectDiscovery installed in PATH
  Install: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  Or:      sudo apt install naabu
  Or:      https://github.com/projectdiscovery/naabu/releases
"""

import os
import re
import sys
import shutil
import subprocess
import tempfile
import time
import threading
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

from ..config import ScannerConfig


@dataclass
class NaabuHostResult:
    """Parsed naabu result for a single host (IP)."""
    ip: str = ""
    ports: List[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "ports": self.ports,
        }


@dataclass
class NaabuStats:
    """Aggregated naabu scan statistics."""
    total_ips_scanned: int = 0
    hosts_with_ports: int = 0
    total_open_ports: int = 0
    unique_ports: int = 0
    scan_time: float = 0.0
    top_ports: List[Dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_ips_scanned": self.total_ips_scanned,
            "hosts_with_ports": self.hosts_with_ports,
            "total_open_ports": self.total_open_ports,
            "unique_ports": self.unique_ports,
            "scan_time": self.scan_time,
            "top_ports": self.top_ports,
        }


class NaabuScanner:
    """
    Naabu fast port scanner wrapper.

    Runs naabu against discovered IP addresses for rapid port discovery.
    Output format: IP:PORT (one per line, -silent mode).
    """

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.naabu_path = self._find_naabu()
        self.available = self.naabu_path is not None
        self.results: Dict[str, NaabuHostResult] = {}  # ip → result
        self.stats = NaabuStats()

    def _find_naabu(self) -> Optional[str]:
        """Find the naabu binary in PATH or common install locations."""
        found = shutil.which("naabu")
        if found:
            return found

        common_paths = [
            "/usr/bin/naabu",
            "/usr/local/bin/naabu",
            os.path.expanduser("~/go/bin/naabu"),
            "/root/go/bin/naabu",
        ]

        for path in common_paths:
            if path and os.path.isfile(path):
                return path

        # Auto-install naabu if not found
        from .auto_install import ensure_tool
        if ensure_tool("naabu"):
            return shutil.which("naabu")

        return None

    def scan(
        self, ip_addresses: Set[str], output_dir: str = ""
    ) -> Dict[str, NaabuHostResult]:
        """
        Run naabu against a set of IP addresses for fast port discovery.

        Command: naabu -l <file> -rate 3000 -retries 3 -warm-up-time 0
                       -c 50 -top-ports 1000 -silent -o <output>

        Args:
            ip_addresses: Set of IP addresses to scan.
            output_dir: Directory to place naabu output files.

        Returns:
            Dict mapping IP → NaabuHostResult.
        """
        if not self.available:
            return {}

        if not ip_addresses:
            return {}

        scan_start = time.time()
        self.stats.total_ips_scanned = len(ip_addresses)

        # Prepare temp dir
        tmpdir = tempfile.mkdtemp(prefix="reconx_naabu_")

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        output_file = os.path.join(tmpdir, "naabu_results.txt")
        input_file = os.path.join(tmpdir, "naabu_targets.txt")

        try:
            self._run_naabu_scan(
                ip_addresses, input_file, output_file,
                label="IPs",
            )

            # Parse results
            if os.path.isfile(output_file):
                self._parse_output(output_file)

            # Copy output to output_dir
            if output_dir and os.path.isfile(output_file):
                txt_dir = os.path.join(output_dir, "txt")
                os.makedirs(txt_dir, exist_ok=True)
                import shutil as _shutil
                _shutil.copy2(output_file, os.path.join(txt_dir, "naabu_scan.txt"))

        except FileNotFoundError:
            self.available = False
        except Exception:
            pass
        finally:
            # Cleanup temp files
            try:
                for f in os.listdir(tmpdir):
                    fp = os.path.join(tmpdir, f)
                    if os.path.isfile(fp):
                        os.remove(fp)
                os.rmdir(tmpdir)
            except Exception:
                pass

        scan_elapsed = time.time() - scan_start
        self._compute_stats(scan_elapsed)

        return self.results

    def _run_naabu_scan(
        self,
        ip_addresses: Set[str],
        input_file: str,
        output_file: str,
        label: str = "",
    ):
        """
        Run naabu with a live progress bar.

        Args:
            ip_addresses: IPs to scan.
            input_file: Path to write target IPs.
            output_file: Path for naabu output.
            label: Display label for the scan.
        """
        if not ip_addresses:
            return

        # Write targets file
        with open(input_file, "w", encoding="utf-8") as f:
            for ip in sorted(ip_addresses):
                f.write(ip + "\n")

        total_hosts = len(ip_addresses)

        cmd = [
            self.naabu_path,
            "-l", input_file,
            "-rate", "3000",
            "-retries", "3",
            "-warm-up-time", "0",
            "-c", "50",
            "-top-ports", "1000",
            "-o", output_file,
        ]

        # Use non-silent mode to stderr for progress, output goes to file
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Shared state for progress
        ports_found = [0]
        hosts_seen: Set[str] = set()
        hosts_seen_lock = threading.Lock()
        bar_width = 30
        spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        spinner_idx = [0]
        scan_start_t = time.time()

        def _reader_stdout():
            """Read stdout for IP:PORT lines (naabu outputs discovered ports here)."""
            buf = ""
            while True:
                chunk = proc.stdout.read(256)
                if not chunk:
                    break
                text = chunk.decode("utf-8", errors="replace")
                buf += text
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if ":" in line:
                        # Format: IP:PORT
                        ip_part = line.rsplit(":", 1)[0]
                        ports_found[0] += 1
                        with hosts_seen_lock:
                            hosts_seen.add(ip_part)

        def _reader_stderr():
            """Read stderr for naabu status messages."""
            buf = ""
            while True:
                chunk = proc.stderr.read(256)
                if not chunk:
                    break
                # Discard stderr (naabu progress/debug info)

        stdout_t = threading.Thread(target=_reader_stdout, daemon=True)
        stderr_t = threading.Thread(target=_reader_stderr, daemon=True)
        stdout_t.start()
        stderr_t.start()

        # Animate progress bar
        scan_label = (
            f"naabu: \033[96m{total_hosts}\033[0m {label} "
            f"\033[90m-rate 3000 -c 50 -top-ports 1000\033[0m"
        )
        sys.stdout.write(f"\033[96m[*]\033[0m {scan_label}\n")
        sys.stdout.flush()

        while proc.poll() is None:
            spinner = spinner_chars[spinner_idx[0] % len(spinner_chars)]
            spinner_idx[0] += 1
            pf = ports_found[0]
            with hosts_seen_lock:
                hs = len(hosts_seen)

            # Estimate progress from hosts seen
            est_pct = min(99.0, (hs / total_hosts * 100)) if total_hosts > 0 else 0
            filled = int(bar_width * est_pct / 100)
            bar = "\033[92m━\033[0m" * filled + "\033[90m━\033[0m" * (bar_width - filled)

            # Elapsed time
            elapsed = time.time() - scan_start_t
            if elapsed >= 3600:
                elapsed_s = f"{elapsed/3600:.1f}h"
            elif elapsed >= 60:
                elapsed_s = f"{int(elapsed)//60}m{int(elapsed)%60:02d}s"
            else:
                elapsed_s = f"{elapsed:.0f}s"

            sys.stdout.write(
                f"\r\033[96m[{spinner}]\033[0m naabu: [{bar}] "
                f"\033[93m{est_pct:5.1f}%\033[0m "
                f"\033[96mhost {hs}/{total_hosts}\033[0m "
                f"\033[92m{pf} ports\033[0m "
                f"\033[90m{elapsed_s}\033[0m\033[K"
            )
            sys.stdout.flush()
            time.sleep(0.15)

        stdout_t.join(timeout=5)
        stderr_t.join(timeout=5)

        # Final state
        pf = ports_found[0]
        with hosts_seen_lock:
            hs = len(hosts_seen)
        elapsed = time.time() - scan_start_t
        if elapsed >= 3600:
            elapsed_s = f"{elapsed/3600:.1f}h"
        elif elapsed >= 60:
            elapsed_s = f"{int(elapsed)//60}m{int(elapsed)%60:02d}s"
        else:
            elapsed_s = f"{elapsed:.0f}s"

        success = proc.returncode == 0
        if success:
            bar = "\033[92m━\033[0m" * bar_width
            sys.stdout.write(
                f"\r\033[96m[⠏]\033[0m naabu: [{bar}] \033[92m100.0%\033[0m "
                f"\033[96mhost {hs}/{total_hosts}\033[0m "
                f"\033[92m{pf} ports\033[0m "
                f"\033[90m{elapsed_s}\033[0m\033[K\n"
            )
        else:
            est_pct = min(99.0, (hs / total_hosts * 100)) if total_hosts > 0 else 0
            filled = int(bar_width * est_pct / 100)
            bar = "\033[91m━\033[0m" * filled + "\033[90m━\033[0m" * (bar_width - filled)
            sys.stdout.write(
                f"\r\033[91m[✗]\033[0m naabu: [{bar}] \033[91m{est_pct:5.1f}%\033[0m "
                f"\033[96mhost {hs}/{total_hosts}\033[0m "
                f"\033[92m{pf} ports\033[0m "
                f"\033[90m{elapsed_s}\033[0m\033[K\n"
            )
        sys.stdout.flush()

    def _parse_output(self, filepath: str):
        """
        Parse naabu output file.
        Each line is: IP:PORT
        """
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or ":" not in line:
                        continue
                    # Format: IP:PORT
                    parts = line.rsplit(":", 1)
                    if len(parts) != 2:
                        continue
                    ip = parts[0].strip()
                    try:
                        port = int(parts[1].strip())
                    except ValueError:
                        continue

                    if ip not in self.results:
                        self.results[ip] = NaabuHostResult(ip=ip)
                    if port not in self.results[ip].ports:
                        self.results[ip].ports.append(port)
        except Exception:
            pass

    def _compute_stats(self, scan_time: float):
        """Compute aggregated statistics from naabu results."""
        self.stats.scan_time = scan_time
        self.stats.hosts_with_ports = len(self.results)

        port_counter: Dict[int, int] = {}
        total = 0

        for ip, host_result in self.results.items():
            for port in host_result.ports:
                total += 1
                port_counter[port] = port_counter.get(port, 0) + 1

        self.stats.total_open_ports = total
        self.stats.unique_ports = len(port_counter)

        # Top 10 ports
        self.stats.top_ports = [
            {"port": port, "count": cnt}
            for port, cnt in sorted(port_counter.items(), key=lambda x: -x[1])[:10]
        ]

    def get_open_ips_with_ports(self) -> Dict[str, List[int]]:
        """
        Return a dict of IP → list of open ports.
        Used to feed into nmap for targeted service detection.
        """
        return {
            ip: sorted(host.ports)
            for ip, host in self.results.items()
            if host.ports
        }

    def get_all_open_ips(self) -> Set[str]:
        """Return set of IPs that have at least one open port."""
        return {ip for ip, host in self.results.items() if host.ports}

    # ── Well-known port → service name mapping (for nmap compat) ─────────

    _PORT_SERVICE_MAP = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
        80: "http", 110: "pop3", 111: "rpcbind", 119: "nntp",
        135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
        139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
        389: "ldap", 443: "https", 445: "microsoft-ds",
        465: "smtps", 514: "syslog", 515: "printer",
        587: "submission", 631: "ipp", 636: "ldapssl",
        993: "imaps", 995: "pop3s", 1080: "socks",
        1433: "ms-sql-s", 1434: "ms-sql-m", 1521: "oracle",
        1723: "pptp", 2049: "nfs", 2181: "zookeeper",
        3000: "ppp", 3306: "mysql", 3389: "ms-wbt-server",
        3690: "svn", 4443: "https-alt", 5000: "upnp",
        5432: "postgresql", 5555: "freeciv", 5672: "amqp",
        5900: "vnc", 5901: "vnc-1", 5985: "wsman", 5986: "wsmans",
        6379: "redis", 6667: "irc", 8000: "http-alt",
        8080: "http-proxy", 8081: "blackice-icecap",
        8082: "blackice-alerts", 8443: "https-alt",
        8888: "sun-answerbook", 9090: "zeus-admin",
        9200: "wap-wsp", 9300: "vrace", 9443: "tungsten-https",
        11211: "memcache", 27017: "mongod", 27018: "mongod",
    }

    def to_nmap_results(self) -> dict:
        """
        Convert naabu results to nmap-compatible format.

        Returns a Dict[str, NmapHostResult] so downstream scanners
        (enum4linux, smbclient, vnc, snmp, ssh, nuclei) can work
        without any changes.
        """
        from .nmap_scan import NmapPort, NmapHostResult

        nmap_compat: dict = {}
        for ip, host in self.results.items():
            if not host.ports:
                continue
            ports = []
            for p in sorted(host.ports):
                svc = self._PORT_SERVICE_MAP.get(p, "")
                ports.append(NmapPort(
                    port=p,
                    protocol="tcp",
                    state="open",
                    service=svc,
                    version="",
                    extra_info="naabu",
                ))
            nmap_compat[ip] = NmapHostResult(
                ip=ip,
                hostname="",
                state="up",
                ports=ports,
            )
        return nmap_compat

    def to_nmap_stats(self) -> dict:
        """
        Convert naabu stats to nmap_stats-compatible dict.
        """
        from collections import Counter
        port_counter = Counter()
        svc_counter = Counter()
        for ip, host in self.results.items():
            for p in host.ports:
                port_counter[p] += 1
                svc = self._PORT_SERVICE_MAP.get(p, f"unknown-{p}")
                svc_counter[svc] += 1

        return {
            "total_ips_scanned": self.stats.total_ips_scanned,
            "hosts_up": self.stats.hosts_with_ports,
            "total_open_ports": self.stats.total_open_ports,
            "unique_services": len(svc_counter),
            "scan_time": self.stats.scan_time,
            "top_ports": [
                {"port": port, "count": cnt}
                for port, cnt in sorted(port_counter.items(), key=lambda x: -x[1])[:10]
            ],
            "top_services": [
                {"service": svc, "count": cnt}
                for svc, cnt in sorted(svc_counter.items(), key=lambda x: -x[1])[:10]
            ],
        }
