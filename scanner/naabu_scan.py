"""
Naabu + Nmap Port & Service Scanner for ReconX.

Default port scanning pipeline:
  naabu -l targets.txt -top-ports 1000 -rate 3000 -c 50

With --nmap-cli flag:
  naabu -l targets.txt -top-ports 1000 -rate 3000 -c 50
        -nmap-cli 'nmap -sV --script vuln -oN nmap-vuln.txt'

The -nmap-cli integration is opt-in (--nmap-cli flag).
Without it, naabu runs port discovery only (no service detection).

Provides nmap-compatible output so downstream scanners
(enum4linux, smbclient, vnc-brute, snmp, ssh, nuclei, etc.)
work transparently.

Requires: naabu from ProjectDiscovery installed in PATH
  Install: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  Or:      sudo apt install naabu
  Or:      https://github.com/projectdiscovery/naabu/releases
Optional: nmap for service detection + vuln scanning
  Install: sudo apt install nmap
"""

import os
import re
import sys
import json
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
        self._nmap_services: Dict[str, Dict] = {}  # "ip:port" → {service, version}
        self._hostname_to_ip: Dict[str, str] = {}   # hostname → resolved IP
        self.used_nmap_cli: bool = False  # True when scan used -nmap-cli

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
        self, targets: Set[str], output_dir: str = ""
    ) -> Dict[str, NaabuHostResult]:
        """
        Run naabu + nmap-cli for port discovery and service detection.

        Pipeline:
          naabu -l targets.txt -top-ports 1000 -rate 3000 -c 50
                -nmap-cli 'nmap -sV --script vuln -oN nmap-vuln.txt'

        When nmap is not installed, runs naabu-only (no service detection).

        Args:
            targets: Set of IPs or hostnames to scan (naabu resolves hostnames).
            output_dir: Directory to place output files.

        Returns:
            Dict mapping IP → NaabuHostResult.
        """
        if not self.available:
            return {}

        if not targets:
            return {}

        # Reset state
        self.results = {}
        self._nmap_services = {}
        self._hostname_to_ip = {}
        self.used_nmap_cli = False

        scan_start = time.time()
        self.stats.total_ips_scanned = len(targets)

        # Prepare temp dir
        tmpdir = tempfile.mkdtemp(prefix="reconx_naabu_")
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        output_file = os.path.join(tmpdir, "naabu_results.txt")
        input_file = os.path.join(tmpdir, "naabu_targets.txt")

        # nmap output goes to output_dir (or tmpdir as fallback)
        nmap_output = os.path.join(
            output_dir if output_dir else tmpdir, "nmap-vuln.txt"
        )

        try:
            self._run_naabu_scan(
                targets, input_file, output_file,
                nmap_output_file=nmap_output,
                label="targets",
            )

            # Parse naabu port discovery results (IP:PORT)
            if os.path.isfile(output_file):
                self._parse_output(output_file)

            # Parse nmap output for service/version enrichment
            if os.path.isfile(nmap_output) and os.path.getsize(nmap_output) > 0:
                self._parse_nmap_output(nmap_output)

            # Copy naabu results to output_dir/txt/ as ip:port format
            if output_dir and self.results:
                txt_dir = os.path.join(output_dir, "txt")
                os.makedirs(txt_dir, exist_ok=True)
                naabu_txt = os.path.join(txt_dir, "naabu_scan.txt")
                ip_port_lines = []
                for ip, hr in sorted(self.results.items()):
                    for port in sorted(hr.ports):
                        ip_port_lines.append(f"{ip}:{port}")
                with open(naabu_txt, "w", encoding="utf-8") as _f:
                    _f.write("\n".join(ip_port_lines) + "\n")

        except FileNotFoundError:
            self.available = False
        except Exception:
            pass
        finally:
            # Cleanup temp files (keep files in output_dir)
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
        targets: Set[str],
        input_file: str,
        output_file: str,
        nmap_output_file: str = "",
        label: str = "",
    ):
        """
        Run naabu with a live progress bar and optional -nmap-cli.

        Args:
            targets: IPs or hostnames to scan.
            input_file: Path to write targets list.
            output_file: Path for naabu output.
            nmap_output_file: Path for nmap -oN output (via -nmap-cli).
            label: Display label for the scan.
        """
        if not targets:
            return

        # Write targets file
        with open(input_file, "w", encoding="utf-8") as f:
            for t in sorted(targets):
                f.write(t + "\n")

        total_hosts = len(targets)

        cmd = [
            self.naabu_path,
            "-l", input_file,
            "-top-ports", "1000",
            "-rate", "3000",
            "-c", "50",
            "-retries", "3",
            "-warm-up-time", "0",
            "-json",       # output JSON lines: {"ip":"...","port":N,"host":"..."}
            "-o", output_file,
        ]

        # Add nmap service detection + vuln scanning via -nmap-cli (opt-in)
        nmap_path = shutil.which("nmap")
        has_nmap_cli = False
        want_nmap_cli = getattr(self.config, 'use_nmap_cli', False)
        if want_nmap_cli and nmap_path and nmap_output_file:
            nmap_script = getattr(self.config, 'nmap_script', '') or 'vuln'
            nmap_out = f'"{nmap_output_file}"' if " " in nmap_output_file else nmap_output_file
            nmap_cli = f"nmap -sV --script {nmap_script} -oN {nmap_out}"
            cmd.extend(["-nmap-cli", nmap_cli])
            has_nmap_cli = True
            self.used_nmap_cli = True

        bar_label = "naabu+nmap" if has_nmap_cli else "naabu"

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
            """Read stdout for JSON lines (naabu -json outputs ports here)."""
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
                    if not line:
                        continue
                    # JSON format: {"ip":"1.2.3.4","port":443,"host":"sub.example.com"}
                    if line.startswith("{"):
                        try:
                            obj = json.loads(line)
                            ip_val = obj.get("ip", "")
                            if ip_val:
                                ports_found[0] += 1
                                with hosts_seen_lock:
                                    hosts_seen.add(ip_val)
                        except Exception:
                            pass
                    elif ":" in line:
                        # Fallback: plain host:port (non-JSON mode)
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
        if has_nmap_cli:
            scan_label = (
                f"{bar_label}: \033[96m{total_hosts}\033[0m {label} "
                f"\033[90m-top-ports 1000 -sV --script vuln\033[0m"
            )
        else:
            scan_label = (
                f"{bar_label}: \033[96m{total_hosts}\033[0m {label} "
                f"\033[90m-top-ports 1000\033[0m"
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
                f"\r\033[96m[{spinner}]\033[0m {bar_label}: [{bar}] "
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
                f"\r\033[96m[⠏]\033[0m {bar_label}: [{bar}] \033[92m100.0%\033[0m "
                f"\033[96mhost {hs}/{total_hosts}\033[0m "
                f"\033[92m{pf} ports\033[0m "
                f"\033[90m{elapsed_s}\033[0m\033[K\n"
            )
        else:
            est_pct = min(99.0, (hs / total_hosts * 100)) if total_hosts > 0 else 0
            filled = int(bar_width * est_pct / 100)
            bar = "\033[91m━\033[0m" * filled + "\033[90m━\033[0m" * (bar_width - filled)
            sys.stdout.write(
                f"\r\033[91m[✗]\033[0m {bar_label}: [{bar}] \033[91m{est_pct:5.1f}%\033[0m "
                f"\033[96mhost {hs}/{total_hosts}\033[0m "
                f"\033[92m{pf} ports\033[0m "
                f"\033[90m{elapsed_s}\033[0m\033[K\n"
            )
        sys.stdout.flush()

    def _parse_output(self, filepath: str):
        """
        Parse naabu JSON output file.
        Each line is a JSON object: {"ip":"1.2.3.4","port":443,"host":"sub.example.com"}
        Falls back to plain host:port format if not JSON.
        Results are always keyed by IP address.
        """
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    ip = ""
                    port = 0

                    if line.startswith("{"):
                        # JSON format: {"ip":"1.2.3.4","port":443,"host":"sub.example.com"}
                        try:
                            obj = json.loads(line)
                            ip = obj.get("ip", "").strip()
                            port = int(obj.get("port", 0))
                            hostname = obj.get("host", "").strip()
                            # Store hostname → IP mapping
                            if hostname and ip and hostname != ip:
                                self._hostname_to_ip[hostname] = ip
                        except Exception:
                            continue
                    elif ":" in line:
                        # Fallback: plain host:port
                        parts = line.rsplit(":", 1)
                        if len(parts) != 2:
                            continue
                        ip = parts[0].strip()
                        try:
                            port = int(parts[1].strip())
                        except ValueError:
                            continue

                    if not ip or not port:
                        continue

                    if ip not in self.results:
                        self.results[ip] = NaabuHostResult(ip=ip)
                    if port not in self.results[ip].ports:
                        self.results[ip].ports.append(port)
        except Exception:
            pass

    def _parse_nmap_output(self, filepath: str):
        """
        Parse nmap normal output (-oN) for service/version enrichment.

        Extracts service names and versions from nmap output produced
        by naabu's -nmap-cli, enriching the port-only results with
        real service detection data.
        """
        try:
            current_ip = None
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip()

                    # Detect scan report header
                    # "Nmap scan report for hostname (IP)" or "... for IP"
                    if line.startswith("Nmap scan report for"):
                        rest = line.replace("Nmap scan report for ", "").strip()
                        if "(" in rest and ")" in rest:
                            current_ip = rest.split("(")[1].split(")")[0]
                        else:
                            current_ip = rest.split()[0] if rest else None
                        continue

                    # Parse port lines: "80/tcp  open  http  Apache/2.4.41"
                    if (current_ip and "/" in line
                            and ("open" in line or "filtered" in line)):
                        parts = line.split()
                        if len(parts) >= 3:
                            try:
                                port_num = int(parts[0].split("/")[0])
                            except (ValueError, IndexError):
                                continue
                            state = parts[1]
                            if state not in ("open", "open|filtered"):
                                continue
                            service = parts[2] if len(parts) > 2 else ""
                            version = " ".join(parts[3:]) if len(parts) > 3 else ""

                            # Store enrichment data
                            key = f"{current_ip}:{port_num}"
                            self._nmap_services[key] = {
                                "service": service,
                                "version": version,
                            }

                            # Also ensure this port is in naabu results
                            if current_ip not in self.results:
                                self.results[current_ip] = NaabuHostResult(ip=current_ip)
                            if port_num not in self.results[current_ip].ports:
                                self.results[current_ip].ports.append(port_num)
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

        Uses real service/version data from -nmap-cli output when
        available, falling back to well-known port mappings.

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
                key = f"{ip}:{p}"
                enriched = self._nmap_services.get(key, {})
                svc = enriched.get("service", self._PORT_SERVICE_MAP.get(p, ""))
                ver = enriched.get("version", "")
                ports.append(NmapPort(
                    port=p,
                    protocol="tcp",
                    state="open",
                    service=svc,
                    version=ver,
                    extra_info="naabu+nmap" if enriched else "naabu",
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
