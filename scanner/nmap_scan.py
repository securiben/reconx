"""
Nmap Port & Service Scanner for ReconX.
Runs nmap against discovered IP addresses for port scanning
and service/version detection.

Command: nmap -iL <ip_file> -sCV --top-ports 1000 -T3 -oA <output_prefix>

Requires: nmap installed in PATH
  Install (Debian/Ubuntu): sudo apt install nmap
  Install (Windows):       https://nmap.org/download.html
  Install (macOS):         brew install nmap
"""

import os
import sys
import shutil
import subprocess
import tempfile
import time
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict

from ..config import ScannerConfig


@dataclass
class NmapPort:
    """A single discovered port/service."""
    port: int = 0
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    extra_info: str = ""

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "extra_info": self.extra_info,
        }


@dataclass
class NmapHostResult:
    """Parsed nmap result for a single host (IP)."""
    ip: str = ""
    hostname: str = ""
    state: str = "up"
    ports: List[NmapPort] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "state": self.state,
            "ports": [p.to_dict() for p in self.ports],
        }


@dataclass
class NmapStats:
    """Aggregated nmap scan statistics."""
    total_ips_scanned: int = 0
    hosts_up: int = 0
    total_open_ports: int = 0
    unique_services: int = 0
    scan_time: float = 0.0
    top_ports: List[Dict] = field(default_factory=list)
    top_services: List[Dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_ips_scanned": self.total_ips_scanned,
            "hosts_up": self.hosts_up,
            "total_open_ports": self.total_open_ports,
            "unique_services": self.unique_services,
            "scan_time": self.scan_time,
            "top_ports": self.top_ports,
            "top_services": self.top_services,
        }


class NmapScanner:
    """
    Nmap port & service scanner wrapper.

    Runs nmap against discovered IP addresses with service version
    detection (-sCV) on the top 1000 ports.
    """

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.nmap_path = self._find_nmap()
        self.available = self.nmap_path is not None
        self.results: Dict[str, NmapHostResult] = {}  # ip → result
        self.stats = NmapStats()

    def _find_nmap(self) -> Optional[str]:
        """Find the nmap binary in PATH or common install locations."""
        found = shutil.which("nmap")
        if found:
            return found

        common_paths = [
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "/opt/homebrew/bin/nmap",
        ]
        if os.name == "nt":
            common_paths.extend([
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
                os.path.join(os.environ.get("PROGRAMFILES", ""), "Nmap", "nmap.exe"),
                os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Nmap", "nmap.exe"),
            ])

        for path in common_paths:
            if path and os.path.isfile(path):
                return path

        return None

    def scan(self, ip_addresses: Set[str], output_dir: str = "") -> Dict[str, NmapHostResult]:
        """
        Run nmap against a set of discovered IP addresses.

        Strategy:
          1. ICMP ping sweep to classify hosts as up/down.
          2. Hosts that respond to ping → scan normally.
          3. Hosts that don't respond → scan with -Pn (skip host discovery).
          This avoids long timeouts on hosts with ICMP disabled.

        Args:
            ip_addresses: Set of IP addresses to scan.
            output_dir: Directory to place nmap output files.
                        If empty, uses a temp directory.

        Returns:
            Dict mapping IP → NmapHostResult.
        """
        if not self.available:
            return {}

        if not ip_addresses:
            return {}

        scan_start = time.time()
        self.stats.total_ips_scanned = len(ip_addresses)

        # ── Phase 1: ICMP ping sweep ────────────────────────────────────
        icmp_up, icmp_down = self._ping_sweep(ip_addresses)

        print(
            f"\033[36m[>]\033[0m nmap: ping sweep → "
            f"\033[92m{len(icmp_up)} up\033[0m / "
            f"\033[91m{len(icmp_down)} down (ICMP blocked)\033[0m"
        )
        if icmp_up:
            print(
                f"\033[92m[+]\033[0m nmap: ICMP up → "
                f"\033[96m{', '.join(sorted(icmp_up))}\033[0m"
            )
        if icmp_down:
            print(
                f"\033[93m[!]\033[0m nmap: ICMP down (will use -Pn) → "
                f"\033[96m{', '.join(sorted(icmp_down))}\033[0m"
            )

        # ── Phase 2: Full scan ──────────────────────────────────────────
        # Prepare temp dir
        tmpdir = tempfile.mkdtemp(prefix="reconx_nmap_")

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        try:
            # Scan ICMP-up hosts normally
            if icmp_up:
                output_prefix_up = os.path.join(
                    output_dir or tmpdir, "nmap_scan"
                )
                self._run_nmap_scan(
                    icmp_up, output_prefix_up, tmpdir,
                    extra_flags=[], label="ICMP-up hosts",
                )

            # Scan ICMP-down hosts with -Pn
            if icmp_down:
                output_prefix_down = os.path.join(
                    output_dir or tmpdir, "nmap_scan_pn"
                )
                self._run_nmap_scan(
                    icmp_down, output_prefix_down, tmpdir,
                    extra_flags=["-Pn"], label="ICMP-down hosts (-Pn)",
                )

            # Copy output files to output_dir if needed
            if output_dir and output_dir != tmpdir:
                for prefix_name in ["nmap_scan", "nmap_scan_pn"]:
                    for ext in [".nmap", ".xml", ".gnmap"]:
                        src = os.path.join(tmpdir, prefix_name + ext)
                        if os.path.isfile(src):
                            dst = os.path.join(output_dir, prefix_name + ext)
                            if os.path.abspath(src) != os.path.abspath(dst):
                                import shutil as _shutil
                                _shutil.copy2(src, dst)

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

    def _ping_sweep(self, ip_addresses: Set[str]) -> tuple:
        """
        Run nmap ICMP ping sweep (-sn) to classify hosts as up/down.

        Returns:
            (icmp_up: Set[str], icmp_down: Set[str])
        """
        icmp_up: Set[str] = set()
        icmp_down: Set[str] = set()

        tmpdir = tempfile.mkdtemp(prefix="reconx_ping_")
        input_file = os.path.join(tmpdir, "ping_targets.txt")
        gnmap_file = os.path.join(tmpdir, "ping_sweep.gnmap")

        try:
            with open(input_file, "w", encoding="utf-8") as f:
                for ip in sorted(ip_addresses):
                    f.write(ip + "\n")

            print(
                f"\033[36m[>]\033[0m nmap: pinging "
                f"\033[96m{len(ip_addresses)}\033[0m IPs (ICMP sweep) ..."
            )

            cmd = [
                self.nmap_path,
                "-sn",           # Ping scan only (no port scan)
                "-PE",           # ICMP echo request
                "-iL", input_file,
                "-oG", gnmap_file,
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                encoding="utf-8",
                errors="replace",
            )

            # Parse gnmap output for up hosts
            if os.path.isfile(gnmap_file):
                with open(gnmap_file, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("Host:") and "Status: Up" in line:
                            # "Host: 1.2.3.4 () Status: Up"
                            parts = line.split()
                            if len(parts) >= 2:
                                icmp_up.add(parts[1])

            icmp_down = ip_addresses - icmp_up

        except subprocess.TimeoutExpired:
            # If ping times out, treat all as down (use -Pn for all)
            icmp_down = set(ip_addresses)
        except Exception:
            # On error, treat all as down (safe fallback)
            icmp_down = set(ip_addresses)
        finally:
            try:
                for f in os.listdir(tmpdir):
                    os.remove(os.path.join(tmpdir, f))
                os.rmdir(tmpdir)
            except Exception:
                pass

        return icmp_up, icmp_down

    def _run_nmap_scan(
        self,
        ip_addresses: Set[str],
        output_prefix: str,
        tmpdir: str,
        extra_flags: List[str] = None,
        label: str = "",
    ):
        """
        Run a full nmap scan on a set of IPs.

        Args:
            ip_addresses: IPs to scan.
            output_prefix: Output file prefix (for -oA).
            tmpdir: Temp directory for the input file.
            extra_flags: Extra nmap flags (e.g. ["-Pn"]).
            label: Display label for the scan.
        """
        if not ip_addresses:
            return

        input_file = os.path.join(tmpdir, f"targets_{os.path.basename(output_prefix)}.txt")

        with open(input_file, "w", encoding="utf-8") as f:
            for ip in sorted(ip_addresses):
                f.write(ip + "\n")

        flags_str = " ".join(extra_flags) if extra_flags else ""
        flag_display = f" {flags_str}" if flags_str else ""

        cmd = [
            self.nmap_path,
            "-iL", input_file,
            "-sCV",
            "--top-ports", "1000",
            "-T3",
            "-oA", output_prefix,
        ]
        if extra_flags:
            cmd.extend(extra_flags)

        print(
            f"\033[36m[>]\033[0m nmap: scanning \033[96m{len(ip_addresses)}\033[0m "
            f"{label} with \033[96m-sCV --top-ports 1000 -T3{flag_display}\033[0m ..."
        )

        timeout_secs = max(1800, len(ip_addresses) * 30)
        proc = subprocess.Popen(
            cmd,
            stdout=sys.stderr,
            stderr=sys.stderr,
        )

        try:
            proc.wait(timeout=timeout_secs)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        # Parse results
        gnmap_file = output_prefix + ".gnmap"
        if os.path.isfile(gnmap_file):
            self._parse_gnmap(gnmap_file)

        nmap_file = output_prefix + ".nmap"
        if os.path.isfile(nmap_file):
            self._parse_nmap_normal(nmap_file)

        # Cleanup input file
        try:
            if os.path.isfile(input_file):
                os.remove(input_file)
        except Exception:
            pass

    def _parse_gnmap(self, filepath: str):
        """
        Parse nmap greppable output (.gnmap) for host/port data.
        Lines look like:
        Host: 1.2.3.4 (hostname) Ports: 80/open/tcp//http///, 443/open/tcp//https///
        """
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line.startswith("Host:"):
                        continue
                    if "Ports:" not in line:
                        continue

                    # Parse host
                    parts = line.split("\t")
                    host_part = parts[0]  # "Host: 1.2.3.4 (hostname)"

                    # Extract IP and hostname
                    host_tokens = host_part.replace("Host: ", "").strip()
                    ip = host_tokens.split()[0]
                    hostname = ""
                    if "(" in host_tokens and ")" in host_tokens:
                        hostname = host_tokens.split("(")[1].split(")")[0]

                    result = NmapHostResult(ip=ip, hostname=hostname, state="up")

                    # Parse ports
                    for part in parts:
                        part = part.strip()
                        if part.startswith("Ports:"):
                            port_str = part.replace("Ports:", "").strip()
                            port_entries = port_str.split(",")
                            for entry in port_entries:
                                entry = entry.strip()
                                if not entry:
                                    continue
                                # Format: port/state/protocol/owner/service/rpc_info/version/
                                fields = entry.split("/")
                                if len(fields) >= 5:
                                    try:
                                        port_num = int(fields[0].strip())
                                    except ValueError:
                                        continue
                                    state = fields[1].strip()
                                    proto = fields[2].strip()
                                    service = fields[4].strip() if len(fields) > 4 else ""
                                    version = fields[6].strip() if len(fields) > 6 else ""

                                    if state in ("open", "open|filtered"):
                                        port = NmapPort(
                                            port=port_num,
                                            protocol=proto,
                                            state=state,
                                            service=service,
                                            version=version,
                                        )
                                        result.ports.append(port)

                    self.results[ip] = result

        except Exception:
            pass

    def _parse_nmap_normal(self, filepath: str):
        """
        Parse nmap normal output (.nmap) for additional service version info.
        Enriches existing results from gnmap with version details.
        """
        try:
            current_ip = None
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip()

                    # Detect scan report header
                    if line.startswith("Nmap scan report for"):
                        # Extract IP from "Nmap scan report for hostname (IP)" or "... for IP"
                        rest = line.replace("Nmap scan report for ", "").strip()
                        if "(" in rest and ")" in rest:
                            current_ip = rest.split("(")[1].split(")")[0]
                        else:
                            current_ip = rest.split()[0] if rest else None
                        continue

                    # Parse port lines like "80/tcp  open  http  Apache/2.4.41"
                    if current_ip and "/" in line and ("open" in line or "filtered" in line):
                        parts = line.split()
                        if len(parts) >= 3:
                            port_proto = parts[0]  # "80/tcp"
                            try:
                                port_num = int(port_proto.split("/")[0])
                                proto = port_proto.split("/")[1]
                            except (ValueError, IndexError):
                                continue

                            state = parts[1]
                            service = parts[2] if len(parts) > 2 else ""
                            version = " ".join(parts[3:]) if len(parts) > 3 else ""

                            if state in ("open", "open|filtered"):
                                if current_ip in self.results:
                                    # Update existing port with better version info
                                    for p in self.results[current_ip].ports:
                                        if p.port == port_num and p.protocol == proto:
                                            if version and not p.version:
                                                p.version = version
                                            if service and not p.service:
                                                p.service = service
                                            break
                                    else:
                                        # Port not found in gnmap, add it
                                        self.results[current_ip].ports.append(NmapPort(
                                            port=port_num,
                                            protocol=proto,
                                            state=state,
                                            service=service,
                                            version=version,
                                        ))
                                else:
                                    # Host not in gnmap results, create new
                                    self.results[current_ip] = NmapHostResult(
                                        ip=current_ip, state="up",
                                        ports=[NmapPort(
                                            port=port_num,
                                            protocol=proto,
                                            state=state,
                                            service=service,
                                            version=version,
                                        )]
                                    )
        except Exception:
            pass

    def _compute_stats(self, scan_time: float):
        """Compute aggregated statistics from nmap results."""
        self.stats.scan_time = scan_time
        self.stats.hosts_up = len(self.results)

        all_ports = []
        service_counter: Dict[str, int] = {}
        port_counter: Dict[int, int] = {}

        for ip, host_result in self.results.items():
            for p in host_result.ports:
                if p.state == "open":
                    all_ports.append(p)
                    svc = p.service or "unknown"
                    service_counter[svc] = service_counter.get(svc, 0) + 1
                    port_counter[p.port] = port_counter.get(p.port, 0) + 1

        self.stats.total_open_ports = len(all_ports)
        self.stats.unique_services = len(service_counter)

        # Top 10 ports
        self.stats.top_ports = [
            {"port": port, "count": cnt}
            for port, cnt in sorted(port_counter.items(), key=lambda x: -x[1])[:10]
        ]

        # Top 10 services
        self.stats.top_services = [
            {"service": svc, "count": cnt}
            for svc, cnt in sorted(service_counter.items(), key=lambda x: -x[1])[:10]
        ]

    def get_results_by_port(self) -> Dict[int, List[str]]:
        """Group IPs by open port number."""
        groups: Dict[int, List[str]] = defaultdict(list)
        for ip, host in self.results.items():
            for p in host.ports:
                if p.state == "open":
                    groups[p.port].append(ip)
        return dict(groups)

    def get_results_by_service(self) -> Dict[str, List[str]]:
        """Group IPs by service name."""
        groups: Dict[str, List[str]] = defaultdict(list)
        for ip, host in self.results.items():
            for p in host.ports:
                if p.state == "open":
                    svc = p.service or "unknown"
                    groups[svc].append(f"{ip}:{p.port}")
        return dict(groups)
