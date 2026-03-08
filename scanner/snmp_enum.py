"""
Metasploit SNMP Enumeration Scanner for ReconX.
Uses msfconsole auxiliary/scanner/snmp/snmp_enum to enumerate
system information from hosts with valid SNMP community strings.

For each IP with a known community string (from snmp_login):
  1. Run auxiliary/scanner/snmp/snmp_enum with discovered community
  2. Parse output for system information, network info, etc.
  3. Report structured enumeration data

Requires: msfconsole (Metasploit Framework) installed in PATH
  Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html
"""

import os
import sys
import shutil
import subprocess
import tempfile
import time
import re
import json
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field

from ..config import ScannerConfig


# ─── SNMP Ports ───────────────────────────────────────────────────────────────

SNMP_PORTS = {161, 162}


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class SNMPSystemInfo:
    """Parsed SNMP system information."""
    host_ip: str = ""
    hostname: str = ""
    description: str = ""
    contact: str = ""
    location: str = ""
    uptime_snmp: str = ""
    uptime_system: str = ""
    system_date: str = ""

    def to_dict(self) -> dict:
        d = {}
        if self.host_ip:
            d["host_ip"] = self.host_ip
        if self.hostname:
            d["hostname"] = self.hostname
        if self.description:
            d["description"] = self.description
        if self.contact:
            d["contact"] = self.contact
        if self.location:
            d["location"] = self.location
        if self.uptime_snmp:
            d["uptime_snmp"] = self.uptime_snmp
        if self.uptime_system:
            d["uptime_system"] = self.uptime_system
        if self.system_date:
            d["system_date"] = self.system_date
        return d


@dataclass
class SNMPNetworkInfo:
    """Parsed SNMP network information."""
    ip_forwarding: str = ""
    interfaces: List[Dict] = field(default_factory=list)
    ip_addresses: List[Dict] = field(default_factory=list)
    routing_table: List[Dict] = field(default_factory=list)
    tcp_connections: List[Dict] = field(default_factory=list)
    listening_udp: List[Dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {}
        if self.ip_forwarding:
            d["ip_forwarding"] = self.ip_forwarding
        if self.interfaces:
            d["interfaces"] = self.interfaces
        if self.ip_addresses:
            d["ip_addresses"] = self.ip_addresses
        if self.routing_table:
            d["routing_table"] = self.routing_table
        if self.tcp_connections:
            d["tcp_connections"] = self.tcp_connections
        if self.listening_udp:
            d["listening_udp"] = self.listening_udp
        return d


@dataclass
class SNMPEnumHostResult:
    """SNMP enumeration result for a single host."""
    ip: str = ""
    port: int = 161
    community: str = ""
    system_info: Optional[SNMPSystemInfo] = None
    network_info: Optional[SNMPNetworkInfo] = None
    processes: List[Dict] = field(default_factory=list)
    software: List[str] = field(default_factory=list)
    storage: List[Dict] = field(default_factory=list)
    user_accounts: List[str] = field(default_factory=list)
    shares: List[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    scan_time: float = 0.0
    raw_output: str = ""

    def to_dict(self) -> dict:
        d = {
            "ip": self.ip,
            "port": self.port,
            "community": self.community,
            "scan_time": round(self.scan_time, 2),
        }
        if self.system_info:
            d["system_info"] = self.system_info.to_dict()
        if self.network_info:
            d["network_info"] = self.network_info.to_dict()
        if self.processes:
            d["processes"] = self.processes
        if self.software:
            d["software"] = self.software
        if self.storage:
            d["storage"] = self.storage
        if self.user_accounts:
            d["user_accounts"] = self.user_accounts
        if self.shares:
            d["shares"] = self.shares
        if self.skipped:
            d["skipped"] = True
            d["skip_reason"] = self.skip_reason
        return d


@dataclass
class SNMPEnumStats:
    """Aggregated SNMP enumeration statistics."""
    total_snmp_hosts: int = 0
    hosts_enumerated: int = 0
    hosts_skipped: int = 0
    hosts_with_sysinfo: int = 0
    hosts_with_netinfo: int = 0
    hosts_with_processes: int = 0
    hosts_with_users: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_snmp_hosts": self.total_snmp_hosts,
            "hosts_enumerated": self.hosts_enumerated,
            "hosts_skipped": self.hosts_skipped,
            "hosts_with_sysinfo": self.hosts_with_sysinfo,
            "hosts_with_netinfo": self.hosts_with_netinfo,
            "hosts_with_processes": self.hosts_with_processes,
            "hosts_with_users": self.hosts_with_users,
            "scan_time": round(self.scan_time, 2),
        }


# ─── Section-header patterns ─────────────────────────────────────────────────

SECTION_PATTERN = re.compile(
    r'^\[\*\]\s*(System information|Network information|'
    r'Network interfaces|IP addresses|Routing information|'
    r'TCP connections|Listening UDP|Processes|Software components|'
    r'Storage information|User accounts|Share|File system)',
    re.IGNORECASE,
)

CONNECTED_PATTERN = re.compile(
    r'\[\+\]\s*(\d+\.\d+\.\d+\.\d+),?\s*Connected',
    re.IGNORECASE,
)

# Key-value patterns for system/network info
KV_PATTERN = re.compile(
    r'^([A-Za-z][A-Za-z0-9 _/]+?)\s{2,}:\s*(.+)$'
)


# ─── Main Scanner ─────────────────────────────────────────────────────────────

class SNMPEnumScanner:
    """
    Metasploit SNMP enumeration scanner.

    Uses msfconsole auxiliary/scanner/snmp/snmp_enum to enumerate
    detailed system information from hosts with known SNMP community strings.

    Requires community strings from SNMPLoginScanner (or defaults to 'public').
    """

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.msf_path = self._find_msfconsole()
        self.available = self.msf_path is not None
        self.results: Dict[str, SNMPEnumHostResult] = {}  # "ip:port" → result
        self.stats = SNMPEnumStats()

    def _find_msfconsole(self) -> Optional[str]:
        """Find the msfconsole binary in PATH or common install locations."""
        found = shutil.which("msfconsole")
        if found:
            return found

        common_paths = [
            "/usr/bin/msfconsole",
            "/usr/local/bin/msfconsole",
            "/opt/metasploit-framework/bin/msfconsole",
            "/opt/metasploit/msfconsole",
        ]
        if os.name == "nt":
            common_paths.extend([
                r"C:\metasploit-framework\bin\msfconsole.bat",
                r"C:\metasploit-framework\msfconsole.bat",
                os.path.join(
                    os.environ.get("PROGRAMFILES", ""),
                    "Metasploit", "bin", "msfconsole.bat"
                ),
                os.path.join(
                    os.environ.get("PROGRAMFILES(X86)", ""),
                    "Metasploit", "bin", "msfconsole.bat"
                ),
            ])

        for path in common_paths:
            if path and os.path.isfile(path):
                return path

        # Auto-install metasploit if not found
        from .auto_install import ensure_tool
        if ensure_tool("msfconsole"):
            return shutil.which("msfconsole")

        return None

    def _get_snmp_hosts(self, nmap_results: Dict) -> List[tuple]:
        """
        Extract hosts with SNMP ports open from nmap results.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.

        Returns:
            List of (ip, port) tuples.
        """
        snmp_targets = []
        for ip, host_result in nmap_results.items():
            ports = []
            if hasattr(host_result, 'ports'):
                ports = host_result.ports
            elif isinstance(host_result, dict):
                ports = host_result.get('ports', [])

            for port_entry in ports:
                port_num = port_entry.port if hasattr(port_entry, 'port') else port_entry.get('port', 0)
                state = port_entry.state if hasattr(port_entry, 'state') else port_entry.get('state', '')
                service = port_entry.service if hasattr(port_entry, 'service') else port_entry.get('service', '')

                if state == "open" and (
                    port_num in SNMP_PORTS
                    or "snmp" in service.lower()
                ):
                    snmp_targets.append((ip, port_num))

        snmp_targets.sort(key=lambda t: (t[0], t[1]))
        return snmp_targets

    def scan(
        self,
        nmap_results: Dict,
        community_map: Optional[Dict[str, List[str]]] = None,
        output_dir: str = "",
    ) -> Dict[str, SNMPEnumHostResult]:
        """
        Run SNMP enumeration against hosts with SNMP ports open.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.
            community_map: Optional Dict[ip, List[community_string]] from
                           SNMPLoginScanner.get_community_strings().
                           If not provided, defaults to 'public'.
            output_dir: Directory to save output files.

        Returns:
            Dict mapping "ip:port" → SNMPEnumHostResult.
        """
        if not self.available:
            return {}

        if not nmap_results:
            return {}

        # Find SNMP hosts from nmap results
        snmp_targets = self._get_snmp_hosts(nmap_results)
        if not snmp_targets:
            return {}

        scan_start = time.time()
        self.stats.total_snmp_hosts = len(snmp_targets)

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        unique_ips = len({t[0] for t in snmp_targets})
        print(
            f"\033[36m[>]\033[0m snmp-enum: SNMP enumeration on "
            f"\033[96m{len(snmp_targets)}\033[0m target(s) "
            f"(\033[96m{unique_ips}\033[0m unique IP(s)) ..."
        )

        for idx, (ip, snmp_port) in enumerate(snmp_targets, 1):
            result_key = f"{ip}:{snmp_port}"

            # Determine community string to use
            community = "public"
            if community_map and ip in community_map:
                community = community_map[ip][0]  # use first discovered community

            print(
                f"\033[36m[>]\033[0m snmp-enum: "
                f"[\033[96m{idx}/{len(snmp_targets)}\033[0m] "
                f"\033[96m{ip}:{snmp_port}\033[0m "
                f"(community: \033[93m{community}\033[0m) ..."
            )

            host_result = self._enum_host(ip, snmp_port, community, output_dir)
            self.results[result_key] = host_result

            # Print per-host status
            if host_result.skipped:
                print(
                    f"\033[93m[!]\033[0m snmp-enum: \033[96m{ip}:{snmp_port}\033[0m → "
                    f"\033[93mskipped ({host_result.skip_reason})\033[0m "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )
            elif host_result.system_info and host_result.system_info.hostname:
                sysinfo = host_result.system_info
                desc_str = f" — {sysinfo.description}" if sysinfo.description else ""
                print(
                    f"\033[1;92m[+]\033[0m snmp-enum: \033[96m{ip}:{snmp_port}\033[0m → "
                    f"\033[1;92m{sysinfo.hostname}\033[0m"
                    f"\033[90m{desc_str}\033[0m "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )
                if sysinfo.contact:
                    print(
                        f"    \033[90mContact: {sysinfo.contact}\033[0m"
                    )
                if sysinfo.location:
                    print(
                        f"    \033[90mLocation: {sysinfo.location}\033[0m"
                    )
                if host_result.network_info and host_result.network_info.ip_forwarding:
                    fwd = host_result.network_info.ip_forwarding
                    if "yes" in fwd.lower():
                        print(
                            f"    \033[93m[!] IP forwarding: {fwd}\033[0m"
                        )
                if host_result.user_accounts:
                    print(
                        f"    \033[96mUsers: {len(host_result.user_accounts)}\033[0m"
                    )
                if host_result.processes:
                    print(
                        f"    \033[96mProcesses: {len(host_result.processes)}\033[0m"
                    )
            else:
                print(
                    f"\033[37m[-]\033[0m snmp-enum: \033[96m{ip}:{snmp_port}\033[0m → "
                    f"\033[37mno data retrieved\033[0m "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )

        scan_elapsed = time.time() - scan_start
        self._compute_stats(scan_elapsed)

        # Save combined results
        if output_dir:
            self._save_results(output_dir)

        return self.results

    def _enum_host(
        self,
        ip: str,
        port: int,
        community: str,
        output_dir: str,
    ) -> SNMPEnumHostResult:
        """
        Run SNMP enumeration against a single host.

        Steps:
          1. Run auxiliary/scanner/snmp/snmp_enum with given community
          2. Parse output sections (system info, network info, etc.)
        """
        result = SNMPEnumHostResult(ip=ip, port=port, community=community)
        host_start = time.time()

        try:
            print(
                f"    \033[36m[>]\033[0m \033[96m{ip}:{port}\033[0m "
                f"running snmp_enum (community: {community}) ..."
            )
            enum_output = self._run_snmp_enum(ip, port, community)
            result.raw_output = enum_output

            # Parse sections
            self._parse_output(result, enum_output)

        except subprocess.TimeoutExpired:
            result.skipped = True
            result.skip_reason = "timeout"
            print(
                f"    \033[93m[!]\033[0m Timeout on \033[96m{ip}:{port}\033[0m "
                f"→ skipping"
            )
        except KeyboardInterrupt:
            raise  # Let the engine's _safe_scan handle this
        except Exception as e:
            result.raw_output = f"ERROR: {e}"

        result.scan_time = time.time() - host_start

        # Save per-host raw output
        if output_dir and result.raw_output.strip():
            safe_ip = ip.replace(".", "_").replace(":", "_")
            out_file = os.path.join(output_dir, f"snmp_enum_{safe_ip}.txt")
            try:
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(f"# Metasploit SNMP enum: {ip}:{port}\n")
                    f.write(f"# Community: {community}\n")
                    f.write(f"# Scan time: {result.scan_time:.1f}s\n\n")
                    f.write(result.raw_output)
            except Exception:
                pass

        return result

    def _run_snmp_enum(self, ip: str, port: int, community: str) -> str:
        """
        Run auxiliary/scanner/snmp/snmp_enum.

        Creates a .rc resource script:
            use auxiliary/scanner/snmp/snmp_enum
            set RHOSTS <ip>
            set RPORT <port>
            set COMMUNITY <community>
            set THREADS 1
            run
            exit

        Returns the raw stdout+stderr output.
        """
        tmpdir = tempfile.mkdtemp(prefix="reconx_snmp_enum_")
        rc_file = os.path.join(tmpdir, "snmp_enum.rc")

        try:
            rc_content = (
                f"use auxiliary/scanner/snmp/snmp_enum\n"
                f"set RHOSTS {ip}\n"
                f"set RPORT {port}\n"
                f"set COMMUNITY {community}\n"
                f"set THREADS 1\n"
                f"run\n"
                f"exit\n"
            )
            with open(rc_file, "w", encoding="utf-8") as f:
                f.write(rc_content)

            cmd = [
                self.msf_path,
                "-q",   # quiet (no banner)
                "-r", rc_file,
            ]

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                close_fds=(os.name != "nt"),
            )

            try:
                stdout, stderr = proc.communicate(timeout=180)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                raise

            output = stdout.decode("utf-8", errors="replace")
            err_output = stderr.decode("utf-8", errors="replace")
            return output + "\n" + err_output

        finally:
            try:
                if os.path.isfile(rc_file):
                    os.remove(rc_file)
                os.rmdir(tmpdir)
            except Exception:
                pass

    def _parse_output(self, result: SNMPEnumHostResult, output: str):
        """
        Parse the full snmp_enum output into structured sections.

        The output is divided into sections like:
          [*] System information:
          [*] Network information:
          [*] Network interfaces:
          etc.

        Each section has key-value pairs or tabular data.
        """
        lines = output.splitlines()
        current_section = None
        section_lines: List[str] = []

        for line in lines:
            # Check for section header
            section_match = SECTION_PATTERN.match(line.strip())
            if section_match:
                # Process previous section
                if current_section and section_lines:
                    self._process_section(result, current_section, section_lines)
                current_section = section_match.group(1).lower().strip()
                section_lines = []
                continue

            # Check for "Connected" (indicates successful connection)
            if CONNECTED_PATTERN.search(line):
                continue

            # Accumulate section lines
            if current_section is not None:
                # Skip empty msf prompt lines and status lines
                stripped = line.strip()
                if stripped and not stripped.startswith("msf") and not stripped.startswith("[*] Scanned"):
                    section_lines.append(line)

        # Process last section
        if current_section and section_lines:
            self._process_section(result, current_section, section_lines)

    def _process_section(
        self,
        result: SNMPEnumHostResult,
        section_name: str,
        lines: List[str],
    ):
        """Process a single parsed section."""
        if "system information" in section_name:
            result.system_info = self._parse_system_info(result.ip, lines)
        elif "network information" in section_name:
            result.network_info = result.network_info or SNMPNetworkInfo()
            self._parse_network_info(result.network_info, lines)
        elif "network interface" in section_name:
            result.network_info = result.network_info or SNMPNetworkInfo()
            result.network_info.interfaces = self._parse_table(lines)
        elif "ip address" in section_name:
            result.network_info = result.network_info or SNMPNetworkInfo()
            result.network_info.ip_addresses = self._parse_table(lines)
        elif "routing" in section_name:
            result.network_info = result.network_info or SNMPNetworkInfo()
            result.network_info.routing_table = self._parse_table(lines)
        elif "tcp connection" in section_name:
            result.network_info = result.network_info or SNMPNetworkInfo()
            result.network_info.tcp_connections = self._parse_table(lines)
        elif "listening udp" in section_name:
            result.network_info = result.network_info or SNMPNetworkInfo()
            result.network_info.listening_udp = self._parse_table(lines)
        elif "process" in section_name:
            result.processes = self._parse_table(lines)
        elif "software" in section_name:
            result.software = [
                l.strip() for l in lines if l.strip() and "[*]" not in l
            ]
        elif "storage" in section_name or "file system" in section_name:
            result.storage = self._parse_table(lines)
        elif "user account" in section_name:
            result.user_accounts = [
                l.strip() for l in lines if l.strip() and "[*]" not in l
            ]
        elif "share" in section_name:
            result.shares = [
                l.strip() for l in lines if l.strip() and "[*]" not in l
            ]

    def _parse_system_info(self, ip: str, lines: List[str]) -> SNMPSystemInfo:
        """Parse system information section into SNMPSystemInfo."""
        info = SNMPSystemInfo(host_ip=ip)

        for line in lines:
            kv = KV_PATTERN.match(line.strip())
            if not kv:
                continue
            key = kv.group(1).strip().lower()
            value = kv.group(2).strip()

            if "host ip" in key:
                info.host_ip = value
            elif "hostname" in key:
                info.hostname = value
            elif "description" in key:
                info.description = value
            elif "contact" in key:
                info.contact = value
            elif "location" in key:
                info.location = value
            elif "uptime snmp" in key:
                info.uptime_snmp = value
            elif "uptime system" in key:
                info.uptime_system = value
            elif "system date" in key:
                info.system_date = value

        return info

    def _parse_network_info(self, net_info: SNMPNetworkInfo, lines: List[str]):
        """Parse network information section."""
        for line in lines:
            kv = KV_PATTERN.match(line.strip())
            if not kv:
                continue
            key = kv.group(1).strip().lower()
            value = kv.group(2).strip()

            if "ip forwarding" in key:
                net_info.ip_forwarding = value

    def _parse_table(self, lines: List[str]) -> List[Dict]:
        """
        Parse tabular data from output lines.
        Returns list of dicts with 'raw' key for each non-empty line.
        For structured tables with headers, attempts to split into columns.
        """
        rows = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("[*]") or stripped.startswith("[+]"):
                continue
            rows.append({"raw": stripped})
        return rows

    def _compute_stats(self, scan_time: float):
        """Compute aggregated statistics."""
        self.stats.scan_time = scan_time
        self.stats.hosts_enumerated = sum(
            1 for r in self.results.values() if not r.skipped
        )
        self.stats.hosts_skipped = sum(
            1 for r in self.results.values() if r.skipped
        )
        self.stats.hosts_with_sysinfo = sum(
            1 for r in self.results.values()
            if r.system_info and r.system_info.hostname
        )
        self.stats.hosts_with_netinfo = sum(
            1 for r in self.results.values()
            if r.network_info and (r.network_info.ip_forwarding or r.network_info.interfaces)
        )
        self.stats.hosts_with_processes = sum(
            1 for r in self.results.values() if r.processes
        )
        self.stats.hosts_with_users = sum(
            1 for r in self.results.values() if r.user_accounts
        )

    def _save_results(self, output_dir: str):
        """Save combined SNMP enumeration results to output directory."""
        # System info summary
        sysinfo_file = os.path.join(output_dir, "snmp_enum_systems.txt")
        try:
            lines = ["# Metasploit SNMP Enum — System Information\n"]
            lines.append(f"# Generated by ReconX\n")
            lines.append(f"# Total hosts: {self.stats.hosts_enumerated}\n\n")

            for key in sorted(self.results.keys()):
                r = self.results[key]
                if r.system_info and r.system_info.hostname:
                    si = r.system_info
                    lines.append(f"── {r.ip}:{r.port} (community: {r.community}) ──")
                    lines.append(f"  Hostname    : {si.hostname}")
                    if si.description:
                        lines.append(f"  Description : {si.description}")
                    if si.contact:
                        lines.append(f"  Contact     : {si.contact}")
                    if si.location:
                        lines.append(f"  Location    : {si.location}")
                    if si.uptime_snmp:
                        lines.append(f"  Uptime SNMP : {si.uptime_snmp}")
                    if si.system_date:
                        lines.append(f"  System Date : {si.system_date}")
                    if r.network_info and r.network_info.ip_forwarding:
                        lines.append(f"  IP Fwd      : {r.network_info.ip_forwarding}")
                    lines.append("")

            with open(sysinfo_file, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except Exception:
            pass

        # Full summary JSON
        summary_file = os.path.join(output_dir, "snmp_enum_summary.json")
        try:
            summary = {
                "stats": self.stats.to_dict(),
                "hosts": {
                    key: r.to_dict()
                    for key, r in sorted(self.results.items())
                },
            }
            with open(summary_file, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def get_all_system_info(self) -> List[SNMPSystemInfo]:
        """Get all discovered system information entries."""
        infos = []
        for r in self.results.values():
            if r.system_info and r.system_info.hostname:
                infos.append(r.system_info)
        return infos

    def get_hosts_with_forwarding(self) -> List[str]:
        """Get list of IP:port strings where IP forwarding is enabled."""
        hosts = []
        for r in self.results.values():
            if (r.network_info and r.network_info.ip_forwarding
                    and "yes" in r.network_info.ip_forwarding.lower()):
                hosts.append(f"{r.ip}:{r.port}")
        return hosts
