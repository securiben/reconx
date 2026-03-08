"""
CrackMapExec (CME) Scanner for ReconX.
Runs crackmapexec against discovered hosts grouped by protocol,
based on open ports found during the Nmap scan phase.

Port → Protocol mapping:
  1433        → mssql
  389,636     → ldap
  5985,5986   → winrm
  445,139     → smb
  135         → wmi
  3389        → rdp
  22          → ssh
  5900        → vnc
  21          → ftp

Requires: crackmapexec (or nxc) installed in PATH
  Install: pip install crackmapexec
  Or:      https://github.com/byt3bl33d3r/CrackMapExec
"""

import os
import sys
import shutil
import subprocess
import tempfile
import time
import json
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

from ..config import ScannerConfig


# ─── Port to CME protocol mapping ───────────────────────────────────────────

CME_PORT_MAP: Dict[int, str] = {
    1433: "mssql",
    389:  "ldap",
    636:  "ldap",
    5985: "winrm",
    5986: "winrm",
    445:  "smb",
    139:  "smb",
    135:  "wmi",
    3389: "rdp",
    22:   "ssh",
    5900: "vnc",
    21:   "ftp",
}

# All supported CME protocols
CME_PROTOCOLS = ["mssql", "ldap", "winrm", "smb", "wmi", "rdp", "ssh", "vnc", "ftp"]

# Protocol display colors (ANSI)
PROTOCOL_COLORS = {
    "smb":   "\033[1;94m",   # Bold blue
    "ssh":   "\033[1;92m",   # Bold green
    "rdp":   "\033[1;93m",   # Bold yellow
    "mssql": "\033[1;91m",   # Bold red
    "ldap":  "\033[1;96m",   # Bold cyan
    "winrm": "\033[1;95m",   # Bold magenta
    "wmi":   "\033[1;33m",   # Bold dark yellow
    "vnc":   "\033[1;35m",   # Bold dark magenta
    "ftp":   "\033[1;36m",   # Bold dark cyan
}


@dataclass
class CMEHostResult:
    """Result from CME scan on a single host for a single protocol."""
    ip: str = ""
    protocol: str = ""
    port: int = 0
    hostname: str = ""
    os_info: str = ""
    signing: str = ""        # e.g., "signing:True" for SMB
    smbv1: bool = False
    domain: str = ""
    raw_output: str = ""

    def to_dict(self) -> dict:
        d = {
            "ip": self.ip,
            "protocol": self.protocol,
            "port": self.port,
        }
        if self.hostname:
            d["hostname"] = self.hostname
        if self.os_info:
            d["os_info"] = self.os_info
        if self.signing:
            d["signing"] = self.signing
        if self.domain:
            d["domain"] = self.domain
        if self.raw_output:
            d["raw_output"] = self.raw_output
        return d


@dataclass
class CMEProtocolResult:
    """Aggregated results for one CME protocol."""
    protocol: str = ""
    hosts_scanned: int = 0
    hosts_responded: int = 0
    host_results: List[CMEHostResult] = field(default_factory=list)
    raw_output: str = ""
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "hosts_scanned": self.hosts_scanned,
            "hosts_responded": self.hosts_responded,
            "host_results": [h.to_dict() for h in self.host_results],
            "scan_time": self.scan_time,
        }


@dataclass
class CMEStats:
    """Aggregated CME scan statistics."""
    protocols_scanned: int = 0
    total_hosts_discovered: int = 0
    protocol_summary: Dict[str, int] = field(default_factory=dict)  # protocol → host count
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "protocols_scanned": self.protocols_scanned,
            "total_hosts_discovered": self.total_hosts_discovered,
            "protocol_summary": self.protocol_summary,
            "scan_time": self.scan_time,
        }


class CMEScanner:
    """
    CrackMapExec scanner wrapper.

    After Nmap discovers open ports, this scanner groups hosts
    by protocol and runs crackmapexec for each protocol to enumerate
    services, OS info, SMB signing status, etc.
    """

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.cme_path = self._find_cme()
        self.available = self.cme_path is not None
        self.protocol_results: Dict[str, CMEProtocolResult] = {}
        self.stats = CMEStats()

    def _find_cme(self) -> Optional[str]:
        """Find crackmapexec or nxc (NetExec) binary in PATH."""
        # Try crackmapexec first, then nxc (newer fork)
        for name in ["crackmapexec", "cme", "nxc", "netexec"]:
            found = shutil.which(name)
            if found:
                return found

        # Common install locations
        common_paths = [
            os.path.expanduser("~/.local/bin/crackmapexec"),
            os.path.expanduser("~/.local/bin/nxc"),
            "/usr/bin/crackmapexec",
            "/usr/local/bin/crackmapexec",
            "/usr/bin/nxc",
            "/usr/local/bin/nxc",
        ]
        if os.name == "nt":
            # Windows paths
            for prog_dir in [os.environ.get("LOCALAPPDATA", ""),
                             os.environ.get("APPDATA", "")]:
                if prog_dir:
                    common_paths.append(os.path.join(prog_dir, "pipx", "venvs",
                                                     "crackmapexec", "Scripts", "crackmapexec.exe"))
                    common_paths.append(os.path.join(prog_dir, "pipx", "venvs",
                                                     "netexec", "Scripts", "nxc.exe"))

            # Check Python Scripts directory
            python_scripts = os.path.join(sys.prefix, "Scripts")
            common_paths.append(os.path.join(python_scripts, "crackmapexec.exe"))
            common_paths.append(os.path.join(python_scripts, "nxc.exe"))

        for path in common_paths:
            if path and os.path.isfile(path):
                return path

        # Auto-install crackmapexec/netexec if not found
        from .auto_install import ensure_tool
        if ensure_tool("nxc"):
            return shutil.which("nxc") or shutil.which("netexec") or shutil.which("crackmapexec")

        return None

    def group_hosts_by_protocol(self, nmap_results: Dict) -> Dict[str, Set[str]]:
        """
        Group IP addresses by CME protocol based on open ports from Nmap.

        Args:
            nmap_results: Dict of ip → NmapHostResult from nmap scan.

        Returns:
            Dict of protocol → set of IP addresses.
        """
        protocol_hosts: Dict[str, Set[str]] = defaultdict(set)

        for ip, host_result in nmap_results.items():
            # host_result can be NmapHostResult dataclass or dict
            ports = []
            if hasattr(host_result, 'ports'):
                ports = host_result.ports
            elif isinstance(host_result, dict):
                ports = host_result.get('ports', [])

            for port_obj in ports:
                # Get port number
                if hasattr(port_obj, 'port'):
                    port_num = port_obj.port
                    state = port_obj.state
                elif isinstance(port_obj, dict):
                    port_num = port_obj.get('port', 0)
                    state = port_obj.get('state', '')
                else:
                    continue

                if state not in ("open", "open|filtered"):
                    continue

                protocol = CME_PORT_MAP.get(port_num)
                if protocol:
                    protocol_hosts[protocol].add(ip)

        return dict(protocol_hosts)

    def scan(self, nmap_results: Dict, output_dir: str = "") -> Dict[str, CMEProtocolResult]:
        """
        Run crackmapexec for each protocol with matching hosts.

        Args:
            nmap_results: Dict of ip → NmapHostResult from nmap scan.
            output_dir: Directory to save CME output files.

        Returns:
            Dict of protocol → CMEProtocolResult.
        """
        if not self.available:
            return {}

        if not nmap_results:
            return {}

        scan_start = time.time()

        # Group hosts by protocol
        protocol_hosts = self.group_hosts_by_protocol(nmap_results)

        if not protocol_hosts:
            return {}

        # Display what we found
        proto_summary = ", ".join(
            f"{PROTOCOL_COLORS.get(p, '')}{p}\033[0m({len(ips)})"
            for p, ips in sorted(protocol_hosts.items())
        )
        print(
            f"\033[36m[>]\033[0m CME: detected protocols from nmap → {proto_summary}"
        )

        # Create output directory
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Run CME for each protocol
        for protocol in CME_PROTOCOLS:
            if protocol not in protocol_hosts:
                continue

            ips = sorted(protocol_hosts[protocol])
            result = self._run_protocol(protocol, ips, output_dir)
            self.protocol_results[protocol] = result

        scan_elapsed = time.time() - scan_start
        self._compute_stats(scan_elapsed)

        return self.protocol_results

    def _run_protocol(self, protocol: str, ips: List[str],
                      output_dir: str = "") -> CMEProtocolResult:
        """
        Run crackmapexec for a single protocol against target IPs.

        Args:
            protocol: CME protocol (smb, ssh, rdp, etc.)
            ips: List of target IP addresses.
            output_dir: Optional output directory for saving results.

        Returns:
            CMEProtocolResult with parsed output.
        """
        result = CMEProtocolResult(protocol=protocol, hosts_scanned=len(ips))
        proto_start = time.time()

        color = PROTOCOL_COLORS.get(protocol, "\033[37m")
        print(
            f"\033[36m[>]\033[0m CME: running {color}{protocol}\033[0m "
            f"against \033[96m{len(ips)}\033[0m hosts ..."
        )

        # Write targets to temp file
        tmpdir = tempfile.mkdtemp(prefix=f"reconx_cme_{protocol}_")
        target_file = os.path.join(tmpdir, "targets.txt")

        try:
            with open(target_file, "w", encoding="utf-8") as f:
                for ip in ips:
                    f.write(ip + "\n")

            # Build CME command
            cmd = [self.cme_path, protocol, target_file]

            # Run CME
            timeout_secs = max(300, len(ips) * 15)
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            try:
                stdout, stderr = proc.communicate(timeout=timeout_secs)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()

            output = stdout.decode("utf-8", errors="replace")
            result.raw_output = output

            # Parse output
            result.host_results = self._parse_output(output, protocol)
            result.hosts_responded = len(result.host_results)

            # Print results to terminal in real-time
            if output.strip():
                for line in output.strip().splitlines():
                    line = line.strip()
                    if line:
                        print(f"    {line}")

            # Save output to file only when there are actual results
            if output_dir and result.host_results:
                out_file = os.path.join(output_dir, f"cme_{protocol}.txt")
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(output)

        except FileNotFoundError:
            self.available = False
        except Exception:
            pass
        finally:
            try:
                if os.path.isfile(target_file):
                    os.remove(target_file)
                os.rmdir(tmpdir)
            except Exception:
                pass

        result.scan_time = time.time() - proto_start

        responded = result.hosts_responded
        scanned = result.hosts_scanned
        elapsed = result.scan_time
        status_color = "\033[92m" if responded > 0 else "\033[37m"
        print(
            f"\033[92m[+]\033[0m CME: {color}{protocol}\033[0m → "
            f"{status_color}{responded}\033[0m/{scanned} hosts responded "
            f"\033[90m({elapsed:.1f}s)\033[0m"
        )

        return result

    def _parse_output(self, output: str, protocol: str) -> List[CMEHostResult]:
        """
        Parse CME stdout for host enumeration results.

        CME output format varies by protocol but generally looks like:
          SMB  192.168.1.1  445  DC01  [*] Windows Server 2019 ...
          SSH  192.168.1.2  22        [*] SSH-2.0-OpenSSH_8.4p1
        """
        results: List[CMEHostResult] = []
        seen_ips: Set[str] = set()

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Skip banner/info lines that don't contain host data
            # Typical CME line starts with protocol name in uppercase
            proto_upper = protocol.upper()

            # Try to extract IP address from the line
            parts = line.split()
            if len(parts) < 3:
                continue

            # Find IP-like token in the line
            ip = ""
            port = 0
            hostname = ""
            for i, part in enumerate(parts):
                # Check if it looks like an IP
                if self._is_ip(part):
                    ip = part
                    # Next token might be a port
                    if i + 1 < len(parts):
                        try:
                            port = int(parts[i + 1])
                        except ValueError:
                            pass
                    # Token after port might be hostname
                    if i + 2 < len(parts):
                        next_token = parts[i + 2]
                        if not next_token.startswith("[") and not next_token.startswith("("):
                            hostname = next_token
                    break

            if not ip:
                continue

            # Skip duplicate IPs within same protocol
            if ip in seen_ips:
                # Update existing result with more info if available
                continue
            seen_ips.add(ip)

            host_result = CMEHostResult(
                ip=ip,
                protocol=protocol,
                port=port,
                hostname=hostname,
                raw_output=line,
            )

            # Extract OS info (typically in brackets or after hostname)
            os_info = self._extract_os_info(line)
            if os_info:
                host_result.os_info = os_info

            # SMB-specific: signing info
            if protocol == "smb":
                if "signing:True" in line:
                    host_result.signing = "required"
                elif "signing:False" in line:
                    host_result.signing = "not required"
                if "SMBv1:True" in line or "(smbv1:True)" in line.lower():
                    host_result.smbv1 = True

            # Extract domain info
            domain = self._extract_domain(line)
            if domain:
                host_result.domain = domain

            results.append(host_result)

        return results

    def _is_ip(self, text: str) -> bool:
        """Check if text looks like an IPv4 address."""
        parts = text.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _extract_os_info(self, line: str) -> str:
        """Try to extract OS info from CME output line."""
        # Look for common OS patterns
        os_patterns = [
            "Windows Server", "Windows 10", "Windows 11",
            "Ubuntu", "Debian", "CentOS", "Red Hat", "RHEL",
            "Linux", "FreeBSD", "macOS",
        ]
        for pattern in os_patterns:
            idx = line.find(pattern)
            if idx != -1:
                # Get a reasonable chunk of OS info
                remainder = line[idx:]
                # Stop at common delimiters
                for delim in ["  ", " [", " (name:", "\t"]:
                    delim_idx = remainder.find(delim)
                    if delim_idx > 0:
                        remainder = remainder[:delim_idx]
                        break
                return remainder.strip()
        return ""

    def _extract_domain(self, line: str) -> str:
        """Try to extract domain/workgroup from CME output."""
        # Look for (domain:XXX) or domain:XXX patterns
        import re
        match = re.search(r'(?:domain:|Domain:)\s*(\S+)', line)
        if match:
            return match.group(1).strip("()")
        return ""

    def _compute_stats(self, scan_time: float):
        """Compute aggregated statistics."""
        self.stats.scan_time = scan_time
        self.stats.protocols_scanned = len(self.protocol_results)

        total_hosts = 0
        for proto, result in self.protocol_results.items():
            count = result.hosts_responded
            self.stats.protocol_summary[proto] = count
            total_hosts += count

        self.stats.total_hosts_discovered = total_hosts

    def get_smb_signing_disabled(self) -> List[str]:
        """Get list of IPs with SMB signing not required (potential relay targets)."""
        smb_result = self.protocol_results.get("smb")
        if not smb_result:
            return []
        return [
            h.ip for h in smb_result.host_results
            if h.signing == "not required"
        ]

    def get_hosts_by_protocol(self) -> Dict[str, List[str]]:
        """Get dict of protocol → list of responding IPs."""
        result = {}
        for proto, proto_result in self.protocol_results.items():
            result[proto] = [h.ip for h in proto_result.host_results]
        return result
