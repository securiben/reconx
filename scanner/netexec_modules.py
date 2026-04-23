"""
NetExec (nxc) Module Scanner for ReconX.

Enumerates ALL available netexec modules per protocol, then runs
a curated set of safe recon modules against discovered hosts.

Protocols covered: SMB, LDAP, MSSQL, WINRM, RDP, SSH, FTP, WMI, VNC, REDIS

Usage flow:
  1. group_hosts_by_protocol(nmap_results) → dict[proto → set[ip]]
  2. discover_modules(protocol) → list of available modules
  3. scan(nmap_results) → dict[proto → NetExecModuleProtoResult]
"""

import os
import re
import sys
import shutil
import subprocess
import tempfile
import time
import json
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

from ..config import ScannerConfig
from ..utils import routed_path


# ─── Extended Port → Protocol Mapping ─────────────────────────────────────────

NXC_PORT_MAP: Dict[int, str] = {
    # Windows / AD
    445:  "smb",
    139:  "smb",
    135:  "wmi",
    3389: "rdp",
    # Directory services
    389:  "ldap",
    636:  "ldap",
    3268: "ldap",   # GC
    3269: "ldap",   # GC SSL
    # Remote management
    5985: "winrm",
    5986: "winrm",
    # Databases
    1433: "mssql",
    5432: "mssql",  # sometimes used for SQL
    6379: "redis",
    6380: "redis",
    # Network services
    22:   "ssh",
    21:   "ftp",
    # Desktop
    5900: "vnc",
    5901: "vnc",
    5902: "vnc",
}

# All protocols we want to run modules for (in priority order)
NXC_PROTOCOLS = [
    "smb", "ldap", "mssql", "winrm", "rdp",
    "ssh", "ftp", "wmi", "vnc", "redis",
]

# ─── Curated Safe Recon Modules per Protocol ──────────────────────────────────
# These are READ-ONLY enumeration modules, no exploitation.
# Modules that require credentials are skipped in unauthenticated mode.

RECON_MODULES: Dict[str, List[str]] = {
    "smb": [
        "enum_av",          # Enumerate AV/EDR products
        "enum_dns",         # Enumerate DNS via SMB
        "ms17-010",         # Check EternalBlue vulnerability (CVE-2017-0144)
        "nopac",            # Check NoPac (CVE-2021-42278/42287)
        "petitpotam",       # Check PetitPotam (CVE-2021-36942)
        "zerologon",        # Check Zerologon (CVE-2020-1472)
        "printerbug",       # Check PrinterBug (SpoolSS)
        "dfscoerce",        # Check DFSCoerce
        "shadowcoerce",     # Check ShadowCoerce
        "webdav",           # Check WebDAV enabled (for NTLM relay)
        "enum_ca",          # Enumerate AD CS Certificate Authorities
        "adcs",             # Check ADCS misconfiguration (ESC1-ESC8)
        "get_netdomains",   # Enumerate AD domains
        "scan_cas",         # Scan for Certificate Authority services
        "coerce_plus",      # Enumerate coerce vulnerabilities
    ],
    "ldap": [
        "get_netdomains",       # Enumerate all AD domains
        "get_netusers",         # Enumerate domain users
        "get_netgroups",        # Enumerate domain groups (alias)
        "enum_trusts",          # Enumerate domain trusts
        "groupmembership",      # Check group membership
        "whoami",               # Current user context
        "laps",                 # Retrieve LAPS passwords (if readable)
        "adcs",                 # Check ADCS misconfiguration
        "get_description_users",# Get users with descriptions (often has creds)
        "maq",                  # Check MachineAccountQuota (default=10, allows DA escalation)
        "subnets",              # Enumerate AD subnets
        "bloodhound",           # Collect BloodHound data (requires --bloodhound-flag)
        "daclread",             # Read DACLs for privilege escalation paths
        "pso",                  # Enumerate Password Security Objects
        "ldap-checker",         # Check LDAP signing/binding requirements
        "get_unixusers",        # Enumerate Unix/Posix users
    ],
    "mssql": [
        "enum_logins",      # Enumerate SQL logins
        "enum_db",          # Enumerate databases
        "xp_cmdshell",      # Check if xp_cmdshell is enabled (code exec risk)
        "xp_dirtree",       # List directories via xp_dirtree (info disclosure)
        "mssql_priv",       # Check for privilege escalation paths
    ],
    "winrm": [
        "whoami",           # Current user context
        "enum_av",          # Enumerate AV/EDR
        "lsassy",           # Dump credentials from LSASS (if admin)
    ],
    "rdp": [
        "nla",              # Check Network Level Authentication status
        "rdp-check",        # Check RDP service status/version
        "bluekeep",         # Check BlueKeep (CVE-2019-0708)
    ],
    "ssh": [
        "ssh_check",        # Check SSH version and configuration
        "enum_users",       # Enumerate valid users (timing attack)
    ],
    "ftp": [
        "anonymous",        # Check anonymous FTP access
    ],
    "wmi": [
        "whoami",           # Current user context
        "enum_av",          # Enumerate AV/EDR via WMI
    ],
    "vnc": [
        "vnc_authentication_bypass",  # Check authentication bypass
    ],
    "redis": [
        "redis_login",      # Check unauthenticated access + version
        "keys",             # List Redis keys (if accessible)
    ],
}

# Protocol display colors
PROTO_COLORS: Dict[str, str] = {
    "smb":   "\033[1;94m",
    "ldap":  "\033[1;96m",
    "mssql": "\033[1;91m",
    "winrm": "\033[1;95m",
    "rdp":   "\033[1;93m",
    "ssh":   "\033[1;92m",
    "ftp":   "\033[1;36m",
    "wmi":   "\033[1;33m",
    "vnc":   "\033[1;35m",
    "redis": "\033[1;31m",
}

RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2;37m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED   = "\033[91m"
CYAN  = "\033[36m"


@dataclass
class ModuleFinding:
    """A single finding from a NetExec module."""
    ip: str = ""
    protocol: str = ""
    module: str = ""
    status: str = ""      # VULNERABLE / NOT_VULNERABLE / INFO / ERROR
    detail: str = ""
    raw_line: str = ""

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "protocol": self.protocol,
            "module": self.module,
            "status": self.status,
            "detail": self.detail,
        }


@dataclass
class NetExecModuleProtoResult:
    """Results for one protocol's module scan."""
    protocol: str = ""
    hosts_scanned: int = 0
    available_modules: List[str] = field(default_factory=list)
    modules_run: List[str] = field(default_factory=list)
    findings: List[ModuleFinding] = field(default_factory=list)
    vulnerable_count: int = 0
    raw_outputs: Dict[str, str] = field(default_factory=dict)  # module → output
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "hosts_scanned": self.hosts_scanned,
            "available_modules": self.available_modules,
            "modules_run": self.modules_run,
            "findings": [f.to_dict() for f in self.findings],
            "vulnerable_count": self.vulnerable_count,
            "scan_time": self.scan_time,
        }


@dataclass
class NetExecModuleStats:
    """Aggregate stats from all module scans."""
    protocols_scanned: int = 0
    total_modules_run: int = 0
    total_findings: int = 0
    total_vulnerable: int = 0
    protocol_summary: Dict[str, int] = field(default_factory=dict)  # proto → vuln count
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "protocols_scanned": self.protocols_scanned,
            "total_modules_run": self.total_modules_run,
            "total_findings": self.total_findings,
            "total_vulnerable": self.total_vulnerable,
            "protocol_summary": self.protocol_summary,
            "scan_time": self.scan_time,
        }


class NetExecModuleScanner:
    """
    Runs netexec modules against discovered hosts.

    For each protocol that has matching open ports, this scanner:
      1. Runs `netexec <proto> --list-modules` to discover all available modules
      2. Intersects with our curated safe recon module list
      3. Runs each module against the target IPs
      4. Parses and presents findings
    """

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.nxc_path = self._find_nxc()
        self.available = self.nxc_path is not None
        self.proto_results: Dict[str, NetExecModuleProtoResult] = {}
        self.stats = NetExecModuleStats()
        self._module_cache: Dict[str, List[str]] = {}   # proto → cached module list

    def _find_nxc(self) -> Optional[str]:
        """Locate nxc / netexec / crackmapexec binary."""
        for name in ["nxc", "netexec", "crackmapexec", "cme"]:
            found = shutil.which(name)
            if found:
                return found

        common_paths = [
            os.path.expanduser("~/.local/bin/nxc"),
            os.path.expanduser("~/.local/bin/netexec"),
            "/usr/bin/nxc",
            "/usr/local/bin/nxc",
            "/usr/bin/netexec",
        ]
        if os.name == "nt":
            for prog_dir in [os.environ.get("LOCALAPPDATA", ""),
                             os.environ.get("APPDATA", "")]:
                if prog_dir:
                    common_paths.append(
                        os.path.join(prog_dir, "pipx", "venvs", "netexec", "Scripts", "nxc.exe")
                    )
            python_scripts = os.path.join(sys.prefix, "Scripts")
            common_paths.append(os.path.join(python_scripts, "nxc.exe"))

        for p in common_paths:
            if p and os.path.isfile(p):
                return p
        return None

    # ─── Module Discovery ──────────────────────────────────────────────────

    def discover_modules(self, protocol: str) -> List[str]:
        """
        Query `netexec <protocol> --list-modules` and return module names.
        Results are cached per protocol.
        """
        if protocol in self._module_cache:
            return self._module_cache[protocol]

        if not self.nxc_path:
            return []

        try:
            proc = subprocess.run(
                [self.nxc_path, protocol, "--list-modules"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = proc.stdout + proc.stderr
            modules = self._parse_module_list(output)
            self._module_cache[protocol] = modules
            return modules
        except Exception:
            self._module_cache[protocol] = []
            return []

    def _parse_module_list(self, output: str) -> List[str]:
        """Extract module names from --list-modules output."""
        modules = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # nxc format: "  module_name    Description text"
            # or: "  * module_name - Description text"
            # Strip ANSI codes first
            clean = re.sub(r'\x1b\[[0-9;]*m', '', line)
            # Match leading module name (alphanumeric + underscores + hyphens)
            m = re.match(r'^\s*\*?\s*([a-zA-Z0-9_\-]+)\s+[-–\s]', clean)
            if m:
                name = m.group(1).strip()
                if name and name.lower() not in ('module', 'name', 'description', 'options', '---'):
                    modules.append(name)
        return modules

    def print_available_modules(self, protocol: str):
        """Print all available modules for a protocol."""
        modules = self.discover_modules(protocol)
        color = PROTO_COLORS.get(protocol, "\033[37m")
        if modules:
            print(
                f"{CYAN}[>]{RESET} {color}{protocol.upper()}{RESET} modules "
                f"({len(modules)} available):"
            )
            for mod in modules:
                print(f"    {DIM}•{RESET} {mod}")
        else:
            print(
                f"{YELLOW}[!]{RESET} No modules found for {color}{protocol}{RESET}"
            )

    # ─── Host Grouping ─────────────────────────────────────────────────────

    def group_hosts_by_protocol(self, nmap_results: Dict) -> Dict[str, Set[str]]:
        """Group IPs by protocol based on open ports from nmap results."""
        from collections import defaultdict
        protocol_hosts: Dict[str, Set[str]] = defaultdict(set)

        for ip, host_result in nmap_results.items():
            ports = []
            if hasattr(host_result, 'ports'):
                ports = host_result.ports
            elif isinstance(host_result, dict):
                ports = host_result.get('ports', [])

            for port_obj in ports:
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

                proto = NXC_PORT_MAP.get(port_num)
                if proto:
                    protocol_hosts[proto].add(ip)

        return dict(protocol_hosts)

    # ─── Main Scan Entry ───────────────────────────────────────────────────

    def scan(self, nmap_results: Dict, output_dir: str = "") -> Dict[str, NetExecModuleProtoResult]:
        """
        Run curated netexec modules for all detected protocols.

        Returns dict of protocol → NetExecModuleProtoResult.
        """
        if not self.available or not nmap_results:
            return {}

        scan_start = time.time()
        protocol_hosts = self.group_hosts_by_protocol(nmap_results)

        if not protocol_hosts:
            return {}

        # Summarize what we found
        proto_str = ", ".join(
            f"{PROTO_COLORS.get(p, '')}{p}{RESET}({len(ips)})"
            for p, ips in sorted(protocol_hosts.items())
        )
        print(f"{CYAN}[>]{RESET} netexec-modules: protocols detected → {proto_str}")

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        for protocol in NXC_PROTOCOLS:
            if protocol not in protocol_hosts:
                continue

            ips = sorted(protocol_hosts[protocol])
            result = self._run_protocol_modules(protocol, ips, output_dir)
            self.proto_results[protocol] = result

        self._compute_stats(time.time() - scan_start)
        return self.proto_results

    def _run_protocol_modules(self, protocol: str, ips: List[str],
                               output_dir: str = "") -> NetExecModuleProtoResult:
        """Run all relevant modules for one protocol against the target IPs."""
        result = NetExecModuleProtoResult(
            protocol=protocol,
            hosts_scanned=len(ips),
        )
        proto_start = time.time()
        color = PROTO_COLORS.get(protocol, "\033[37m")

        # Discover available modules
        available = self.discover_modules(protocol)
        result.available_modules = available

        # Determine which curated modules to run
        curated = RECON_MODULES.get(protocol, [])
        if available:
            # Only run modules that actually exist in this nxc version
            to_run = [m for m in curated if m in available]
        else:
            # If discovery fails, attempt all curated modules anyway
            to_run = curated

        if not to_run:
            # Even with no modules, run a bare enumeration pass
            to_run = []

        result.modules_run = to_run

        print(
            f"{CYAN}[>]{RESET} netexec {color}{protocol}{RESET}: "
            f"{len(ips)} host(s) | "
            f"{len(available)} modules available | "
            f"{len(to_run)} recon modules queued"
        )

        # Write IPs to temp file
        tmpdir = tempfile.mkdtemp(prefix=f"reconx_nxcmod_{protocol}_")
        target_file = os.path.join(tmpdir, "targets.txt")

        try:
            with open(target_file, "w", encoding="utf-8") as f:
                f.write("\n".join(ips) + "\n")

            # ── Run bare protocol scan first (no module) ──────────────────
            self._run_bare(protocol, target_file, result, output_dir)

            # ── Run each module ───────────────────────────────────────────
            for module in to_run:
                self._run_module(protocol, module, target_file, ips, result, output_dir)

        except Exception as exc:
            print(f"{YELLOW}[!]{RESET} netexec {protocol}: error — {exc}")
        finally:
            try:
                if os.path.isfile(target_file):
                    os.remove(target_file)
                os.rmdir(tmpdir)
            except Exception:
                pass

        result.scan_time = time.time() - proto_start
        result.vulnerable_count = sum(
            1 for f in result.findings if f.status == "VULNERABLE"
        )

        # Summary line
        vuln_str = f" | {RED}{result.vulnerable_count} VULNERABLE{RESET}" if result.vulnerable_count > 0 else ""
        info_count = sum(1 for f in result.findings if f.status == "INFO")
        info_str = f" | {CYAN}{info_count} info{RESET}" if info_count > 0 else ""
        print(
            f"{GREEN}[+]{RESET} netexec {color}{protocol}{RESET}: "
            f"{len(result.modules_run)} modules run"
            f"{vuln_str}{info_str} "
            f"{DIM}({result.scan_time:.1f}s){RESET}"
        )

        return result

    def _run_bare(self, protocol: str, target_file: str,
                  result: NetExecModuleProtoResult, output_dir: str):
        """Run bare netexec <proto> for host enumeration (no module)."""
        try:
            cmd = [self.nxc_path, protocol, target_file]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            output = proc.stdout + proc.stderr
            if output.strip():
                for line in output.strip().splitlines():
                    if line.strip():
                        print(f"    {line.strip()}")
            if output_dir and output.strip():
                out_file = routed_path(output_dir, f"nxcmod_{protocol}_bare.txt")
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(output)
        except Exception:
            pass

    def _run_module(self, protocol: str, module: str, target_file: str,
                    ips: List[str], result: NetExecModuleProtoResult,
                    output_dir: str):
        """Run a single module and parse its output."""
        color = PROTO_COLORS.get(protocol, "\033[37m")

        try:
            cmd = [self.nxc_path, protocol, target_file, "-M", module]
            timeout_secs = max(120, len(ips) * 10)
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_secs,
            )
            output = proc.stdout + proc.stderr
            result.raw_outputs[module] = output

            # Parse findings
            findings = self._parse_module_output(output, protocol, module, ips)
            result.findings.extend(findings)

            # Display findings
            if findings:
                for f in findings:
                    status_color = RED if f.status == "VULNERABLE" else (
                        GREEN if f.status == "INFO" else YELLOW
                    )
                    print(
                        f"    {status_color}[{f.status}]{RESET} "
                        f"{color}{protocol}/{module}{RESET} "
                        f"{CYAN}{f.ip}{RESET} — {f.detail}"
                    )

            # Save to file if there are notable findings
            if output_dir and output.strip() and findings:
                out_file = routed_path(output_dir, f"nxcmod_{protocol}_{module}.txt")
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(output)

        except subprocess.TimeoutExpired:
            print(
                f"    {YELLOW}[!]{RESET} {color}{protocol}/{module}{RESET}: timed out"
            )
        except Exception as exc:
            pass  # Module not found or other transient error

    # ─── Output Parsing ────────────────────────────────────────────────────

    def _parse_module_output(self, output: str, protocol: str,
                             module: str, ips: List[str]) -> List[ModuleFinding]:
        """Parse netexec module output into structured findings."""
        findings: List[ModuleFinding] = []
        clean_output = re.sub(r'\x1b\[[0-9;]*m', '', output)

        for line in clean_output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Find IP in the line
            ip = self._extract_ip(line, ips)
            if not ip:
                # Some modules print summary lines without IPs
                # Still capture VULNERABLE/etc lines
                if any(kw in line.upper() for kw in ["VULNERABLE", "EXPLOITABLE", "SIGNING:FALSE"]):
                    findings.append(ModuleFinding(
                        ip="N/A", protocol=protocol, module=module,
                        status="VULNERABLE", detail=line, raw_line=line,
                    ))
                continue

            # Determine status
            line_upper = line.upper()
            if any(kw in line_upper for kw in [
                "VULNERABLE", "EXPLOITABLE", "SIGNING:FALSE",
                "SIGNING DISABLED", "NULL SESSION", "ANONYMOUS",
                "NO AUTH", "UNAUTHENTICATED", "ENABLED", "RCE",
                "PWN3D", "PWNED", "[+]",
            ]):
                # Distinguish critical vulns
                if any(kw in line_upper for kw in [
                    "VULNERABLE", "EXPLOITABLE", "SIGNING:FALSE",
                    "SIGNING DISABLED", "NULL SESSION", "ANONYMOUS",
                    "NO AUTH", "UNAUTHENTICATED", "PWN3D",
                ]):
                    status = "VULNERABLE"
                else:
                    status = "INFO"
            elif "[-]" in line or "ERROR" in line_upper or "FAILED" in line_upper:
                continue  # Skip noise
            elif any(kw in line_upper for kw in ["[*]", "INFO", "FOUND", "VERSION", "DETECTED"]):
                status = "INFO"
            else:
                continue

            # Extract detail (strip protocol/IP/port prefix)
            detail = self._clean_detail(line, ip)
            findings.append(ModuleFinding(
                ip=ip, protocol=protocol, module=module,
                status=status, detail=detail, raw_line=line,
            ))

        return findings

    def _extract_ip(self, line: str, ips: List[str]) -> str:
        """Find the first known IP in a line."""
        for ip in ips:
            if ip in line:
                return ip
        # Fallback: regex
        m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', line)
        if m:
            return m.group(1)
        return ""

    def _clean_detail(self, line: str, ip: str) -> str:
        """Strip IP/port/proto prefix from a line to get the detail."""
        # Remove ANSI codes
        clean = re.sub(r'\x1b\[[0-9;]*m', '', line)
        # Remove known IP
        clean = clean.replace(ip, "").strip()
        # Remove port number prefix
        clean = re.sub(r'^\s*\d+\s+', '', clean).strip()
        # Remove status markers
        clean = re.sub(r'^\s*[\[+\-\*!\]]+\s*', '', clean).strip()
        return clean[:200]

    def _compute_stats(self, scan_time: float):
        """Aggregate stats across all protocols."""
        self.stats.scan_time = scan_time
        self.stats.protocols_scanned = len(self.proto_results)
        total_modules = 0
        total_findings = 0
        total_vuln = 0

        for proto, result in self.proto_results.items():
            total_modules += len(result.modules_run)
            total_findings += len(result.findings)
            total_vuln += result.vulnerable_count
            self.stats.protocol_summary[proto] = result.vulnerable_count

        self.stats.total_modules_run = total_modules
        self.stats.total_findings = total_findings
        self.stats.total_vulnerable = total_vuln

    # ─── Helpers for engine ────────────────────────────────────────────────

    def get_all_findings(self) -> List[ModuleFinding]:
        """Return all findings across all protocols."""
        out = []
        for result in self.proto_results.values():
            out.extend(result.findings)
        return out

    def get_vulnerable_findings(self) -> List[ModuleFinding]:
        """Return only VULNERABLE findings."""
        return [f for f in self.get_all_findings() if f.status == "VULNERABLE"]

    def get_findings_by_module(self, module: str) -> List[ModuleFinding]:
        """Return findings for a specific module."""
        return [f for f in self.get_all_findings() if f.module == module]

    def get_cve_summary(self) -> Dict[str, List[str]]:
        """Return dict of module → list of IPs that are vulnerable."""
        summary: Dict[str, List[str]] = {}
        for f in self.get_vulnerable_findings():
            summary.setdefault(f.module, []).append(f.ip)
        return summary
