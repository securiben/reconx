"""
Metasploit SNMP Login Scanner for ReconX.
Uses msfconsole auxiliary/scanner/snmp/snmp_login to brute-force
SNMP community strings on hosts where nmap discovered SNMP ports.

For each IP that has SNMP port(s) open (161/udp, 162/udp):
  1. Run auxiliary/scanner/snmp/snmp_login with default wordlist
  2. Parse output for successful community strings
  3. Report access level (read-only / read-write) and sysDescr proof

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
from ..utils import routed_path


# ─── SNMP Ports ───────────────────────────────────────────────────────────────

SNMP_PORTS = {161, 162}


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class SNMPCredential:
    """A successfully discovered SNMP community string."""
    ip: str = ""
    port: int = 161
    community: str = ""
    access_level: str = ""   # e.g. "read-only", "read-write"
    proof: str = ""          # e.g. sysDescr.0 value

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "community": self.community,
            "access_level": self.access_level,
            "proof": self.proof,
        }


@dataclass
class SNMPLoginHostResult:
    """SNMP login result for a single host."""
    ip: str = ""
    port: int = 161
    credentials: List[SNMPCredential] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    scan_time: float = 0.0
    raw_output: str = ""

    def to_dict(self) -> dict:
        d = {
            "ip": self.ip,
            "port": self.port,
            "credentials": [c.to_dict() for c in self.credentials],
            "scan_time": round(self.scan_time, 2),
        }
        if self.skipped:
            d["skipped"] = True
            d["skip_reason"] = self.skip_reason
        return d


@dataclass
class SNMPLoginStats:
    """Aggregated SNMP login statistics."""
    total_snmp_hosts: int = 0
    hosts_tested: int = 0
    hosts_skipped: int = 0
    credentials_found: int = 0
    read_write_found: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_snmp_hosts": self.total_snmp_hosts,
            "hosts_tested": self.hosts_tested,
            "hosts_skipped": self.hosts_skipped,
            "credentials_found": self.credentials_found,
            "read_write_found": self.read_write_found,
            "scan_time": round(self.scan_time, 2),
        }


# ─── Success Pattern ─────────────────────────────────────────────────────────

# [+] 192.168.20.18:161 - Login Successful: public (Access level: read-only); Proof (sysDescr.0): RouterOS RB3011UiAS
SUCCESS_PATTERN = re.compile(
    r'\[\+\]\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s*-\s*Login Successful:\s*'
    r'(\S+)\s*'
    r'\(Access level:\s*([^)]+)\)'
    r'(?:;\s*Proof\s*\([^)]*\):\s*(.*))?',
    re.IGNORECASE,
)

# Fallback: simpler pattern
SUCCESS_PATTERN_SIMPLE = re.compile(
    r'\[\+\]\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s*-\s*Login Successful:\s*(\S+)',
    re.IGNORECASE,
)

# Error / rate limit patterns
RATE_LIMIT_PATTERNS = [
    r"connection.*refused",
    r"connection.*reset",
    r"Connection timed out",
    r"Unable to Connect",
    r"Rex::ConnectionRefused",
    r"Rex::ConnectionTimeout",
    r"Rex::HostUnreachable",
    r"No response",
]


# ─── Main Scanner ─────────────────────────────────────────────────────────────

class SNMPLoginScanner:
    """
    Metasploit SNMP login scanner.

    Uses msfconsole auxiliary/scanner/snmp/snmp_login to attempt
    community string brute-force against hosts with SNMP ports open.

    Workflow per IP:
      1. Run snmp_login with default community string list
      2. Parse output for successful logins
      3. Report access level and proof
    """

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.msf_path = self._find_msfconsole()
        self.available = self.msf_path is not None
        self.results: Dict[str, SNMPLoginHostResult] = {}  # "ip:port" → result
        self.stats = SNMPLoginStats()

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
                protocol = port_entry.protocol if hasattr(port_entry, 'protocol') else port_entry.get('protocol', 'tcp')

                if state == "open" and (
                    port_num in SNMP_PORTS
                    or "snmp" in service.lower()
                ):
                    snmp_targets.append((ip, port_num))

        # Sort by IP then port for consistent ordering
        snmp_targets.sort(key=lambda t: (t[0], t[1]))
        return snmp_targets

    def scan(
        self,
        nmap_results: Dict,
        output_dir: str = "",
    ) -> Dict[str, SNMPLoginHostResult]:
        """
        Run SNMP login brute-force against hosts with SNMP ports open.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.
            output_dir: Directory to save output files.

        Returns:
            Dict mapping "ip:port" → SNMPLoginHostResult.
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

        print(
            f"\033[36m[>]\033[0m snmp-login: SNMP community string brute-force on "
            f"\033[96m{len(snmp_targets)}\033[0m target(s) ..."
        )

        for idx, (ip, snmp_port) in enumerate(snmp_targets, 1):
            result_key = f"{ip}:{snmp_port}"

            print(
                f"\033[36m[>]\033[0m snmp-login: "
                f"[\033[96m{idx}/{len(snmp_targets)}\033[0m] "
                f"\033[96m{ip}:{snmp_port}\033[0m ..."
            )

            host_result = self._scan_host(ip, snmp_port, output_dir)
            self.results[result_key] = host_result

            # Print per-host status
            if host_result.skipped:
                print(
                    f"\033[93m[!]\033[0m snmp-login: \033[96m{ip}:{snmp_port}\033[0m → "
                    f"\033[93mskipped ({host_result.skip_reason})\033[0m "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )
            elif host_result.credentials:
                for cred in host_result.credentials:
                    rw_tag = ""
                    if "write" in cred.access_level.lower():
                        rw_tag = " \033[1;91m[READ-WRITE!]\033[0m"
                    proof_str = f" — {cred.proof}" if cred.proof else ""
                    print(
                        f"\033[1;92m[+]\033[0m snmp-login: \033[96m{ip}:{snmp_port}\033[0m → "
                        f"\033[1;92m{cred.community}\033[0m "
                        f"(\033[93m{cred.access_level}\033[0m){rw_tag}"
                        f"\033[90m{proof_str}\033[0m "
                        f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                    )
            else:
                print(
                    f"\033[37m[-]\033[0m snmp-login: \033[96m{ip}:{snmp_port}\033[0m → "
                    f"\033[37mno valid community strings\033[0m "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )

        scan_elapsed = time.time() - scan_start
        self._compute_stats(scan_elapsed)

        # Save combined results only if there are findings
        if output_dir and self.stats.credentials_found:
            self._save_results(output_dir)

        return self.results

    def _scan_host(
        self,
        ip: str,
        port: int,
        output_dir: str,
    ) -> SNMPLoginHostResult:
        """
        Run SNMP login against a single host.

        Steps:
          1. Run auxiliary/scanner/snmp/snmp_login
          2. Parse output for successful community strings
        """
        result = SNMPLoginHostResult(ip=ip, port=port)
        host_start = time.time()

        try:
            print(
                f"    \033[36m[>]\033[0m \033[96m{ip}:{port}\033[0m "
                f"running snmp_login ..."
            )
            login_output = self._run_snmp_login(ip, port)
            result.raw_output = login_output

            # Parse successful logins
            creds = self._parse_success(ip, port, login_output)
            result.credentials = creds

            # Check for rate limit / connection issues
            if self._detect_rate_limit(login_output):
                result.skipped = True
                result.skip_reason = "rate_limit"

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

        # Save per-host raw output only if there are findings
        if output_dir and result.credentials and result.raw_output.strip():
            safe_ip = ip.replace(".", "_").replace(":", "_")
            out_file = routed_path(output_dir, f"snmp_login_{safe_ip}.txt")
            try:
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(f"# Metasploit SNMP login: {ip}:{port}\n")
                    f.write(f"# Scan time: {result.scan_time:.1f}s\n\n")
                    f.write(result.raw_output)
            except Exception:
                pass

        return result

    def _run_snmp_login(self, ip: str, port: int) -> str:
        """
        Run auxiliary/scanner/snmp/snmp_login.

        Creates a .rc resource script:
            use auxiliary/scanner/snmp/snmp_login
            set RHOSTS <ip>
            set RPORT <port>
            set THREADS 1
            run
            exit

        Returns the raw stdout+stderr output.
        """
        tmpdir = tempfile.mkdtemp(prefix="reconx_snmp_login_")
        rc_file = os.path.join(tmpdir, "snmp_login.rc")

        try:
            rc_content = (
                f"use auxiliary/scanner/snmp/snmp_login\n"
                f"set RHOSTS {ip}\n"
                f"set RPORT {port}\n"
                f"set THREADS 1\n"
                f"set VERBOSE false\n"
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
                stdout, stderr = proc.communicate(timeout=120)
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

    def _parse_success(self, ip: str, port: int, output: str) -> List[SNMPCredential]:
        """Parse msfconsole output for successful SNMP community strings."""
        creds = []
        seen = set()

        for line in output.splitlines():
            if "[+]" not in line:
                continue

            # Try full pattern:
            # [+] 192.168.20.18:161 - Login Successful: public (Access level: read-only); Proof (sysDescr.0): RouterOS RB3011UiAS
            match = SUCCESS_PATTERN.search(line)
            if match:
                community = match.group(3)
                access_level = match.group(4).strip()
                proof = (match.group(5) or "").strip()
                key = f"{match.group(1)}:{match.group(2)}:{community}"
                if key not in seen:
                    seen.add(key)
                    creds.append(SNMPCredential(
                        ip=match.group(1),
                        port=int(match.group(2)),
                        community=community,
                        access_level=access_level,
                        proof=proof,
                    ))
                continue

            # Try simple pattern
            match = SUCCESS_PATTERN_SIMPLE.search(line)
            if match:
                community = match.group(3)
                key = f"{match.group(1)}:{match.group(2)}:{community}"
                if key not in seen:
                    seen.add(key)
                    creds.append(SNMPCredential(
                        ip=match.group(1),
                        port=int(match.group(2)),
                        community=community,
                        access_level="unknown",
                        proof="",
                    ))

        return creds

    def _detect_rate_limit(self, output: str) -> bool:
        """Check if the output indicates rate limiting or connection issues."""
        error_count = 0
        total_attempts = 0

        for line in output.splitlines():
            if "[-]" in line or "[*]" in line:
                total_attempts += 1
                line_lower = line.lower()
                for pattern in RATE_LIMIT_PATTERNS:
                    if re.search(pattern, line_lower):
                        error_count += 1
                        break

        if total_attempts > 3 and error_count > total_attempts * 0.5:
            return True
        return False

    def _compute_stats(self, scan_time: float):
        """Compute aggregated statistics."""
        self.stats.scan_time = scan_time
        self.stats.hosts_tested = sum(
            1 for r in self.results.values() if not r.skipped
        )
        self.stats.hosts_skipped = sum(
            1 for r in self.results.values() if r.skipped
        )
        self.stats.credentials_found = sum(
            len(r.credentials) for r in self.results.values()
        )
        self.stats.read_write_found = sum(
            1 for r in self.results.values()
            for c in r.credentials
            if "write" in c.access_level.lower()
        )

    def _save_results(self, output_dir: str):
        """Save combined SNMP login results to output directory."""
        # Community strings summary
        all_creds = []
        for key in sorted(self.results.keys()):
            host_result = self.results[key]
            for cred in host_result.credentials:
                all_creds.append(cred)

        if all_creds:
            cred_file = routed_path(output_dir, "snmp_communities.txt")
            try:
                with open(cred_file, "w", encoding="utf-8") as f:
                    f.write("# Metasploit SNMP Login — Valid Community Strings\n")
                    f.write(f"# Generated by ReconX\n")
                    f.write(f"# Total: {len(all_creds)} community string(s)\n\n")
                    for cred in all_creds:
                        proof_str = f" — {cred.proof}" if cred.proof else ""
                        f.write(
                            f"{cred.ip}:{cred.port} → "
                            f"{cred.community} ({cred.access_level})"
                            f"{proof_str}\n"
                        )
            except Exception:
                pass

        # Read-write community strings (critical finding)
        rw_creds = [c for c in all_creds if "write" in c.access_level.lower()]
        if rw_creds:
            rw_file = routed_path(output_dir, "snmp_read_write.txt")
            try:
                with open(rw_file, "w", encoding="utf-8") as f:
                    f.write("# SNMP Hosts with Read-Write Community Strings\n")
                    f.write(f"# Generated by ReconX\n")
                    f.write(f"# Total: {len(rw_creds)} host(s)\n\n")
                    for cred in rw_creds:
                        f.write(f"{cred.ip}:{cred.port} → {cred.community}\n")
            except Exception:
                pass

        # Full summary JSON
        summary_file = routed_path(output_dir, "snmp_login_summary.json")
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

    def get_all_credentials(self) -> List[SNMPCredential]:
        """Get all discovered valid community strings across all hosts."""
        creds = []
        for host_result in self.results.values():
            creds.extend(host_result.credentials)
        return creds

    def get_read_write_hosts(self) -> List[str]:
        """Get list of ip:port strings with read-write SNMP access."""
        hosts = []
        for r in self.results.values():
            for c in r.credentials:
                if "write" in c.access_level.lower():
                    hosts.append(f"{r.ip}:{r.port}")
                    break
        return hosts

    def get_community_strings(self) -> Dict[str, List[str]]:
        """
        Get discovered community strings grouped by IP.
        Returns Dict[ip, List[community_string]].
        Used by SNMPEnumScanner to know which community to use.
        """
        result = {}
        for host_result in self.results.values():
            for cred in host_result.credentials:
                if cred.ip not in result:
                    result[cred.ip] = []
                if cred.community not in result[cred.ip]:
                    result[cred.ip].append(cred.community)
        return result
