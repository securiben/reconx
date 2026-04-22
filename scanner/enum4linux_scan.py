"""
Enum4linux Scanner for ReconX.
Runs enum4linux -a against each discovered IP address for
Windows/Samba enumeration (users, shares, groups, policies, etc.).

Command: enum4linux -a <ip>

Requires: enum4linux installed in PATH
  Install (Debian/Ubuntu): sudo apt install enum4linux
  Install (Kali):          pre-installed
  Manual:                  https://github.com/CiscoCXSecurity/enum4linux
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
import re

from ..config import ScannerConfig
from ..utils import routed_path


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class Enum4linuxShare:
    """A single discovered SMB share."""
    name: str = ""
    share_type: str = ""
    comment: str = ""
    access: str = ""       # e.g. "READ", "WRITE", "READ/WRITE", "DENIED"

    def to_dict(self) -> dict:
        d = {"name": self.name}
        if self.share_type:
            d["type"] = self.share_type
        if self.comment:
            d["comment"] = self.comment
        if self.access:
            d["access"] = self.access
        return d


@dataclass
class Enum4linuxUser:
    """A discovered user account."""
    username: str = ""
    rid: str = ""
    description: str = ""

    def to_dict(self) -> dict:
        d = {"username": self.username}
        if self.rid:
            d["rid"] = self.rid
        if self.description:
            d["description"] = self.description
        return d


@dataclass
class Enum4linuxGroup:
    """A discovered group."""
    name: str = ""
    rid: str = ""
    members: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {"name": self.name}
        if self.rid:
            d["rid"] = self.rid
        if self.members:
            d["members"] = self.members
        return d


@dataclass
class Enum4linuxHostResult:
    """Parsed enum4linux result for a single host (IP)."""
    ip: str = ""
    target_info: str = ""          # Target information string
    workgroup: str = ""
    domain: str = ""
    os_info: str = ""
    server_string: str = ""
    null_session: bool = False     # Whether null session was successful
    shares: List[Enum4linuxShare] = field(default_factory=list)
    users: List[Enum4linuxUser] = field(default_factory=list)
    groups: List[Enum4linuxGroup] = field(default_factory=list)
    password_policy: Dict[str, str] = field(default_factory=dict)
    rid_cycling_users: List[str] = field(default_factory=list)
    printers: List[str] = field(default_factory=list)
    raw_output: str = ""
    scan_time: float = 0.0
    success: bool = False

    def to_dict(self) -> dict:
        d = {
            "ip": self.ip,
            "success": self.success,
            "scan_time": round(self.scan_time, 2),
        }
        if self.workgroup:
            d["workgroup"] = self.workgroup
        if self.domain:
            d["domain"] = self.domain
        if self.os_info:
            d["os_info"] = self.os_info
        if self.server_string:
            d["server_string"] = self.server_string
        if self.null_session:
            d["null_session"] = True
        if self.shares:
            d["shares"] = [s.to_dict() for s in self.shares]
        if self.users:
            d["users"] = [u.to_dict() for u in self.users]
        if self.groups:
            d["groups"] = [g.to_dict() for g in self.groups]
        if self.password_policy:
            d["password_policy"] = self.password_policy
        if self.rid_cycling_users:
            d["rid_cycling_users"] = self.rid_cycling_users
        if self.printers:
            d["printers"] = self.printers
        return d


@dataclass
class Enum4linuxStats:
    """Aggregated enum4linux scan statistics."""
    total_ips_scanned: int = 0
    hosts_responded: int = 0
    null_sessions: int = 0
    total_shares: int = 0
    total_users: int = 0
    total_groups: int = 0
    hosts_with_shares: int = 0
    hosts_with_users: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_ips_scanned": self.total_ips_scanned,
            "hosts_responded": self.hosts_responded,
            "null_sessions": self.null_sessions,
            "total_shares": self.total_shares,
            "total_users": self.total_users,
            "total_groups": self.total_groups,
            "hosts_with_shares": self.hosts_with_shares,
            "hosts_with_users": self.hosts_with_users,
            "scan_time": self.scan_time,
        }


# ─── Main Scanner ─────────────────────────────────────────────────────────────

class Enum4linuxScanner:
    """
    Enum4linux SMB/Windows enumeration scanner wrapper.

    Runs enum4linux -a against each IP from the ip_addresses list
    (typically read from ip_addresses.txt after nmap).
    Parses output for: shares, users, groups, password policy, OS info.
    """

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.enum4linux_path = self._find_enum4linux()
        self.available = self.enum4linux_path is not None
        self.results: Dict[str, Enum4linuxHostResult] = {}  # ip → result
        self.stats = Enum4linuxStats()

    def _find_enum4linux(self) -> Optional[str]:
        """Find the enum4linux binary in PATH or common install locations."""
        # Try enum4linux first, then enum4linux-ng (newer Python rewrite)
        for name in ["enum4linux", "enum4linux-ng", "enum4linux.pl"]:
            found = shutil.which(name)
            if found:
                return found

        common_paths = [
            "/usr/bin/enum4linux",
            "/usr/local/bin/enum4linux",
            "/usr/share/enum4linux/enum4linux.pl",
            "/opt/enum4linux/enum4linux.pl",
            "/usr/bin/enum4linux-ng",
            "/usr/local/bin/enum4linux-ng",
        ]

        for path in common_paths:
            if path and os.path.isfile(path):
                return path

        # Auto-install enum4linux if not found
        from .auto_install import ensure_tool
        if ensure_tool("enum4linux"):
            return shutil.which("enum4linux") or shutil.which("enum4linux-ng")

        return None

    def scan(self, ip_addresses: Set[str], output_dir: str = "") -> Dict[str, Enum4linuxHostResult]:
        """
        Run enum4linux -a against each IP address.

        Iterates through IPs one by one (enum4linux doesn't support batch):
            for ip in ip_addresses:
                enum4linux -a <ip>

        Args:
            ip_addresses: Set of IP addresses to scan.
            output_dir: Directory to place output files.

        Returns:
            Dict mapping IP → Enum4linuxHostResult.
        """
        if not self.available:
            return {}

        if not ip_addresses:
            return {}

        scan_start = time.time()
        self.stats.total_ips_scanned = len(ip_addresses)

        # Create output directory
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        print(
            f"\033[36m[>]\033[0m enum4linux: scanning \033[96m{len(ip_addresses)}\033[0m "
            f"IPs with \033[96m-a\033[0m (full enumeration) ..."
        )

        sorted_ips = sorted(ip_addresses)
        for idx, ip in enumerate(sorted_ips, 1):
            print(
                f"\033[36m[>]\033[0m enum4linux: "
                f"[\033[96m{idx}/{len(sorted_ips)}\033[0m] "
                f"scanning \033[96m{ip}\033[0m ..."
            )

            host_result = self._scan_host(ip, output_dir)
            self.results[ip] = host_result

            # Print per-host status
            if host_result.success:
                parts = []
                if host_result.shares:
                    parts.append(f"{len(host_result.shares)} shares")
                if host_result.users:
                    parts.append(f"{len(host_result.users)} users")
                if host_result.groups:
                    parts.append(f"{len(host_result.groups)} groups")
                if host_result.null_session:
                    parts.append("null session")
                detail = ", ".join(parts) if parts else "responded"
                print(
                    f"\033[92m[+]\033[0m enum4linux: \033[96m{ip}\033[0m → "
                    f"\033[92m{detail}\033[0m "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )
            else:
                print(
                    f"\033[37m[-]\033[0m enum4linux: \033[96m{ip}\033[0m → "
                    f"\033[37mno response / failed\033[0m "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )

        scan_elapsed = time.time() - scan_start
        self._compute_stats(scan_elapsed)

        return self.results

    def _scan_host(self, ip: str, output_dir: str = "") -> Enum4linuxHostResult:
        """
        Run enum4linux -a against a single IP.

        Args:
            ip: Target IP address.
            output_dir: Optional directory for saving raw output.

        Returns:
            Enum4linuxHostResult with parsed data.
        """
        result = Enum4linuxHostResult(ip=ip)
        host_start = time.time()

        try:
            # Build enum4linux command (null session — no user/pass)
            cmd = [self.enum4linux_path, "-a", "-u", "", "-p", "", ip]

            # Set PASSWD env var so smbclient (called internally by enum4linux)
            # doesn't prompt for a password via /dev/tty
            env = os.environ.copy()
            env["PASSWD"] = ""
            env["SMBPASSWD"] = ""

            # Wrap with setsid so the subprocess has no controlling TTY.
            # This prevents smbclient from opening /dev/tty directly for the
            # password prompt — it will fall back to the empty PASSWD env var.
            if shutil.which("setsid"):
                cmd = ["setsid"] + cmd

            # Run enum4linux
            timeout_secs = 300  # 5 minutes per host
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                env=env,
            )

            try:
                stdout, stderr = proc.communicate(timeout=timeout_secs)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()

            output = stdout.decode("utf-8", errors="replace")
            result.raw_output = output

            # Parse the output
            self._parse_output(result, output)

            # Check if we got any useful data
            if (result.workgroup or result.shares or result.users
                    or result.groups or result.os_info or result.null_session):
                result.success = True

            # Save raw output to file
            if output_dir and output.strip():
                safe_ip = ip.replace(".", "_").replace(":", "_")
                out_file = routed_path(output_dir, f"enum4linux_{safe_ip}.txt")
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(f"# enum4linux -a {ip}\n")
                    f.write(f"# Scan time: {time.time() - host_start:.1f}s\n\n")
                    f.write(output)

        except FileNotFoundError:
            self.available = False
        except Exception:
            pass

        result.scan_time = time.time() - host_start
        return result

    def _parse_output(self, result: Enum4linuxHostResult, output: str):
        """
        Parse enum4linux output for structured data.

        Enum4linux output sections:
        - Target Information
        - Workgroup/Domain via session
        - Nbtstat Information
        - Session Check (null session)
        - OS Information
        - Share Enumeration
        - User Enumeration (RID cycling)
        - Group Membership
        - Password Policy
        - Printer Enumeration
        """
        lines = output.splitlines()

        # Parse workgroup/domain
        for line in lines:
            # Workgroup: e.g. "[+] Got domain/workgroup name: WORKGROUP"
            match = re.search(r'Got domain/workgroup name:\s*(\S+)', line)
            if match:
                result.workgroup = match.group(1)
                continue

            # Domain: e.g. "[+] Domain: CORP.LOCAL"
            match = re.search(r'Domain:\s*(\S+)', line)
            if match and "Domain:" in line and "[+]" in line:
                result.domain = match.group(1)
                continue

        # Parse OS information
        self._parse_os_info(result, lines)

        # Parse null session check
        self._parse_null_session(result, lines)

        # Parse shares
        self._parse_shares(result, lines)

        # Parse users
        self._parse_users(result, lines)

        # Parse groups
        self._parse_groups(result, lines)

        # Parse password policy
        self._parse_password_policy(result, lines)

        # Parse RID cycling users
        self._parse_rid_cycling(result, lines)

        # Parse printers
        self._parse_printers(result, lines)

    def _parse_os_info(self, result: Enum4linuxHostResult, lines: List[str]):
        """Parse OS information from enum4linux output."""
        for line in lines:
            # OS info patterns
            if "OS:" in line or "os info:" in line.lower():
                match = re.search(r'OS:\s*(.+?)(?:\s*$)', line)
                if match:
                    result.os_info = match.group(1).strip()
                    continue

            # Server string: e.g. "server string: Samba 4.x"
            match = re.search(r'[Ss]erver\s+string:\s*(.+)', line)
            if match:
                result.server_string = match.group(1).strip()

    def _parse_null_session(self, result: Enum4linuxHostResult, lines: List[str]):
        """Check if null session was successful."""
        for line in lines:
            if ("session check" in line.lower() or "null session" in line.lower()):
                if "success" in line.lower() or "[+]" in line:
                    result.null_session = True
                    break

    def _parse_shares(self, result: Enum4linuxHostResult, lines: List[str]):
        """Parse share enumeration results."""
        in_share_section = False
        for line in lines:
            # Detect share enumeration section
            if "share enumeration" in line.lower() or "Enumerating Shares" in line:
                in_share_section = True
                continue

            if in_share_section:
                # End of section markers
                if line.startswith("====") or (line.startswith("[") and "Enumerating" in line):
                    if result.shares:  # Only stop if we've found shares
                        in_share_section = False
                        continue

                # Share line patterns:
                # "//SERVER/sharename  Disk  Comment here"
                # "|    SHARENAME    |    Disk    |    Comment    |"
                match = re.search(
                    r'//\S+/(\S+)\s+(Disk|IPC|Printer|Special)\s*(.*)',
                    line, re.IGNORECASE
                )
                if match:
                    share = Enum4linuxShare(
                        name=match.group(1),
                        share_type=match.group(2),
                        comment=match.group(3).strip() if match.group(3) else "",
                    )
                    result.shares.append(share)
                    continue

                # Alternate table format with pipes
                match = re.search(
                    r'\|\s*(\S+)\s*\|\s*(Disk|IPC|Printer|Special)\s*\|\s*(.*?)\s*\|',
                    line, re.IGNORECASE
                )
                if match:
                    share = Enum4linuxShare(
                        name=match.group(1),
                        share_type=match.group(2),
                        comment=match.group(3).strip() if match.group(3) else "",
                    )
                    result.shares.append(share)
                    continue

                # Access check: "Mapping: OK, Listing: OK" or "ACCESS_DENIED"
                if result.shares:
                    if "mapping: ok" in line.lower() and "listing: ok" in line.lower():
                        result.shares[-1].access = "READ"
                    elif "access_denied" in line.lower() or "mapping: denied" in line.lower():
                        result.shares[-1].access = "DENIED"

    def _parse_users(self, result: Enum4linuxHostResult, lines: List[str]):
        """Parse user enumeration results."""
        for line in lines:
            # user:[username] rid:[0xRID]
            match = re.search(r'user:\[([^\]]+)\]\s*rid:\[([^\]]+)\]', line)
            if match:
                user = Enum4linuxUser(
                    username=match.group(1),
                    rid=match.group(2),
                )
                # Check for duplicates
                if not any(u.username == user.username for u in result.users):
                    result.users.append(user)
                continue

            # S-1-5-... <username> (Local User)
            match = re.search(r'S-\d+-\d+-\d+.*?\s+(\S+)\s+\((Local|Domain)\s+User\)', line)
            if match:
                username = match.group(1)
                if not any(u.username == username for u in result.users):
                    result.users.append(Enum4linuxUser(username=username))

    def _parse_groups(self, result: Enum4linuxHostResult, lines: List[str]):
        """Parse group enumeration results."""
        for line in lines:
            # group:[groupname] rid:[0xRID]
            match = re.search(r'group:\[([^\]]+)\]\s*rid:\[([^\]]+)\]', line)
            if match:
                group = Enum4linuxGroup(
                    name=match.group(1),
                    rid=match.group(2),
                )
                if not any(g.name == group.name for g in result.groups):
                    result.groups.append(group)

    def _parse_password_policy(self, result: Enum4linuxHostResult, lines: List[str]):
        """Parse password policy information."""
        in_policy = False
        for line in lines:
            if "password policy" in line.lower() and ("==" in line or "[+]" in line):
                in_policy = True
                continue

            if in_policy:
                if line.startswith("====") or (line.startswith("[") and "==" in line):
                    if result.password_policy:
                        in_policy = False
                        continue

                # Parse policy lines: "Minimum password length: 7"
                match = re.search(r'^\s*(.+?):\s*(.+)$', line)
                if match:
                    key = match.group(1).strip()
                    value = match.group(2).strip()
                    if key and value and len(key) > 2:
                        result.password_policy[key] = value

    def _parse_rid_cycling(self, result: Enum4linuxHostResult, lines: List[str]):
        """Parse RID cycling user enumeration."""
        for line in lines:
            # S-1-5-21-xxx-xxx-xxx-500 DOMAIN\Administrator (Local User)
            match = re.search(
                r'S-\d+-\d+-[\d-]+\s+\S+\\(\S+)\s+\((Local|Domain)\s+(User|Group)\)',
                line
            )
            if match:
                name = match.group(1)
                entity_type = match.group(3)
                if entity_type == "User" and name not in result.rid_cycling_users:
                    result.rid_cycling_users.append(name)

    def _parse_printers(self, result: Enum4linuxHostResult, lines: List[str]):
        """Parse printer enumeration."""
        in_printer = False
        for line in lines:
            if "printer" in line.lower() and ("enumerat" in line.lower() or "==" in line):
                in_printer = True
                continue

            if in_printer:
                if line.startswith("====") or (line.startswith("[") and "==" in line):
                    in_printer = False
                    continue

                line_stripped = line.strip()
                if line_stripped and not line_stripped.startswith("["):
                    if line_stripped not in result.printers:
                        result.printers.append(line_stripped)

    def _compute_stats(self, scan_time: float):
        """Compute aggregated statistics from enum4linux results."""
        self.stats.scan_time = scan_time
        self.stats.hosts_responded = sum(
            1 for r in self.results.values() if r.success
        )

        total_shares = 0
        total_users = 0
        total_groups = 0
        hosts_with_shares = 0
        hosts_with_users = 0
        null_sessions = 0

        for ip, host_result in self.results.items():
            if host_result.shares:
                total_shares += len(host_result.shares)
                hosts_with_shares += 1
            if host_result.users:
                total_users += len(host_result.users)
                hosts_with_users += 1
            if host_result.groups:
                total_groups += len(host_result.groups)
            if host_result.null_session:
                null_sessions += 1

        self.stats.total_shares = total_shares
        self.stats.total_users = total_users
        self.stats.total_groups = total_groups
        self.stats.hosts_with_shares = hosts_with_shares
        self.stats.hosts_with_users = hosts_with_users
        self.stats.null_sessions = null_sessions

    def get_null_session_hosts(self) -> List[str]:
        """Get list of IPs where null session was successful."""
        return [
            ip for ip, r in self.results.items()
            if r.null_session
        ]

    def get_all_users(self) -> Dict[str, List[str]]:
        """Get dict of IP → list of discovered usernames."""
        result = {}
        for ip, host_result in self.results.items():
            users = [u.username for u in host_result.users]
            if host_result.rid_cycling_users:
                users.extend(
                    u for u in host_result.rid_cycling_users if u not in users
                )
            if users:
                result[ip] = users
        return result

    def get_all_shares(self) -> Dict[str, List[str]]:
        """Get dict of IP → list of discovered share names."""
        return {
            ip: [s.name for s in r.shares]
            for ip, r in self.results.items()
            if r.shares
        }
