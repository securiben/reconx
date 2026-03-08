"""
Metasploit MongoDB Login / Info / Enum Scanner for ReconX.
Uses msfconsole to brute-force MongoDB credentials, gather server
info, and enumerate databases/collections on hosts where nmap
discovered MongoDB ports.

For each IP that has MongoDB port(s) open (27017, 27018, 27019, etc.):
  1. Run auxiliary/scanner/mongodb/mongodb_login with:
     - RHOSTS = target IP
     - USERNAME  = wordlists/mongodb-userpass-enum.txt
     - PASS_FILE = wordlists/mongodb-userpass-enum.txt
     - STOP_ON_SUCCESS = true
  2. Run auxiliary/scanner/mongodb/mongodb_info
  3. Run auxiliary/scanner/mongodb/mongodb_enum
  4. Parse output for successful logins + server info + databases
  5. On rate limit / account lockout / delay / timeout → skip to next IP

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


# ─── MongoDB Ports ────────────────────────────────────────────────────────────

MONGODB_PORTS = {27017, 27018, 27019, 28017}


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class MongoDBCredential:
    """A successfully brute-forced MongoDB credential."""
    ip: str = ""
    port: int = 27017
    username: str = ""
    password: str = ""

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "username": self.username,
            "password": self.password,
        }


@dataclass
class MongoDBServerInfo:
    """Server info gathered by mongodb_info."""
    version: str = ""
    git_version: str = ""
    os_type: str = ""
    os_name: str = ""
    os_architecture: str = ""
    sysinfo: str = ""
    raw: str = ""

    def to_dict(self) -> dict:
        d = {}
        if self.version:
            d["version"] = self.version
        if self.git_version:
            d["git_version"] = self.git_version
        if self.os_type:
            d["os_type"] = self.os_type
        if self.os_name:
            d["os_name"] = self.os_name
        if self.os_architecture:
            d["os_architecture"] = self.os_architecture
        if self.sysinfo:
            d["sysinfo"] = self.sysinfo
        return d


@dataclass
class MongoDBEnumInfo:
    """Enumeration data gathered by mongodb_enum."""
    databases: List[str] = field(default_factory=list)
    collections: Dict[str, List[str]] = field(default_factory=dict)
    users: List[str] = field(default_factory=list)
    raw: str = ""

    def to_dict(self) -> dict:
        d = {}
        if self.databases:
            d["databases"] = self.databases
        if self.collections:
            d["collections"] = self.collections
        if self.users:
            d["users"] = self.users
        return d


@dataclass
class MongoDBHostResult:
    """Combined result for a single MongoDB host (login + info + enum)."""
    ip: str = ""
    port: int = 27017
    credentials: List[MongoDBCredential] = field(default_factory=list)
    server_info: Optional[MongoDBServerInfo] = None
    enum_info: Optional[MongoDBEnumInfo] = None
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
        if self.server_info:
            d["server_info"] = self.server_info.to_dict()
        if self.enum_info:
            d["enum_info"] = self.enum_info.to_dict()
        if self.skipped:
            d["skipped"] = True
            d["skip_reason"] = self.skip_reason
        return d


@dataclass
class MongoDBLoginStats:
    """Aggregated MongoDB login statistics."""
    total_mongodb_hosts: int = 0
    hosts_tested: int = 0
    hosts_skipped: int = 0
    credentials_found: int = 0
    hosts_with_info: int = 0
    databases_found: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_mongodb_hosts": self.total_mongodb_hosts,
            "hosts_tested": self.hosts_tested,
            "hosts_skipped": self.hosts_skipped,
            "credentials_found": self.credentials_found,
            "hosts_with_info": self.hosts_with_info,
            "databases_found": self.databases_found,
            "scan_time": round(self.scan_time, 2),
        }


# ─── Lockout / Rate Limit / Delay Detection Patterns ─────────────────────────

LOCKOUT_PATTERNS = [
    r"account.*lock",
    r"too many.*(?:login|auth|fail)",
    r"login.*disabled",
    r"temporarily.*locked",
    r"account.*disabled",
    r"maximum.*(?:retries|attempts)",
    r"auth.*failed.*too many",
]

RATE_LIMIT_PATTERNS = [
    r"connection.*refused",
    r"connection.*reset",
    r"Connection timed out",
    r"Unable to Connect",
    r"Rex::ConnectionRefused",
    r"Rex::ConnectionTimeout",
    r"Rex::HostUnreachable",
    r"No connection could be made",
    r"Errno::ECONNREFUSED",
    r"Errno::ECONNRESET",
    r"Errno::ETIMEDOUT",
]

DELAY_PATTERNS = [
    r"connection.*delay",
    r"throttl",
    r"rate.*limit",
    r"too fast",
    r"slow down",
]

# ─── Success / Parsing Patterns ──────────────────────────────────────────────

# mongodb_login:
# [+] 192.168.1.1:27017 - Login Successful: admin:admin
# [+] 192.168.1.1:27017 -  - SUCCESSFUL LOGIN admin:admin
SUCCESS_PATTERN = re.compile(
    r'\[\+\]\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s*-\s*'
    r'(?:Login Successful|SUCCESSFUL LOGIN)[:\s]*'
    r'[\'"]?(\S+?):(\S+?)[\'"]?'
    r'(?:\s|$)',
    re.IGNORECASE,
)

# Fallback: [+] line with "Success" and user:pass in quotes
SUCCESS_PATTERN_ALT = re.compile(
    r'\[\+\]\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s*-\s*'
    r'.*?[Ss]uccess.*?[\'"](\S+?):(\S+?)[\'"]',
    re.IGNORECASE,
)

# Fallback: any [+] line with user:pass in quotes
SUCCESS_PATTERN_QUOTED = re.compile(
    r"\[\+\].*?'([^':]+):([^']+)'",
    re.IGNORECASE,
)

# mongodb_info version parsing:
# [*] 192.168.1.1:27017 - MongoDB version: 3.6.8
INFO_VERSION_PATTERN = re.compile(
    r'(?:MongoDB|Server)\s*version[:\s]+(\S+)',
    re.IGNORECASE,
)

# [*] 192.168.1.1:27017 - gitVersion: ...
INFO_GIT_PATTERN = re.compile(
    r'gitVersion[:\s]+(\S+)',
    re.IGNORECASE,
)

# OS info
INFO_OS_PATTERN = re.compile(
    r'(?:os|operating\s*system)[:\s]+(.*)',
    re.IGNORECASE,
)

# mongodb_enum database/collection parsing:
# [*] 192.168.1.1:27017 -   Database Name: admin
ENUM_DB_PATTERN = re.compile(
    r'Database\s*Name[:\s]+(\S+)',
    re.IGNORECASE,
)

# Collection name
ENUM_COLL_PATTERN = re.compile(
    r'Collection[:\s]+(\S+)',
    re.IGNORECASE,
)

# User/role
ENUM_USER_PATTERN = re.compile(
    r'User[:\s]+(\S+)',
    re.IGNORECASE,
)


# ─── Main Scanner ─────────────────────────────────────────────────────────────

class MongoDBLoginScanner:
    """
    Metasploit MongoDB login + info + enum scanner.

    Uses msfconsole to:
      1. Brute-force MongoDB credentials (mongodb_login)
      2. Gather server info (mongodb_info)
      3. Enumerate databases/collections (mongodb_enum)

    Workflow per IP:
      1. Run mongodb_login with USER_FILE + PASS_FILE
      2. Run mongodb_info for version/OS info
      3. Run mongodb_enum for databases/collections
      4. On lockout / rate limit / delay → skip to next IP
    """

    DEFAULT_USERPASS_FILE = os.path.join("wordlists", "mongodb-userpass-enum.txt")

    def __init__(self, config: ScannerConfig, userpass_file: str = ""):
        self.config = config
        self.msf_path = self._find_msfconsole()
        self.available = self.msf_path is not None
        self.userpass_file = userpass_file or self.DEFAULT_USERPASS_FILE
        self.results: Dict[str, MongoDBHostResult] = {}  # "ip:port" → result
        self.stats = MongoDBLoginStats()

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

    def _find_file(self, filename: str, output_dir: str = "") -> Optional[str]:
        """
        Locate a file (userpass file). Search order:
          1. Exact path if absolute
          2. Current working directory
          3. Output directory
          4. Package directory (scanner/)
          5. Parent directory (reconx/)
          6. Project root
        """
        if os.path.isabs(filename) and os.path.isfile(filename):
            return filename

        search_dirs = [
            os.getcwd(),
            output_dir,
            os.path.dirname(os.path.abspath(__file__)),   # scanner/
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),  # reconx/
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        ]

        for d in search_dirs:
            if not d:
                continue
            candidate = os.path.join(d, filename)
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)

        return None

    def _get_mongodb_hosts(self, nmap_results: Dict) -> List[tuple]:
        """
        Extract hosts with MongoDB ports open from nmap results.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.

        Returns:
            List of (ip, port) tuples.
        """
        mongodb_targets = []
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
                    port_num in MONGODB_PORTS
                    or "mongo" in service.lower()
                ):
                    mongodb_targets.append((ip, port_num))

        # Sort by IP then port for consistent ordering
        mongodb_targets.sort(key=lambda t: (t[0], t[1]))
        return mongodb_targets

    def scan(
        self,
        nmap_results: Dict,
        output_dir: str = "",
    ) -> Dict[str, MongoDBHostResult]:
        """
        Run MongoDB login + info + enum against hosts with MongoDB ports open.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.
            output_dir: Directory to save output files.

        Returns:
            Dict mapping "ip:port" → MongoDBHostResult.
        """
        if not self.available:
            return {}

        if not nmap_results:
            return {}

        # Find MongoDB hosts from nmap results
        mongodb_targets = self._get_mongodb_hosts(nmap_results)
        if not mongodb_targets:
            return {}

        # Locate userpass file
        userpass_path = self._find_file(self.userpass_file, output_dir)
        if not userpass_path:
            print(
                f"\033[91m[!]\033[0m mongodb-login: userpass file "
                f"\033[96m{self.userpass_file}\033[0m not found – skipping"
            )
            return {}

        scan_start = time.time()
        self.stats.total_mongodb_hosts = len(mongodb_targets)

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        unique_ips = len({t[0] for t in mongodb_targets})
        print(
            f"\033[36m[>]\033[0m mongodb-login: MongoDB login/info/enum on "
            f"\033[96m{len(mongodb_targets)}\033[0m target(s) "
            f"(\033[96m{unique_ips}\033[0m unique IP(s)) "
            f"with \033[96m{os.path.basename(userpass_path)}\033[0m ..."
        )

        for idx, (ip, mongo_port) in enumerate(mongodb_targets, 1):
            result_key = f"{ip}:{mongo_port}"

            print(
                f"\033[36m[>]\033[0m mongodb-login: "
                f"[\033[96m{idx}/{len(mongodb_targets)}\033[0m] "
                f"\033[96m{ip}:{mongo_port}\033[0m ..."
            )

            host_result = self._scan_host(
                ip, mongo_port, userpass_path, output_dir,
            )
            self.results[result_key] = host_result

            # Print per-host status
            if host_result.skipped:
                print(
                    f"\033[93m[!]\033[0m mongodb-login: \033[96m{ip}:{mongo_port}\033[0m → "
                    f"\033[93mskipped ({host_result.skip_reason})\033[0m "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )
            else:
                parts = []
                if host_result.credentials:
                    cred_str = ", ".join(
                        f"\033[1;92m{c.username}:{c.password}\033[0m"
                        for c in host_result.credentials
                    )
                    parts.append(
                        f"\033[1;92m{len(host_result.credentials)} credential(s)\033[0m "
                        f"→ {cred_str}"
                    )
                if host_result.server_info and host_result.server_info.version:
                    parts.append(
                        f"ver \033[96m{host_result.server_info.version}\033[0m"
                    )
                if host_result.enum_info and host_result.enum_info.databases:
                    parts.append(
                        f"\033[96m{len(host_result.enum_info.databases)} db(s)\033[0m"
                    )
                if parts:
                    print(
                        f"\033[92m[+]\033[0m mongodb-login: \033[96m{ip}:{mongo_port}\033[0m → "
                        f"{' | '.join(parts)} "
                        f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                    )
                else:
                    print(
                        f"\033[37m[-]\033[0m mongodb-login: \033[96m{ip}:{mongo_port}\033[0m → "
                        f"\033[37mno valid credentials / no data\033[0m "
                        f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                    )

        scan_elapsed = time.time() - scan_start
        self._compute_stats(scan_elapsed)

        # Save combined results
        if output_dir:
            self._save_results(output_dir)

        return self.results

    def _scan_host(
        self,
        ip: str,
        port: int,
        userpass_file: str,
        output_dir: str,
    ) -> MongoDBHostResult:
        """
        Run MongoDB login + info + enum against a single host.

        Steps:
          1. Run mongodb_login with USERNAME + PASS_FILE
          2. Run mongodb_info
          3. Run mongodb_enum
          4. On lockout / rate limit / delay → skip
        """
        result = MongoDBHostResult(ip=ip, port=port)
        host_start = time.time()
        raw_parts = []

        try:
            # ── Step 1: mongodb_login ────────────────────────────────────
            print(
                f"    \033[36m[>]\033[0m \033[96m{ip}:{port}\033[0m "
                f"running mongodb_login ..."
            )
            login_output = self._run_mongodb_login(ip, port, userpass_file)
            raw_parts.append(f"=== mongodb_login ===\n{login_output}")

            # Parse successful logins
            creds = self._parse_success(ip, port, login_output)
            result.credentials = creds

            for cred in creds:
                print(
                    f"    \033[1;92m[+]\033[0m \033[1;92mSUCCESS\033[0m: "
                    f"\033[96m{ip}:{port}\033[0m → "
                    f"\033[1;92m{cred.username}:{cred.password}\033[0m"
                )

            # Check for account lockout
            if self._detect_lockout(login_output):
                result.skipped = True
                result.skip_reason = "account_lockout"
                print(
                    f"    \033[91m[!]\033[0m Account lockout detected on "
                    f"\033[96m{ip}:{port}\033[0m"
                )
                result.raw_output = "\n\n".join(raw_parts)
                result.scan_time = time.time() - host_start
                return result

            # Check for rate limit / connection issues
            if self._detect_rate_limit(login_output):
                result.skipped = True
                result.skip_reason = "rate_limit"
                print(
                    f"    \033[93m[!]\033[0m Rate limit / connection issue on "
                    f"\033[96m{ip}:{port}\033[0m"
                )
                result.raw_output = "\n\n".join(raw_parts)
                result.scan_time = time.time() - host_start
                return result

            # Check for delay / throttling
            if self._detect_delay(login_output):
                result.skipped = True
                result.skip_reason = "delay_throttle"
                print(
                    f"    \033[93m[!]\033[0m Delay/throttling detected on "
                    f"\033[96m{ip}:{port}\033[0m"
                )
                result.raw_output = "\n\n".join(raw_parts)
                result.scan_time = time.time() - host_start
                return result

            # ── Step 2: mongodb_info ─────────────────────────────────────
            print(
                f"    \033[36m[>]\033[0m \033[96m{ip}:{port}\033[0m "
                f"running mongodb_info ..."
            )
            info_output = self._run_mongodb_info(ip, port)
            raw_parts.append(f"=== mongodb_info ===\n{info_output}")
            result.server_info = self._parse_info(info_output)

            if result.server_info and result.server_info.version:
                print(
                    f"    \033[92m[+]\033[0m Server version: "
                    f"\033[96m{result.server_info.version}\033[0m"
                )

            # ── Step 3: mongodb_enum ─────────────────────────────────────
            print(
                f"    \033[36m[>]\033[0m \033[96m{ip}:{port}\033[0m "
                f"running mongodb_enum ..."
            )
            enum_output = self._run_mongodb_enum(ip, port)
            raw_parts.append(f"=== mongodb_enum ===\n{enum_output}")
            result.enum_info = self._parse_enum(enum_output)

            if result.enum_info and result.enum_info.databases:
                print(
                    f"    \033[92m[+]\033[0m Databases: "
                    f"\033[96m{', '.join(result.enum_info.databases)}\033[0m"
                )

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
            raw_parts.append(f"ERROR: {e}")

        result.raw_output = "\n\n".join(raw_parts)
        result.scan_time = time.time() - host_start

        # Save per-host raw output
        if output_dir and result.raw_output.strip():
            safe_ip = ip.replace(".", "_").replace(":", "_")
            out_file = os.path.join(output_dir, f"mongodb_login_{safe_ip}_{port}.txt")
            try:
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(f"# Metasploit MongoDB login/info/enum: {ip}:{port}\n")
                    f.write(f"# Userpass file: {userpass_file}\n")
                    f.write(f"# Scan time: {result.scan_time:.1f}s\n\n")
                    f.write(result.raw_output)
            except Exception:
                pass

        return result

    # ─── MSF Module Runners ───────────────────────────────────────────────────

    def _run_msfconsole(self, rc_content: str, timeout: int = 300) -> str:
        """
        Run msfconsole with a .rc resource script and return output.
        """
        tmpdir = tempfile.mkdtemp(prefix="reconx_mongodb_")
        rc_file = os.path.join(tmpdir, "mongodb.rc")

        try:
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
                stdout, stderr = proc.communicate(timeout=timeout)
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

    def _run_mongodb_login(self, ip: str, port: int, userpass_file: str) -> str:
        """
        Run auxiliary/scanner/mongodb/mongodb_login.

        Resource script:
            use auxiliary/scanner/mongodb/mongodb_login
            set RHOSTS <ip>
            set RPORT <port>
            set USERNAME <userpass_file>
            set PASS_FILE <userpass_file>
            set STOP_ON_SUCCESS true
            run
            exit
        """
        rc = (
            f"use auxiliary/scanner/mongodb/mongodb_login\n"
            f"set RHOSTS {ip}\n"
            f"set RPORT {port}\n"
            f"set USER_FILE {userpass_file}\n"
            f"set PASS_FILE {userpass_file}\n"
            f"set STOP_ON_SUCCESS true\n"
            f"set VERBOSE false\n"
            f"set ConnectTimeout 10\n"
            f"set THREADS 1\n"
            f"run\n"
            f"exit\n"
        )
        return self._run_msfconsole(rc, timeout=300)

    def _run_mongodb_info(self, ip: str, port: int) -> str:
        """
        Run auxiliary/scanner/mongodb/mongodb_info.

        Resource script:
            use auxiliary/scanner/mongodb/mongodb_info
            set RHOSTS <ip>
            set RPORT <port>
            run
            exit
        """
        rc = (
            f"use auxiliary/scanner/mongodb/mongodb_info\n"
            f"set RHOSTS {ip}\n"
            f"set RPORT {port}\n"
            f"run\n"
            f"exit\n"
        )
        return self._run_msfconsole(rc, timeout=120)

    def _run_mongodb_enum(self, ip: str, port: int) -> str:
        """
        Run auxiliary/scanner/mongodb/mongodb_enum.

        Resource script:
            use auxiliary/scanner/mongodb/mongodb_enum
            set RHOSTS <ip>
            set RPORT <port>
            run
            exit
        """
        rc = (
            f"use auxiliary/scanner/mongodb/mongodb_enum\n"
            f"set RHOSTS {ip}\n"
            f"set RPORT {port}\n"
            f"run\n"
            f"exit\n"
        )
        return self._run_msfconsole(rc, timeout=120)

    # ─── Output Parsing ──────────────────────────────────────────────────────

    def _parse_success(self, ip: str, port: int, output: str) -> List[MongoDBCredential]:
        """Parse msfconsole output for successful MongoDB login credentials."""
        creds = []
        seen = set()

        for line in output.splitlines():
            if "[+]" not in line:
                continue

            line_lower = line.lower()
            if ("success" not in line_lower
                    and "login" not in line_lower
                    and "authenticated" not in line_lower):
                continue

            # Try standard pattern
            match = SUCCESS_PATTERN.search(line)
            if match:
                key = f"{match.group(1)}:{match.group(2)}:{match.group(3)}:{match.group(4)}"
                if key not in seen:
                    seen.add(key)
                    creds.append(MongoDBCredential(
                        ip=match.group(1),
                        port=int(match.group(2)),
                        username=match.group(3),
                        password=match.group(4),
                    ))
                continue

            # Try alt pattern
            match = SUCCESS_PATTERN_ALT.search(line)
            if match:
                key = f"{match.group(1)}:{match.group(2)}:{match.group(3)}:{match.group(4)}"
                if key not in seen:
                    seen.add(key)
                    creds.append(MongoDBCredential(
                        ip=match.group(1),
                        port=int(match.group(2)),
                        username=match.group(3),
                        password=match.group(4),
                    ))
                continue

            # Fallback: quoted user:pass
            match = SUCCESS_PATTERN_QUOTED.search(line)
            if match:
                key = f"{ip}:{port}:{match.group(1)}:{match.group(2)}"
                if key not in seen:
                    seen.add(key)
                    creds.append(MongoDBCredential(
                        ip=ip,
                        port=port,
                        username=match.group(1),
                        password=match.group(2),
                    ))

        return creds

    def _parse_info(self, output: str) -> MongoDBServerInfo:
        """Parse msfconsole mongodb_info output for server information."""
        info = MongoDBServerInfo(raw=output)

        for line in output.splitlines():
            # Version
            if not info.version:
                m = INFO_VERSION_PATTERN.search(line)
                if m:
                    info.version = m.group(1).strip()

            # Git version
            if not info.git_version:
                m = INFO_GIT_PATTERN.search(line)
                if m:
                    info.git_version = m.group(1).strip()

            # OS info
            if not info.os_name:
                m = INFO_OS_PATTERN.search(line)
                if m:
                    info.os_name = m.group(1).strip()

            # sysInfo
            if "sysinfo" in line.lower() or "sys_info" in line.lower():
                parts = line.split(":", 1)
                if len(parts) > 1:
                    info.sysinfo = parts[1].strip()

        return info

    def _parse_enum(self, output: str) -> MongoDBEnumInfo:
        """Parse msfconsole mongodb_enum output for databases/collections."""
        enum = MongoDBEnumInfo(raw=output)
        current_db = ""

        for line in output.splitlines():
            # Database
            m = ENUM_DB_PATTERN.search(line)
            if m:
                db_name = m.group(1).strip()
                if db_name and db_name not in enum.databases:
                    enum.databases.append(db_name)
                current_db = db_name
                continue

            # Collection
            m = ENUM_COLL_PATTERN.search(line)
            if m:
                coll_name = m.group(1).strip()
                if current_db:
                    enum.collections.setdefault(current_db, [])
                    if coll_name not in enum.collections[current_db]:
                        enum.collections[current_db].append(coll_name)
                continue

            # User
            m = ENUM_USER_PATTERN.search(line)
            if m:
                user = m.group(1).strip()
                if user and user not in enum.users:
                    enum.users.append(user)

        return enum

    # ─── Detection Helpers ───────────────────────────────────────────────────

    def _detect_lockout(self, output: str) -> bool:
        """Check if the output indicates account lockout."""
        output_lower = output.lower()
        for pattern in LOCKOUT_PATTERNS:
            if re.search(pattern, output_lower):
                return True
        return False

    def _detect_rate_limit(self, output: str) -> bool:
        """
        Check if the output indicates rate limiting or connection issues.
        Count connection errors — if > 50% of attempts fail with
        connection issues, treat it as a rate limit.
        """
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

    def _detect_delay(self, output: str) -> bool:
        """Check if the output indicates delay or throttling."""
        output_lower = output.lower()
        for pattern in DELAY_PATTERNS:
            if re.search(pattern, output_lower):
                return True
        return False

    # ─── Stats / Save ────────────────────────────────────────────────────────

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
        self.stats.hosts_with_info = sum(
            1 for r in self.results.values()
            if r.server_info and r.server_info.version
        )
        self.stats.databases_found = sum(
            len(r.enum_info.databases) if r.enum_info else 0
            for r in self.results.values()
        )

    def _save_results(self, output_dir: str):
        """Save combined MongoDB login results to output directory."""
        # Credentials summary
        all_creds = []
        for key in sorted(self.results.keys()):
            host_result = self.results[key]
            for cred in host_result.credentials:
                all_creds.append(cred)

        if all_creds:
            cred_file = os.path.join(output_dir, "mongodb_credentials.txt")
            try:
                with open(cred_file, "w", encoding="utf-8") as f:
                    f.write("# Metasploit MongoDB Login — Valid Credentials\n")
                    f.write(f"# Generated by ReconX\n")
                    f.write(f"# Total: {len(all_creds)} credential(s)\n\n")
                    for cred in all_creds:
                        f.write(
                            f"{cred.ip}:{cred.port} → "
                            f"{cred.username}:{cred.password}\n"
                        )
            except Exception:
                pass

        # Full summary JSON
        summary_file = os.path.join(output_dir, "mongodb_login_summary.json")
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

    def get_all_credentials(self) -> List[MongoDBCredential]:
        """Get all discovered valid credentials across all hosts."""
        creds = []
        for host_result in self.results.values():
            creds.extend(host_result.credentials)
        return creds
