"""
Metasploit FTP Login Scanner for ReconX.
Uses msfconsole auxiliary/scanner/ftp/anonymous + auxiliary/scanner/ftp/ftp_login
to check anonymous FTP access and brute-force FTP credentials on hosts where
nmap discovered FTP ports.

For each IP that has FTP port(s) open (21, 2121, etc.):
  1. Run auxiliary/scanner/ftp/anonymous with:
     - RHOSTS  = target IP
     - FTPUSER = anonymous
     - FTPPASS = anonymous
  2. Run auxiliary/scanner/ftp/ftp_login with:
     - RHOSTS         = target IP
     - USER_FILE      = wordlists/ftp-user-enum.txt
     - PASS_FILE      = wordlists/enum-pass.txt
     - STOP_ON_SUCCESS = true
  3. Parse output for anonymous access + successful logins
  4. On rate limit / account lockout / delay / timeout → skip to next IP

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


# ─── FTP Ports ────────────────────────────────────────────────────────────────

FTP_PORTS = {21, 2121, 990}


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class FTPCredential:
    """A successfully brute-forced or discovered FTP credential."""
    ip: str = ""
    port: int = 21
    username: str = ""
    password: str = ""
    anonymous: bool = False

    def to_dict(self) -> dict:
        d = {
            "ip": self.ip,
            "port": self.port,
            "username": self.username,
            "password": self.password,
        }
        if self.anonymous:
            d["anonymous"] = True
        return d


@dataclass
class FTPHostResult:
    """Brute-force result for a single FTP host."""
    ip: str = ""
    port: int = 21
    anonymous_access: bool = False
    credentials: List[FTPCredential] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    scan_time: float = 0.0
    raw_output: str = ""

    def to_dict(self) -> dict:
        d = {
            "ip": self.ip,
            "port": self.port,
            "anonymous_access": self.anonymous_access,
            "credentials": [c.to_dict() for c in self.credentials],
            "scan_time": round(self.scan_time, 2),
        }
        if self.skipped:
            d["skipped"] = True
            d["skip_reason"] = self.skip_reason
        return d


@dataclass
class FTPLoginStats:
    """Aggregated FTP login statistics."""
    total_ftp_hosts: int = 0
    hosts_tested: int = 0
    hosts_skipped: int = 0
    anonymous_hosts: int = 0
    credentials_found: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_ftp_hosts": self.total_ftp_hosts,
            "hosts_tested": self.hosts_tested,
            "hosts_skipped": self.hosts_skipped,
            "anonymous_hosts": self.anonymous_hosts,
            "credentials_found": self.credentials_found,
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
    r"kex_exchange_identification",
    r"Connection closed by.*remote host",
    r"read: Connection reset",
    r"banner exchange",
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

# ─── Success Patterns ────────────────────────────────────────────────────────

# ftp_login / anonymous:
# [+] 192.168.1.1:21 - 192.168.1.1:21 - Login Successful: admin:password
# [+] 192.168.1.1:21 - Anonymous LOGIN Successful
SUCCESS_PATTERN = re.compile(
    r'\[\+\]\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s*-\s*'
    r'(?:\d+\.\d+\.\d+\.\d+:\d+\s*-\s*)?'
    r'(?:Login Successful|SUCCESS)[:\s]*'
    r'[\'"]?(\S+?):(\S+?)[\'"]?'
    r'(?:\s|$)',
    re.IGNORECASE,
)

# Alternative: [+] ip:port - Login Successful: user:pass
SUCCESS_PATTERN_ALT = re.compile(
    r'\[\+\]\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s*-\s*'
    r'.*?(?:Login Successful|Logged in)[:\s]*[\'"]?(\S+?):(\S+?)[\'"]?'
    r'(?:\s|$)',
    re.IGNORECASE,
)

# Fallback: any [+] line with user:pass in quotes
SUCCESS_PATTERN_QUOTED = re.compile(
    r"\[\+\].*?'([^':]+):([^']+)'",
    re.IGNORECASE,
)

# Anonymous access pattern
# [+] 192.168.1.1:21 - Anonymous LOGIN Successful
ANONYMOUS_PATTERN = re.compile(
    r'\[\+\]\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s*-\s*'
    r'.*?[Aa]nonymous.*?(?:LOGIN|access|allowed|Successful)',
    re.IGNORECASE,
)


# ─── Main Scanner ─────────────────────────────────────────────────────────────

class FTPLoginScanner:
    """
    Metasploit FTP anonymous + login brute-force scanner.

    Uses msfconsole to:
      1. Check anonymous FTP access (ftp/anonymous)
      2. Brute-force FTP credentials (ftp/ftp_login)

    Workflow per IP:
      1. Run ftp/anonymous
      2. Run ftp/ftp_login with USER_FILE + PASS_FILE
      3. On lockout / rate limit / delay → skip to next IP
    """

    DEFAULT_USER_FILE = os.path.join("wordlists", "ftp-user-enum.txt")
    DEFAULT_PASS_FILE = os.path.join("wordlists", "enum-pass.txt")

    def __init__(self, config: ScannerConfig, user_file: str = "", pass_file: str = ""):
        self.config = config
        self.msf_path = self._find_msfconsole()
        self.available = self.msf_path is not None
        self.user_file = user_file or self.DEFAULT_USER_FILE
        self.pass_file = pass_file or self.DEFAULT_PASS_FILE
        self.results: Dict[str, FTPHostResult] = {}  # "ip:port" → result
        self.stats = FTPLoginStats()

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
        Locate a file (user file or pass file). Search order:
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

    def _get_ftp_hosts(self, nmap_results: Dict) -> List[tuple]:
        """
        Extract hosts with FTP ports open from nmap results.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.

        Returns:
            List of (ip, port) tuples.
        """
        ftp_targets = []
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
                    port_num in FTP_PORTS
                    or "ftp" in service.lower()
                ):
                    ftp_targets.append((ip, port_num))

        # Sort by IP then port for consistent ordering
        ftp_targets.sort(key=lambda t: (t[0], t[1]))
        return ftp_targets

    def scan(
        self,
        nmap_results: Dict,
        output_dir: str = "",
    ) -> Dict[str, FTPHostResult]:
        """
        Run FTP anonymous check + login brute-force against hosts with FTP ports open.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.
            output_dir: Directory to save output files.

        Returns:
            Dict mapping "ip:port" → FTPHostResult.
        """
        if not self.available:
            return {}

        if not nmap_results:
            return {}

        # Find FTP hosts from nmap results
        ftp_targets = self._get_ftp_hosts(nmap_results)
        if not ftp_targets:
            return {}

        # Locate user file and password file
        user_file_path = self._find_file(self.user_file, output_dir)
        if not user_file_path:
            print(
                f"\033[91m[!]\033[0m ftp-login: user file "
                f"\033[96m{self.user_file}\033[0m not found – skipping"
            )
            return {}

        pass_file_path = self._find_file(self.pass_file, output_dir)
        if not pass_file_path:
            print(
                f"\033[91m[!]\033[0m ftp-login: password file "
                f"\033[96m{self.pass_file}\033[0m not found – skipping"
            )
            return {}

        scan_start = time.time()
        self.stats.total_ftp_hosts = len(ftp_targets)

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        unique_ips = len({t[0] for t in ftp_targets})
        print(
            f"\033[36m[>]\033[0m ftp-login: FTP anonymous + login brute-force on "
            f"\033[96m{len(ftp_targets)}\033[0m target(s) "
            f"(\033[96m{unique_ips}\033[0m unique IP(s)) "
            f"with \033[96m{os.path.basename(user_file_path)}\033[0m + "
            f"\033[96m{os.path.basename(pass_file_path)}\033[0m ..."
        )

        for idx, (ip, ftp_port) in enumerate(ftp_targets, 1):
            result_key = f"{ip}:{ftp_port}"

            print(
                f"\033[36m[>]\033[0m ftp-login: "
                f"[\033[96m{idx}/{len(ftp_targets)}\033[0m] "
                f"\033[96m{ip}:{ftp_port}\033[0m ..."
            )

            host_result = self._brute_host(
                ip, ftp_port, user_file_path, pass_file_path, output_dir,
            )
            self.results[result_key] = host_result

            # Print per-host status
            if host_result.skipped:
                print(
                    f"\033[93m[!]\033[0m ftp-login: \033[96m{ip}:{ftp_port}\033[0m → "
                    f"\033[93mskipped ({host_result.skip_reason})\033[0m "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )
            else:
                parts = []
                if host_result.anonymous_access:
                    parts.append(
                        f"\033[1;91mANONYMOUS ACCESS!\033[0m"
                    )
                if host_result.credentials:
                    cred_str = ", ".join(
                        f"\033[1;92m{c.username}:{c.password}\033[0m"
                        for c in host_result.credentials
                        if not c.anonymous
                    )
                    non_anon = [c for c in host_result.credentials if not c.anonymous]
                    if non_anon:
                        parts.append(
                            f"\033[1;92m{len(non_anon)} credential(s)\033[0m → {cred_str}"
                        )
                if parts:
                    print(
                        f"\033[92m[+]\033[0m ftp-login: \033[96m{ip}:{ftp_port}\033[0m → "
                        f"{' | '.join(parts)} "
                        f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                    )
                else:
                    print(
                        f"\033[37m[-]\033[0m ftp-login: \033[96m{ip}:{ftp_port}\033[0m → "
                        f"\033[37mno valid credentials\033[0m "
                        f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                    )

        scan_elapsed = time.time() - scan_start
        self._compute_stats(scan_elapsed)

        # Save combined results
        if output_dir:
            self._save_results(output_dir)

        return self.results

    def _brute_host(
        self,
        ip: str,
        port: int,
        user_file: str,
        pass_file: str,
        output_dir: str,
    ) -> FTPHostResult:
        """
        Run FTP anonymous check + login brute-force against a single host.

        Steps:
          1. Run auxiliary/scanner/ftp/anonymous
          2. Run auxiliary/scanner/ftp/ftp_login with USER_FILE + PASS_FILE
          3. On lockout / rate limit / delay → skip
        """
        result = FTPHostResult(ip=ip, port=port)
        host_start = time.time()
        raw_parts = []

        try:
            # ── Step 1: ftp/anonymous ────────────────────────────────────
            print(
                f"    \033[36m[>]\033[0m \033[96m{ip}:{port}\033[0m "
                f"running ftp/anonymous ..."
            )
            anon_output = self._run_ftp_anonymous(ip, port)
            raw_parts.append(f"=== ftp/anonymous ===\n{anon_output}")

            # Check for anonymous access
            if self._detect_anonymous(ip, port, anon_output):
                result.anonymous_access = True
                result.credentials.append(FTPCredential(
                    ip=ip, port=port,
                    username="anonymous", password="anonymous",
                    anonymous=True,
                ))
                print(
                    f"    \033[1;91m[!]\033[0m \033[1;91mANONYMOUS FTP ACCESS\033[0m: "
                    f"\033[96m{ip}:{port}\033[0m"
                )

            # Check for connection issues on anonymous scan
            if self._detect_rate_limit(anon_output):
                result.skipped = True
                result.skip_reason = "rate_limit"
                print(
                    f"    \033[93m[!]\033[0m Rate limit / connection issue on "
                    f"\033[96m{ip}:{port}\033[0m"
                )
                result.raw_output = "\n\n".join(raw_parts)
                result.scan_time = time.time() - host_start
                return result

            # ── Step 2: ftp/ftp_login ────────────────────────────────────
            print(
                f"    \033[36m[>]\033[0m \033[96m{ip}:{port}\033[0m "
                f"running ftp_login ..."
            )
            login_output = self._run_ftp_login(ip, port, user_file, pass_file)
            raw_parts.append(f"=== ftp/ftp_login ===\n{login_output}")

            # Parse successful logins
            creds = self._parse_success(ip, port, login_output)
            result.credentials.extend(creds)

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

            # Check for rate limit / connection issues
            if self._detect_rate_limit(login_output):
                result.skipped = True
                result.skip_reason = "rate_limit"
                print(
                    f"    \033[93m[!]\033[0m Rate limit / connection issue on "
                    f"\033[96m{ip}:{port}\033[0m"
                )

            # Check for delay / throttling
            if self._detect_delay(login_output):
                result.skipped = True
                result.skip_reason = "delay_throttle"
                print(
                    f"    \033[93m[!]\033[0m FTP delay/throttling detected on "
                    f"\033[96m{ip}:{port}\033[0m"
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
            out_file = routed_path(output_dir, f"ftp_login_{safe_ip}_{port}.txt")
            try:
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(f"# Metasploit FTP login: {ip}:{port}\n")
                    f.write(f"# User file: {user_file}\n")
                    f.write(f"# Pass file: {pass_file}\n")
                    f.write(f"# Scan time: {result.scan_time:.1f}s\n\n")
                    f.write(result.raw_output)
            except Exception:
                pass

        return result

    # ─── MSF Module Runners ───────────────────────────────────────────────────

    def _run_msfconsole(self, rc_content: str, timeout: int = 300) -> str:
        """Run msfconsole with a .rc resource script and return output."""
        tmpdir = tempfile.mkdtemp(prefix="reconx_ftp_login_")
        rc_file = os.path.join(tmpdir, "ftp_login.rc")

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

    def _run_ftp_anonymous(self, ip: str, port: int) -> str:
        """
        Run auxiliary/scanner/ftp/anonymous.

        Resource script:
            use auxiliary/scanner/ftp/anonymous
            set RHOSTS <ip>
            set RPORT <port>
            set FTPUSER anonymous
            set FTPPASS anonymous
            run
            exit
        """
        rc = (
            f"use auxiliary/scanner/ftp/anonymous\n"
            f"set RHOSTS {ip}\n"
            f"set RPORT {port}\n"
            f"set FTPUSER anonymous\n"
            f"set FTPPASS anonymous\n"
            f"set THREADS 1\n"
            f"run\n"
            f"exit\n"
        )
        return self._run_msfconsole(rc, timeout=120)

    def _run_ftp_login(self, ip: str, port: int, user_file: str, pass_file: str) -> str:
        """
        Run auxiliary/scanner/ftp/ftp_login with user + pass files.

        Resource script:
            use auxiliary/scanner/ftp/ftp_login
            set RHOSTS <ip>
            set RPORT <port>
            set USER_FILE <user_file>
            set PASS_FILE <pass_file>
            set STOP_ON_SUCCESS true
            set VERBOSE false
            run
            exit
        """
        rc = (
            f"use auxiliary/scanner/ftp/ftp_login\n"
            f"set RHOSTS {ip}\n"
            f"set RPORT {port}\n"
            f"set USER_FILE {user_file}\n"
            f"set PASS_FILE {pass_file}\n"
            f"set STOP_ON_SUCCESS true\n"
            f"set VERBOSE false\n"
            f"set ConnectTimeout 10\n"
            f"set THREADS 1\n"
            f"run\n"
            f"exit\n"
        )
        return self._run_msfconsole(rc, timeout=300)

    # ─── Output Parsing ──────────────────────────────────────────────────────

    def _detect_anonymous(self, ip: str, port: int, output: str) -> bool:
        """Detect if anonymous FTP access is allowed."""
        for line in output.splitlines():
            if "[+]" not in line:
                continue
            if ANONYMOUS_PATTERN.search(line):
                return True
            # Also check for generic "anonymous" + "Successful"
            line_lower = line.lower()
            if "anonymous" in line_lower and ("success" in line_lower or "allowed" in line_lower):
                return True
        return False

    def _parse_success(self, ip: str, port: int, output: str) -> List[FTPCredential]:
        """Parse msfconsole output for successful FTP login credentials."""
        creds = []
        seen = set()

        for line in output.splitlines():
            if "[+]" not in line:
                continue

            line_lower = line.lower()
            if ("success" not in line_lower
                    and "logged in" not in line_lower
                    and "login" not in line_lower):
                continue

            # Try standard pattern
            match = SUCCESS_PATTERN.search(line)
            if match:
                username = match.group(3)
                password = match.group(4)
                key = f"{match.group(1)}:{match.group(2)}:{username}:{password}"
                if key not in seen:
                    seen.add(key)
                    creds.append(FTPCredential(
                        ip=match.group(1),
                        port=int(match.group(2)),
                        username=username,
                        password=password,
                    ))
                continue

            # Try alt pattern
            match = SUCCESS_PATTERN_ALT.search(line)
            if match:
                username = match.group(3)
                password = match.group(4)
                key = f"{match.group(1)}:{match.group(2)}:{username}:{password}"
                if key not in seen:
                    seen.add(key)
                    creds.append(FTPCredential(
                        ip=match.group(1),
                        port=int(match.group(2)),
                        username=username,
                        password=password,
                    ))
                continue

            # Fallback: quoted user:pass
            match = SUCCESS_PATTERN_QUOTED.search(line)
            if match:
                username = match.group(1)
                password = match.group(2)
                key = f"{ip}:{port}:{username}:{password}"
                if key not in seen:
                    seen.add(key)
                    creds.append(FTPCredential(
                        ip=ip,
                        port=port,
                        username=username,
                        password=password,
                    ))

        return creds

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

        # If there were attempts and most failed with connection errors
        if total_attempts > 3 and error_count > total_attempts * 0.5:
            return True
        return False

    def _detect_delay(self, output: str) -> bool:
        """Check if the output indicates FTP delay or throttling."""
        output_lower = output.lower()
        for pattern in DELAY_PATTERNS:
            if re.search(pattern, output_lower):
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
        self.stats.anonymous_hosts = sum(
            1 for r in self.results.values() if r.anonymous_access
        )
        self.stats.credentials_found = sum(
            len(r.credentials) for r in self.results.values()
        )

    def _save_results(self, output_dir: str):
        """Save combined FTP login results to output directory."""
        # Credentials summary
        all_creds = []
        for key in sorted(self.results.keys()):
            host_result = self.results[key]
            for cred in host_result.credentials:
                all_creds.append(cred)

        if all_creds:
            cred_file = routed_path(output_dir, "ftp_credentials.txt")
            try:
                with open(cred_file, "w", encoding="utf-8") as f:
                    f.write("# Metasploit FTP Login — Valid Credentials\n")
                    f.write(f"# Generated by ReconX\n")
                    f.write(f"# Total: {len(all_creds)} credential(s)\n\n")
                    for cred in all_creds:
                        anon_tag = " [ANONYMOUS]" if cred.anonymous else ""
                        f.write(
                            f"{cred.ip}:{cred.port} → "
                            f"{cred.username}:{cred.password}{anon_tag}\n"
                        )
            except Exception:
                pass

        # Full summary JSON
        summary_file = routed_path(output_dir, "ftp_login_summary.json")
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

    def get_all_credentials(self) -> List[FTPCredential]:
        """Get all discovered valid credentials across all hosts."""
        creds = []
        for host_result in self.results.values():
            creds.extend(host_result.credentials)
        return creds
