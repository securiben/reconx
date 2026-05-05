"""
Metasploit SMB Brute-Force Scanner for ReconX.
Uses msfconsole auxiliary/scanner/smb/smb_login to brute-force
SMB credentials on hosts where enum4linux discovered usernames.

For each IP that has discovered users from enum4linux:
  1. Iterate through each username
  2. Run auxiliary/scanner/smb/smb_login with:
     - RHOSTS = target IP
     - SMBUser = username
     - PASS_FILE = wordlists/enum-pass.txt
     - STOP_ON_SUCCESS = true
  3. Parse output for successful logins
  4. On rate limit / account lockout / timeout → skip to next IP

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
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field

from ..config import ScannerConfig
from ..utils import routed_path


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class MSFCredential:
    """A successfully brute-forced credential."""
    ip: str = ""
    username: str = ""
    password: str = ""
    domain: str = ""
    port: int = 445

    def to_dict(self) -> dict:
        d = {
            "ip": self.ip,
            "username": self.username,
            "password": self.password,
            "port": self.port,
        }
        if self.domain:
            d["domain"] = self.domain
        return d


@dataclass
class MSFHostResult:
    """Brute-force result for a single host."""
    ip: str = ""
    users_tested: List[str] = field(default_factory=list)
    credentials: List[MSFCredential] = field(default_factory=list)
    skipped: bool = False         # True if skipped due to lockout/rate limit
    skip_reason: str = ""         # "lockout", "rate_limit", "timeout", "error"
    scan_time: float = 0.0
    raw_output: str = ""

    def to_dict(self) -> dict:
        d = {
            "ip": self.ip,
            "users_tested": self.users_tested,
            "credentials": [c.to_dict() for c in self.credentials],
            "scan_time": round(self.scan_time, 2),
        }
        if self.skipped:
            d["skipped"] = True
            d["skip_reason"] = self.skip_reason
        return d


@dataclass
class MSFBruteStats:
    """Aggregated MSF brute-force statistics."""
    total_ips: int = 0
    ips_tested: int = 0
    ips_skipped: int = 0
    total_users_tested: int = 0
    credentials_found: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_ips": self.total_ips,
            "ips_tested": self.ips_tested,
            "ips_skipped": self.ips_skipped,
            "total_users_tested": self.total_users_tested,
            "credentials_found": self.credentials_found,
            "scan_time": round(self.scan_time, 2),
        }


# ─── Lockout / Rate Limit Detection Patterns ─────────────────────────────────

LOCKOUT_PATTERNS = [
    r"STATUS_ACCOUNT_LOCKED_OUT",
    r"account.*lock",
    r"Account has been locked",
    r"too many login attempts",
    r"login.*disabled",
    r"temporarily.*locked",
    r"account.*disabled",
]

RATE_LIMIT_PATTERNS = [
    r"STATUS_LOGON_FAILURE.*rate",
    r"connection.*refused",
    r"connection.*reset",
    r"Connection timed out",
    r"Unable to Connect",
    r"Rex::ConnectionRefused",
    r"Rex::ConnectionTimeout",
    r"Rex::HostUnreachable",
]

SUCCESS_PATTERN = re.compile(
    r'\[\+\].*?(\d+\.\d+\.\d+\.\d+):(\d+)\s*-\s*'
    r'(?:.*\\)?(\S+):(\S+)',
    re.IGNORECASE,
)

# Alternative success pattern for newer Metasploit output
SUCCESS_PATTERN_ALT = re.compile(
    r'\[\+\].*?Success.*?["\'](\S+?)["\'].*?["\'](\S+?)["\']',
    re.IGNORECASE,
)


# ─── Main Scanner ─────────────────────────────────────────────────────────────

class MSFSMBBruteScanner:
    """
    Metasploit SMB brute-force scanner.

    Uses msfconsole auxiliary/scanner/smb/smb_login to attempt
    password brute-force against hosts with discovered usernames.

    Workflow per IP:
      1. Get usernames from enum4linux results
      2. For each username, run smb_login with PASS_FILE
      3. Parse output for successful logins
      4. On lockout/rate limit → skip remaining users and move to next IP
    """

    DEFAULT_PASS_FILE = os.path.join("wordlists", "enum-pass.txt")

    def __init__(self, config: ScannerConfig, pass_file: str = ""):
        self.config = config
        self.msf_path = self._find_msfconsole()
        self.available = self.msf_path is not None
        self.pass_file = pass_file or self.DEFAULT_PASS_FILE
        self.results: Dict[str, MSFHostResult] = {}  # ip → result
        self.stats = MSFBruteStats()

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

    def _find_pass_file(self, output_dir: str = "") -> Optional[str]:
        """
        Locate the password file. Search order:
          1. Exact path if absolute
          2. Current working directory
          3. Output directory
          4. Package directory (reconx/)
          5. Project root
        """
        if os.path.isabs(self.pass_file) and os.path.isfile(self.pass_file):
            return self.pass_file

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
            candidate = os.path.join(d, self.pass_file)
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)

        return None

    def scan(
        self,
        enum4linux_users: Dict[str, List[str]],
        output_dir: str = "",
    ) -> Dict[str, MSFHostResult]:
        """
        Run SMB brute-force against hosts with discovered usernames.

        Args:
            enum4linux_users: Dict mapping IP → list of usernames
                              (from Enum4linuxScanner.get_all_users())
            output_dir: Directory to save output files.

        Returns:
            Dict mapping IP → MSFHostResult.
        """
        if not self.available:
            return {}

        if not enum4linux_users:
            return {}

        # Locate password file
        pass_file_path = self._find_pass_file(output_dir)
        if not pass_file_path:
            print(
                f"\033[91m[!]\033[0m msf-brute: password file "
                f"\033[96m{self.pass_file}\033[0m not found – skipping"
            )
            return {}

        scan_start = time.time()
        self.stats.total_ips = len(enum4linux_users)

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Count total users
        total_users = sum(len(users) for users in enum4linux_users.values())

        print(
            f"\033[36m[>]\033[0m msf-brute: SMB login brute-force on "
            f"\033[96m{len(enum4linux_users)}\033[0m IPs, "
            f"\033[96m{total_users}\033[0m users ..."
        )

        sorted_ips = sorted(enum4linux_users.keys())
        for idx, ip in enumerate(sorted_ips, 1):
            users = enum4linux_users[ip]
            if not users:
                continue

            print(
                f"\033[36m[>]\033[0m msf-brute: "
                f"[\033[96m{idx}/{len(sorted_ips)}\033[0m] "
                f"\033[96m{ip}\033[0m → "
                f"{len(users)} user(s): "
                f"\033[93m{', '.join(users[:5])}"
                f"{'...' if len(users) > 5 else ''}\033[0m"
            )

            host_result = self._brute_host(
                ip, users, pass_file_path, output_dir,
            )
            self.results[ip] = host_result

            # Print per-host status
            if host_result.skipped:
                print(
                    f"\033[93m[!]\033[0m msf-brute: \033[96m{ip}\033[0m → "
                    f"\033[93mskipped ({host_result.skip_reason})\033[0m "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )
            elif host_result.credentials:
                cred_str = ", ".join(
                    f"\033[1;92m{c.username}:{c.password}\033[0m"
                    for c in host_result.credentials
                )
                print(
                    f"\033[1;92m[+]\033[0m msf-brute: \033[96m{ip}\033[0m → "
                    f"\033[1;92m{len(host_result.credentials)} credential(s) found!\033[0m "
                    f"→ {cred_str} "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )
            else:
                print(
                    f"\033[37m[-]\033[0m msf-brute: \033[96m{ip}\033[0m → "
                    f"\033[37mno valid credentials\033[0m "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )

        scan_elapsed = time.time() - scan_start
        self._compute_stats(scan_elapsed)

        # Save combined results only if there are findings
        if output_dir and self.stats.credentials_found:
            self._save_results(output_dir)

        return self.results

    def _brute_host(
        self,
        ip: str,
        users: List[str],
        pass_file: str,
        output_dir: str,
    ) -> MSFHostResult:
        """
        Run SMB brute-force against a single host for all given users.

        For each user, generates an MSF resource script and runs msfconsole -r.
        Uses STOP_ON_SUCCESS so each user stops after first valid password.
        On lockout/rate limit detection, stops testing this host entirely.
        """
        result = MSFHostResult(ip=ip)
        host_start = time.time()
        all_output = []

        for user_idx, username in enumerate(users, 1):
            if result.skipped:
                break

            result.users_tested.append(username)

            print(
                f"    \033[36m[>]\033[0m \033[96m{ip}\033[0m user "
                f"[\033[96m{user_idx}/{len(users)}\033[0m] "
                f"\033[93m{username}\033[0m ..."
            )

            try:
                output = self._run_smb_login(ip, username, pass_file)
                all_output.append(f"=== {username} ===\n{output}\n")

                # Check for successful login
                creds = self._parse_success(ip, output)
                for cred in creds:
                    cred.username = username  # ensure correct username
                    result.credentials.append(cred)
                    print(
                        f"    \033[1;92m[+]\033[0m \033[1;92mSUCCESS\033[0m: "
                        f"\033[96m{ip}\033[0m → "
                        f"\033[1;92m{username}:{cred.password}\033[0m"
                    )

                # Check for lockout
                if self._detect_lockout(output):
                    result.skipped = True
                    result.skip_reason = "account_lockout"
                    print(
                        f"    \033[91m[!]\033[0m Account lockout detected on "
                        f"\033[96m{ip}\033[0m → skipping remaining users"
                    )
                    break

                # Check for rate limit / connection issues
                if self._detect_rate_limit(output):
                    result.skipped = True
                    result.skip_reason = "rate_limit"
                    print(
                        f"    \033[93m[!]\033[0m Rate limit / connection issue on "
                        f"\033[96m{ip}\033[0m → skipping remaining users"
                    )
                    break

            except subprocess.TimeoutExpired:
                result.skipped = True
                result.skip_reason = "timeout"
                print(
                    f"    \033[93m[!]\033[0m Timeout on \033[96m{ip}\033[0m "
                    f"user \033[93m{username}\033[0m → skipping to next IP"
                )
                break
            except KeyboardInterrupt:
                raise  # Let the engine's _safe_scan handle this
            except Exception as e:
                all_output.append(f"=== {username} === ERROR: {e}\n")
                continue

        result.raw_output = "\n".join(all_output)
        result.scan_time = time.time() - host_start

        # Save per-host raw output only if there are findings
        if output_dir and result.credentials and result.raw_output.strip():
            safe_ip = ip.replace(".", "_").replace(":", "_")
            out_file = routed_path(output_dir, f"msf_smb_{safe_ip}.txt")
            try:
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(f"# Metasploit SMB brute-force: {ip}\n")
                    f.write(f"# Users tested: {', '.join(result.users_tested)}\n")
                    f.write(f"# Password file: {pass_file}\n")
                    f.write(f"# Scan time: {result.scan_time:.1f}s\n\n")
                    f.write(result.raw_output)
            except Exception:
                pass

        return result

    def _run_smb_login(self, ip: str, username: str, pass_file: str) -> str:
        """
        Run a single msfconsole smb_login attempt via resource script.

        Creates a .rc resource script:
            use auxiliary/scanner/smb/smb_login
            set RHOSTS <ip>
            set SMBUser <username>
            set PASS_FILE <pass_file>
            set STOP_ON_SUCCESS true
            set VERBOSE false
            run
            exit

        Returns the raw stdout+stderr output.
        """
        tmpdir = tempfile.mkdtemp(prefix="reconx_msf_")
        rc_file = os.path.join(tmpdir, "smb_brute.rc")

        try:
            # Write resource script
            rc_content = (
                f"use auxiliary/scanner/smb/smb_login\n"
                f"set RHOSTS {ip}\n"
                f"set SMBUser {username}\n"
                f"set PASS_FILE {pass_file}\n"
                # f"set STOP_ON_SUCCESS true\n"
                f"set VERBOSE false\n"
                f"set ConnectTimeout 10\n"
                f"set THREADS 1\n"
                f"run\n"
                f"exit\n"
            )
            with open(rc_file, "w", encoding="utf-8") as f:
                f.write(rc_content)

            # Run msfconsole with resource script
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
                # Timeout: 120s per user should be generous
                stdout, stderr = proc.communicate(timeout=120)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                raise

            output = stdout.decode("utf-8", errors="replace")
            err_output = stderr.decode("utf-8", errors="replace")
            return output + "\n" + err_output

        finally:
            # Cleanup
            try:
                if os.path.isfile(rc_file):
                    os.remove(rc_file)
                os.rmdir(tmpdir)
            except Exception:
                pass

    def _parse_success(self, ip: str, output: str) -> List[MSFCredential]:
        """Parse msfconsole output for successful login credentials."""
        creds = []

        for line in output.splitlines():
            # Pattern: [+] 10.10.0.5:445 - 10.10.0.5:445 - Success: '.\username:password'
            # Or: [+] 10.10.0.5:445 - [+] ... username:password
            if "[+]" not in line:
                continue

            if "success" in line.lower():
                # Try standard pattern
                match = SUCCESS_PATTERN.search(line)
                if match:
                    cred = MSFCredential(
                        ip=match.group(1),
                        port=int(match.group(2)),
                        username=match.group(3),
                        password=match.group(4),
                    )
                    creds.append(cred)
                    continue

                # Try to extract from quoted credentials
                # Pattern: Success: '.\user:pass' or Success: 'DOMAIN\user:pass'
                cred_match = re.search(
                    r"Success:\s*'(?:([^\\]*?)\\)?([^:]+):([^']+)'",
                    line,
                )
                if cred_match:
                    domain = cred_match.group(1) or ""
                    cred = MSFCredential(
                        ip=ip,
                        username=cred_match.group(2),
                        password=cred_match.group(3),
                        domain=domain,
                    )
                    creds.append(cred)
                    continue

                # Fallback: any [+] line with user:pass pattern
                match = SUCCESS_PATTERN_ALT.search(line)
                if match:
                    cred = MSFCredential(
                        ip=ip,
                        username=match.group(1),
                        password=match.group(2),
                    )
                    creds.append(cred)

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
        We count connection errors — if > 50% of attempts fail with
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

    def _compute_stats(self, scan_time: float):
        """Compute aggregated statistics."""
        self.stats.scan_time = scan_time
        self.stats.ips_tested = sum(
            1 for r in self.results.values() if not r.skipped
        )
        self.stats.ips_skipped = sum(
            1 for r in self.results.values() if r.skipped
        )
        self.stats.total_users_tested = sum(
            len(r.users_tested) for r in self.results.values()
        )
        self.stats.credentials_found = sum(
            len(r.credentials) for r in self.results.values()
        )

    def _save_results(self, output_dir: str):
        """Save combined brute-force results to output directory."""
        # Credentials summary
        all_creds = []
        for ip, host_result in sorted(self.results.items()):
            for cred in host_result.credentials:
                all_creds.append(cred)

        if all_creds:
            cred_file = routed_path(output_dir, "msf_smb_credentials.txt")
            try:
                with open(cred_file, "w", encoding="utf-8") as f:
                    f.write("# Metasploit SMB Brute-Force — Valid Credentials\n")
                    f.write(f"# Generated by ReconX\n")
                    f.write(f"# Total: {len(all_creds)} credential(s)\n\n")
                    for cred in all_creds:
                        domain_str = f"{cred.domain}\\" if cred.domain else ""
                        f.write(
                            f"{cred.ip}:{cred.port} → "
                            f"{domain_str}{cred.username}:{cred.password}\n"
                        )
            except Exception:
                pass

        # Full summary JSON
        import json
        summary_file = routed_path(output_dir, "msf_smb_summary.json")
        try:
            summary = {
                "stats": self.stats.to_dict(),
                "hosts": {
                    ip: r.to_dict()
                    for ip, r in sorted(self.results.items())
                },
            }
            with open(summary_file, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def get_all_credentials(self) -> List[MSFCredential]:
        """Get all discovered valid credentials across all hosts."""
        creds = []
        for ip, host_result in self.results.items():
            creds.extend(host_result.credentials)
        return creds
