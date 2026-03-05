"""
Metasploit VNC Brute-Force Scanner for ReconX.
Uses msfconsole auxiliary/scanner/vnc/vnc_login to brute-force
VNC credentials on hosts where nmap discovered VNC ports.

For each IP that has VNC port(s) open (5900-5910):
  1. First check anonymous/no-auth VNC access (vnc_none_auth)
  2. Run auxiliary/scanner/vnc/vnc_login with:
     - RHOSTS = target IP
     - RPORT  = VNC port
     - PASS_FILE = kamus-pass.txt
     - STOP_ON_SUCCESS = true
     - ANONYMOUS_LOGIN = true
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
import json
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field

from ..config import ScannerConfig


# ─── VNC Ports ────────────────────────────────────────────────────────────────

VNC_PORTS = set(range(5900, 5911))  # 5900-5910 are common VNC display ports


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class VNCCredential:
    """A successfully brute-forced VNC credential."""
    ip: str = ""
    password: str = ""
    port: int = 5900
    anonymous: bool = False   # True if no-auth / anonymous access

    def to_dict(self) -> dict:
        d = {
            "ip": self.ip,
            "password": self.password,
            "port": self.port,
        }
        if self.anonymous:
            d["anonymous"] = True
        return d


@dataclass
class VNCHostResult:
    """Brute-force result for a single VNC host."""
    ip: str = ""
    port: int = 5900
    no_auth: bool = False         # True if VNC has no authentication
    credentials: List[VNCCredential] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    scan_time: float = 0.0
    raw_output: str = ""

    def to_dict(self) -> dict:
        d = {
            "ip": self.ip,
            "port": self.port,
            "no_auth": self.no_auth,
            "credentials": [c.to_dict() for c in self.credentials],
            "scan_time": round(self.scan_time, 2),
        }
        if self.skipped:
            d["skipped"] = True
            d["skip_reason"] = self.skip_reason
        return d


@dataclass
class VNCBruteStats:
    """Aggregated VNC brute-force statistics."""
    total_vnc_hosts: int = 0
    hosts_tested: int = 0
    hosts_skipped: int = 0
    hosts_no_auth: int = 0
    credentials_found: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_vnc_hosts": self.total_vnc_hosts,
            "hosts_tested": self.hosts_tested,
            "hosts_skipped": self.hosts_skipped,
            "hosts_no_auth": self.hosts_no_auth,
            "credentials_found": self.credentials_found,
            "scan_time": round(self.scan_time, 2),
        }


# ─── Lockout / Rate Limit Detection Patterns ─────────────────────────────────

LOCKOUT_PATTERNS = [
    r"too many security failures",
    r"too many login attempts",
    r"login.*disabled",
    r"temporarily.*locked",
    r"account.*disabled",
    r"authentication.*disabled",
]

RATE_LIMIT_PATTERNS = [
    r"connection.*refused",
    r"connection.*reset",
    r"Connection timed out",
    r"Unable to Connect",
    r"Rex::ConnectionRefused",
    r"Rex::ConnectionTimeout",
    r"Rex::HostUnreachable",
    r"No authentication types available",
]

# Success pattern for VNC login
# Example: [+] 172.18.2.213:5901 - 172.18.2.213:5901 - Login Successful: :P@ssw0rd!123
SUCCESS_PATTERN = re.compile(
    r'\[\+\].*?(\d+\.\d+\.\d+\.\d+):(\d+).*?'
    r'(?:Login Successful|Success).*?:(\S+)',
    re.IGNORECASE,
)

# Alternative: Success with quoted password
SUCCESS_PATTERN_ALT = re.compile(
    r'\[\+\].*?(?:Login Successful|Success).*?["\']?:?([^\s\'"]+)["\']?',
    re.IGNORECASE,
)

# No-auth detection pattern
# Example: [+] 172.18.2.213:5901 - 172.18.2.213:5901 - VNC server does not require authentication
NO_AUTH_PATTERN = re.compile(
    r'\[\+\].*?(\d+\.\d+\.\d+\.\d+):(\d+).*?'
    r'(?:does not require authentication|No authentication required|'
    r'none auth|no auth)',
    re.IGNORECASE,
)


# ─── Main Scanner ─────────────────────────────────────────────────────────────

class VNCBruteScanner:
    """
    Metasploit VNC brute-force scanner.

    Uses msfconsole auxiliary/scanner/vnc/vnc_login to attempt
    password brute-force against hosts with VNC ports open.

    Workflow per IP:
      1. Check for anonymous/no-auth access (vnc_none_auth)
      2. Run vnc_login with PASS_FILE + ANONYMOUS_LOGIN=true
      3. Parse output for successful logins
      4. On lockout/rate limit → skip to next IP
    """

    DEFAULT_PASS_FILE = "kamus-pass.txt"

    def __init__(self, config: ScannerConfig, pass_file: str = ""):
        self.config = config
        self.msf_path = self._find_msfconsole()
        self.available = self.msf_path is not None
        self.pass_file = pass_file or self.DEFAULT_PASS_FILE
        self.results: Dict[str, VNCHostResult] = {}  # "ip:port" → result
        self.stats = VNCBruteStats()

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

    def _get_vnc_hosts(self, nmap_results: Dict) -> List[tuple]:
        """
        Extract hosts with VNC ports open from nmap results.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.

        Returns:
            List of (ip, port) tuples – includes ALL VNC ports per host.
        """
        vnc_targets = []
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
                    port_num in VNC_PORTS
                    or "vnc" in service.lower()
                ):
                    vnc_targets.append((ip, port_num))

        # Sort by IP then port for consistent ordering
        vnc_targets.sort(key=lambda t: (t[0], t[1]))
        return vnc_targets

    def scan(
        self,
        nmap_results: Dict,
        output_dir: str = "",
    ) -> Dict[str, VNCHostResult]:
        """
        Run VNC brute-force against hosts with VNC ports open.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.
            output_dir: Directory to save output files.

        Returns:
            Dict mapping IP → VNCHostResult.
        """
        if not self.available:
            return {}

        if not nmap_results:
            return {}

        # Find VNC hosts from nmap results (all VNC ports per host)
        vnc_targets = self._get_vnc_hosts(nmap_results)
        if not vnc_targets:
            return {}

        # Locate password file
        pass_file_path = self._find_pass_file(output_dir)
        if not pass_file_path:
            print(
                f"\033[91m[!]\033[0m vnc-brute: password file "
                f"\033[96m{self.pass_file}\033[0m not found – skipping"
            )
            return {}

        scan_start = time.time()
        self.stats.total_vnc_hosts = len(vnc_targets)

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        unique_ips = len({t[0] for t in vnc_targets})
        print(
            f"\033[36m[>]\033[0m vnc-brute: VNC login brute-force on "
            f"\033[96m{len(vnc_targets)}\033[0m target(s) "
            f"(\033[96m{unique_ips}\033[0m unique IP(s)) "
            f"with \033[96m{os.path.basename(pass_file_path)}\033[0m ..."
        )

        for idx, (ip, vnc_port) in enumerate(vnc_targets, 1):
            result_key = f"{ip}:{vnc_port}"

            print(
                f"\033[36m[>]\033[0m vnc-brute: "
                f"[\033[96m{idx}/{len(vnc_targets)}\033[0m] "
                f"\033[96m{ip}:{vnc_port}\033[0m ..."
            )

            host_result = self._brute_host(
                ip, vnc_port, pass_file_path, output_dir,
            )
            self.results[result_key] = host_result

            # Print per-host status
            if host_result.no_auth:
                print(
                    f"\033[1;91m[!]\033[0m vnc-brute: \033[96m{ip}:{vnc_port}\033[0m → "
                    f"\033[1;91mNO AUTHENTICATION REQUIRED!\033[0m "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )
            elif host_result.skipped:
                print(
                    f"\033[93m[!]\033[0m vnc-brute: \033[96m{ip}:{vnc_port}\033[0m → "
                    f"\033[93mskipped ({host_result.skip_reason})\033[0m "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )
            elif host_result.credentials:
                cred_str = ", ".join(
                    f"\033[1;92m:{c.password}\033[0m"
                    for c in host_result.credentials
                )
                print(
                    f"\033[1;92m[+]\033[0m vnc-brute: \033[96m{ip}:{vnc_port}\033[0m → "
                    f"\033[1;92m{len(host_result.credentials)} credential(s) found!\033[0m "
                    f"→ {cred_str} "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )
            else:
                print(
                    f"\033[37m[-]\033[0m vnc-brute: \033[96m{ip}:{vnc_port}\033[0m → "
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
        pass_file: str,
        output_dir: str,
    ) -> VNCHostResult:
        """
        Run VNC brute-force against a single host.

        Steps:
          1. Check anonymous/no-auth access (vnc_none_auth)
          2. Run vnc_login with PASS_FILE + ANONYMOUS_LOGIN=true
          3. Parse output for successful logins
          4. On lockout/rate limit → skip
        """
        result = VNCHostResult(ip=ip, port=port)
        host_start = time.time()
        all_output = []

        # ── Step 1: Check for no-auth VNC (vnc_none_auth) ────────────────
        try:
            print(
                f"    \033[36m[>]\033[0m \033[96m{ip}:{port}\033[0m "
                f"checking no-auth (vnc_none_auth) ..."
            )
            none_auth_output = self._run_vnc_none_auth(ip, port)
            all_output.append(f"=== vnc_none_auth ===\n{none_auth_output}\n")

            if self._detect_no_auth(none_auth_output):
                result.no_auth = True
                cred = VNCCredential(
                    ip=ip,
                    password="",
                    port=port,
                    anonymous=True,
                )
                result.credentials.append(cred)
                print(
                    f"    \033[1;91m[!]\033[0m \033[1;91mNO AUTH\033[0m: "
                    f"\033[96m{ip}:{port}\033[0m → "
                    f"\033[1;91mVNC server does not require authentication!\033[0m"
                )
        except subprocess.TimeoutExpired:
            all_output.append("=== vnc_none_auth === TIMEOUT\n")
        except KeyboardInterrupt:
            raise
        except Exception as e:
            all_output.append(f"=== vnc_none_auth === ERROR: {e}\n")

        # ── Step 2: VNC login brute-force (vnc_login) ────────────────────
        try:
            print(
                f"    \033[36m[>]\033[0m \033[96m{ip}:{port}\033[0m "
                f"brute-forcing with vnc_login + password file ..."
            )
            login_output = self._run_vnc_login(ip, port, pass_file)
            all_output.append(f"=== vnc_login ===\n{login_output}\n")

            # Parse successful logins
            creds = self._parse_success(ip, port, login_output)
            for cred in creds:
                # Avoid duplicate of no-auth empty password
                existing_passwords = {c.password for c in result.credentials}
                if cred.password not in existing_passwords:
                    result.credentials.append(cred)
                    print(
                        f"    \033[1;92m[+]\033[0m \033[1;92mSUCCESS\033[0m: "
                        f"\033[96m{ip}:{port}\033[0m → "
                        f"\033[1;92m:{cred.password}\033[0m"
                    )

            # Check for lockout / too many security failures
            if self._detect_lockout(login_output):
                result.skipped = True
                result.skip_reason = "security_lockout"
                print(
                    f"    \033[91m[!]\033[0m Security lockout detected on "
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
            all_output.append(f"=== vnc_login === ERROR: {e}\n")

        result.raw_output = "\n".join(all_output)
        result.scan_time = time.time() - host_start

        # Save per-host raw output
        if output_dir and result.raw_output.strip():
            safe_ip = ip.replace(".", "_").replace(":", "_")
            out_file = os.path.join(output_dir, f"vnc_brute_{safe_ip}.txt")
            try:
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(f"# Metasploit VNC brute-force: {ip}:{port}\n")
                    f.write(f"# Password file: {pass_file}\n")
                    f.write(f"# Scan time: {result.scan_time:.1f}s\n\n")
                    f.write(result.raw_output)
            except Exception:
                pass

        return result

    def _run_vnc_none_auth(self, ip: str, port: int) -> str:
        """
        Run auxiliary/scanner/vnc/vnc_none_auth to check for no-auth VNC.

        Creates a .rc resource script:
            use auxiliary/scanner/vnc/vnc_none_auth
            set RHOSTS <ip>
            set RPORT <port>
            run
            exit

        Returns the raw stdout+stderr output.
        """
        tmpdir = tempfile.mkdtemp(prefix="reconx_vnc_noauth_")
        rc_file = os.path.join(tmpdir, "vnc_none_auth.rc")

        try:
            rc_content = (
                f"use auxiliary/scanner/vnc/vnc_none_auth\n"
                f"set RHOSTS {ip}\n"
                f"set RPORT {port}\n"
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
                stdout, stderr = proc.communicate(timeout=60)
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

    def _run_vnc_login(self, ip: str, port: int, pass_file: str) -> str:
        """
        Run auxiliary/scanner/vnc/vnc_login with password file.

        Creates a .rc resource script:
            use auxiliary/scanner/vnc/vnc_login
            set RHOSTS <ip>
            set RPORT <port>
            set PASS_FILE <pass_file>
            set ANONYMOUS_LOGIN true
            set STOP_ON_SUCCESS true
            set VERBOSE false
            run
            exit

        Returns the raw stdout+stderr output.
        """
        tmpdir = tempfile.mkdtemp(prefix="reconx_vnc_login_")
        rc_file = os.path.join(tmpdir, "vnc_login.rc")

        try:
            rc_content = (
                f"use auxiliary/scanner/vnc/vnc_login\n"
                f"set RHOSTS {ip}\n"
                f"set RPORT {port}\n"
                f"set PASS_FILE {pass_file}\n"
                f"set ANONYMOUS_LOGIN true\n"
                # f"set STOP_ON_SUCCESS true\n"
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
                "-q",
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
                # Timeout: 180s should be generous for VNC password file
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

    def _parse_success(self, ip: str, port: int, output: str) -> List[VNCCredential]:
        """Parse msfconsole output for successful VNC login credentials."""
        creds = []

        for line in output.splitlines():
            if "[+]" not in line:
                continue

            line_lower = line.lower()

            if "success" in line_lower or "login successful" in line_lower:
                # Try standard pattern:
                # [+] 172.18.2.213:5901 - 172.18.2.213:5901 - Login Successful: :P@ssw0rd!123
                match = SUCCESS_PATTERN.search(line)
                if match:
                    password = match.group(3)
                    cred = VNCCredential(
                        ip=match.group(1),
                        port=int(match.group(2)),
                        password=password,
                    )
                    creds.append(cred)
                    continue

                # Try extracting password from "Login Successful: :password" pattern
                cred_match = re.search(
                    r"Login Successful:\s*:?(\S+)",
                    line,
                    re.IGNORECASE,
                )
                if cred_match:
                    password = cred_match.group(1)
                    cred = VNCCredential(
                        ip=ip,
                        port=port,
                        password=password,
                    )
                    creds.append(cred)
                    continue

                # Fallback: try alt pattern
                match = SUCCESS_PATTERN_ALT.search(line)
                if match:
                    password = match.group(1)
                    cred = VNCCredential(
                        ip=ip,
                        port=port,
                        password=password,
                    )
                    creds.append(cred)

            # Check for no-auth success (also captured by vnc_none_auth phase)
            elif "does not require authentication" in line_lower or "no auth" in line_lower:
                cred = VNCCredential(
                    ip=ip,
                    port=port,
                    password="",
                    anonymous=True,
                )
                # Avoid duplicate
                if not any(c.anonymous for c in creds):
                    creds.append(cred)

        return creds

    def _detect_no_auth(self, output: str) -> bool:
        """Check if VNC server does not require authentication."""
        if NO_AUTH_PATTERN.search(output):
            return True
        output_lower = output.lower()
        if "does not require authentication" in output_lower:
            return True
        if "[+]" in output and "no auth" in output_lower:
            return True
        return False

    def _detect_lockout(self, output: str) -> bool:
        """Check if the output indicates security lockout."""
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

    def _compute_stats(self, scan_time: float):
        """Compute aggregated statistics."""
        self.stats.scan_time = scan_time
        self.stats.hosts_tested = sum(
            1 for r in self.results.values() if not r.skipped
        )
        self.stats.hosts_skipped = sum(
            1 for r in self.results.values() if r.skipped
        )
        self.stats.hosts_no_auth = sum(
            1 for r in self.results.values() if r.no_auth
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
            cred_file = os.path.join(output_dir, "vnc_credentials.txt")
            try:
                with open(cred_file, "w", encoding="utf-8") as f:
                    f.write("# Metasploit VNC Brute-Force — Valid Credentials\n")
                    f.write(f"# Generated by ReconX\n")
                    f.write(f"# Total: {len(all_creds)} credential(s)\n\n")
                    for cred in all_creds:
                        if cred.anonymous:
                            f.write(
                                f"{cred.ip}:{cred.port} → "
                                f"NO AUTHENTICATION (anonymous access)\n"
                            )
                        else:
                            f.write(
                                f"{cred.ip}:{cred.port} → "
                                f":{cred.password}\n"
                            )
            except Exception:
                pass

        # No-auth hosts list
        no_auth_hosts = [
            (ip, r.port) for ip, r in sorted(self.results.items()) if r.no_auth
        ]
        if no_auth_hosts:
            no_auth_file = os.path.join(output_dir, "vnc_no_auth.txt")
            try:
                with open(no_auth_file, "w", encoding="utf-8") as f:
                    f.write("# VNC Servers with No Authentication Required\n")
                    f.write(f"# Generated by ReconX\n")
                    f.write(f"# Total: {len(no_auth_hosts)} host(s)\n\n")
                    for ip, port in no_auth_hosts:
                        f.write(f"{ip}:{port}\n")
            except Exception:
                pass

        # Full summary JSON
        summary_file = os.path.join(output_dir, "vnc_brute_summary.json")
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

    def get_all_credentials(self) -> List[VNCCredential]:
        """Get all discovered valid credentials across all hosts/ports."""
        creds = []
        for host_result in self.results.values():
            creds.extend(host_result.credentials)
        return creds

    def get_no_auth_hosts(self) -> List[str]:
        """Get list of ip:port strings with no-auth VNC access."""
        return [
            f"{r.ip}:{r.port}" for r in self.results.values() if r.no_auth
        ]
