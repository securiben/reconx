"""
Metasploit PostgreSQL Login Scanner for ReconX.
Uses msfconsole auxiliary/scanner/postgres/postgres_login to check
anonymous/default PostgreSQL credentials on hosts where nmap discovered
PostgreSQL ports (5432).

For each IP that has PostgreSQL port(s) open:
  1. Run auxiliary/scanner/postgres/postgres_login with:
     - RHOSTS           = target IP
     - ANONYMOUS_LOGIN  = true
     - BLANK_PASSWORDS  = true
     - USERNAME         = postgres
     - STOP_ON_SUCCESS  = true
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
from ..utils import routed_path


# ─── PostgreSQL Ports ─────────────────────────────────────────────────────────

POSTGRES_PORTS = {5432, 5433}


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class PostgresCredential:
    """A successfully discovered PostgreSQL credential."""
    ip: str = ""
    port: int = 5432
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
class PostgresHostResult:
    """Login result for a single PostgreSQL host."""
    ip: str = ""
    port: int = 5432
    credentials: List[PostgresCredential] = field(default_factory=list)
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
class PostgresLoginStats:
    """Aggregated PostgreSQL login statistics."""
    total_postgres_hosts: int = 0
    hosts_tested: int = 0
    hosts_skipped: int = 0
    credentials_found: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_postgres_hosts": self.total_postgres_hosts,
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

# ─── Success Patterns ────────────────────────────────────────────────────────

# postgres_login:
# [+] 192.168.1.1:5432 - Login Successful: postgres:postgres
# [+] 192.168.1.1:5432 - Login Successful: postgres:
SUCCESS_PATTERN = re.compile(
    r'\[\+\]\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s*-\s*'
    r'(?:\d+\.\d+\.\d+\.\d+:\d+\s*-\s*)?'
    r'(?:Login Successful|SUCCESS)[:\s]*'
    r"['\"]?(\S+?):(.*?)['\"]?"
    r'(?:\s|$)',
    re.IGNORECASE,
)

# Alt: [+] ip:port - Login Successful: user:pass
SUCCESS_PATTERN_ALT = re.compile(
    r'\[\+\]\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s*-\s*'
    r'.*?(?:Login Successful|Logged in)[:\s]*[\'"]?(\S+?):(.*?)[\'"]?'
    r'(?:\s|$)',
    re.IGNORECASE,
)

# Fallback: any [+] line with user:pass in quotes
SUCCESS_PATTERN_QUOTED = re.compile(
    r"\[\+\].*?'([^':]+):(.*?)'",
    re.IGNORECASE,
)


# ─── Main Scanner ─────────────────────────────────────────────────────────────

class PostgresLoginScanner:
    """
    Metasploit PostgreSQL login scanner.

    Uses msfconsole auxiliary/scanner/postgres/postgres_login to:
      - Check anonymous/blank-password access (ANONYMOUS_LOGIN + BLANK_PASSWORDS)
      - Default username: postgres
      - STOP_ON_SUCCESS = true

    Workflow per IP:
      1. Run postgres_login with anonymous + blank passwords
      2. On lockout / rate limit / delay → skip
    """

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.msf_path = self._find_msfconsole()
        self.available = self.msf_path is not None
        self.results: Dict[str, PostgresHostResult] = {}  # "ip:port" → result
        self.stats = PostgresLoginStats()

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

    def _get_postgres_hosts(self, nmap_results: Dict) -> List[tuple]:
        """
        Extract hosts with PostgreSQL ports open from nmap results.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.

        Returns:
            List of (ip, port) tuples.
        """
        targets = []
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
                    port_num in POSTGRES_PORTS
                    or "postgres" in service.lower()
                    or "postgresql" in service.lower()
                ):
                    targets.append((ip, port_num))

        targets.sort(key=lambda t: (t[0], t[1]))
        return targets

    def scan(
        self,
        nmap_results: Dict,
        output_dir: str = "",
    ) -> Dict[str, PostgresHostResult]:
        """
        Run PostgreSQL login check against hosts with PostgreSQL ports open.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.
            output_dir: Directory to save output files.

        Returns:
            Dict mapping "ip:port" → PostgresHostResult.
        """
        if not self.available:
            return {}

        if not nmap_results:
            return {}

        # Find PostgreSQL hosts from nmap results
        pg_targets = self._get_postgres_hosts(nmap_results)
        if not pg_targets:
            return {}

        scan_start = time.time()
        self.stats.total_postgres_hosts = len(pg_targets)

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        print(
            f"\033[36m[>]\033[0m postgres-login: scanning "
            f"\033[96m{len(pg_targets)}\033[0m PostgreSQL target(s) ..."
        )

        for idx, (ip, pg_port) in enumerate(pg_targets, 1):
            result_key = f"{ip}:{pg_port}"

            print(
                f"\033[36m[>]\033[0m postgres-login: "
                f"[\033[96m{idx}/{len(pg_targets)}\033[0m] "
                f"\033[96m{ip}:{pg_port}\033[0m ..."
            )

            host_result = self._brute_host(ip, pg_port, output_dir)
            self.results[result_key] = host_result

            # Print per-host status
            if host_result.skipped:
                print(
                    f"\033[93m[!]\033[0m postgres-login: \033[96m{ip}:{pg_port}\033[0m → "
                    f"\033[93mskipped ({host_result.skip_reason})\033[0m "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )
            else:
                if host_result.credentials:
                    cred_str = ", ".join(
                        f"\033[1;92m{c.username}:{c.password}\033[0m"
                        for c in host_result.credentials
                    )
                    print(
                        f"\033[92m[+]\033[0m postgres-login: \033[96m{ip}:{pg_port}\033[0m → "
                        f"\033[1;92m{len(host_result.credentials)} credential(s)\033[0m → {cred_str} "
                        f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                    )
                else:
                    print(
                        f"\033[37m[-]\033[0m postgres-login: \033[96m{ip}:{pg_port}\033[0m → "
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
        output_dir: str,
    ) -> PostgresHostResult:
        """
        Run PostgreSQL login check against a single host.

        Uses auxiliary/scanner/postgres/postgres_login with:
          - ANONYMOUS_LOGIN = true
          - BLANK_PASSWORDS = true
          - USERNAME = postgres
          - STOP_ON_SUCCESS = true
        """
        result = PostgresHostResult(ip=ip, port=port)
        host_start = time.time()
        raw_parts = []

        try:
            login_output = self._run_postgres_login(ip, port)
            raw_parts.append(f"=== postgres/postgres_login ===\n{login_output}")

            # Parse successful logins
            creds = self._parse_success(ip, port, login_output)
            result.credentials.extend(creds)

            for cred in creds:
                pw_display = cred.password if cred.password else "(blank)"
                print(
                    f"    \033[1;92m[+]\033[0m \033[1;92mSUCCESS\033[0m: "
                    f"\033[96m{ip}:{port}\033[0m → "
                    f"\033[1;92m{cred.username}:{pw_display}\033[0m"
                )

            # Check for account lockout
            if self._detect_lockout(login_output):
                result.skipped = True
                result.skip_reason = "account_lockout"

            # Check for rate limit / connection issues
            if self._detect_rate_limit(login_output):
                result.skipped = True
                result.skip_reason = "rate_limit"

            # Check for delay / throttling
            if self._detect_delay(login_output):
                result.skipped = True
                result.skip_reason = "delay_throttle"

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
            out_file = routed_path(output_dir, f"postgres_login_{safe_ip}_{port}.txt")
            try:
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(f"# Metasploit PostgreSQL login: {ip}:{port}\n")
                    f.write(f"# Scan time: {result.scan_time:.1f}s\n\n")
                    f.write(result.raw_output)
            except Exception:
                pass

        return result

    # ─── MSF Module Runners ───────────────────────────────────────────────────

    def _run_msfconsole(self, rc_content: str, timeout: int = 300) -> str:
        """Run msfconsole with a .rc resource script and return output."""
        tmpdir = tempfile.mkdtemp(prefix="reconx_pg_login_")
        rc_file = os.path.join(tmpdir, "pg_login.rc")

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

    def _run_postgres_login(self, ip: str, port: int) -> str:
        """
        Run auxiliary/scanner/postgres/postgres_login.

        Resource script:
            use auxiliary/scanner/postgres/postgres_login
            set RHOSTS <ip>
            set RPORT <port>
            set ANONYMOUS_LOGIN true
            set BLANK_PASSWORDS true
            set USERNAME postgres
            set STOP_ON_SUCCESS true
            run
            exit
        """
        rc = (
            f"use auxiliary/scanner/postgres/postgres_login\n"
            f"set RHOSTS {ip}\n"
            f"set RPORT {port}\n"
            f"set ANONYMOUS_LOGIN true\n"
            f"set BLANK_PASSWORDS true\n"
            f"set USERNAME postgres\n"
            f"set STOP_ON_SUCCESS true\n"
            f"set VERBOSE false\n"
            f"set ConnectTimeout 10\n"
            f"set THREADS 1\n"
            f"run\n"
            f"exit\n"
        )
        return self._run_msfconsole(rc, timeout=180)

    # ─── Output Parsing ──────────────────────────────────────────────────────

    def _parse_success(self, ip: str, port: int, output: str) -> List[PostgresCredential]:
        """Parse msfconsole output for successful PostgreSQL login credentials."""
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
                    creds.append(PostgresCredential(
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
                    creds.append(PostgresCredential(
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
                    creds.append(PostgresCredential(
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
        """Save combined PostgreSQL login results to output directory."""
        all_creds = []
        for key in sorted(self.results.keys()):
            host_result = self.results[key]
            for cred in host_result.credentials:
                all_creds.append(cred)

        if all_creds:
            cred_file = routed_path(output_dir, "postgres_credentials.txt")
            try:
                with open(cred_file, "w", encoding="utf-8") as f:
                    f.write("# Metasploit PostgreSQL Login — Valid Credentials\n")
                    f.write(f"# Generated by ReconX\n")
                    f.write(f"# Total: {len(all_creds)} credential(s)\n\n")
                    for cred in all_creds:
                        pw_display = cred.password if cred.password else "(blank)"
                        f.write(
                            f"{cred.ip}:{cred.port} → "
                            f"{cred.username}:{pw_display}\n"
                        )
            except Exception:
                pass

        # Full summary JSON
        summary_file = routed_path(output_dir, "postgres_login_summary.json")
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

    def get_all_credentials(self) -> List[PostgresCredential]:
        """Get all discovered valid credentials across all hosts."""
        creds = []
        for host_result in self.results.values():
            creds.extend(host_result.credentials)
        return creds
