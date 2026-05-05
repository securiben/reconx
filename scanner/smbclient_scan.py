"""
SMBClient Scanner for ReconX.
Runs smbclient against targets with SMB ports (445, 139) detected by nmap.
Detects SMB null sessions and enumerates accessible shares + files.

Phase 1: smbclient -L //<IP>/ -N
  Lists all shares available via null session (anonymous).

Phase 2: For each non-default share discovered, attempt:
  smbclient //<IP>/<share> -N -c "ls"
  Lists files in the root of each accessible share.

Detection of null session = if share listing succeeds without credentials.

Requires: smbclient installed in PATH
  Install (Debian/Ubuntu): sudo apt install smbclient
  Install (Kali): pre-installed
"""

import os
import re
import sys
import json
import shutil
import subprocess
import time as _time
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field

from ..config import ScannerConfig
from ..utils import routed_path


# ─── SMB ports to look for in nmap results ────────────────────────────────────

SMB_PORTS = {445, 139}

# Shares to skip when attempting file listing (default/admin shares)
DEFAULT_SHARES = {"IPC$", "ADMIN$", "C$", "D$", "E$", "F$"}


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class SMBShare:
    """A single SMB share discovered via null session."""
    name: str = ""
    share_type: str = ""      # Disk, IPC, Printer
    comment: str = ""
    accessible: bool = False  # True if we could list files
    files: List[str] = field(default_factory=list)  # File/dir entries
    error: str = ""

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "type": self.share_type,
            "comment": self.comment,
            "accessible": self.accessible,
        }
        if self.files:
            d["files"] = self.files
        if self.error:
            d["error"] = self.error
        return d


@dataclass
class SMBClientHostResult:
    """SMBClient scan results for a single host."""
    ip: str = ""
    null_session: bool = False     # True if share listing succeeded
    shares: List[SMBShare] = field(default_factory=list)
    accessible_shares: int = 0     # Shares where ls worked
    total_files_listed: int = 0    # Total file entries across all shares
    workgroup: str = ""
    os_info: str = ""
    scan_time: float = 0.0
    error: str = ""

    @property
    def total_shares(self) -> int:
        return len(self.shares)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "null_session": self.null_session,
            "shares": [s.to_dict() for s in self.shares],
            "total_shares": self.total_shares,
            "accessible_shares": self.accessible_shares,
            "total_files_listed": self.total_files_listed,
            "workgroup": self.workgroup,
            "os_info": self.os_info,
            "scan_time": self.scan_time,
            "error": self.error,
        }


@dataclass
class SMBClientStats:
    """Aggregated smbclient scan statistics."""
    total_hosts_scanned: int = 0
    hosts_with_null_session: int = 0
    total_shares: int = 0
    accessible_shares: int = 0
    total_files_listed: int = 0
    hosts_with_accessible_shares: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_hosts_scanned": self.total_hosts_scanned,
            "hosts_with_null_session": self.hosts_with_null_session,
            "total_shares": self.total_shares,
            "accessible_shares": self.accessible_shares,
            "total_files_listed": self.total_files_listed,
            "hosts_with_accessible_shares": self.hosts_with_accessible_shares,
            "scan_time": self.scan_time,
        }


class SMBClientScanner:
    """
    SMBClient wrapper for ReconX.
    Runs smbclient -L (list shares) and smbclient //ip/share -c ls
    against hosts with SMB ports detected by nmap.
    """

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.smbclient_path = self._find_smbclient()
        self.available = self.smbclient_path is not None
        self.results: Dict[str, SMBClientHostResult] = {}
        self.stats = SMBClientStats()

    def _find_smbclient(self) -> Optional[str]:
        """Find the smbclient binary in PATH."""
        found = shutil.which("smbclient")
        if found:
            return found

        common_paths = [
            "/usr/bin/smbclient",
            "/usr/local/bin/smbclient",
        ]
        for path in common_paths:
            if os.path.isfile(path):
                return path

        # Auto-install smbclient if not found
        from .auto_install import ensure_tool
        if ensure_tool("smbclient"):
            return shutil.which("smbclient")

        return None

    @staticmethod
    def get_smb_hosts(nmap_results: dict) -> Set[str]:
        """
        Extract IPs that have SMB ports (445, 139) open from nmap results.
        """
        smb_hosts: Set[str] = set()
        for ip, host_result in nmap_results.items():
            ports = host_result.ports if hasattr(host_result, 'ports') else []
            for p in ports:
                port_num = p.port if hasattr(p, 'port') else p.get('port', 0)
                state = p.state if hasattr(p, 'state') else p.get('state', '')
                if port_num in SMB_PORTS and state == "open":
                    smb_hosts.add(ip)
                    break
        return smb_hosts

    def scan(self, smb_hosts: Set[str],
             output_dir: str = ".") -> Dict[str, SMBClientHostResult]:
        """
        Run smbclient null session checks against all SMB hosts.

        Args:
            smb_hosts: Set of IP addresses with SMB ports open.
            output_dir: Directory for output files.

        Returns:
            Dict mapping IP → SMBClientHostResult.
        """
        if not self.available:
            return {}

        if not smb_hosts:
            return {}

        # Reset
        self.results = {}
        self.stats = SMBClientStats()

        scan_start = _time.time()
        os.makedirs(output_dir, exist_ok=True)

        print(
            f"\033[36m[>]\033[0m smbclient: checking null sessions on "
            f"\033[92m{len(smb_hosts)}\033[0m SMB host(s) ..."
        )

        for ip in sorted(smb_hosts):
            host_result = self._scan_host(ip)
            self.results[ip] = host_result

        scan_elapsed = _time.time() - scan_start
        self._compute_stats(scan_elapsed)

        # Save output only if there are findings
        if self.stats.hosts_with_null_session or self.stats.accessible_shares:
            self._save_output(output_dir)

        return self.results

    def _scan_host(self, ip: str) -> SMBClientHostResult:
        """
        Run smbclient against a single host:
        1. List shares with null session
        2. Attempt to list files on each non-default share
        """
        result = SMBClientHostResult(ip=ip)
        host_start = _time.time()

        print(
            f"\033[36m    [>]\033[0m smbclient: \033[96m{ip}\033[0m ..."
        )

        # ── Phase 1: List shares ──────────────────────────────────────────
        shares, workgroup, null_session, error = self._list_shares(ip)
        result.shares = shares
        result.workgroup = workgroup
        result.null_session = null_session
        result.error = error

        if null_session and shares:
            share_names = [s.name for s in shares]
            print(
                f"\033[91m    [!]\033[0m smbclient: \033[96m{ip}\033[0m → "
                f"\033[91mnull session!\033[0m "
                f"\033[92m{len(shares)} share(s)\033[0m: "
                f"{', '.join(share_names[:8])}"
                f"{'...' if len(share_names) > 8 else ''}"
            )

            # ── Phase 2: List files on accessible shares ──────────────────
            for share in shares:
                # Skip default/admin shares and IPC$
                if share.name in DEFAULT_SHARES or share.share_type == "IPC":
                    continue

                files, accessible, ls_error = self._list_files(ip, share.name)
                share.accessible = accessible
                share.files = files
                share.error = ls_error

                if accessible and files:
                    result.accessible_shares += 1
                    result.total_files_listed += len(files)
                    print(
                        f"\033[91m    [!]\033[0m smbclient: \033[96m{ip}\033[0m/"
                        f"\033[93m{share.name}\033[0m → "
                        f"\033[92m{len(files)} file(s)/dir(s)\033[0m accessible"
                    )
        elif not null_session and error:
            print(
                f"\033[90m    [·]\033[0m smbclient: \033[96m{ip}\033[0m → "
                f"no null session"
            )

        result.scan_time = _time.time() - host_start
        return result

    def _list_shares(self, ip: str) -> Tuple[List[SMBShare], str, bool, str]:
        """
        Run 'smbclient -L //<ip>/ -N' to list shares via null session.

        Returns:
            (shares, workgroup, null_session_success, error_message)
        """
        shares: List[SMBShare] = []
        workgroup = ""
        null_session = False
        error = ""

        cmd = [self.smbclient_path, "-L", f"//{ip}/", "-N"]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                encoding="utf-8",
                errors="replace",
            )

            output = proc.stdout + proc.stderr

            # Parse shares from output
            # Format:
            #   Sharename       Type      Comment
            #   ---------       ----      -------
            #   ADMIN$          Disk      Remote Admin
            #   IPC$            IPC       Remote IPC
            in_share_section = False
            for line in output.splitlines():
                stripped = line.strip()

                # Detect start of share listing
                if re.match(r'^-+\s+-+\s+-+', stripped):
                    in_share_section = True
                    continue

                if in_share_section:
                    # Blank line or new section ends shares
                    if not stripped or stripped.startswith("Reconnecting") or stripped.startswith("Server"):
                        # Check if it's the server/workgroup section
                        if stripped.startswith("Server") or stripped.startswith("Workgroup"):
                            in_share_section = False
                            continue
                        if not stripped:
                            in_share_section = False
                            continue

                    # Parse share line: <name>  <type>  <comment>
                    # The columns are variable-width
                    share_match = re.match(
                        r'^(.+?)\s{2,}(Disk|IPC|Printer)\s{2,}(.*)$',
                        stripped,
                    )
                    if share_match:
                        name = share_match.group(1).strip()
                        stype = share_match.group(2).strip()
                        comment = share_match.group(3).strip()
                        shares.append(SMBShare(
                            name=name,
                            share_type=stype,
                            comment=comment,
                        ))
                        null_session = True
                    elif re.match(r'^(.+?)\s{2,}(Disk|IPC|Printer)\s*$', stripped):
                        # Share with no comment
                        m2 = re.match(r'^(.+?)\s{2,}(Disk|IPC|Printer)\s*$', stripped)
                        if m2:
                            shares.append(SMBShare(
                                name=m2.group(1).strip(),
                                share_type=m2.group(2).strip(),
                            ))
                            null_session = True

            # Extract workgroup
            wg_match = re.search(r'Domain=\[([^\]]+)\]', output)
            if wg_match:
                workgroup = wg_match.group(1)

            # If we got shares, it's a null session
            if shares:
                null_session = True
            elif "NT_STATUS_ACCESS_DENIED" in output:
                error = "access denied"
            elif "NT_STATUS_LOGON_FAILURE" in output:
                error = "logon failure"
            elif "Connection to" in output and "failed" in output:
                error = "connection failed"
            elif proc.returncode != 0:
                error = f"exit code {proc.returncode}"

        except subprocess.TimeoutExpired:
            error = "timeout"
        except FileNotFoundError:
            error = "smbclient not found"
            self.available = False
        except Exception as e:
            error = str(e)

        return shares, workgroup, null_session, error

    def _list_files(self, ip: str, share_name: str) -> Tuple[List[str], bool, str]:
        """
        Recursively list files in a share via null session.
        Descends into subdirectories (max depth 3, max 500 entries total).

        Returns:
            (file_entries, accessible, error_message)
        """
        all_entries: List[str] = []
        accessible = False
        error = ""

        # Start recursive listing from root "\"
        ok, err = self._list_directory(
            ip, share_name, "\\", depth=0, max_depth=3,
            entries=all_entries, max_entries=500,
        )
        if ok:
            accessible = True
        if err and not all_entries:
            error = err

        return all_entries, accessible, error

    def _list_directory(
        self, ip: str, share_name: str, path: str,
        depth: int, max_depth: int,
        entries: List[str], max_entries: int,
    ) -> Tuple[bool, str]:
        """
        List files at a specific path inside a share.
        Recursively descends into subdirectories.

        Args:
            ip: Target IP.
            share_name: Share name.
            path: SMB path to list (e.g. "\\" for root, "\\IT\\" for subdir).
            depth: Current recursion depth.
            max_depth: Maximum recursion depth.
            entries: Accumulator list for all discovered entries.
            max_entries: Stop after this many total entries.

        Returns:
            (accessible, error_message)
        """
        if len(entries) >= max_entries:
            return True, ""

        # Build smbclient command: ls "<path>\*"
        # For root: ls "\*"
        # For subdir: ls "\IT\*"
        ls_path = path.rstrip("\\") + "\\*" if path != "\\" else "\\*"

        escaped_share = share_name.replace("'", "'\\''")
        escaped_path = ls_path.replace("'", "'\\''")
        cmd = f"{self.smbclient_path} '//{ip}/{escaped_share}' -N -c 'ls \"{escaped_path}\"'"

        accessible = False
        error = ""
        subdirs: List[Tuple[str, str]] = []  # (name, full_path)

        # Indent prefix for tree display
        indent = "  " * depth

        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
                encoding="utf-8",
                errors="replace",
            )

            output = proc.stdout + proc.stderr

            # Check for errors
            if "NT_STATUS_ACCESS_DENIED" in output:
                return False, "access denied"
            if "NT_STATUS_LOGON_FAILURE" in output:
                return False, "logon failure"
            if "NT_STATUS_BAD_NETWORK_NAME" in output:
                return False, "bad network name"
            if "NT_STATUS_NO_SUCH_FILE" in output:
                return False, "no such path"
            if "NT_STATUS_OBJECT_NAME_NOT_FOUND" in output:
                return False, "path not found"

            # Parse file listing
            for line in output.splitlines():
                stripped = line.strip()

                if not stripped or stripped.startswith("smb:"):
                    continue

                # Match: <name>  <attrs>  <size>  <date>
                file_match = re.match(
                    r'^(.+?)\s+([ADHNRS]+)\s+(\d+)\s+(.+)$',
                    stripped,
                )
                if file_match:
                    fname = file_match.group(1).strip()
                    attrs = file_match.group(2).strip()
                    fsize = file_match.group(3).strip()
                    fdate = file_match.group(4).strip()

                    if fname in (".", ".."):
                        continue

                    is_dir = "D" in attrs
                    type_indicator = "DIR " if is_dir else "FILE"

                    # Build display path
                    if path == "\\":
                        display_path = fname
                    else:
                        display_path = path.strip("\\") + "\\" + fname

                    entry = f"{indent}[{type_indicator}] {display_path}  ({fsize} bytes)  {fdate}"
                    entries.append(entry)
                    accessible = True

                    if len(entries) >= max_entries:
                        entries.append(f"{indent}  ... (truncated at {max_entries} entries)")
                        return True, ""

                    # Queue subdirectory for recursive listing
                    if is_dir and depth < max_depth:
                        if path == "\\":
                            sub_path = "\\" + fname + "\\"
                        else:
                            sub_path = path.rstrip("\\") + "\\" + fname + "\\"
                        subdirs.append((fname, sub_path))

            # "blocks of size" = successful connection
            if "blocks of size" in output or "blocks available" in output:
                accessible = True

        except subprocess.TimeoutExpired:
            return accessible, "timeout"
        except Exception as e:
            return accessible, str(e)

        # Recurse into subdirectories
        for dir_name, sub_path in subdirs:
            if len(entries) >= max_entries:
                break
            self._list_directory(
                ip, share_name, sub_path,
                depth=depth + 1, max_depth=max_depth,
                entries=entries, max_entries=max_entries,
            )

        return accessible, error

    def _compute_stats(self, scan_time: float):
        """Compute aggregated statistics."""
        self.stats.scan_time = scan_time
        self.stats.total_hosts_scanned = len(self.results)

        for ip, host_result in self.results.items():
            if host_result.null_session:
                self.stats.hosts_with_null_session += 1
            self.stats.total_shares += host_result.total_shares
            self.stats.accessible_shares += host_result.accessible_shares
            self.stats.total_files_listed += host_result.total_files_listed
            if host_result.accessible_shares > 0:
                self.stats.hosts_with_accessible_shares += 1

    def _save_output(self, output_dir: str):
        """Save smbclient results to a human-readable text file."""
        filepath = routed_path(output_dir, "smbclient_nullsession.txt")
        lines = [
            "# ReconX - SMBClient Null Session Results",
            f"# Hosts scanned: {self.stats.total_hosts_scanned}",
            f"# Hosts with null session: {self.stats.hosts_with_null_session}",
            f"# Total shares: {self.stats.total_shares}",
            f"# Accessible shares: {self.stats.accessible_shares}",
            f"# Total files listed: {self.stats.total_files_listed}",
            f"# Scan time: {self.stats.scan_time:.1f}s",
            "",
        ]

        for ip in sorted(self.results.keys()):
            hr = self.results[ip]
            null_str = "NULL SESSION" if hr.null_session else "no null session"
            lines.append(f"══ {ip} ({null_str}) ══")
            if hr.workgroup:
                lines.append(f"  Workgroup: {hr.workgroup}")
            if hr.error and not hr.null_session:
                lines.append(f"  Error: {hr.error}")

            if hr.shares:
                lines.append(f"  Shares ({len(hr.shares)}):")
                lines.append(f"  {'Sharename':<40s} {'Type':<10s} Comment")
                lines.append(f"  {'-' * 40} {'-' * 10} {'-' * 30}")
                for share in hr.shares:
                    acc_str = " [ACCESSIBLE]" if share.accessible else ""
                    comment_str = f"  {share.comment}" if share.comment else ""
                    lines.append(
                        f"  {share.name:<40s} {share.share_type:<10s}{comment_str}{acc_str}"
                    )

                # Show file listings for accessible shares
                for share in hr.shares:
                    if not share.accessible or not share.files:
                        continue

                    lines.append("")
                    lines.append(
                        f"  ── //{ip}/{share.name} "
                        f"({len(share.files)} entries) ──"
                    )
                    for f_entry in share.files:
                        # Entries already have depth-based indentation
                        lines.append(f"    {f_entry}")

            lines.append("")

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except Exception:
            pass

        # JSON summary
        json_file = routed_path(output_dir, "smbclient_summary.json")
        try:
            summary = {
                "stats": self.stats.to_dict(),
                "hosts": {
                    ip: hr.to_dict() for ip, hr in sorted(self.results.items())
                    if hr.null_session or hr.accessible_shares > 0
                },
            }
            import json as _json
            with open(json_file, "w", encoding="utf-8") as f:
                _json.dump(summary, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def get_null_session_hosts(self) -> List[str]:
        """Return list of IPs with null sessions."""
        return [
            ip for ip, hr in self.results.items()
            if hr.null_session
        ]

    def get_accessible_share_hosts(self) -> List[str]:
        """Return list of IPs with accessible (readable) shares."""
        return [
            ip for ip, hr in self.results.items()
            if hr.accessible_shares > 0
        ]
