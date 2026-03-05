"""
Terminal Output Renderer for ReconX.
Renders the scan summary with ANSI colors matching the reference output.
Uses raw ANSI escape codes for maximum compatibility (no external deps required).
Falls back to Rich library if available for enhanced rendering.

Output matches the reference image exactly:
- Summary block with box drawing characters
- Color-coded infrastructure stats
- Takeover results with vulnerability indicators
- Tech profiling with severity tags
- Source statistics
- ASCII indicators (→, ←, !!)
"""

import sys
import os
from typing import Dict, List, Optional
from collections import Counter, defaultdict

from ..models import (
    ScanResult, TakeoverResult, TakeoverStatus, TechMatch,
    Severity, SourceStats,
)


# ─── ANSI Color Codes ────────────────────────────────────────────────────────

class C:
    """ANSI color escape sequences for terminal output."""
    # Reset
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

    # Regular colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright colors
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Background
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"

    # Specific semantic colors matching the reference image
    LABEL = "\033[37m"           # White for labels
    VALUE_NUM = "\033[92m"       # Bright green for numbers
    VALUE_AWS = "\033[93m"       # Yellow for AWS
    VALUE_AZURE = "\033[94m"     # Blue for Azure
    VALUE_CF = "\033[33m"        # Orange/Yellow for Cloudflare
    VALUE_AKAMAI = "\033[36m"    # Cyan for Akamai
    VALUE_OTHER = "\033[1;37m"   # Bold white for Other
    VALUE_CT = "\033[37m"        # White for CT-only

    VULN = "\033[1;91m"          # Bold bright red for VULNERABLE
    WARN = "\033[93m"            # Yellow for warnings/dangling
    OK = "\033[32m"              # Green for OK/not vulnerable
    CRITICAL = "\033[1;91m"      # Bold bright red for CRITICAL
    HIGH = "\033[91m"            # Red for high
    MEDIUM = "\033[93m"          # Yellow for medium
    LOW = "\033[36m"             # Cyan for low
    INFO_SEV = "\033[37m"        # White for info

    ARROW_R = "\033[93m"         # Yellow for →
    ARROW_L = "\033[36m"         # Cyan for ←
    PROVIDER = "\033[95m"        # Magenta for provider names
    TECH_NAME = "\033[96m"       # Bright cyan for tech names
    MATCH_TYPE = "\033[90m"      # Gray for match type brackets

    BORDER = "\033[90m"          # Gray for box borders
    HEADER = "\033[1;97m"        # Bold bright white for header
    SUMMARY_TITLE = "\033[1;37m" # Bold white for "Summary"

    TIME = "\033[92m"            # Green for time
    SAVED = "\033[96m"           # Cyan for saved file indicator


def _enable_windows_ansi():
    """Enable ANSI escape code processing on Windows."""
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # Enable ENABLE_VIRTUAL_TERMINAL_PROCESSING
            kernel32.SetConsoleMode(
                kernel32.GetStdHandle(-11), 0x0001 | 0x0002 | 0x0004
            )
        except Exception:
            pass


# Enable on import
_enable_windows_ansi()


# ─── Box Drawing Characters ──────────────────────────────────────────────────

BOX_TL = "┌"  # Top-left
BOX_TR = "┐"  # Top-right (not used, open right)
BOX_BL = "└"  # Bottom-left
BOX_BR = "┘"  # Bottom-right (not used)
BOX_H = "─"   # Horizontal
BOX_V = "│"   # Vertical

# Width of the summary box
BOX_WIDTH = 100


# ─── Helper Functions ─────────────────────────────────────────────────────────

def _severity_color(severity: str) -> str:
    """Get ANSI color for a severity level."""
    mapping = {
        "CRITICAL": C.CRITICAL,
        "high": C.HIGH,
        "medium": C.MEDIUM,
        "low": C.LOW,
        "info": C.INFO_SEV,
    }
    return mapping.get(severity, C.WHITE)


def _redact(text: str, visible_chars: int = 0) -> str:
    """Redact sensitive subdomain names for display."""
    if len(text) <= 8:
        return "\u2588" * len(text)
    parts = text.split(".")
    if len(parts) >= 3:
        # Show partial first part, redact middle
        redacted = "\u2588" * 6 + "." + "\u2588" * 4 + "." + ".".join(parts[-2:])
        return redacted
    return "\u2588" * 8 + "." + parts[-1] if len(parts) >= 2 else "\u2588" * len(text)


# ─── Main Renderer ────────────────────────────────────────────────────────────

class TerminalRenderer:
    """
    Renders ReconX scan results to the terminal with ANSI colors.
    Output format matches the reference image exactly.
    """

    def __init__(self, redact_subdomains: bool = False):
        self.redact = redact_subdomains
        self.lines: List[str] = []

    def _w(self, text: str = ""):
        """Write a line to output buffer and print."""
        print(text)
        self.lines.append(text)

    def _box_top(self, title: str = "Summary"):
        """Render the top border of the summary box."""
        title_str = f" {title} "
        remaining = BOX_WIDTH - len(title_str) - 1
        line = f"{C.BORDER}{BOX_TL}{BOX_H}{C.SUMMARY_TITLE}{title_str}{C.BORDER}{BOX_H * remaining}{C.RESET}"
        self._w(line)

    def _box_bottom(self):
        """Render the bottom border of the summary box."""
        line = f"{C.BORDER}{BOX_BL}{BOX_H * BOX_WIDTH}{C.RESET}"
        self._w(line)

    def _box_line(self, content: str):
        """Render a line inside the summary box."""
        line = f"{C.BORDER}{BOX_V}{C.RESET} {content}"
        self._w(line)

    def _box_empty(self):
        """Render an empty line inside the box."""
        self._box_line("")

    # ─── Section Renderers ────────────────────────────────────────────────

    def _render_infrastructure(self, result: ScanResult):
        """Render the Infrastructure line."""
        infra = result.infra
        parts = []
        parts.append(f"{C.VALUE_NUM}{infra.aws}{C.RESET} {C.VALUE_AWS}AWS{C.RESET}")
        parts.append(f"{C.VALUE_NUM}{infra.azure}{C.RESET} {C.VALUE_AZURE}Azure{C.RESET}")
        parts.append(f"{C.VALUE_NUM}{infra.cloudflare}{C.RESET} {C.VALUE_CF}Cloudflare{C.RESET}")
        parts.append(f"{C.VALUE_NUM}{infra.akamai}{C.RESET} {C.VALUE_AKAMAI}Akamai{C.RESET}")
        parts.append(f"{C.VALUE_OTHER}{infra.other} Other{C.RESET}")
        parts.append(f"{C.VALUE_CT}{infra.ct_only} CT-only{C.RESET}")

        content = f"{C.LABEL}Infrastructure:{C.RESET} {' {0} '.format(f'{C.BORDER}|{C.RESET}').join(parts)}"
        self._box_line(content)

    def _render_ct_triage(self, result: ScanResult):
        """Render the CT Triage line."""
        parts = []
        parts.append(f"{C.YELLOW}{result.ct_stale} stale{C.RESET} {C.DIM}(1-2yr){C.RESET}")
        parts.append(f"{C.RED}{result.ct_aged} aged{C.RESET} {C.DIM}(2yr+){C.RESET}")
        parts.append(f"{C.WHITE}{result.ct_no_date} no date{C.RESET}")

        content = f"{C.LABEL}CT Triage:{C.RESET} {f' {C.BORDER}|{C.RESET} '.join(parts)}"
        self._box_line(content)

    def _render_collapsed(self, result: ScanResult):
        """Render the Collapsed entries line."""
        c = result.collapse
        content = (
            f"{C.LABEL}Collapsed:{C.RESET} "
            f"{C.BRIGHT_GREEN}{c.total_entries} entries{C.RESET} "
            f"{C.BRIGHT_YELLOW}\u2192{C.RESET} "
            f"{C.BRIGHT_GREEN}{c.pattern_groups} pattern groups{C.RESET} "
            f"{C.DIM}(threshold: {c.threshold}+){C.RESET}"
        )
        self._box_line(content)

    def _render_takeover(self, result: ScanResult):
        """Render the Takeover section with vulnerability details."""
        vuln_count = result.vulnerable_count
        dangling_count = result.dangling_count
        not_vuln_count = result.not_vulnerable_count
        provider = result.takeover_provider

        # Main takeover line
        parts = []
        if vuln_count > 0:
            parts.append(
                f"\u26A0 {C.VULN}{vuln_count} VULNERABLE{C.RESET} "
                f"{C.DIM}({C.PROVIDER}{provider}{C.DIM}){C.RESET}"
            )
        if dangling_count > 0:
            parts.append(
                f"{C.WARN}{dangling_count} dangling CNAME(s){C.RESET}"
            )
        if not_vuln_count > 0:
            parts.append(
                f"{C.OK}{not_vuln_count} not vulnerable{C.RESET}"
            )

        content = f"{C.LABEL}Takeover:{C.RESET} {f' {C.BORDER}|{C.RESET} '.join(parts)}"
        self._box_line(content)

        # Show top entries (up to 3) - vulnerable first, then dangling
        display_entries = [
            r for r in result.takeover_results
            if r.status == TakeoverStatus.VULNERABLE
        ][:3]
        if not display_entries:
            display_entries = [
                r for r in result.takeover_results
                if r.status == TakeoverStatus.DANGLING
            ][:3]

        for entry in display_entries:
            sub_display = entry.subdomain
            line = (
                f"    {C.ARROW_R}\u2192{C.RESET} "
                f"{C.WHITE}{sub_display}{C.RESET} "
                f"{C.ARROW_L}\u2190{C.RESET} "
                f"{C.PROVIDER}{entry.provider}{C.RESET} "
                f"{C.MATCH_TYPE}[{entry.match_type}]{C.RESET}"
            )
            self._box_line(line)

    def _render_flagged(self, result: ScanResult):
        """Render the Flagged interesting subdomains line."""
        content = (
            f"{C.LABEL}Flagged:{C.RESET} "
            f"{C.BRIGHT_GREEN}{result.flagged_interesting}{C.RESET} "
            f"{C.WHITE}interesting subdomain(s){C.RESET}"
        )
        self._box_line(content)

    def _render_httpx(self, result: ScanResult):
        """Render the HTTPX HTTP Probe summary line."""
        stats = getattr(result, 'httpx_stats', {})
        available = getattr(result, 'httpx_available', False)

        if not available or not stats:
            return

        alive = stats.get("alive", 0)
        total = stats.get("total_probed", 0)
        cdn_count = stats.get("cdn_detected", 0)
        tech_count = stats.get("tech_detected", 0)
        favicon_count = stats.get("unique_favicon_hashes", 0)
        new_fqdns = stats.get("new_fqdns_discovered", 0)
        status_dist = stats.get("status_distribution", {})
        server_dist = stats.get("server_distribution", {})

        # Build parts
        parts = [
            f"{C.BRIGHT_GREEN}{alive}{C.RESET}{C.WHITE}/{total} alive{C.RESET}",
        ]

        # Status distribution — individual codes (200, 301, 403, ...)
        status_codes = stats.get("status_codes", {})
        status_parts = []
        if status_codes:
            for sc in sorted(status_codes.keys()):
                cnt = status_codes[sc]
                sc_class = sc // 100
                color = (
                    C.BRIGHT_GREEN if sc_class == 2
                    else C.BRIGHT_YELLOW if sc_class == 3
                    else C.BRIGHT_RED if sc_class in (4, 5)
                    else C.WHITE
                )
                status_parts.append(f"{color}{cnt}\u00d7{sc}{C.RESET}")
        else:
            # Fallback to range-based distribution
            for code_range in sorted(status_dist.keys()):
                cnt = status_dist[code_range]
                color = (
                    C.BRIGHT_GREEN if code_range == "2xx"
                    else C.BRIGHT_YELLOW if code_range == "3xx"
                    else C.BRIGHT_RED if code_range in ("4xx", "5xx")
                    else C.WHITE
                )
                status_parts.append(f"{color}{cnt} {code_range}{C.RESET}")
        if status_parts:
            parts.append(" ".join(status_parts))

        if cdn_count > 0:
            parts.append(f"{C.BRIGHT_MAGENTA}{cdn_count} CDN{C.RESET}")
        if tech_count > 0:
            parts.append(f"{C.BRIGHT_CYAN}{tech_count} tech{C.RESET}")
        if favicon_count > 0:
            parts.append(f"{C.YELLOW}{favicon_count} favicons{C.RESET}")

        content = f"{C.LABEL}httpx:{C.RESET} {f' {C.BORDER}|{C.RESET} '.join(parts)}"
        self._box_line(content)

        # Show top servers
        if server_dist:
            top_servers = sorted(server_dist.items(), key=lambda x: -x[1])[:5]
            srv_parts = [
                f"{C.DIM}{name}{C.RESET}({C.WHITE}{cnt}{C.RESET})"
                for name, cnt in top_servers
            ]
            self._box_line(f"    {C.DIM}Servers:{C.RESET} {', '.join(srv_parts)}")

        # New FQDNs discovered
        if new_fqdns > 0:
            self._box_line(
                f"    {C.BRIGHT_GREEN}\u2728 {new_fqdns} new FQDNs{C.RESET} "
                f"{C.DIM}discovered from response bodies{C.RESET}"
            )

    def _render_tech(self, result: ScanResult):
        """
        Render the Tech section with severity breakdown and narrative details.
        Matches the reference image pattern where tech findings are shown as:
        - Summary line with severity counts and tech name breakdowns
        - Grouped narrative entries showing (subdomain redacted) ← TechName [Location] – Description
        - Multiple groups repeating the same tech descriptions for different subdomain clusters
        """
        severity_groups = result.tech_severity_summary

        # ── Build the summary line ────────────────────────────────────────
        severity_parts = []

        for sev_label in ["CRITICAL", "high", "medium", "low", "info"]:
            if sev_label not in severity_groups:
                continue

            matches = severity_groups[sev_label]
            count = len(matches)
            color = _severity_color(sev_label)

            # Count per unique tech name
            tech_counts = Counter(m.tech.name for m in matches)
            tech_str = ", ".join(
                f"{name}({cnt})" for name, cnt in tech_counts.items()
            )

            prefix = ""
            if sev_label == "CRITICAL":
                prefix = f"{C.CRITICAL}!!{C.RESET} "

            severity_parts.append(
                f"{prefix}{color}{count} {sev_label}{C.RESET} "
                f"{C.DIM}({tech_str}){C.RESET}"
            )

        content = f"{C.LABEL}Tech:{C.RESET} {f' {C.BORDER}|{C.RESET} '.join(severity_parts)}"
        self._box_line(content)

        # ── Render narrative entries ──────────────────────────────────────
        # Reference image pattern: only CRITICAL and HIGH get narrative rows.
        # Entries are grouped by subdomain clusters showing tech pairs.
        #
        # Pattern from reference (7 narrative rows):
        #   ████.████.███  ← Spring Boot Actuator [Body] – ...
        #   ████.████.███  ← Spring Boot [Body] – ...
        #   ████.████.███  ← Apache Tomcat [Body] – ...
        #   ████.████.███  ← Spring Boot Actuator [Body] – ...  (group 2)
        #   ████.████.███  ← Spring Boot [Body] – ...           (group 2)
        #          ← Spring Boot Actuator [Body] – ...           (group 3, indent)
        #          ← Spring Boot [Body] – ...                    (group 3, indent)

        # Collect matches per subdomain for CRITICAL and HIGH, preserving order
        from collections import OrderedDict
        sub_matches = OrderedDict()

        # Use original tech_matches list to preserve subdomain ordering
        # Show CRITICAL and HIGH first; fall back to all if none exist
        all_crit_high = [
            m for m in result.tech_matches
            if m.tech.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        if not all_crit_high:
            # Fall back: show all severity levels in narratives
            all_crit_high = list(result.tech_matches)

        # Build ordered subdomain groups from original match order
        for m in all_crit_high:
            if m.subdomain not in sub_matches:
                sub_matches[m.subdomain] = []
            existing = [x.tech.name for x in sub_matches[m.subdomain]]
            if m.tech.name not in existing:
                sub_matches[m.subdomain].append(m)

        indent_sub = "    "     # 4 spaces for entries with subdomain shown

        for sub_hostname, matches_list in sub_matches.items():
            for match in matches_list:
                # Always show subdomain name with every tech match
                sub_display = sub_hostname
                line = (
                    f"{indent_sub}"
                    f"{C.DIM}{sub_display}{C.RESET}  "
                    f"{C.ARROW_L}\u2190{C.RESET} "
                    f"{C.TECH_NAME}{match.tech.name}{C.RESET} "
                    f"{C.MATCH_TYPE}[{match.match_location}]{C.RESET} "
                    f"{C.DIM}\u2013{C.RESET} "
                    f"{C.WHITE}{match.tech.description}{C.RESET}"
                )

                self._box_line(line)

    def _render_nuclei(self, result: ScanResult):
        """Render the Nuclei vulnerability scan summary."""
        nuclei_stats = getattr(result, 'nuclei_stats', {})
        nuclei_available = getattr(result, 'nuclei_available', False)
        nuclei_results = getattr(result, 'nuclei_results', [])

        if not nuclei_available or not nuclei_stats:
            return

        total = nuclei_stats.get("total_findings", 0)
        critical = nuclei_stats.get("critical", 0)
        high = nuclei_stats.get("high", 0)
        medium = nuclei_stats.get("medium", 0)
        low = nuclei_stats.get("low", 0)
        info = nuclei_stats.get("info", 0)
        hosts_scanned = nuclei_stats.get("hosts_scanned", 0)
        scan_time = nuclei_stats.get("scan_time", 0.0)

        if total == 0 and hosts_scanned == 0:
            return

        # Severity color map
        sev_color = {
            "critical": C.VULN,
            "high": C.BRIGHT_RED,
            "medium": C.BRIGHT_YELLOW,
            "low": C.BRIGHT_CYAN,
            "info": C.WHITE,
        }

        # Main nuclei line
        parts = [
            f"{C.BRIGHT_GREEN}{total}{C.RESET}{C.WHITE} finding(s){C.RESET}",
            f"{C.WHITE}{hosts_scanned} hosts scanned{C.RESET}",
        ]
        content = (
            f"{C.LABEL}Nuclei:{C.RESET} "
            f"{f' {C.BORDER}|{C.RESET} '.join(parts)} "
            f"{C.DIM}({scan_time:.1f}s){C.RESET}"
        )
        self._box_line(content)

        # Severity breakdown
        sev_parts = []
        if critical > 0:
            sev_parts.append(f"{sev_color['critical']}{critical} critical{C.RESET}")
        if high > 0:
            sev_parts.append(f"{sev_color['high']}{high} high{C.RESET}")
        if medium > 0:
            sev_parts.append(f"{sev_color['medium']}{medium} medium{C.RESET}")
        if low > 0:
            sev_parts.append(f"{sev_color['low']}{low} low{C.RESET}")
        if info > 0:
            sev_parts.append(f"{sev_color['info']}{info} info{C.RESET}")
        if sev_parts:
            self._box_line(f"    {C.DIM}Severity:{C.RESET} {', '.join(sev_parts)}")

        # Show critical/high findings detail (limit to 10)
        shown = 0
        for finding in nuclei_results:
            sev = finding.severity if hasattr(finding, 'severity') else finding.get('severity', '')
            if sev not in ('critical', 'high'):
                continue
            tid = finding.template_id if hasattr(finding, 'template_id') else finding.get('template_id', '')
            tname = finding.template_name if hasattr(finding, 'template_name') else finding.get('template_name', tid)
            host = finding.host if hasattr(finding, 'host') else finding.get('host', '')
            color = sev_color.get(sev, C.WHITE)
            self._box_line(
                f"    {color}!! [{sev.upper()}] {tname}{C.RESET} {C.DIM}→{C.RESET} {C.WHITE}{host}{C.RESET}"
            )
            shown += 1
            if shown >= 10:
                remaining = sum(1 for f in nuclei_results
                    if (f.severity if hasattr(f, 'severity') else f.get('severity', ''))
                    in ('critical', 'high')) - shown
                if remaining > 0:
                    self._box_line(f"    {C.DIM}... and {remaining} more critical/high findings{C.RESET}")
                break

    def _render_nmap(self, result: ScanResult):
        """Render the Nmap port scan summary line."""
        nmap_stats = getattr(result, 'nmap_stats', {})
        nmap_available = getattr(result, 'nmap_available', False)

        if not nmap_available or not nmap_stats:
            return

        hosts_up = nmap_stats.get("hosts_up", 0)
        total_scanned = nmap_stats.get("total_ips_scanned", 0)
        open_ports = nmap_stats.get("total_open_ports", 0)
        unique_services = nmap_stats.get("unique_services", 0)
        scan_time = nmap_stats.get("scan_time", 0.0)
        top_ports = nmap_stats.get("top_ports", [])
        top_services = nmap_stats.get("top_services", [])

        # Main nmap line
        parts = [
            f"{C.BRIGHT_GREEN}{hosts_up}{C.RESET}{C.WHITE}/{total_scanned} hosts up{C.RESET}",
            f"{C.BRIGHT_GREEN}{open_ports}{C.RESET}{C.WHITE} open ports{C.RESET}",
            f"{C.BRIGHT_CYAN}{unique_services}{C.RESET}{C.WHITE} services{C.RESET}",
        ]

        content = (
            f"{C.LABEL}Nmap:{C.RESET} "
            f"{f' {C.BORDER}|{C.RESET} '.join(parts)} "
            f"{C.DIM}({scan_time:.1f}s){C.RESET}"
        )
        self._box_line(content)

        # Top services
        if top_services:
            svc_parts = [
                f"{C.DIM}{s['service']}{C.RESET}({C.WHITE}{s['count']}{C.RESET})"
                for s in top_services[:5]
            ]
            self._box_line(f"    {C.DIM}Services:{C.RESET} {', '.join(svc_parts)}")

        # Top ports
        if top_ports:
            port_parts = [
                f"{C.BRIGHT_YELLOW}{p['port']}{C.RESET}({C.WHITE}{p['count']}{C.RESET})"
                for p in top_ports[:8]
            ]
            self._box_line(f"    {C.DIM}Top ports:{C.RESET} {', '.join(port_parts)}")

    def _render_enum4linux(self, result: ScanResult):
        """Render the Enum4linux SMB/Windows enumeration summary."""
        enum_stats = getattr(result, 'enum4linux_stats', {})
        enum_available = getattr(result, 'enum4linux_available', False)
        enum_results = getattr(result, 'enum4linux_results', {})

        if not enum_available or not enum_stats:
            return

        hosts_responded = enum_stats.get("hosts_responded", 0)
        total_scanned = enum_stats.get("total_ips_scanned", 0)
        total_shares = enum_stats.get("total_shares", 0)
        total_users = enum_stats.get("total_users", 0)
        total_groups = enum_stats.get("total_groups", 0)
        null_sessions = enum_stats.get("null_sessions", 0)
        hosts_with_shares = enum_stats.get("hosts_with_shares", 0)
        hosts_with_users = enum_stats.get("hosts_with_users", 0)
        scan_time = enum_stats.get("scan_time", 0.0)

        if hosts_responded == 0:
            return

        # Main enum4linux line
        parts = [
            f"{C.BRIGHT_GREEN}{hosts_responded}{C.RESET}{C.WHITE}/{total_scanned} hosts{C.RESET}",
        ]
        if total_shares > 0:
            parts.append(f"{C.BRIGHT_CYAN}{total_shares}{C.RESET}{C.WHITE} shares{C.RESET}")
        if total_users > 0:
            parts.append(f"{C.BRIGHT_CYAN}{total_users}{C.RESET}{C.WHITE} users{C.RESET}")
        if total_groups > 0:
            parts.append(f"{C.BRIGHT_CYAN}{total_groups}{C.RESET}{C.WHITE} groups{C.RESET}")

        content = (
            f"{C.LABEL}Enum4linux:{C.RESET} "
            f"{f' {C.BORDER}|{C.RESET} '.join(parts)} "
            f"{C.DIM}({scan_time:.1f}s){C.RESET}"
        )
        self._box_line(content)

        # Null session warning (critical finding)
        if null_sessions > 0:
            self._box_line(
                f"    {C.VULN}!! {null_sessions} host(s) allow null sessions{C.RESET} "
                f"{C.DIM}(anonymous access){C.RESET}"
            )

        # Show discovered shares summary
        if enum_results and total_shares > 0:
            share_names = []
            for ip, host_result in enum_results.items():
                shares = []
                if hasattr(host_result, 'shares'):
                    shares = host_result.shares
                elif isinstance(host_result, dict):
                    shares = host_result.get('shares', [])
                for s in shares:
                    name = s.name if hasattr(s, 'name') else s.get('name', '')
                    if name and name not in share_names:
                        share_names.append(name)
            if share_names:
                shares_display = ", ".join(
                    f"{C.DIM}{name}{C.RESET}" for name in share_names[:10]
                )
                extra = f" {C.DIM}(+{len(share_names) - 10} more){C.RESET}" if len(share_names) > 10 else ""
                self._box_line(f"    {C.DIM}Shares:{C.RESET} {shares_display}{extra}")

        # Show discovered users summary
        if enum_results and total_users > 0:
            all_usernames = []
            for ip, host_result in enum_results.items():
                users = []
                if hasattr(host_result, 'users'):
                    users = host_result.users
                elif isinstance(host_result, dict):
                    users = host_result.get('users', [])
                for u in users:
                    username = u.username if hasattr(u, 'username') else u.get('username', '')
                    if username and username not in all_usernames:
                        all_usernames.append(username)
            if all_usernames:
                users_display = ", ".join(
                    f"{C.BRIGHT_YELLOW}{name}{C.RESET}" for name in all_usernames[:8]
                )
                extra = f" {C.DIM}(+{len(all_usernames) - 8} more){C.RESET}" if len(all_usernames) > 8 else ""
                self._box_line(f"    {C.DIM}Users:{C.RESET} {users_display}{extra}")

    def _render_cme(self, result: ScanResult):
        """Render the CrackMapExec protocol enumeration summary."""
        cme_stats = getattr(result, 'cme_stats', {})
        cme_available = getattr(result, 'cme_available', False)
        cme_results = getattr(result, 'cme_results', {})

        if not cme_available or not cme_stats:
            return

        protocols_scanned = cme_stats.get("protocols_scanned", 0)
        total_hosts = cme_stats.get("total_hosts_discovered", 0)
        protocol_summary = cme_stats.get("protocol_summary", {})
        scan_time = cme_stats.get("scan_time", 0.0)

        if protocols_scanned == 0:
            return

        # Protocol colors for summary box
        proto_color_map = {
            "smb": C.BRIGHT_BLUE,
            "ssh": C.BRIGHT_GREEN,
            "rdp": C.BRIGHT_YELLOW,
            "mssql": C.BRIGHT_RED,
            "ldap": C.BRIGHT_CYAN,
            "winrm": C.BRIGHT_MAGENTA,
            "wmi": C.YELLOW,
            "vnc": C.MAGENTA,
            "ftp": C.CYAN,
        }

        # Main CME line
        parts = [
            f"{C.BRIGHT_GREEN}{protocols_scanned}{C.RESET}{C.WHITE} protocols{C.RESET}",
            f"{C.BRIGHT_GREEN}{total_hosts}{C.RESET}{C.WHITE} hosts responded{C.RESET}",
        ]
        content = (
            f"{C.LABEL}CME:{C.RESET} "
            f"{f' {C.BORDER}|{C.RESET} '.join(parts)} "
            f"{C.DIM}({scan_time:.1f}s){C.RESET}"
        )
        self._box_line(content)

        # Protocol breakdown
        if protocol_summary:
            proto_parts = []
            for proto in ["smb", "ssh", "rdp", "winrm", "mssql", "ldap", "wmi", "vnc", "ftp"]:
                count = protocol_summary.get(proto, 0)
                if count > 0:
                    color = proto_color_map.get(proto, C.WHITE)
                    proto_parts.append(
                        f"{color}{proto}{C.RESET}({C.WHITE}{count}{C.RESET})"
                    )
            if proto_parts:
                self._box_line(f"    {C.DIM}Protocols:{C.RESET} {', '.join(proto_parts)}")

        # Highlight SMB signing disabled
        if cme_results:
            smb_result = cme_results.get("smb")
            if smb_result:
                # Count hosts with signing not required
                nosign_count = 0
                if hasattr(smb_result, 'host_results'):
                    nosign_count = sum(
                        1 for h in smb_result.host_results
                        if h.signing == "not required"
                    )
                elif isinstance(smb_result, dict):
                    for h in smb_result.get('host_results', []):
                        if isinstance(h, dict) and h.get('signing') == 'not required':
                            nosign_count += 1

                if nosign_count > 0:
                    self._box_line(
                        f"    {C.VULN}!! {nosign_count} host(s) SMB signing disabled{C.RESET} "
                        f"{C.DIM}(relay targets){C.RESET}"
                    )

    def _render_msf(self, result: ScanResult):
        """Render MSF SMB brute-force results summary."""
        msf_stats = getattr(result, 'msf_stats', {})
        msf_available = getattr(result, 'msf_available', False)
        msf_results = getattr(result, 'msf_results', {})

        if not msf_available or not msf_stats:
            return

        total_ips = msf_stats.get("total_ips", 0)
        ips_tested = msf_stats.get("ips_tested", 0)
        ips_skipped = msf_stats.get("ips_skipped", 0)
        total_users = msf_stats.get("total_users_tested", 0)
        creds_found = msf_stats.get("credentials_found", 0)
        scan_time = msf_stats.get("scan_time", 0.0)

        if total_ips == 0:
            return

        # Main MSF line
        parts = [
            f"{C.BRIGHT_GREEN}{ips_tested}{C.RESET}{C.WHITE}/{total_ips} IPs tested{C.RESET}",
            f"{C.BRIGHT_GREEN}{total_users}{C.RESET}{C.WHITE} users tested{C.RESET}",
        ]
        if creds_found > 0:
            parts.append(
                f"{C.VULN}{creds_found} credentials found{C.RESET}"
            )
        else:
            parts.append(
                f"{C.DIM}0 credentials{C.RESET}"
            )
        if ips_skipped > 0:
            parts.append(
                f"{C.BRIGHT_YELLOW}{ips_skipped} skipped{C.RESET}"
            )
        content = (
            f"{C.LABEL}MSF-Brute:{C.RESET} "
            f"{f' {C.BORDER}|{C.RESET} '.join(parts)} "
            f"{C.DIM}({scan_time:.1f}s){C.RESET}"
        )
        self._box_line(content)

        # Show found credentials
        if creds_found > 0 and msf_results:
            for ip, host_result in msf_results.items():
                creds = []
                if hasattr(host_result, 'credentials'):
                    creds = host_result.credentials
                elif isinstance(host_result, dict):
                    creds = host_result.get('credentials', [])
                for cred in creds:
                    user = cred.username if hasattr(cred, 'username') else cred.get('username', '')
                    pwd = cred.password if hasattr(cred, 'password') else cred.get('password', '')
                    domain = cred.domain if hasattr(cred, 'domain') else cred.get('domain', '')
                    domain_str = f"{domain}\\" if domain else ""
                    self._box_line(
                        f"    {C.VULN}!! {ip} {domain_str}{user}:{pwd}{C.RESET}"
                    )

    def _render_rdp(self, result: ScanResult):
        """Render RDP brute-force results summary."""
        rdp_stats = getattr(result, 'rdp_stats', {})
        rdp_available = getattr(result, 'rdp_available', False)
        rdp_results = getattr(result, 'rdp_results', {})

        if not rdp_available or not rdp_stats:
            return

        total_hosts = rdp_stats.get("total_rdp_hosts", 0)
        hosts_tested = rdp_stats.get("hosts_tested", 0)
        hosts_skipped = rdp_stats.get("hosts_skipped", 0)
        total_users = rdp_stats.get("total_users_tested", 0)
        creds_found = rdp_stats.get("credentials_found", 0)
        pwned_count = rdp_stats.get("pwned_count", 0)
        scan_time = rdp_stats.get("scan_time", 0.0)

        if total_hosts == 0:
            return

        # Main RDP line
        parts = [
            f"{C.BRIGHT_GREEN}{hosts_tested}{C.RESET}{C.WHITE}/{total_hosts} RDP hosts tested{C.RESET}",
            f"{C.BRIGHT_GREEN}{total_users}{C.RESET}{C.WHITE} users tested{C.RESET}",
        ]
        if creds_found > 0:
            parts.append(
                f"{C.VULN}{creds_found} credentials found{C.RESET}"
            )
            if pwned_count > 0:
                parts.append(
                    f"\033[1;91m{pwned_count} Pwn3d!\033[0m"
                )
        else:
            parts.append(
                f"{C.DIM}0 credentials{C.RESET}"
            )
        if hosts_skipped > 0:
            parts.append(
                f"{C.BRIGHT_YELLOW}{hosts_skipped} skipped{C.RESET}"
            )
        content = (
            f"{C.LABEL}RDP-Brute:{C.RESET} "
            f"{f' {C.BORDER}|{C.RESET} '.join(parts)} "
            f"{C.DIM}({scan_time:.1f}s){C.RESET}"
        )
        self._box_line(content)

        # Show found credentials
        if creds_found > 0 and rdp_results:
            for ip, host_result in rdp_results.items():
                creds = []
                if hasattr(host_result, 'credentials'):
                    creds = host_result.credentials
                elif isinstance(host_result, dict):
                    creds = host_result.get('credentials', [])
                for cred in creds:
                    user = cred.username if hasattr(cred, 'username') else cred.get('username', '')
                    pwd = cred.password if hasattr(cred, 'password') else cred.get('password', '')
                    domain = cred.domain if hasattr(cred, 'domain') else cred.get('domain', '')
                    pwned = cred.pwned if hasattr(cred, 'pwned') else cred.get('pwned', False)
                    domain_str = f"{domain}\\" if domain else ""
                    pwn_str = " (Pwn3d!)" if pwned else ""
                    self._box_line(
                        f"    {C.VULN}!! {ip} {domain_str}{user}:{pwd}{pwn_str}{C.RESET}"
                    )

    def _render_wpscan(self, result: ScanResult):
        """Render the WPScan WordPress scan summary."""
        wpscan_stats = getattr(result, 'wpscan_stats', {})
        wpscan_available = getattr(result, 'wpscan_available', False)
        wpscan_results = getattr(result, 'wpscan_results', {})

        if not wpscan_available or not wpscan_stats:
            return

        targets_scanned = wpscan_stats.get("targets_scanned", 0)
        targets_with_vulns = wpscan_stats.get("targets_with_vulns", 0)
        total_vulns = wpscan_stats.get("total_vulns", 0)
        total_plugins = wpscan_stats.get("total_plugins", 0)
        total_users = wpscan_stats.get("total_users", 0)
        outdated_plugins = wpscan_stats.get("outdated_plugins", 0)
        config_backups = wpscan_stats.get("config_backups", 0)
        db_exports = wpscan_stats.get("db_exports", 0)
        scan_time = wpscan_stats.get("scan_time", 0.0)

        if targets_scanned == 0:
            return

        # Main wpscan line
        parts = [
            f"{C.BRIGHT_GREEN}{targets_scanned}{C.RESET}{C.WHITE} WordPress target(s){C.RESET}",
        ]
        if total_vulns > 0:
            parts.append(f"{C.VULN}{total_vulns} vuln(s){C.RESET}")
        if total_plugins > 0:
            parts.append(f"{C.CYAN}{total_plugins} plugin(s){C.RESET}")
        if total_users > 0:
            parts.append(f"{C.WHITE}{total_users} user(s){C.RESET}")
        content = (
            f"{C.LABEL}WPScan:{C.RESET} "
            f"{f' {C.BORDER}|{C.RESET} '.join(parts)} "
            f"{C.DIM}({scan_time:.1f}s){C.RESET}"
        )
        self._box_line(content)

        # Detail line
        detail_parts = []
        if outdated_plugins > 0:
            detail_parts.append(f"{C.BRIGHT_YELLOW}{outdated_plugins} outdated plugin(s){C.RESET}")
        if config_backups > 0:
            detail_parts.append(f"{C.VULN}{config_backups} config backup(s){C.RESET}")
        if db_exports > 0:
            detail_parts.append(f"{C.VULN}{db_exports} DB export(s){C.RESET}")
        if targets_with_vulns > 0:
            detail_parts.append(f"{C.BRIGHT_RED}{targets_with_vulns} vulnerable target(s){C.RESET}")
        if detail_parts:
            self._box_line(f"    {C.DIM}Details:{C.RESET} {', '.join(detail_parts)}")

        # Show per-target vulnerabilities (limit to 10)
        shown = 0
        for url, host_result in wpscan_results.items():
            # Core vulns
            vulns = host_result.vulnerabilities if hasattr(host_result, 'vulnerabilities') else []
            for v in vulns:
                title = v.title if hasattr(v, 'title') else v.get('title', '')
                self._box_line(
                    f"    {C.VULN}!! [CORE] {title}{C.RESET} {C.DIM}→{C.RESET} {C.WHITE}{url}{C.RESET}"
                )
                shown += 1
                if shown >= 10:
                    break
            if shown >= 10:
                break

            # Plugin vulns
            plugins = host_result.plugins if hasattr(host_result, 'plugins') else []
            for p in plugins:
                p_vulns = p.vulnerabilities if hasattr(p, 'vulnerabilities') else []
                p_slug = p.slug if hasattr(p, 'slug') else p.get('slug', '')
                for v in p_vulns:
                    title = v.title if hasattr(v, 'title') else v.get('title', '')
                    self._box_line(
                        f"    {C.BRIGHT_RED}!! [{p_slug}] {title}{C.RESET} {C.DIM}→{C.RESET} {C.WHITE}{url}{C.RESET}"
                    )
                    shown += 1
                    if shown >= 10:
                        break
                if shown >= 10:
                    break
            if shown >= 10:
                break

        if shown >= 10:
            remaining = total_vulns - shown
            if remaining > 0:
                self._box_line(f"    {C.DIM}... and {remaining} more vulnerability/ies{C.RESET}")

    def _render_stats(self, result: ScanResult):
        """Render the Time/Total/DB stats line."""
        parts = [
            f"{C.LABEL}Time:{C.RESET} {C.TIME}{result.scan_time:.1f}s{C.RESET}",
            f"{C.LABEL}Total:{C.RESET} {C.BRIGHT_GREEN}{result.total_unique} unique{C.RESET}",
            f"{C.LABEL}TakeoverDB:{C.RESET} {C.CYAN}{result.takeover_db_services} services{C.RESET}",
            f"{C.LABEL}TechDB:{C.RESET} {C.CYAN}{result.tech_db_signatures} signatures{C.RESET}",
        ]
        content = f" {C.BORDER}|{C.RESET} ".join(parts)
        self._box_line(content)

    def _render_sources(self, result: ScanResult):
        """Render the Sources statistics line."""
        parts = []
        for name, stats in result.source_stats.items():
            parts.append(
                f"{C.BRIGHT_CYAN}{stats.name}{C.RESET} "
                f"{C.BRIGHT_GREEN}{stats.count}{C.RESET}"
            )

        content = f"{C.LABEL}Sources:{C.RESET} {f' {C.BORDER}|{C.RESET} '.join(parts)}"
        self._box_line(content)

    # ─── Main Print Function ──────────────────────────────────────────────

    def print_summary(self, result: ScanResult):
        """
        Render the complete scan summary to terminal.
        This is the primary output function that produces the
        reference image-matching output.
        """
        self.lines = []

        # Top border with title
        self._box_top("Summary")

        # Infrastructure
        self._render_infrastructure(result)

        # CT Triage
        self._render_ct_triage(result)

        # Collapsed
        self._render_collapsed(result)

        # Takeover
        self._render_takeover(result)

        # Flagged
        self._render_flagged(result)

        # HTTPX Probe
        self._render_httpx(result)

        # Nuclei
        self._render_nuclei(result)

        # Tech
        self._render_tech(result)

        # Nmap
        self._render_nmap(result)

        # Enum4linux
        self._render_enum4linux(result)

        # CrackMapExec
        self._render_cme(result)

        # MSF SMB Brute-force
        self._render_msf(result)

        # RDP Brute-force
        self._render_rdp(result)

        # WPScan WordPress
        self._render_wpscan(result)

        # Stats
        self._render_stats(result)

        # Sources
        self._render_sources(result)

        # Bottom border
        self._box_bottom()

    def print_saved(self, filename: str):
        """Print the 'Saved to' footer message."""
        self._w("")
        self._w(
            f"{C.BRIGHT_WHITE}[{C.BRIGHT_GREEN}*{C.BRIGHT_WHITE}]{C.RESET} "
            f"{C.WHITE}Saved to{C.RESET} "
            f"{C.SAVED}{filename}{C.RESET}"
        )
