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

        # Status distribution
        status_parts = []
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
        """Render the Nuclei vulnerability scan results section."""
        from ..scanner.nuclei_scan import NUCLEI_SEVERITY_COLORS

        nuclei_results = getattr(result, 'nuclei_results', [])
        nuclei_stats = getattr(result, 'nuclei_stats', {})
        nuclei_available = getattr(result, 'nuclei_available', False)

        if not nuclei_available:
            return

        total = nuclei_stats.get("total_findings", 0)
        crit = nuclei_stats.get("critical", 0)
        high = nuclei_stats.get("high", 0)
        med = nuclei_stats.get("medium", 0)
        low = nuclei_stats.get("low", 0)
        info = nuclei_stats.get("info", 0)
        scan_time = nuclei_stats.get("scan_time", 0.0)
        tags_used = nuclei_stats.get("tags_used", [])

        # Summary line
        sev_parts = []
        if crit > 0:
            sev_parts.append(f"{C.CRITICAL}!! {crit} critical{C.RESET}")
        if high > 0:
            sev_parts.append(f"{C.HIGH}{high} high{C.RESET}")
        if med > 0:
            sev_parts.append(f"{C.MEDIUM}{med} medium{C.RESET}")
        if low > 0:
            sev_parts.append(f"{C.LOW}{low} low{C.RESET}")
        if info > 0:
            sev_parts.append(f"{C.INFO_SEV}{info} info{C.RESET}")

        if not sev_parts:
            sev_parts.append(f"{C.BRIGHT_GREEN}0 findings{C.RESET}")

        sev_str = f" {C.BORDER}|{C.RESET} ".join(sev_parts)
        content = (
            f"{C.LABEL}Nuclei:{C.RESET} "
            f"{C.BRIGHT_GREEN}{total} findings{C.RESET} "
            f"({sev_str}) "
            f"{C.DIM}({scan_time:.1f}s){C.RESET}"
        )
        self._box_line(content)

        # Tags used (show tech-detected extras only)
        if tags_used:
            base_tags = {"vuln", "cve", "discovery", "vkev", "panel", "xss"}
            extras = [t for t in tags_used if t not in base_tags]
            if extras:
                self._box_line(
                    f"    {C.DIM}Tech tags:{C.RESET} "
                    f"{C.BRIGHT_YELLOW}{', '.join(extras)}{C.RESET}"
                )

        # Show top findings (critical and high first, then medium)
        if nuclei_results:
            shown = 0
            max_display = 10
            sev_order = ["critical", "high", "medium", "low", "info"]

            for sev in sev_order:
                for r in nuclei_results:
                    if r.severity != sev:
                        continue
                    if shown >= max_display:
                        break

                    sev_color = NUCLEI_SEVERITY_COLORS.get(r.severity, C.WHITE)
                    host_display = r.host.replace("https://", "").replace("http://", "").rstrip("/")

                    self._box_line(
                        f"    {sev_color}[{r.severity.upper()}]{C.RESET} "
                        f"{C.TECH_NAME}{r.template_name}{C.RESET} "
                        f"{C.DIM}\u2192{C.RESET} "
                        f"{C.WHITE}{host_display}{C.RESET}"
                    )
                    shown += 1
                if shown >= max_display:
                    break

            remaining = total - shown
            if remaining > 0:
                self._box_line(
                    f"    {C.DIM}... and {remaining} more finding(s){C.RESET}"
                )

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

        # Tech
        self._render_tech(result)

        # Nuclei
        self._render_nuclei(result)

        # Nmap
        self._render_nmap(result)

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
