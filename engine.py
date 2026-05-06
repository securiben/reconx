"""
ReconX Engine - Main orchestrator.
Coordinates all data sources, scanners, and output rendering.
Manages concurrent execution and result aggregation.
"""

import os
import sys
import time
import pickle
import random
import signal
import subprocess
import threading
from typing import Dict, List, Optional
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import ReconConfig
from .models import (
    ScanResult, Subdomain, SourceStats, InfraStats,
    CollapseStats, TakeoverResult, TakeoverStatus,
    TechMatch, Severity,
)
from .sources import (
    AtlasSource, SphinxSource, OracleSource,
    RadarSource, TorrentSource, VenomSource,
    ShodanSource, CensysSource, SecurityTrailsSource, URLScanSource,
    VTSiblingsSource,
    ChaosSource, CommonCrawlSource, FOFASource, ZoomEyeSource,
    ASNExpansionSource,
)
from .sources.base import BaseSource
from .scanner import (
    InfrastructureScanner, CTLogScanner,
    TakeoverScanner, TechProfiler, HttpxProbe,
    NmapScanner, NucleiScanner, Enum4linuxScanner, CMEScanner,
    MSFSMBBruteScanner, RDPBruteScanner, VNCBruteScanner, SMBBruteScanner, WPScanner, SMBClientScanner,
    KatanaScanner, DirsearchScanner, SNMPLoginScanner, SNMPEnumScanner,
    SSHLoginScanner,
    MongoDBLoginScanner,
    FTPLoginScanner,
    PostgresLoginScanner,
    NetExecModuleScanner,
    ServiceMisconfigScanner,
    AIAnalyst,
)
from .output.terminal import TerminalRenderer
from .output.json_export import JSONExporter
from .output.file_export import FileExporter
from .utils import collapse_subdomains, is_interesting_subdomain, sanitize_hostname


class ReconEngine:
    """
    Main ReconX engine.
    Orchestrates the entire reconnaissance pipeline:
    1. Fetch subdomains from all sources (concurrent)
    2. Deduplicate and aggregate
    3. Run infrastructure classification
    4. Run CT log triage
    5. Run subdomain takeover checks
    6. Run tech stack profiling
    7. Compute statistics
    8. Render output
    9. Export to JSON
    """

    def __init__(self, config: ReconConfig):
        self.config = config
        self.result = ScanResult(target_domain=config.target_domain)
        self.renderer = TerminalRenderer(redact_subdomains=False)
        self.exporter = JSONExporter(pretty=True)
        self.file_exporter = FileExporter(base_dir="targets")

        # Initialize sources
        self.sources: Dict[str, BaseSource] = {}
        self._init_sources()

        # Initialize scanners
        self.infra_scanner = InfrastructureScanner(config.scanner)
        self.ct_scanner = CTLogScanner(config.scanner)
        self.takeover_scanner = TakeoverScanner(config.scanner)
        self.tech_profiler = TechProfiler(config.scanner)
        self.httpx_probe = HttpxProbe(config.scanner)
        self.nuclei_scanner = NucleiScanner(config.scanner)
        self.nmap_scanner = NmapScanner(config.scanner)
        self.enum4linux_scanner = Enum4linuxScanner(config.scanner)
        self.cme_scanner = CMEScanner(config.scanner)
        self.msf_scanner = MSFSMBBruteScanner(config.scanner)
        self.rdp_scanner = RDPBruteScanner(config.scanner)
        self.vnc_scanner = VNCBruteScanner(config.scanner)
        self.smb_brute_scanner = SMBBruteScanner(config.scanner)
        self.wpscan_scanner = WPScanner(config.scanner)
        self.smbclient_scanner = SMBClientScanner(config.scanner)
        self.katana_scanner = KatanaScanner(config.scanner)
        self.dirsearch_scanner = DirsearchScanner(config.scanner)
        self.snmp_login_scanner = SNMPLoginScanner(config.scanner)
        self.snmp_enum_scanner = SNMPEnumScanner(config.scanner)
        self.ssh_login_scanner = SSHLoginScanner(config.scanner)
        self.mongodb_login_scanner = MongoDBLoginScanner(config.scanner)
        self.ftp_login_scanner = FTPLoginScanner(config.scanner)
        self.postgres_login_scanner = PostgresLoginScanner(config.scanner)
        self.netexec_module_scanner = NetExecModuleScanner(config.scanner)
        self.service_misconfig_scanner = ServiceMisconfigScanner(config.scanner)
        # AI analyst — only initialised when API key is provided
        gemini_key = getattr(config.scanner, 'gemini_api_key', '')
        self.ai_analyst: AIAnalyst = AIAnalyst(gemini_key) if gemini_key else AIAnalyst("")

        # Ctrl+C skip state
        self._skip_requested = False
        self._current_phase = ""

        # Resume checkpoint state
        self._completed_phases: set = set()

    @staticmethod
    def _prompt_skip(phase_name: str) -> bool:
        """
        Ask the user whether to skip the current phase or abort entirely.
        Returns True if user wants to skip, False if user wants to continue waiting.
        Raises SystemExit if user wants to abort the whole scan.
        """
        try:
            print(
                f"\n\033[93m[!]\033[0m Ctrl+C detected during \033[96m{phase_name}\033[0m"
            )
            print(
                f"\033[93m[?]\033[0m Skip \033[96m{phase_name}\033[0m and continue to next step? "
                f"\033[1;97m[y/N/q]\033[0m "
                f"\033[90m(y=skip, n=resume, q=quit)\033[0m"
            )
            answer = ""
            try:
                answer = input("    > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                # Second Ctrl+C during prompt = quit
                print(f"\n\033[91m[!]\033[0m Aborting scan.\033[0m")
                raise SystemExit(1)

            if answer == "q":
                print(f"\033[91m[!]\033[0m Aborting scan.\033[0m")
                raise SystemExit(1)
            elif answer == "y":
                print(
                    f"\033[93m[>]\033[0m Skipping \033[96m{phase_name}\033[0m → "
                    f"continuing to next phase ...\n"
                )
                return True
            else:
                print(
                    f"\033[36m[>]\033[0m Resuming \033[96m{phase_name}\033[0m ...\n"
                )
                return False
        except Exception:
            return False

    def _safe_scan(self, phase_name: str, scan_func, *args, **kwargs):
        """
        Run a scan function with Ctrl+C interception.
        If the user presses Ctrl+C, prompt to skip/continue/quit.
        If user picks 'n' (resume), re-run the scan from scratch
        because the subprocess is already dead after Ctrl+C.

        Args:
            phase_name: Human-readable phase name (e.g. "nmap", "enum4linux").
            scan_func: The scanning function to call.
            *args, **kwargs: Arguments forwarded to scan_func.

        Returns:
            The result of scan_func, or None if skipped.
        """
        self._current_phase = phase_name
        self._skip_requested = False

        while True:
            try:
                result = scan_func(*args, **kwargs)
                return result
            except KeyboardInterrupt:
                should_skip = self._prompt_skip(phase_name)
                if should_skip:
                    self._skip_requested = True
                    return None
                # User chose 'n' (resume) — re-run the scan from scratch
                # because the subprocess was already killed by Ctrl+C.
                continue

    def _print_tool_inventory(self):
        """
        Print a preflight tool inventory:
        - which tools are available / missing with install hints
        - which NetExec modules will be run per protocol
        Called once at the very start of every scan.
        """
        CYAN   = "\033[36m"
        GREEN  = "\033[92m"
        RED    = "\033[91m"
        YELLOW = "\033[93m"
        DIM    = "\033[2;37m"
        BOLD   = "\033[1;97m"
        PURPLE = "\033[95m"
        RESET  = "\033[0m"

        # ── Tool definitions: (name, available, install_hint) ─────────────
        tools = [
            ("nmap",        self.nmap_scanner.available,
             "apt install nmap"),
            ("nxc/netexec", self.netexec_module_scanner.available,
             "pip install netexec"),
            ("enum4linux",  self.enum4linux_scanner.available,
             "apt install enum4linux"),
            ("smbclient",   self.smbclient_scanner.available,
             "apt install smbclient"),
            ("httpx",       self.httpx_probe.available,
             "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
            ("nuclei",      self.nuclei_scanner.available,
             "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
            ("katana",      self.katana_scanner.available,
             "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
            ("dirsearch",   self.dirsearch_scanner.available,
             "pip install dirsearch"),
            ("wpscan",      self.wpscan_scanner.available,
             "gem install wpscan"),
            ("msfconsole",  self.msf_scanner.available,
             "https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"),
        ]

        print(f"{BOLD}{'─' * 60}{RESET}")
        print(f"{BOLD} Tool Inventory{RESET}")
        print(f"{BOLD}{'─' * 60}{RESET}")

        missing_tools = []
        for name, avail, hint in tools:
            if avail:
                print(f"  {GREEN}[✓]{RESET} {name:<18}")
            else:
                print(f"  {RED}[✗]{RESET} {name:<18} {DIM}→ install: {hint}{RESET}")
                missing_tools.append((name, hint))

        # AI mode status
        if self.ai_analyst.available:
            print(f"  {PURPLE}[✓]{RESET} AI Analyst         {DIM}(Gemini 2.5 Flash — active){RESET}")
        else:
            print(f"  {DIM}[·]{RESET} AI Analyst         {DIM}(disabled — use --ai --gemini-key){RESET}")

        # ── NetExec module preview (only when nxc is available) ────────────
        if self.netexec_module_scanner.available:
            from .scanner.netexec_modules import NXC_PROTOCOLS, RECON_MODULES, PROTO_COLORS

            print(f"\n{BOLD} NetExec Recon Modules (will run per detected protocol){RESET}")
            print(f"{BOLD}{'─' * 60}{RESET}")

            for proto in NXC_PROTOCOLS:
                modules = RECON_MODULES.get(proto, [])
                if not modules:
                    continue
                color = PROTO_COLORS.get(proto, "\033[37m")
                mods_str = ", ".join(modules)
                # wrap at 55 chars
                wrapped = []
                line = ""
                for m in modules:
                    if len(line) + len(m) + 2 > 52:
                        wrapped.append(line.rstrip(", "))
                        line = ""
                    line += m + ", "
                if line:
                    wrapped.append(line.rstrip(", "))

                print(f"  {color}{proto.upper():<8}{RESET} ({len(modules)} modules)")
                for i, w in enumerate(wrapped):
                    prefix = "           " if i > 0 else "           "
                    print(f"  {DIM}{prefix}{w}{RESET}")

        print(f"{BOLD}{'─' * 60}{RESET}\n")

    def _init_sources(self):
        """Initialize all data source modules."""
        source_classes = {
            "atlas": AtlasSource,
            "sphinx": SphinxSource,
            "oracle": OracleSource,
            "radar": RadarSource,
            "torrent": TorrentSource,
            "venom": VenomSource,
            "shodan": ShodanSource,
            "censys": CensysSource,
            "sectrails": SecurityTrailsSource,
            "urlscan": URLScanSource,
            "vt_siblings": VTSiblingsSource,
            "chaos": ChaosSource,
            "commoncrawl": CommonCrawlSource,
            "fofa": FOFASource,
            "zoomeye": ZoomEyeSource,
            "asn": ASNExpansionSource,
        }

        for key, cls in source_classes.items():
            if key in self.config.sources and self.config.sources[key].enabled:
                self.sources[key] = cls(self.config.sources[key])

    # ─── Incremental save helpers ──────────────────────────────────────────

    def _ensure_output_dir(self) -> str:
        """Create and return the domain output directory path."""
        domain = self.result.target_domain
        domain_dir = os.path.join(self.file_exporter.base_dir, domain)
        os.makedirs(domain_dir, exist_ok=True)
        return domain_dir

    def _target_output_dir(self, target_name: str) -> str:
        """Create and return the output directory for a target label."""
        target_dir = os.path.join(self.file_exporter.base_dir, target_name)
        os.makedirs(target_dir, exist_ok=True)
        return target_dir

    def _run_katana_httpx_enrichment(self, katana_urls_file: str, katana_httpx_file: str,
                                     target_count: int, total_urls: int) -> Optional[int]:
        """Probe katana URLs with httpx using a compact combined progress line."""
        httpx_cmd = [
            self.httpx_probe.httpx_path,
            "-l", katana_urls_file,
            "-sc", "-cl", "-title", "-location",
            "-silent",
            "-follow-redirects",
            "-o", katana_httpx_file,
        ]
        timeout_secs = max(600, total_urls * 2)
        spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        spinner_idx = 0
        line_count = 0
        bar = "\033[92m━\033[0m" * 30
        scan_label = f"katana+httpx crawling: \033[92m{target_count}\033[0m targets"

        proc = subprocess.Popen(
            httpx_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        started_at = time.time()
        while proc.poll() is None:
            if time.time() - started_at > timeout_secs:
                proc.kill()
                proc.wait()
                sys.stdout.write(
                    f"\r\033[93m[!]\033[0m {scan_label}: timed out\033[K\n"
                )
                sys.stdout.flush()
                return None

            time.sleep(0.15)
            if os.path.isfile(katana_httpx_file):
                try:
                    line_count = sum(
                        1 for _ in open(katana_httpx_file, encoding="utf-8", errors="replace")
                    )
                except Exception:
                    pass

            spinner = spinner_chars[spinner_idx % len(spinner_chars)]
            spinner_idx += 1
            sys.stdout.write(
                f"\r\033[96m[{spinner}]\033[0m {scan_label} [{bar}] "
                f"\033[92m{line_count}\033[0m urls\033[K"
            )
            sys.stdout.flush()

        if os.path.isfile(katana_httpx_file):
            try:
                line_count = sum(
                    1 for _ in open(katana_httpx_file, encoding="utf-8", errors="replace")
                )
            except Exception:
                pass

        sys.stdout.write(
            f"\r\033[92m[✓]\033[0m {scan_label} [{bar}] "
            f"\033[92m{line_count}\033[0m urls\033[K\n"
        )
        sys.stdout.flush()
        return line_count

    # ─── Resume / checkpoint helpers ───────────────────────────────────────

    def _checkpoint_dir(self) -> str:
        """Return the output directory used for checkpoint files."""
        if self.config.input_mode == "direct":
            label = self.config.target_domain.replace("/", "_")
            return self._target_output_dir(label)
        return self._target_output_dir(self.config.target_domain)

    def _phase_done(self, phase: str) -> bool:
        """Check if a phase was already completed in a previous run."""
        return phase in self._completed_phases

    def _save_checkpoint(self):
        """Persist current progress so the scan can be resumed later."""
        try:
            d = self._checkpoint_dir()
            os.makedirs(d, exist_ok=True)
            cp = os.path.join(d, ".reconx_checkpoint.pkl")
            with open(cp, "wb") as f:
                pickle.dump({
                    "completed_phases": sorted(self._completed_phases),
                    "result": self.result,
                }, f)
        except Exception:
            pass

    def _load_checkpoint(self) -> bool:
        """
        Load a previous checkpoint if available.
        Returns True if a checkpoint was loaded successfully.
        """
        d = self._checkpoint_dir()
        cp = os.path.join(d, ".reconx_checkpoint.pkl")
        if not os.path.isfile(cp):
            return False
        try:
            with open(cp, "rb") as f:
                data = pickle.load(f)
            self._completed_phases = set(data.get("completed_phases", []))
            self.result = data["result"]
            return True
        except Exception:
            return False

    def _clear_checkpoint(self):
        """Remove the checkpoint file after a successful full scan."""
        try:
            d = self._checkpoint_dir()
            cp = os.path.join(d, ".reconx_checkpoint.pkl")
            if os.path.isfile(cp):
                os.remove(cp)
        except Exception:
            pass

    def _save_phase(self, phase: str):
        """
        Incrementally save results for a specific phase to disk.
        Called right after each scan phase completes so files are
        available immediately (live results).
        """
        try:
            d = self._ensure_output_dir()
            fe = self.file_exporter
            r = self.result

            if phase == "subdomains":
                fe._export_all_subdomains(d, r)
                fe._export_sources(d, r)
            elif phase == "ct":
                fe._export_ct_entries(d, r)
            elif phase == "infrastructure":
                fe._export_infrastructure(d, r)
                fe._export_ip_addresses(d, r)
            elif phase == "httpx":
                fe._export_httpx(d, r)
                fe._export_alive_subdomains(d, r)
            elif phase == "nuclei":
                fe._export_nuclei(d, r)
            elif phase == "takeover":
                fe._export_takeover(d, r)
                fe._export_dangling(d, r)
            elif phase == "tech":
                fe._export_tech(d, r)
            elif phase == "flagged":
                fe._export_flagged(d, r)
            elif phase == "collapsed":
                fe._export_collapsed(d, r)
            elif phase == "nmap":
                fe._export_nmap(d, r)
            elif phase == "enum4linux":
                fe._export_enum4linux(d, r)
            elif phase == "cme":
                fe._export_cme(d, r)
            elif phase == "msf":
                fe._export_msf(d, r)
            elif phase == "rdp":
                fe._export_rdp(d, r)
            elif phase == "vnc":
                fe._export_vnc(d, r)
            elif phase == "smb_brute":
                fe._export_smb_brute(d, r)
            elif phase == "wpscan":
                fe._export_wpscan(d, r)
            elif phase == "smbclient":
                fe._export_smbclient(d, r)
            elif phase == "katana":
                fe._export_katana(d, r)
            elif phase == "dirsearch":
                fe._export_dirsearch(d, r)
            elif phase == "snmp_login":
                fe._export_snmp_login(d, r)
            elif phase == "snmp_enum":
                fe._export_snmp_enum(d, r)
            elif phase == "ssh_login":
                fe._export_ssh_login(d, r)
            elif phase == "mongodb_login":
                fe._export_mongodb_login(d, r)
            elif phase == "ftp_login":
                fe._export_ftp_login(d, r)
            elif phase == "postgres_login":
                fe._export_postgres_login(d, r)
            elif phase == "netexec_modules":
                pass  # results stored in JSON only
            elif phase == "service_misconfig":
                fe._export_service_misconfig(d, r)
            elif phase == "ai_analysis":
                pass  # report printed inline; stored in result.ai_report
            elif phase == "summary":
                fe._export_summary(d, r)
            self._completed_phases.add(phase)
            self._save_checkpoint()
        except Exception:
            pass  # Don't let a save failure crash the pipeline

    def run(self) -> ScanResult:
        """
        Execute the full reconnaissance pipeline.
        Returns the complete ScanResult.
        """
        start_time = time.time()
        domain = self.config.target_domain

        # ── Preflight: tool inventory ──────────────────────────────────────
        self._print_tool_inventory()

        # ── Direct mode: IP / CIDR / file-of-IPs → skip enum ──────────────
        if self.config.input_mode == "direct":
            return self._run_direct(start_time)

        # ── Resume from checkpoint if available ────────────────────────────
        resumed = self._load_checkpoint()
        if resumed:
            phases_done = len(self._completed_phases)
            print(
                f"\033[92m[+]\033[0m Resuming from checkpoint "
                f"(\033[92m{phases_done}\033[0m phases completed)\n"
            )

        # ── Phases 1-4: Subdomain enum + CT + Infrastructure ───────────────
        if self._phase_done("infrastructure"):
            subdomain_objects = self.result.subdomains
        else:
            # ── Phase 1: Fetch subdomains from all sources concurrently ────
            all_subdomains_by_source: Dict[str, List[str]] = {}

            # Print source start messages
            max_name_len = max(
                (len(s.name) for s in self.sources.values()), default=7,
            )
            source_order = list(self.sources.keys())
            for key in source_order:
                source = self.sources[key]
                desc = getattr(source, 'SOURCE_DESC', source.config.description or f'querying {source.name}')
                print(f"\033[36m[>]\033[0m {source.name + ':':<{max_name_len + 1}} {desc} ...")

            with ThreadPoolExecutor(max_workers=len(self.sources)) as executor:
                futures = {
                    executor.submit(source.run, domain, False): key
                    for key, source in self.sources.items()
                }
                for future in as_completed(futures):
                    key = futures[future]
                    try:
                        raw_subs = future.result()
                        cleaned_subs = []
                        seen = set()
                        for sub in raw_subs:
                            hostname = sanitize_hostname(sub, domain)
                            if hostname and hostname not in seen:
                                seen.add(hostname)
                                cleaned_subs.append(hostname)
                        all_subdomains_by_source[key] = cleaned_subs
                    except Exception:
                        all_subdomains_by_source[key] = []

            # Print results in the same order as queries
            for key in source_order:
                source = self.sources[key]
                count = len(all_subdomains_by_source.get(key, []))
                elapsed_ms = int(source.elapsed * 1000)
                print(
                    f"\033[92m[+]\033[0m {source.name + ':':<{max_name_len + 1}} "
                    f"\033[92m{count:>4}\033[0m subdomains "
                    f"\033[90m({elapsed_ms}ms)\033[0m"
                )

            # ── Phase 2: Deduplicate and aggregate ─────────────────────────
            unique_hostnames = set()
            for key, subs in all_subdomains_by_source.items():
                for sub in subs:
                    hostname = sanitize_hostname(sub, domain)
                    if hostname:
                        unique_hostnames.add(hostname)
                self.result.source_stats[key] = SourceStats(
                    name=self.sources[key].name,
                    count=len(subs),
                    subdomains=subs,
                )

            # ── Phase 3: CT Log triage (using atlas/crt.sh source data) ────
            ct_entries, ct_subs = self.ct_scanner.scan(domain)
            self.result.ct_entries = ct_entries
            stale, aged, no_date = self.ct_scanner.triage(ct_entries)
            self.result.ct_stale = stale
            self.result.ct_aged = aged
            self.result.ct_no_date = no_date

            # Print takeover candidates warning if any
            takeover_hint = len([h for h in unique_hostnames if any(
                kw in h for kw in ['azure', 'cloudapp', 'trafficmanager', 'azurewebsites',
                                   'herokuapp', 's3.amazonaws', 'github.io', 'shopify',
                                   'fastly', 'pantheon', 'ghost', 'surge']
            )])
            if takeover_hint > 0:
                print(f"\n\033[93m[!]\033[0m \033[93m\u26A0{takeover_hint} potential subdomain takeover candidate(s)!\033[0m")

            print(f"\n\033[36m[>]\033[0m Beacon: HTTP probing {len(unique_hostnames)} subdomains ...")

            # Create Subdomain objects from ALL unique hostnames
            subdomain_objects = []
            for hostname in sorted(unique_hostnames):
                sub = Subdomain(hostname=hostname)
                # Check interesting
                interesting, reason = is_interesting_subdomain(hostname)
                sub.interesting = interesting
                sub.interesting_reason = reason
                subdomain_objects.append(sub)

            self.result.subdomains = subdomain_objects
            self.result.total_unique = len(unique_hostnames)

            # Live save: subdomains + CT
            self._save_phase("subdomains")
            self._save_phase("ct")

            # ── Phase 4: Infrastructure classification ─────────────────────
            self.result.infra = self.infra_scanner.scan(subdomain_objects)
            self._save_phase("infrastructure")

        # ── Phase 5: HTTPX Probe ──────────────────────────────────────────
        httpx_start = time.time()

        # Attempt auto-install if httpx is not available
        if not self.httpx_probe.available:
            print(
                f"\033[93m[!]\033[0m httpx not found \u2013 attempting auto-install..."
            )
            self.httpx_probe.ensure_available()

        if self.httpx_probe.available and not self._phase_done("httpx"):
            print(
                f"\033[36m[>]\033[0m httpx: probing with "
                f"\033[96m-sc -title -td -favicon -cdn -server\033[0m ..."
            )
            alive_hostnames = [s.hostname for s in subdomain_objects if s.is_alive]
            if not alive_hostnames:
                # If infrastructure scan didn't mark alive, probe all
                alive_hostnames = [s.hostname for s in subdomain_objects]
            self.httpx_probe.probe(alive_hostnames)
            alive_count, new_fqdn_count, new_fqdns = self.httpx_probe.enrich_subdomains(
                subdomain_objects
            )
            httpx_elapsed = time.time() - httpx_start
            httpx_stats = self.httpx_probe.get_stats()

            # Merge newly discovered FQDNs back into subdomain list
            existing_hosts = {s.hostname for s in subdomain_objects}
            new_from_httpx = 0
            for fqdn in new_fqdns:
                if fqdn.endswith(f".{domain}") and fqdn not in existing_hosts:
                    new_sub = Subdomain(hostname=fqdn)
                    interesting, reason = is_interesting_subdomain(fqdn)
                    new_sub.interesting = interesting
                    new_sub.interesting_reason = reason
                    subdomain_objects.append(new_sub)
                    existing_hosts.add(fqdn)
                    new_from_httpx += 1

            if new_from_httpx > 0:
                self.result.total_unique += new_from_httpx

            # Print httpx stats (individual status codes)
            sc_codes = httpx_stats.get("status_codes", {})
            status_str = " ".join(
                f"\033[{'92' if sc // 100 == 2 else '93' if sc // 100 == 3 else '91' if sc // 100 in (4,5) else '37'}m"
                f"{cnt}×{sc}\033[0m"
                for sc, cnt in sorted(sc_codes.items())
            ) if sc_codes else " ".join(
                f"\033[{'92' if k == '2xx' else '93' if k == '3xx' else '91' if k in ('4xx','5xx') else '37'}m"
                f"{v} {k}\033[0m"
                for k, v in sorted(httpx_stats.get("status_distribution", {}).items())
            )
            cdn_str = f"\033[95m{httpx_stats.get('cdn_detected', 0)} CDN\033[0m"
            tech_str = f"\033[96m{httpx_stats.get('tech_detected', 0)} tech\033[0m"
            favicon_str = f"\033[33m{httpx_stats.get('unique_favicon_hashes', 0)} favicons\033[0m"

            print(
                f"\033[92m[+]\033[0m httpx: \033[92m{alive_count} alive\033[0m / "
                f"{len(alive_hostnames)} probed | "
                f"{status_str} | {cdn_str} | {tech_str} | {favicon_str} "
                f"\033[90m({httpx_elapsed:.1f}s)\033[0m"
            )
            if new_from_httpx > 0:
                print(
                    f"\033[92m[+]\033[0m httpx: discovered \033[92m{new_from_httpx}\033[0m "
                    f"new FQDNs from response bodies"
                )
        elif not self.httpx_probe.available:
            # Fallback: count alive from infrastructure scan
            alive_count = sum(1 for s in subdomain_objects if s.is_alive)
            print(
                f"\033[91m[✗]\033[0m httpx auto-install failed \u2013 using basic DNS probe only "
                f"(\033[92m{alive_count} alive\033[0m)"
            )
            print(
                f"\033[90m    Manual install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest\033[0m"
            )
            print(
                f"\033[90m    Or download: https://github.com/projectdiscovery/httpx/releases\033[0m"
            )

        # Store httpx stats on result for rendering
        self.result.httpx_stats = getattr(self.httpx_probe, 'get_stats', lambda: {})() if self.httpx_probe.available else {}
        self.result.httpx_available = self.httpx_probe.available
        self._save_phase("httpx")

        # ── Phase 5b: Reconcile infra stats with httpx CDN/server data ────
        if self.httpx_probe.available:
            self._reconcile_infra_from_httpx(subdomain_objects)

        # ── Phase 6: Pattern collapse ──────────────────────────────────────
        all_hostnames = [s.hostname for s in subdomain_objects]
        collapsed_entries, pattern_groups = collapse_subdomains(
            all_hostnames, self.config.scanner.collapse_threshold
        )
        self.result.collapse = CollapseStats(
            total_entries=collapsed_entries,
            pattern_groups=pattern_groups,
            threshold=self.config.scanner.collapse_threshold,
        )
        self._save_phase("collapsed")

        # ── Phase 7: Subdomain takeover check ─────────────────────────────
        takeover_results = self.takeover_scanner.scan(subdomain_objects)
        self.result.takeover_results = takeover_results
        self.result.vulnerable_count = sum(
            1 for r in takeover_results if r.status == TakeoverStatus.VULNERABLE
        )
        self.result.dangling_count = sum(
            1 for r in takeover_results if r.status == TakeoverStatus.DANGLING
        )
        self.result.not_vulnerable_count = sum(
            1 for r in takeover_results if r.status == TakeoverStatus.NOT_VULNERABLE
        )

        # Determine primary vulnerable provider
        if takeover_results:
            from collections import Counter
            provider_counts = Counter(
                r.provider for r in takeover_results
                if r.status == TakeoverStatus.VULNERABLE
            )
            if provider_counts:
                self.result.takeover_provider = provider_counts.most_common(1)[0][0]

        self._save_phase("takeover")

        # ── Phase 8: Tech stack profiling ──────────────────────────────────
        beacon_start = time.time()
        # Only profile alive subdomains (avoids false positives on dead hosts)
        alive_subs = [s for s in subdomain_objects if s.is_alive]
        tech_matches = self.tech_profiler.scan(alive_subs)
        self.result.tech_matches = tech_matches
        self.result.tech_severity_summary = self.tech_profiler.group_by_severity(tech_matches)
        beacon_elapsed = time.time() - beacon_start

        # Count alive and body snippets from tech scanning
        alive_count = sum(1 for s in subdomain_objects if getattr(s, 'is_alive', False))
        body_count = len(tech_matches)
        print(
            f"\033[92m[+]\033[0m TechScan: \033[92m{body_count} tech matches\033[0m "
            f"\033[90m({beacon_elapsed:.1f}s)\033[0m\n"
        )
        self._save_phase("tech")
        self._save_phase("flagged")

        # ── Phase 9: Port & service scanning (nmap) ─────────────────────────
        _nmap_import = getattr(self.config.scanner, 'nmap_import_file', '')
        if self.nmap_scanner.available and not self._phase_done("nmap"):
            all_ips = set()
            for sub in subdomain_objects:
                for ip in sub.ip_addresses:
                    all_ips.add(ip)

            if _nmap_import or all_ips:
                nmap_output_dir = self._ensure_output_dir()
                os.makedirs(nmap_output_dir, exist_ok=True)

                if _nmap_import:
                    nmap_results = self.nmap_scanner.load_from_file(_nmap_import)
                    _scan_ips = sorted(nmap_results.keys()) if not all_ips else sorted(all_ips)
                else:
                    nmap_results = self._safe_scan(
                        "nmap", self.nmap_scanner.scan,
                        all_ips, output_dir=nmap_output_dir,
                    )
                    _scan_ips = sorted(all_ips)

                if nmap_results is not None:
                    nmap_stats = self.nmap_scanner.stats

                    self.result.nmap_results = nmap_results
                    self.result.nmap_stats = nmap_stats.to_dict()
                    self.result.nmap_available = True
                    self.result.nmap_scanned_ips = _scan_ips
                    self._save_phase("nmap")

                    if nmap_stats.hosts_up > 0:
                        svc_str = ", ".join(
                            f"\033[96m{s['service']}\033[0m(\033[37m{s['count']}\033[0m)"
                            for s in nmap_stats.top_services[:5]
                        )
                        port_str = ", ".join(
                            f"\033[93m{p['port']}\033[0m(\033[37m{p['count']}\033[0m)"
                            for p in nmap_stats.top_ports[:5]
                        )
                        print(
                            f"\033[92m[+]\033[0m nmap: \033[92m{nmap_stats.hosts_up} hosts up\033[0m / "
                            f"{nmap_stats.total_ips_scanned} scanned | "
                            f"\033[92m{nmap_stats.total_open_ports} open ports\033[0m | "
                            f"{nmap_stats.unique_services} services "
                            f"\033[90m({nmap_stats.scan_time:.1f}s)\033[0m"
                        )
                        if svc_str:
                            print(f"\033[92m[+]\033[0m nmap: services = {svc_str}")
                        if port_str:
                            print(f"\033[92m[+]\033[0m nmap: top ports = {port_str}")
                        print()
                    else:
                        print(
                            f"\033[92m[+]\033[0m nmap: \033[37m0 hosts up\033[0m / "
                            f"{nmap_stats.total_ips_scanned} scanned "
                            f"\033[90m({nmap_stats.scan_time:.1f}s)\033[0m\n"
                        )
                else:
                    print(
                        f"\033[93m[!]\033[0m nmap: skipped by user\n"
                    )
            else:
                print(
                    f"\033[93m[!]\033[0m nmap: no IP addresses resolved – skipping port scan\n"
                )
        elif not self.nmap_scanner.available:
            print(
                f"\033[93m[!]\033[0m nmap not found – skipping port & service scan"
            )
            print(
                f"\033[90m    Install: https://nmap.org/download.html\033[0m\n"
            )

        # ── Phase 9a: Service misconfiguration checks ───────────────────────
        if (self.service_misconfig_scanner.available
                and self.result.nmap_available
                and self.result.nmap_results
                and not self._phase_done("service_misconfig")):
            service_output_dir = self._ensure_output_dir()
            os.makedirs(service_output_dir, exist_ok=True)

            service_results = self._safe_scan(
                "service-misconfig", self.service_misconfig_scanner.scan,
                self.result.nmap_results, target_domain=self.result.target_domain,
                output_dir=service_output_dir,
            )

            if service_results:
                svc_stats = self.service_misconfig_scanner.stats
                self.result.service_misconfig_results = service_results
                self.result.service_misconfig_stats = svc_stats.to_dict()
                self.result.service_misconfig_available = True
                self._save_phase("service_misconfig")

                sev_parts = []
                if svc_stats.critical:
                    sev_parts.append(f"\033[1;91m{svc_stats.critical} critical\033[0m")
                if svc_stats.high:
                    sev_parts.append(f"\033[91m{svc_stats.high} high\033[0m")
                if svc_stats.medium:
                    sev_parts.append(f"\033[93m{svc_stats.medium} medium\033[0m")
                if svc_stats.low:
                    sev_parts.append(f"\033[36m{svc_stats.low} low\033[0m")
                if svc_stats.info:
                    sev_parts.append(f"\033[37m{svc_stats.info} info\033[0m")
                service_parts = []
                if svc_stats.smtp_hosts:
                    service_parts.append(f"smtp({svc_stats.smtp_hosts})")
                if svc_stats.pop3_hosts:
                    service_parts.append(f"pop3({svc_stats.pop3_hosts})")
                if svc_stats.mongodb_hosts:
                    service_parts.append(f"mongodb({svc_stats.mongodb_hosts})")
                if svc_stats.docker_hosts:
                    service_parts.append(f"docker({svc_stats.docker_hosts})")
                if svc_stats.elasticsearch_hosts:
                    service_parts.append(f"elasticsearch({svc_stats.elasticsearch_hosts})")
                if svc_stats.etcd_hosts:
                    service_parts.append(f"etcd({svc_stats.etcd_hosts})")
                if svc_stats.grafana_hosts:
                    service_parts.append(f"grafana({svc_stats.grafana_hosts})")
                if svc_stats.imap_hosts:
                    service_parts.append(f"imap({svc_stats.imap_hosts})")
                if svc_stats.jenkins_hosts:
                    service_parts.append(f"jenkins({svc_stats.jenkins_hosts})")
                if svc_stats.kafka_hosts:
                    service_parts.append(f"kafka({svc_stats.kafka_hosts})")
                if svc_stats.kerberos_hosts:
                    service_parts.append(f"kerberos({svc_stats.kerberos_hosts})")
                if svc_stats.kubernetes_hosts:
                    service_parts.append(f"kubernetes({svc_stats.kubernetes_hosts})")
                if svc_stats.ldap_hosts:
                    service_parts.append(f"ldap({svc_stats.ldap_hosts})")
                if svc_stats.memcached_hosts:
                    service_parts.append(f"memcached({svc_stats.memcached_hosts})")
                if svc_stats.mssql_hosts:
                    service_parts.append(f"mssql({svc_stats.mssql_hosts})")
                if svc_stats.netbios_hosts:
                    service_parts.append(f"netbios({svc_stats.netbios_hosts})")
                if svc_stats.nfs_hosts:
                    service_parts.append(f"nfs({svc_stats.nfs_hosts})")
                if svc_stats.ntp_hosts:
                    service_parts.append(f"ntp({svc_stats.ntp_hosts})")
                if svc_stats.oracle_hosts:
                    service_parts.append(f"oracle({svc_stats.oracle_hosts})")
                if svc_stats.postgresql_hosts:
                    service_parts.append(f"postgresql({svc_stats.postgresql_hosts})")
                if svc_stats.rabbitmq_hosts:
                    service_parts.append(f"rabbitmq({svc_stats.rabbitmq_hosts})")
                if svc_stats.rdp_hosts:
                    service_parts.append(f"rdp({svc_stats.rdp_hosts})")
                if svc_stats.redis_hosts:
                    service_parts.append(f"redis({svc_stats.redis_hosts})")
                if svc_stats.tftp_hosts:
                    service_parts.append(f"tftp({svc_stats.tftp_hosts})")
                if svc_stats.tomcat_hosts:
                    service_parts.append(f"tomcat({svc_stats.tomcat_hosts})")
                if svc_stats.vnc_hosts:
                    service_parts.append(f"vnc({svc_stats.vnc_hosts})")
                if svc_stats.webdav_hosts:
                    service_parts.append(f"webdav({svc_stats.webdav_hosts})")
                if svc_stats.winrm_hosts:
                    service_parts.append(f"winrm({svc_stats.winrm_hosts})")

                print(
                    f"\033[92m[+]\033[0m service-misconfig: "
                    f"\033[92m{svc_stats.findings_total} finding(s)\033[0m | "
                    f"{', '.join(sev_parts) if sev_parts else 'no findings'} | "
                    f"{', '.join(service_parts)} "
                    f"\033[90m({svc_stats.scan_time:.1f}s)\033[0m"
                )
                shown = 0
                for host_result in service_results.values():
                    for finding in host_result.findings:
                        print(
                            f"\033[91m[!]\033[0m {finding.service}:{finding.ip}:{finding.port} "
                            f"{finding.check} \033[90m({finding.severity})\033[0m"
                        )
                        shown += 1
                        if shown >= 10:
                            break
                    if shown >= 10:
                        break
                print()
            elif service_results is None:
                print(f"\033[93m[!]\033[0m service-misconfig: skipped by user\n")

        # ── Phase 9c-1: Enum4linux SMB/Windows enumeration ───────────────────
        if (self.enum4linux_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("enum4linux")):
            # Only scan IPs that have SMB/NetBIOS ports open
            smb_ports = {445, 139, 137, 138}
            enum_ips = set()
            for ip, host_result in self.result.nmap_results.items():
                ports = host_result.ports if hasattr(host_result, 'ports') else []
                for p in ports:
                    port_num = p.port if hasattr(p, 'port') else p.get('port', 0)
                    state = p.state if hasattr(p, 'state') else p.get('state', '')
                    if port_num in smb_ports and state == "open":
                        enum_ips.add(ip)
                        break
            if enum_ips:
                enum_output_dir = self._ensure_output_dir()
                os.makedirs(enum_output_dir, exist_ok=True)

                enum_results = self._safe_scan(
                    "enum4linux", self.enum4linux_scanner.scan,
                    enum_ips, output_dir=enum_output_dir,
                )

                if enum_results is not None:
                    enum_stats = self.enum4linux_scanner.stats

                    self.result.enum4linux_results = enum_results
                    self.result.enum4linux_stats = enum_stats.to_dict()
                    self.result.enum4linux_available = True
                    self._save_phase("enum4linux")

                    # Print enum4linux summary
                    if enum_stats.hosts_responded > 0:
                        parts = [
                            f"\033[92m{enum_stats.hosts_responded} hosts responded\033[0m / "
                            f"{enum_stats.total_ips_scanned} scanned"
                        ]
                        if enum_stats.total_shares > 0:
                            parts.append(f"\033[96m{enum_stats.total_shares} shares\033[0m")
                        if enum_stats.total_users > 0:
                            parts.append(f"\033[96m{enum_stats.total_users} users\033[0m")
                        if enum_stats.total_groups > 0:
                            parts.append(f"\033[96m{enum_stats.total_groups} groups\033[0m")
                        if enum_stats.null_sessions > 0:
                            parts.append(
                                f"\033[91m{enum_stats.null_sessions} null session(s)\033[0m"
                            )
                        print(
                            f"\033[92m[+]\033[0m enum4linux: {' | '.join(parts)} "
                            f"\033[90m({enum_stats.scan_time:.1f}s)\033[0m"
                        )

                        # Highlight null sessions (critical finding)
                        null_hosts = self.enum4linux_scanner.get_null_session_hosts()
                        if null_hosts:
                            print(
                                f"\033[91m[!]\033[0m enum4linux: \033[91m{len(null_hosts)} host(s) "
                                f"allow null sessions\033[0m (anonymous access)"
                            )
                        print()
                    else:
                        print(
                            f"\033[92m[+]\033[0m enum4linux: \033[37m0 hosts responded\033[0m / "
                            f"{enum_stats.total_ips_scanned} scanned "
                            f"\033[90m({enum_stats.scan_time:.1f}s)\033[0m\n"
                        )
                else:
                    print(
                        f"\033[93m[!]\033[0m enum4linux: skipped by user\n"
                    )
        elif not self.enum4linux_scanner.available and self.result.nmap_available:
            print(
                f"\033[93m[!]\033[0m enum4linux not found – skipping SMB/Windows enumeration"
            )
            print(
                f"\033[90m    Install: apt install enum4linux\033[0m\n"
            )

        # ── Phase 9a-2: SMBClient null session detection ─────────────────────
        if (self.smbclient_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("smbclient")):
            from .scanner.smbclient_scan import SMBClientScanner as _SMBC
            smb_hosts = _SMBC.get_smb_hosts(self.result.nmap_results)
            if smb_hosts:
                smb_output_dir = self._ensure_output_dir()
                os.makedirs(smb_output_dir, exist_ok=True)

                smb_results = self._safe_scan(
                    "smbclient", self.smbclient_scanner.scan,
                    smb_hosts, output_dir=smb_output_dir,
                )

                if smb_results is not None:
                    smb_stats = self.smbclient_scanner.stats

                    self.result.smbclient_results = smb_results
                    self.result.smbclient_stats = smb_stats.to_dict()
                    self.result.smbclient_available = True
                    self._save_phase("smbclient")

                    if smb_stats.hosts_with_null_session > 0:
                        parts = [
                            f"\033[91m{smb_stats.hosts_with_null_session} null session(s)\033[0m / "
                            f"{smb_stats.total_hosts_scanned} scanned"
                        ]
                        if smb_stats.total_shares > 0:
                            parts.append(f"\033[96m{smb_stats.total_shares} shares\033[0m")
                        if smb_stats.accessible_shares > 0:
                            parts.append(
                                f"\033[91m{smb_stats.accessible_shares} accessible share(s)\033[0m"
                            )
                        if smb_stats.total_files_listed > 0:
                            parts.append(
                                f"\033[92m{smb_stats.total_files_listed} files listed\033[0m"
                            )
                        print(
                            f"\033[92m[+]\033[0m smbclient: {' | '.join(parts)} "
                            f"\033[90m({smb_stats.scan_time:.1f}s)\033[0m"
                        )

                        null_hosts = self.smbclient_scanner.get_null_session_hosts()
                        if null_hosts:
                            print(
                                f"\033[91m[!]\033[0m smbclient: \033[91m{len(null_hosts)} host(s) "
                                f"allow null sessions\033[0m (anonymous SMB access)"
                            )
                            for ip in null_hosts[:5]:
                                hr = smb_results[ip]
                                share_names = [s.name for s in hr.shares]
                                print(
                                    f"\033[91m[!]\033[0m smbclient: \033[96m{ip}\033[0m → "
                                    f"{', '.join(share_names[:6])}"
                                    f"{'...' if len(share_names) > 6 else ''}"
                                )
                        acc_hosts = self.smbclient_scanner.get_accessible_share_hosts()
                        if acc_hosts:
                            print(
                                f"\033[1;91m[!]\033[0m smbclient: \033[1;91m{len(acc_hosts)} host(s) "
                                f"with readable shares\033[0m (data exposure!)"
                            )
                        print()
                    else:
                        print(
                            f"\033[92m[+]\033[0m smbclient: \033[37m0 null sessions\033[0m / "
                            f"{smb_stats.total_hosts_scanned} scanned "
                            f"\033[90m({smb_stats.scan_time:.1f}s)\033[0m\n"
                        )
                else:
                    print(
                        f"\033[93m[!]\033[0m smbclient: skipped by user\n"
                    )
        elif not self.smbclient_scanner.available and self.result.nmap_available:
            # Check if SMB hosts exist
            from .scanner.smbclient_scan import SMBClientScanner as _SMBC2
            smb_check = _SMBC2.get_smb_hosts(self.result.nmap_results) if self.result.nmap_results else set()
            if smb_check:
                print(
                    f"\033[93m[!]\033[0m smbclient not found – skipping null session detection "
                    f"({len(smb_check)} SMB host(s) detected)"
                )
                print(
                    f"\033[90m    Install: sudo apt install smbclient\033[0m\n"
                )

        # ── Phase 9b-3: SMB brute-force (netexec / nxc) ───────────────────
        if self.smb_brute_scanner.available and self.result.nmap_available and self.result.nmap_results:
            smb_brute_output_dir = self._ensure_output_dir()
            os.makedirs(smb_brute_output_dir, exist_ok=True)

            smb_brute_results = self._safe_scan(
                "smb-brute", self.smb_brute_scanner.scan,
                self.result.nmap_results, output_dir=smb_brute_output_dir,
            )

            if smb_brute_results:
                smb_brute_stats = self.smb_brute_scanner.stats

                self.result.smb_brute_results = smb_brute_results
                self.result.smb_brute_stats = smb_brute_stats.to_dict()
                self.result.smb_brute_available = True
                self._save_phase("smb_brute")

                if smb_brute_stats.credentials_found > 0:
                    pwn_str = ""
                    if smb_brute_stats.pwned_count > 0:
                        pwn_str = (
                            f" | \033[1;91m{smb_brute_stats.pwned_count} Pwn3d!\033[0m"
                        )
                    sam_str = ""
                    if smb_brute_stats.sam_hashes_dumped > 0:
                        sam_str = (
                            f" | \033[1;95m{smb_brute_stats.sam_hashes_dumped} SAM hashes\033[0m"
                        )
                    print(
                        f"\033[1;92m[+]\033[0m smb-brute: "
                        f"\033[1;92m{smb_brute_stats.credentials_found} credential(s) found!\033[0m | "
                        f"{smb_brute_stats.hosts_tested} hosts tested"
                        f"{pwn_str}{sam_str} "
                        f"\033[90m({smb_brute_stats.scan_time:.1f}s)\033[0m"
                    )
                    # Show found credentials
                    for cred in self.smb_brute_scanner.get_all_credentials():
                        domain_str = f"{cred.domain}\\" if cred.domain else ""
                        pwn_tag = " \033[1;91m(Pwn3d!)\033[0m" if cred.pwned else ""
                        anon_tag = " \033[1;93m(anonymous)\033[0m" if cred.anonymous else ""
                        print(
                            f"\033[1;92m[+]\033[0m smb-brute: "
                            f"\033[96m{cred.ip}\033[0m → "
                            f"\033[1;92m{domain_str}{cred.username}:{cred.password}\033[0m"
                            f"{pwn_tag}{anon_tag}"
                        )
                else:
                    print(
                        f"\033[92m[+]\033[0m smb-brute: "
                        f"\033[37mno valid credentials\033[0m | "
                        f"{smb_brute_stats.hosts_tested}/{smb_brute_stats.total_smb_hosts} hosts tested "
                        f"\033[90m({smb_brute_stats.scan_time:.1f}s)\033[0m"
                    )
                # Show null auth hosts
                null_hosts = self.smb_brute_scanner.get_null_auth_hosts()
                if null_hosts:
                    print(
                        f"\033[1;91m[!]\033[0m smb-brute: \033[1;91m{len(null_hosts)} host(s) "
                        f"allow anonymous/null access\033[0m"
                    )
                # Show Pwn3d hosts
                pwned_hosts = self.smb_brute_scanner.get_pwned_hosts()
                if pwned_hosts:
                    print(
                        f"\033[1;91m[!]\033[0m smb-brute: \033[1;91m{len(pwned_hosts)} host(s) "
                        f"Pwn3d!\033[0m (admin access)"
                    )
                # Show SAM hashes
                sam_hashes = self.smb_brute_scanner.get_all_sam_hashes()
                if sam_hashes:
                    print(
                        f"\033[1;95m[+]\033[0m smb-brute: \033[1;95m{len(sam_hashes)} SAM hash(es) "
                        f"dumped\033[0m"
                    )
                    for h in sam_hashes[:10]:
                        print(
                            f"\033[1;95m[+]\033[0m   {h.username}:{h.rid}:{h.lm_hash}:{h.nt_hash}"
                        )
                    if len(sam_hashes) > 10:
                        print(
                            f"\033[90m    ... and {len(sam_hashes) - 10} more (see smb_brute_sam_hashes.txt)\033[0m"
                        )
                if smb_brute_stats.hosts_skipped > 0:
                    print(
                        f"\033[93m[!]\033[0m smb-brute: "
                        f"{smb_brute_stats.hosts_skipped} host(s) skipped "
                        f"(lockout/connection errors)"
                    )
                print()
            elif smb_brute_results is None:
                print(
                    f"\033[93m[!]\033[0m smb-brute: skipped by user\n"
                )
        elif (not self.smb_brute_scanner.available
              and self.result.nmap_available
              and self.result.nmap_results):
            from .scanner.smb_brute import SMBBruteScanner as _SMBB2
            smb_b_check = _SMBB2(self.config.scanner)._get_smb_hosts(self.result.nmap_results)
            if smb_b_check:
                print(
                    f"\033[93m[!]\033[0m netexec (nxc) not found – skipping SMB brute-force "
                    f"({len(smb_b_check)} SMB host(s) detected)"
                )
                print(
                    f"\033[90m    Install: pip install netexec\033[0m\n"
                )

        # ── Phase 9b-2: VNC brute-force (msfconsole) ────────────────────────
        if (self.vnc_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("vnc")):
            vnc_output_dir = self._ensure_output_dir()
            os.makedirs(vnc_output_dir, exist_ok=True)

            vnc_results = self._safe_scan(
                "vnc-brute", self.vnc_scanner.scan,
                self.result.nmap_results, output_dir=vnc_output_dir,
            )

            if vnc_results:
                vnc_stats = self.vnc_scanner.stats

                self.result.vnc_results = vnc_results
                self.result.vnc_stats = vnc_stats.to_dict()
                self.result.vnc_available = True
                self._save_phase("vnc")

                if vnc_stats.credentials_found > 0:
                    no_auth_str = ""
                    if vnc_stats.hosts_no_auth > 0:
                        no_auth_str = (
                            f" | \033[1;91m{vnc_stats.hosts_no_auth} NO AUTH\033[0m"
                        )
                    print(
                        f"\033[1;92m[+]\033[0m vnc-brute: "
                        f"\033[1;92m{vnc_stats.credentials_found} credential(s) found!\033[0m | "
                        f"{vnc_stats.hosts_tested} hosts tested"
                        f"{no_auth_str} "
                        f"\033[90m({vnc_stats.scan_time:.1f}s)\033[0m"
                    )
                    # Show found credentials
                    for cred in self.vnc_scanner.get_all_credentials():
                        if cred.anonymous:
                            print(
                                f"\033[1;91m[!]\033[0m vnc-brute: "
                                f"\033[96m{cred.ip}:{cred.port}\033[0m → "
                                f"\033[1;91mNO AUTHENTICATION REQUIRED\033[0m"
                            )
                        else:
                            print(
                                f"\033[1;92m[+]\033[0m vnc-brute: "
                                f"\033[96m{cred.ip}:{cred.port}\033[0m → "
                                f"\033[1;92m:{cred.password}\033[0m"
                            )
                else:
                    print(
                        f"\033[92m[+]\033[0m vnc-brute: "
                        f"\033[37mno valid credentials\033[0m | "
                        f"{vnc_stats.hosts_tested}/{vnc_stats.total_vnc_hosts} hosts tested "
                        f"\033[90m({vnc_stats.scan_time:.1f}s)\033[0m"
                    )
                if vnc_stats.hosts_skipped > 0:
                    print(
                        f"\033[93m[!]\033[0m vnc-brute: "
                        f"{vnc_stats.hosts_skipped} host(s) skipped "
                        f"(lockout/connection errors)"
                    )
                # Highlight no-auth hosts (critical finding)
                no_auth = self.vnc_scanner.get_no_auth_hosts()
                if no_auth:
                    print(
                        f"\033[1;91m[!]\033[0m vnc-brute: \033[1;91m{len(no_auth)} host(s) "
                        f"with NO AUTHENTICATION\033[0m (open VNC access!)"
                    )
                print()
            elif vnc_results is None:
                print(
                    f"\033[93m[!]\033[0m vnc-brute: skipped by user\n"
                )
        elif (not self.vnc_scanner.available
              and self.result.nmap_available
              and self.result.nmap_results):
            from .scanner.vnc_brute import VNCBruteScanner as _VNC2
            vnc_check = _VNC2(self.config.scanner)._get_vnc_hosts(self.result.nmap_results)
            if vnc_check:
                print(
                    f"\033[93m[!]\033[0m msfconsole not found – skipping VNC brute-force "
                    f"({len(vnc_check)} VNC host(s) detected)"
                )
                print(
                    f"\033[90m    Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html\033[0m\n"
                )

        # ── Phase 9b-3: SNMP login brute-force (msfconsole) ─────────────────
        if (self.snmp_login_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("snmp_login")):
            snmp_output_dir = self._ensure_output_dir()
            os.makedirs(snmp_output_dir, exist_ok=True)

            snmp_login_results = self._safe_scan(
                "snmp-login", self.snmp_login_scanner.scan,
                self.result.nmap_results, output_dir=snmp_output_dir,
            )

            if snmp_login_results:
                snmp_login_stats = self.snmp_login_scanner.stats

                self.result.snmp_login_results = snmp_login_results
                self.result.snmp_login_stats = snmp_login_stats.to_dict()
                self.result.snmp_login_available = True
                self._save_phase("snmp_login")

                if snmp_login_stats.credentials_found > 0:
                    rw_str = ""
                    if snmp_login_stats.read_write_found > 0:
                        rw_str = (
                            f" | \033[1;91m{snmp_login_stats.read_write_found} READ-WRITE\033[0m"
                        )
                    print(
                        f"\033[1;92m[+]\033[0m snmp-login: "
                        f"\033[1;92m{snmp_login_stats.credentials_found} community string(s) found!\033[0m | "
                        f"{snmp_login_stats.hosts_tested} hosts tested"
                        f"{rw_str} "
                        f"\033[90m({snmp_login_stats.scan_time:.1f}s)\033[0m"
                    )
                    for cred in self.snmp_login_scanner.get_all_credentials():
                        rw_tag = ""
                        if "write" in cred.access_level.lower():
                            rw_tag = " \033[1;91m[READ-WRITE!]\033[0m"
                        proof_str = f" — {cred.proof}" if cred.proof else ""
                        print(
                            f"\033[1;92m[+]\033[0m snmp-login: "
                            f"\033[96m{cred.ip}:{cred.port}\033[0m → "
                            f"\033[1;92m{cred.community}\033[0m "
                            f"(\033[93m{cred.access_level}\033[0m){rw_tag}"
                            f"\033[90m{proof_str}\033[0m"
                        )
                else:
                    print(
                        f"\033[92m[+]\033[0m snmp-login: "
                        f"\033[37mno valid community strings\033[0m | "
                        f"{snmp_login_stats.hosts_tested}/{snmp_login_stats.total_snmp_hosts} hosts tested "
                        f"\033[90m({snmp_login_stats.scan_time:.1f}s)\033[0m"
                    )
                if snmp_login_stats.hosts_skipped > 0:
                    print(
                        f"\033[93m[!]\033[0m snmp-login: "
                        f"{snmp_login_stats.hosts_skipped} host(s) skipped "
                        f"(rate limit/connection errors)"
                    )
                rw_hosts = self.snmp_login_scanner.get_read_write_hosts()
                if rw_hosts:
                    print(
                        f"\033[1;91m[!]\033[0m snmp-login: \033[1;91m{len(rw_hosts)} host(s) "
                        f"with READ-WRITE community\033[0m (config modification possible!)"
                    )
                print()
            elif snmp_login_results is None:
                print(
                    f"\033[93m[!]\033[0m snmp-login: skipped by user\n"
                )

            # ── Phase 9b-4: SNMP enumeration (msfconsole) ───────────────────
            if (self.snmp_enum_scanner.available
                    and self.result.snmp_login_available
                    and snmp_login_results):
                community_map = self.snmp_login_scanner.get_community_strings()
                if community_map:
                    snmp_enum_results = self._safe_scan(
                        "snmp-enum", self.snmp_enum_scanner.scan,
                        self.result.nmap_results,
                        community_map=community_map,
                        output_dir=snmp_output_dir,
                    )

                    if snmp_enum_results is not None:
                        snmp_enum_stats = self.snmp_enum_scanner.stats

                        self.result.snmp_enum_results = snmp_enum_results
                        self.result.snmp_enum_stats = snmp_enum_stats.to_dict()
                        self.result.snmp_enum_available = True
                        self._save_phase("snmp_enum")

                        if snmp_enum_stats.hosts_with_sysinfo > 0:
                            parts = [
                                f"\033[92m{snmp_enum_stats.hosts_with_sysinfo} system(s)\033[0m"
                            ]
                            if snmp_enum_stats.hosts_with_netinfo > 0:
                                parts.append(
                                    f"\033[96m{snmp_enum_stats.hosts_with_netinfo} network\033[0m"
                                )
                            if snmp_enum_stats.hosts_with_users > 0:
                                parts.append(
                                    f"\033[93m{snmp_enum_stats.hosts_with_users} users\033[0m"
                                )
                            if snmp_enum_stats.hosts_with_processes > 0:
                                parts.append(
                                    f"\033[36m{snmp_enum_stats.hosts_with_processes} processes\033[0m"
                                )
                            print(
                                f"\033[92m[+]\033[0m snmp-enum: "
                                f"{' | '.join(parts)} enumerated "
                                f"\033[90m({snmp_enum_stats.scan_time:.1f}s)\033[0m"
                            )
                            for si in self.snmp_enum_scanner.get_all_system_info():
                                desc_str = f" — {si.description}" if si.description else ""
                                print(
                                    f"\033[92m[+]\033[0m snmp-enum: "
                                    f"\033[96m{si.host_ip}\033[0m → "
                                    f"\033[1;92m{si.hostname}\033[0m"
                                    f"\033[90m{desc_str}\033[0m"
                                )
                        else:
                            print(
                                f"\033[92m[+]\033[0m snmp-enum: "
                                f"\033[37mno data retrieved\033[0m | "
                                f"{snmp_enum_stats.hosts_enumerated}/{snmp_enum_stats.total_snmp_hosts} hosts "
                                f"\033[90m({snmp_enum_stats.scan_time:.1f}s)\033[0m"
                            )
                        fwd_hosts = self.snmp_enum_scanner.get_hosts_with_forwarding()
                        if fwd_hosts:
                            print(
                                f"\033[93m[!]\033[0m snmp-enum: \033[93m{len(fwd_hosts)} host(s) "
                                f"with IP forwarding enabled\033[0m (potential router/gateway)"
                            )
                        print()
                    else:
                        print(
                            f"\033[93m[!]\033[0m snmp-enum: skipped by user\n"
                        )

        elif (not self.snmp_login_scanner.available
              and self.result.nmap_available
              and self.result.nmap_results):
            from .scanner.snmp_login import SNMPLoginScanner as _SNMP2
            snmp_check = _SNMP2(self.config.scanner)._get_snmp_hosts(self.result.nmap_results)
            if snmp_check:
                print(
                    f"\033[93m[!]\033[0m msfconsole not found – skipping SNMP login/enum "
                    f"({len(snmp_check)} SNMP host(s) detected)"
                )
                print(
                    f"\033[90m    Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html\033[0m\n"
                )

        # ── Phase 9b-2: SSH login brute-force (msfconsole) ──────────────────
        if (self.ssh_login_scanner.available
                and self.result.nmap_available
                and self.result.nmap_results
                and not self._phase_done("ssh_login")):
            ssh_output_dir = self._ensure_output_dir()
            os.makedirs(ssh_output_dir, exist_ok=True)

            ssh_results = self._safe_scan(
                "ssh-login", self.ssh_login_scanner.scan,
                self.result.nmap_results, output_dir=ssh_output_dir,
            )

            if ssh_results:
                ssh_stats = self.ssh_login_scanner.stats

                self.result.ssh_login_results = ssh_results
                self.result.ssh_login_stats = ssh_stats.to_dict()
                self.result.ssh_login_available = True
                self._save_phase("ssh_login")

                if ssh_stats.credentials_found > 0:
                    print(
                        f"\033[1;92m[+]\033[0m ssh-login: "
                        f"\033[1;92m{ssh_stats.credentials_found} credential(s) found!\033[0m | "
                        f"{ssh_stats.hosts_tested} hosts tested | "
                        f"{ssh_stats.hosts_skipped} skipped "
                        f"\033[90m({ssh_stats.scan_time:.1f}s)\033[0m"
                    )
                    for cred in self.ssh_login_scanner.get_all_credentials():
                        print(
                            f"\033[1;92m[+]\033[0m ssh-login: "
                            f"\033[96m{cred.ip}:{cred.port}\033[0m → "
                            f"\033[1;92m{cred.username}:{cred.password}\033[0m"
                        )
                else:
                    print(
                        f"\033[37m[-]\033[0m ssh-login: no valid credentials | "
                        f"{ssh_stats.hosts_tested}/{ssh_stats.total_ssh_hosts} hosts tested | "
                        f"{ssh_stats.hosts_skipped} skipped "
                        f"\033[90m({ssh_stats.scan_time:.1f}s)\033[0m"
                    )
                print()
            elif ssh_results is None:
                print(
                    f"\033[93m[!]\033[0m ssh-login: skipped by user\n"
                )
        elif (not self.ssh_login_scanner.available
              and self.result.nmap_available
              and self.result.nmap_results):
            from .scanner.ssh_login import SSHLoginScanner as _SSH2
            ssh_check = _SSH2(self.config.scanner)._get_ssh_hosts(self.result.nmap_results)
            if ssh_check:
                print(
                    f"\033[93m[!]\033[0m msfconsole not found – skipping SSH login "
                    f"({len(ssh_check)} SSH host(s) detected)"
                )
                print(
                    f"\033[90m    Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html\033[0m\n"
                )

        # ── Phase 9b-3: MongoDB login/info/enum (msfconsole) ────────────────
        if (self.mongodb_login_scanner.available
                and self.result.nmap_available
                and self.result.nmap_results
                and not self._phase_done("mongodb_login")):
            mongo_output_dir = self._ensure_output_dir()
            os.makedirs(mongo_output_dir, exist_ok=True)

            mongo_results = self._safe_scan(
                "mongodb-login", self.mongodb_login_scanner.scan,
                self.result.nmap_results, output_dir=mongo_output_dir,
            )

            if mongo_results:
                mongo_stats = self.mongodb_login_scanner.stats

                self.result.mongodb_login_results = mongo_results
                self.result.mongodb_login_stats = mongo_stats.to_dict()
                self.result.mongodb_login_available = True
                self._save_phase("mongodb_login")

                parts = []
                if mongo_stats.credentials_found > 0:
                    parts.append(
                        f"\033[1;92m{mongo_stats.credentials_found} credential(s)\033[0m"
                    )
                if mongo_stats.hosts_with_info > 0:
                    parts.append(
                        f"{mongo_stats.hosts_with_info} server info"
                    )
                if mongo_stats.databases_found > 0:
                    parts.append(
                        f"\033[96m{mongo_stats.databases_found} database(s)\033[0m"
                    )
                if parts:
                    print(
                        f"\033[92m[+]\033[0m mongodb-login: "
                        f"{' | '.join(parts)} | "
                        f"{mongo_stats.hosts_tested}/{mongo_stats.total_mongodb_hosts} hosts "
                        f"\033[90m({mongo_stats.scan_time:.1f}s)\033[0m"
                    )
                    for cred in self.mongodb_login_scanner.get_all_credentials():
                        print(
                            f"\033[1;92m[+]\033[0m mongodb-login: "
                            f"\033[96m{cred.ip}:{cred.port}\033[0m → "
                            f"\033[1;92m{cred.username}:{cred.password}\033[0m"
                        )
                else:
                    print(
                        f"\033[37m[-]\033[0m mongodb-login: no data | "
                        f"{mongo_stats.hosts_tested}/{mongo_stats.total_mongodb_hosts} hosts | "
                        f"{mongo_stats.hosts_skipped} skipped "
                        f"\033[90m({mongo_stats.scan_time:.1f}s)\033[0m"
                    )
                print()
            elif mongo_results is None:
                print(
                    f"\033[93m[!]\033[0m mongodb-login: skipped by user\n"
                )
        elif (not self.mongodb_login_scanner.available
              and self.result.nmap_available
              and self.result.nmap_results):
            from .scanner.mongodb_login import MongoDBLoginScanner as _Mongo2
            mongo_check = _Mongo2(self.config.scanner)._get_mongodb_hosts(self.result.nmap_results)
            if mongo_check:
                print(
                    f"\033[93m[!]\033[0m msfconsole not found – skipping MongoDB login/info/enum "
                    f"({len(mongo_check)} MongoDB host(s) detected)"
                )
                print(
                    f"\033[90m    Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html\033[0m\n"
                )

        # ── Phase 9b-4: FTP login brute-force (msfconsole) ──────────────────
        if (self.ftp_login_scanner.available
                and self.result.nmap_available
                and self.result.nmap_results
                and not self._phase_done("ftp_login")):
            ftp_output_dir = self._ensure_output_dir()
            os.makedirs(ftp_output_dir, exist_ok=True)

            ftp_results = self._safe_scan(
                "ftp-login", self.ftp_login_scanner.scan,
                self.result.nmap_results, output_dir=ftp_output_dir,
            )

            if ftp_results:
                ftp_stats = self.ftp_login_scanner.stats

                self.result.ftp_login_results = ftp_results
                self.result.ftp_login_stats = ftp_stats.to_dict()
                self.result.ftp_login_available = True
                self._save_phase("ftp_login")

                parts = []
                if ftp_stats.anonymous_hosts > 0:
                    parts.append(
                        f"\033[1;91m{ftp_stats.anonymous_hosts} anonymous access!\033[0m"
                    )
                if ftp_stats.credentials_found > 0:
                    parts.append(
                        f"\033[1;92m{ftp_stats.credentials_found} credential(s)\033[0m"
                    )
                if parts:
                    print(
                        f"\033[92m[+]\033[0m ftp-login: "
                        f"{' | '.join(parts)} | "
                        f"{ftp_stats.hosts_tested}/{ftp_stats.total_ftp_hosts} hosts "
                        f"\033[90m({ftp_stats.scan_time:.1f}s)\033[0m"
                    )
                    for cred in self.ftp_login_scanner.get_all_credentials():
                        anon_tag = " \033[1;91m[ANON]\033[0m" if cred.anonymous else ""
                        print(
                            f"\033[1;92m[+]\033[0m ftp-login: "
                            f"\033[96m{cred.ip}:{cred.port}\033[0m → "
                            f"\033[1;92m{cred.username}:{cred.password}\033[0m{anon_tag}"
                        )
                else:
                    print(
                        f"\033[37m[-]\033[0m ftp-login: no valid credentials | "
                        f"{ftp_stats.hosts_tested}/{ftp_stats.total_ftp_hosts} hosts tested | "
                        f"{ftp_stats.hosts_skipped} skipped "
                        f"\033[90m({ftp_stats.scan_time:.1f}s)\033[0m"
                    )
                print()
            elif ftp_results is None:
                print(
                    f"\033[93m[!]\033[0m ftp-login: skipped by user\n"
                )
        elif (not self.ftp_login_scanner.available
              and self.result.nmap_available
              and self.result.nmap_results):
            from .scanner.ftp_login import FTPLoginScanner as _FTP2
            ftp_check = _FTP2(self.config.scanner)._get_ftp_hosts(self.result.nmap_results)
            if ftp_check:
                print(
                    f"\033[93m[!]\033[0m msfconsole not found – skipping FTP login "
                    f"({len(ftp_check)} FTP host(s) detected)"
                )
                print(
                    f"\033[90m    Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html\033[0m\n"
                )

        # ── Phase 9b-5: PostgreSQL login (msfconsole) ────────────────────
        if (self.postgres_login_scanner.available
                and self.result.nmap_available
                and self.result.nmap_results
                and not self._phase_done("postgres_login")):
            pg_output_dir = self._ensure_output_dir()
            os.makedirs(pg_output_dir, exist_ok=True)

            pg_results = self._safe_scan(
                "postgres-login", self.postgres_login_scanner.scan,
                self.result.nmap_results, output_dir=pg_output_dir,
            )

            if pg_results:
                pg_stats = self.postgres_login_scanner.stats

                self.result.postgres_login_results = pg_results
                self.result.postgres_login_stats = pg_stats.to_dict()
                self.result.postgres_login_available = True
                self._save_phase("postgres_login")

                if pg_stats.credentials_found > 0:
                    print(
                        f"\033[92m[+]\033[0m postgres-login: "
                        f"\033[1;92m{pg_stats.credentials_found} credential(s)\033[0m | "
                        f"{pg_stats.hosts_tested}/{pg_stats.total_postgres_hosts} hosts "
                        f"\033[90m({pg_stats.scan_time:.1f}s)\033[0m"
                    )
                    for cred in self.postgres_login_scanner.get_all_credentials():
                        pw = cred.password if cred.password else '(blank)'
                        print(
                            f"\033[1;92m[+]\033[0m postgres-login: "
                            f"\033[96m{cred.ip}:{cred.port}\033[0m → "
                            f"\033[1;92m{cred.username}:{pw}\033[0m"
                        )
                else:
                    print(
                        f"\033[37m[-]\033[0m postgres-login: no valid credentials | "
                        f"{pg_stats.hosts_tested}/{pg_stats.total_postgres_hosts} hosts tested | "
                        f"{pg_stats.hosts_skipped} skipped "
                        f"\033[90m({pg_stats.scan_time:.1f}s)\033[0m"
                    )
                print()
            elif pg_results is None:
                print(
                    f"\033[93m[!]\033[0m postgres-login: skipped by user\n"
                )
        elif (not self.postgres_login_scanner.available
              and self.result.nmap_available
              and self.result.nmap_results):
            from .scanner.postgres_login import PostgresLoginScanner as _PG2
            pg_check = _PG2(self.config.scanner)._get_postgres_hosts(self.result.nmap_results)
            if pg_check:
                print(
                    f"\033[93m[!]\033[0m msfconsole not found – skipping PostgreSQL login "
                    f"({len(pg_check)} PostgreSQL host(s) detected)"
                )
                print(
                    f"\033[90m    Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html\033[0m\n"
                )

        # ── Phase 9b: RDP brute-force (netexec) ─────────────────────────────
        if (self.rdp_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("rdp")):
            rdp_output_dir = self._ensure_output_dir()
            os.makedirs(rdp_output_dir, exist_ok=True)

            rdp_results = self._safe_scan(
                "rdp-brute", self.rdp_scanner.scan,
                self.result.nmap_results, output_dir=rdp_output_dir,
            )

            if rdp_results:
                rdp_stats = self.rdp_scanner.stats

                self.result.rdp_results = rdp_results
                self.result.rdp_stats = rdp_stats.to_dict()
                self.result.rdp_available = True
                self._save_phase("rdp")

                if rdp_stats.credentials_found > 0:
                    pwn_str = ""
                    if rdp_stats.pwned_count > 0:
                        pwn_str = (
                            f" | \033[1;91m{rdp_stats.pwned_count} Pwn3d!\033[0m"
                        )
                    print(
                        f"\033[1;92m[+]\033[0m rdp-brute: "
                        f"\033[1;92m{rdp_stats.credentials_found} credential(s) found!\033[0m | "
                        f"{rdp_stats.hosts_tested} hosts tested | "
                        f"{rdp_stats.total_users_tested} users tested"
                        f"{pwn_str} "
                        f"\033[90m({rdp_stats.scan_time:.1f}s)\033[0m"
                    )
                else:
                    print(
                        f"\033[92m[+]\033[0m rdp-brute: "
                        f"\033[37mno valid credentials\033[0m | "
                        f"{rdp_stats.hosts_tested}/{rdp_stats.total_rdp_hosts} hosts tested "
                        f"\033[90m({rdp_stats.scan_time:.1f}s)\033[0m"
                    )
                if rdp_stats.hosts_skipped > 0:
                    print(
                        f"\033[93m[!]\033[0m rdp-brute: "
                        f"{rdp_stats.hosts_skipped} host(s) skipped "
                        f"(lockout/connection errors)"
                    )
                print()
            elif rdp_results is None:
                print(
                    f"\033[93m[!]\033[0m rdp-brute: skipped by user\n"
                )
        elif (not self.rdp_scanner.available
              and self.result.nmap_available
              and self.result.nmap_results):
            # Check if there are any RDP hosts to notify user
            rdp_check = self.rdp_scanner._get_rdp_hosts(self.result.nmap_results) if hasattr(self.rdp_scanner, '_get_rdp_hosts') else {}
            if rdp_check:
                print(
                    f"\033[93m[!]\033[0m netexec not found – skipping RDP brute-force "
                    f"({len(rdp_check)} RDP host(s) detected)"
                )
                print(
                    f"\033[90m    Install: pip install netexec\033[0m\n"
                )

        # ── Phase 9c-2: MSF SMB brute-force (after enum4linux finds users) ──
        if (self.msf_scanner.available
                and self.result.enum4linux_available
                and self.result.enum4linux_results
                and not self._phase_done("msf")):
            # Get users discovered by enum4linux
            enum_users = self.enum4linux_scanner.get_all_users()
            if enum_users:
                msf_output_dir = self._ensure_output_dir()
                os.makedirs(msf_output_dir, exist_ok=True)

                msf_results = self._safe_scan(
                    "msf-brute", self.msf_scanner.scan,
                    enum_users, output_dir=msf_output_dir,
                )

                if msf_results is not None:
                    msf_stats = self.msf_scanner.stats

                    self.result.msf_results = msf_results
                    self.result.msf_stats = msf_stats.to_dict()
                    self.result.msf_available = True
                    self._save_phase("msf")

                    # Print MSF summary
                    if msf_stats.credentials_found > 0:
                        print(
                            f"\033[1;92m[+]\033[0m msf-brute: "
                            f"\033[1;92m{msf_stats.credentials_found} credential(s) found!\033[0m | "
                            f"{msf_stats.ips_tested} IPs tested | "
                            f"{msf_stats.total_users_tested} users tested "
                            f"\033[90m({msf_stats.scan_time:.1f}s)\033[0m"
                        )
                        # Show found credentials
                        for cred in self.msf_scanner.get_all_credentials():
                            domain_str = f"{cred.domain}\\" if cred.domain else ""
                            print(
                                f"\033[1;92m[+]\033[0m msf-brute: "
                                f"\033[96m{cred.ip}\033[0m → "
                                f"\033[1;92m{domain_str}{cred.username}:{cred.password}\033[0m"
                            )
                    else:
                        print(
                            f"\033[92m[+]\033[0m msf-brute: "
                            f"\033[37mno valid credentials\033[0m | "
                            f"{msf_stats.ips_tested} IPs tested | "
                            f"{msf_stats.total_users_tested} users tested "
                            f"\033[90m({msf_stats.scan_time:.1f}s)\033[0m"
                        )
                    if msf_stats.ips_skipped > 0:
                        print(
                            f"\033[93m[!]\033[0m msf-brute: "
                            f"{msf_stats.ips_skipped} IP(s) skipped "
                            f"(lockout/rate limit/timeout)"
                        )
                    print()
                else:
                    print(
                        f"\033[93m[!]\033[0m msf-brute: skipped by user\n"
                    )
        elif (not self.msf_scanner.available
              and self.result.enum4linux_available
              and self.enum4linux_scanner.get_all_users()):
            print(
                f"\033[93m[!]\033[0m msfconsole not found – skipping SMB brute-force"
            )
            print(
                f"\033[90m    Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html\033[0m\n"
            )

        # ── Phase 9c: CrackMapExec protocol enumeration ─────────────────────
        if (self.cme_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("cme")):
            print(
                f"\033[36m[>]\033[0m CME: grouping hosts by protocol from nmap results ..."
            )
            cme_output_dir = self._ensure_output_dir()
            os.makedirs(cme_output_dir, exist_ok=True)

            cme_results = self._safe_scan(
                "CME", self.cme_scanner.scan,
                self.result.nmap_results, output_dir=cme_output_dir,
            )

            if cme_results:
                cme_stats = self.cme_scanner.stats

                self.result.cme_results = cme_results
                self.result.cme_stats = cme_stats.to_dict()
                self.result.cme_available = True
                self._save_phase("cme")

                # Print CME summary
                if cme_stats.protocols_scanned > 0:
                    proto_parts = []
                    for proto, count in sorted(cme_stats.protocol_summary.items()):
                        proto_parts.append(
                            f"\033[96m{proto}\033[0m(\033[92m{count}\033[0m)"
                        )
                    proto_str = ", ".join(proto_parts)
                    print(
                        f"\033[92m[+]\033[0m CME: \033[92m{cme_stats.protocols_scanned} protocols\033[0m "
                        f"scanned | {cme_stats.total_hosts_discovered} hosts responded "
                        f"\033[90m({cme_stats.scan_time:.1f}s)\033[0m"
                    )
                    if proto_parts:
                        print(f"\033[92m[+]\033[0m CME: {proto_str}")

                    # Highlight SMB signing disabled (important for pentesting)
                    smb_nosign = self.cme_scanner.get_smb_signing_disabled()
                    if smb_nosign:
                        print(
                            f"\033[91m[!]\033[0m CME: \033[91m{len(smb_nosign)} hosts "
                            f"with SMB signing disabled\033[0m (relay targets)"
                        )
                    print()
                else:
                    print(
                        f"\033[92m[+]\033[0m CME: no matching protocols found in nmap results\n"
                    )
            elif cme_results is None:
                print(
                    f"\033[93m[!]\033[0m CME: skipped by user\n"
                )
        elif not self.cme_scanner.available and self.result.nmap_available:
            print(
                f"\033[93m[!]\033[0m crackmapexec/nxc not found – skipping protocol enumeration"
            )
            print(
                f"\033[90m    Install: pip install crackmapexec | or: https://github.com/byt3bl33d3r/CrackMapExec\033[0m\n"
            )

        # ── Phase 9d: NetExec Module Scan (per-protocol vuln checks) ────────
        if (self.netexec_module_scanner.available
                and self.result.nmap_available
                and self.result.nmap_results
                and not self._phase_done("netexec_modules")):
            print(
                f"\033[36m[>]\033[0m netexec-modules: scanning all protocols with recon modules ..."
            )
            nxcmod_output_dir = self._ensure_output_dir()
            os.makedirs(nxcmod_output_dir, exist_ok=True)

            nxcmod_results = self._safe_scan(
                "netexec-modules", self.netexec_module_scanner.scan,
                self.result.nmap_results, output_dir=nxcmod_output_dir,
            )

            if nxcmod_results:
                nxcmod_stats = self.netexec_module_scanner.stats
                self.result.netexec_module_results = {
                    p: r.to_dict() for p, r in nxcmod_results.items()
                }
                self.result.netexec_module_stats = nxcmod_stats.to_dict()
                self.result.netexec_module_available = True
                self._save_phase("netexec_modules")

                if nxcmod_stats.total_vulnerable > 0:
                    cve_map = self.netexec_module_scanner.get_cve_summary()
                    for module, hosts in sorted(cve_map.items()):
                        print(
                            f"\033[1;91m[!]\033[0m nxc-module \033[91m{module}\033[0m "
                            f"VULNERABLE on: \033[96m{', '.join(hosts[:10])}\033[0m"
                            + (" ..." if len(hosts) > 10 else "")
                        )
                print()
            elif nxcmod_results is None:
                print(f"\033[93m[!]\033[0m netexec-modules: skipped by user\n")

        elif not self.netexec_module_scanner.available and self.result.nmap_available:
            print(
                f"\033[93m[!]\033[0m nxc/netexec not found – skipping module scan"
            )
            print(
                f"\033[90m    Install: pip install netexec\033[0m\n"
            )

        # ── Phase 5d: Nuclei vulnerability scanning (last) ───────────────
        # Attempt auto-install if nuclei is not available
        if not self.nuclei_scanner.available:
            print(
                f"\033[93m[!]\033[0m nuclei not found \u2013 attempting auto-install..."
            )
            self.nuclei_scanner.ensure_available()

        if self.nuclei_scanner.available and not self._phase_done("nuclei"):
            # Collect targets for nuclei:
            #   - subdomain (bare hostname or httpx URL)
            #   - ip address (bare IP)
            #   - ip:port (all open ports from nmap)
            nuclei_targets: list = []
            seen: set = set()

            # Subdomains: use httpx URL if available, else bare hostname
            if hasattr(self.result, 'subdomains') and self.result.subdomains:
                for sub in self.result.subdomains:
                    if sub.is_alive:
                        if sub.http_url:
                            target = sub.http_url.rstrip("/")
                        else:
                            target = sub.hostname
                        if target not in seen:
                            nuclei_targets.append(target)
                            seen.add(target)

            # Fallback: bare hostnames if nothing from httpx
            if not nuclei_targets:
                for sub in subdomain_objects:
                    if sub.is_alive and sub.hostname not in seen:
                        nuclei_targets.append(sub.hostname)
                        seen.add(sub.hostname)
                if not nuclei_targets:
                    for sub in subdomain_objects:
                        if sub.hostname not in seen:
                            nuclei_targets.append(sub.hostname)
                            seen.add(sub.hostname)

            # Add ALL open ip:port from nmap results
            if self.result.nmap_available and self.result.nmap_results:
                HTTP_PORTS_D = {80, 443, 8080, 8443, 8000, 8888, 8081, 8082, 3000, 5000, 9090, 9443, 3333, 5555}
                for ip, host_result in self.result.nmap_results.items():
                    # Add bare IP
                    if ip not in seen:
                        nuclei_targets.append(ip)
                        seen.add(ip)
                    # Add ip:port for every open port
                    if hasattr(host_result, 'ports'):
                        for port_obj in host_result.ports:
                            if port_obj.state == "open":
                                pnum = port_obj.port
                                if pnum in HTTP_PORTS_D or 'http' in (getattr(port_obj, 'service', '') or '').lower():
                                    scheme = "https" if pnum in {443, 8443, 9443} else "http"
                                    http_target = f"{scheme}://{ip}:{pnum}"
                                    if http_target not in seen:
                                        nuclei_targets.append(http_target)
                                        seen.add(http_target)
                                else:
                                    target = f"{ip}:{pnum}"
                                    if target not in seen:
                                        nuclei_targets.append(target)
                                        seen.add(target)

            if nuclei_targets:
                nuclei_output_dir = self._ensure_output_dir()
                os.makedirs(nuclei_output_dir, exist_ok=True)

                try:
                    nuclei_results = self.nuclei_scanner.scan(
                        nuclei_targets, output_dir=nuclei_output_dir,
                    )
                except KeyboardInterrupt:
                    nuclei_results = None
                    print("\n\033[93m[!]\033[0m nuclei: interrupted by user\n")

                if nuclei_results is not None:
                    nuclei_stats = self.nuclei_scanner.stats

                    self.result.nuclei_results = nuclei_results
                    self.result.nuclei_stats = nuclei_stats.to_dict()
                    self.result.nuclei_available = True

                    # Print nuclei summary
                    total = nuclei_stats.total_findings
                    if total > 0:
                        sev_parts = []
                        if nuclei_stats.critical > 0:
                            sev_parts.append(f"\033[1;91m{nuclei_stats.critical} critical\033[0m")
                        if nuclei_stats.high > 0:
                            sev_parts.append(f"\033[91m{nuclei_stats.high} high\033[0m")
                        if nuclei_stats.medium > 0:
                            sev_parts.append(f"\033[93m{nuclei_stats.medium} medium\033[0m")
                        if nuclei_stats.low > 0:
                            sev_parts.append(f"\033[36m{nuclei_stats.low} low\033[0m")
                        if nuclei_stats.info > 0:
                            sev_parts.append(f"\033[37m{nuclei_stats.info} info\033[0m")
                        print(
                            f"\033[92m[+]\033[0m nuclei: \033[92m{total} finding(s)\033[0m | "
                            f"{' | '.join(sev_parts)} "
                            f"\033[90m({nuclei_stats.scan_time:.1f}s)\033[0m"
                        )
                    else:
                        print(
                            f"\033[92m[+]\033[0m nuclei: \033[37m0 findings\033[0m "
                            f"on {nuclei_stats.hosts_scanned} hosts "
                            f"\033[90m({nuclei_stats.scan_time:.1f}s)\033[0m"
                        )
                    print()
                    self._save_phase("nuclei")
                else:
                    print(
                        f"\033[93m[!]\033[0m nuclei: skipped by user\n"
                    )
        else:
            print(
                f"\033[91m[✗]\033[0m nuclei auto-install failed \u2013 skipping vulnerability scan"
            )
            print(
                f"\033[90m    Manual install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\033[0m\n"
            )

        # ── Phase 5c: WPScan WordPress scanning ──────────────────────────
        if self.wpscan_scanner.available and not self.wpscan_scanner.api_token:
            print(
                "\033[93m[!]\033[0m wpscan: \033[93mWPSCAN_API_TOKEN not set in .env\033[0m \u2013 skipping"
            )
            print(
                "\033[90m    Get a free token at: https://wpscan.com/api\033[0m\n"
            )
        elif (self.wpscan_scanner.available and self.result.nuclei_available and self.result.nuclei_results
                and not self._phase_done("wpscan")):
            from .scanner.wpscan import WPScanner as _WPS

            # Detect WordPress targets from nuclei results
            wp_targets = _WPS.detect_wordpress_targets(self.result.nuclei_results)

            if wp_targets:
                wpscan_output_dir = self._ensure_output_dir()
                os.makedirs(wpscan_output_dir, exist_ok=True)

                wpscan_results = self._safe_scan(
                    "wpscan", self.wpscan_scanner.scan,
                    sorted(wp_targets), output_dir=wpscan_output_dir,
                )

                if wpscan_results is not None:
                    wpscan_stats = self.wpscan_scanner.stats

                    self.result.wpscan_results = wpscan_results
                    self.result.wpscan_stats = wpscan_stats.to_dict()
                    self.result.wpscan_available = True
                    self._save_phase("wpscan")

                    total_vulns = wpscan_stats.total_vulns
                    if total_vulns > 0:
                        print(
                            f"\033[92m[+]\033[0m wpscan: \033[92m{total_vulns} vulnerability/ies\033[0m "
                            f"on \033[96m{wpscan_stats.targets_scanned}\033[0m WordPress target(s) "
                            f"\033[90m({wpscan_stats.scan_time:.1f}s)\033[0m"
                        )
                    else:
                        print(
                            f"\033[92m[+]\033[0m wpscan: \033[37m0 vulnerabilities\033[0m "
                            f"on {wpscan_stats.targets_scanned} WordPress target(s) "
                            f"\033[90m({wpscan_stats.scan_time:.1f}s)\033[0m"
                        )
                    print()
                else:
                    print(
                        f"\033[93m[!]\033[0m wpscan: skipped by user\n"
                    )
            else:
                print(
                    f"\033[90m[·]\033[0m wpscan: no WordPress targets detected by nuclei\n"
                )
        elif not self.wpscan_scanner.available and self.result.nuclei_available:
            print(
                f"\033[93m[!]\033[0m wpscan not found – skipping WordPress scan"
            )
            print(
                f"\033[90m    Install: gem install wpscan | or: https://github.com/wpscanteam/wpscan\033[0m\n"
            )

        # ── Katana web crawling (domain mode) ─────────────────────────────
        # Attempt auto-install if katana is not available
        if not self.katana_scanner.available:
            print(
                f"\033[93m[!]\033[0m katana not found \u2013 attempting auto-install..."
            )
            self.katana_scanner.ensure_available()

        if self.katana_scanner.available and not self._phase_done("katana"):
            from .scanner.katana_scan import KatanaScanner as _KAT
            katana_targets: set = set()

            # Gather HTTP/HTTPS targets from httpx results
            if hasattr(self.result, 'httpx_results') and self.result.httpx_results:
                katana_targets |= _KAT.get_http_targets_from_httpx(self.result.httpx_results)

            # Also gather from nmap HTTP/HTTPS services
            if self.result.nmap_available and self.result.nmap_results:
                katana_targets |= _KAT.get_http_targets_from_nmap(self.result.nmap_results)

            # Add alive subdomains as targets (domain mode)
            if hasattr(self.result, 'subdomains') and self.result.subdomains:
                for sub in self.result.subdomains:
                    if sub.is_alive:
                        scheme = getattr(sub, 'http_scheme', 'https') or 'https'
                        katana_targets.add(f"{scheme}://{sub.hostname}")

            if katana_targets:
                katana_output_dir = self._ensure_output_dir()
                os.makedirs(katana_output_dir, exist_ok=True)

                katana_results = self._safe_scan(
                    "katana", self.katana_scanner.scan,
                    sorted(katana_targets), output_dir=katana_output_dir,
                )

                if katana_results is not None:
                    katana_stats = self.katana_scanner.stats

                    self.result.katana_results = katana_results
                    self.result.katana_stats = katana_stats.to_dict()
                    self.result.katana_available = True
                    self._save_phase("katana")

                    total_urls = katana_stats.total_urls
                    if total_urls > 0:
                        parts = [f"\033[92m{total_urls} URLs\033[0m"]
                        if katana_stats.js_files > 0:
                            parts.append(f"\033[96m{katana_stats.js_files} JS\033[0m")
                        if katana_stats.api_endpoints > 0:
                            parts.append(f"\033[93m{katana_stats.api_endpoints} API\033[0m")
                        print(
                            f"\033[92m[+]\033[0m katana: {' | '.join(parts)} "
                            f"from \033[96m{katana_stats.targets_crawled}\033[0m target(s) "
                            f"\033[90m({katana_stats.scan_time:.1f}s)\033[0m"
                        )
                    else:
                        print(
                            f"\033[92m[+]\033[0m katana: \033[37m0 URLs\033[0m "
                            f"from {katana_stats.targets_crawled} target(s) "
                            f"\033[90m({katana_stats.scan_time:.1f}s)\033[0m"
                        )
                    print()

                    # Run httpx on katana URLs for enriched output
                    if total_urls > 0 and self.httpx_probe.available:
                        katana_urls_file = os.path.join(katana_output_dir, "txt", "katana_urls.txt")
                        if os.path.isfile(katana_urls_file):
                            katana_httpx_file = os.path.join(katana_output_dir, "txt", "katana_httpx.txt")
                            try:
                                line_count = self._run_katana_httpx_enrichment(
                                    katana_urls_file,
                                    katana_httpx_file,
                                    katana_stats.targets_crawled,
                                    total_urls,
                                )
                                if line_count is None:
                                    print()
                                elif line_count > 0:
                                    print(
                                        f"\033[92m[+]\033[0m katana+httpx: "
                                        f"\033[92m{line_count} alive URLs\033[0m "
                                        f"saved to \033[96mkatana_httpx.txt\033[0m"
                                    )
                                else:
                                    print(
                                        f"\033[37m[-]\033[0m katana+httpx: no alive URLs"
                                    )
                                print()
                            except Exception:
                                pass
                else:
                    print(
                        f"\033[93m[!]\033[0m katana: skipped by user\n"
                    )
            else:
                print(
                    f"\033[90m[\u00b7]\033[0m katana: no HTTP/HTTPS targets found\n"
                )
        elif not self.katana_scanner.available:
            print(
                f"\033[91m[✗]\033[0m katana auto-install failed \u2013 skipping web crawling"
            )
            print(
                f"\033[90m    Manual install: go install github.com/projectdiscovery/katana/cmd/katana@latest\033[0m\n"
            )

        # ── Dirsearch directory brute-force (domain mode) ────────────────
        if self.dirsearch_scanner.available and not self._phase_done("dirsearch"):
            from .scanner.katana_scan import KatanaScanner as _KAT_D
            dirsearch_targets: set = set()

            if hasattr(self.result, 'httpx_results') and self.result.httpx_results:
                dirsearch_targets |= _KAT_D.get_http_targets_from_httpx(self.result.httpx_results)
            if self.result.nmap_available and self.result.nmap_results:
                dirsearch_targets |= _KAT_D.get_http_targets_from_nmap(self.result.nmap_results)
            if hasattr(self.result, 'subdomains') and self.result.subdomains:
                for sub in self.result.subdomains:
                    if sub.is_alive:
                        scheme = getattr(sub, 'http_scheme', 'https') or 'https'
                        dirsearch_targets.add(f"{scheme}://{sub.hostname}")

            if dirsearch_targets:
                dirsearch_output_dir = self._ensure_output_dir()
                os.makedirs(dirsearch_output_dir, exist_ok=True)

                dirsearch_results = self._safe_scan(
                    "dirsearch", self.dirsearch_scanner.scan,
                    sorted(dirsearch_targets), output_dir=dirsearch_output_dir,
                )

                if dirsearch_results is not None:
                    dirsearch_stats = self.dirsearch_scanner.stats
                    self.result.dirsearch_results = dirsearch_results
                    self.result.dirsearch_stats = dirsearch_stats.to_dict()
                    self.result.dirsearch_available = True
                    self._save_phase("dirsearch")

                    total = dirsearch_stats.total_findings
                    print(
                        f"\033[92m[+]\033[0m dirsearch: "
                        f"\033[92m{total} finding(s)\033[0m "
                        f"from \033[96m{dirsearch_stats.targets_scanned}\033[0m target(s) "
                        f"\033[90m({dirsearch_stats.scan_time:.1f}s)\033[0m\n"
                    )
                else:
                    print(
                        f"\033[93m[!]\033[0m dirsearch: skipped by user\n"
                    )
            else:
                print(
                    f"\033[90m[\u00b7]\033[0m dirsearch: no HTTP/HTTPS targets found\n"
                )
        elif not self.dirsearch_scanner.available:
            print(
                f"\033[93m[!]\033[0m dirsearch not found \u2013 skipping directory brute-force"
            )
            print(
                f"\033[90m    Install: pip3 install dirsearch | or: apt install dirsearch\033[0m\n"
            )

        # ── Phase 10: Statistics ───────────────────────────────────────────
        self.result.flagged_interesting = sum(
            1 for s in subdomain_objects if s.interesting
        )
        self.result.takeover_db_services = self.takeover_scanner.db_service_count
        self.result.tech_db_signatures = self.tech_profiler.total_signatures
        self.result.scan_time = time.time() - start_time

        # ── Phase 11a: AI Pentest Analysis (Gemini 2.5 Flash) ─────────────
        if self.ai_analyst.available and not self._phase_done("ai_analysis"):
            ai_report = self.ai_analyst.analyse(
                self.result.to_dict(),
                target=self.config.target_domain,
            )
            if ai_report:
                self.result.ai_report = ai_report
                self.result.ai_available = True
                self._save_phase("ai_analysis")
                # Output directory for AI report file
                try:
                    ai_out_dir = self._ensure_output_dir()
                    ai_report_file = os.path.join(ai_out_dir, "ai_pentest_report.txt")
                    self.ai_analyst.print_report(ai_report, output_file=ai_report_file)
                except Exception:
                    self.ai_analyst.print_report(ai_report)

        # ── Phase 11: Render & Export ──────────────────────────────────────
        self._output()
        self._clear_checkpoint()

        return self.result

    # ══════════════════════════════════════════════════════════════════════
    # Direct-target mode — IP / CIDR / file of IPs
    # Skips all subdomain enumeration and goes straight to nmap + CME + enum4linux.
    # ══════════════════════════════════════════════════════════════════════

    def _run_direct(self, start_time: float) -> ScanResult:
        """
        Execute a direct scan on IP addresses / CIDR ranges.
        Skips subdomain enum, CT logs, takeover, tech profiler, httpx, etc.
        Runs nmap → CME → enum4linux against the provided targets.
        """
        targets = list(set(self.config.direct_targets))  # deduplicate
        label = self.config.input_label or self.config.target_domain

        self.result.target_domain = label
        self.result.total_unique = len(targets)

        # ── Resume from checkpoint if available ────────────────────────────
        resumed = self._load_checkpoint()
        if resumed:
            phases_done = len(self._completed_phases)
            print(
                f"\033[92m[+]\033[0m Resuming from checkpoint "
                f"(\033[92m{phases_done}\033[0m phases completed)\n"
            )

        print(
            f"\033[1;97m[»]\033[0m Direct mode: \033[1;96m{len(targets)}\033[0m "
            f"target(s) from \033[96m{label}\033[0m"
        )
        print(
            f"\033[1;97m[»]\033[0m Skipping subdomain enumeration — "
            f"jumping to nmap, enum4linux, smbclient, smb-brute, vnc-brute, RDP-brute, MSF-brute, CME, Nuclei & WPScan\n"
        )

        # ── Nmap port & service scanning ──────────────────────────────────
        _nmap_import = getattr(self.config.scanner, 'nmap_import_file', '')
        if self.nmap_scanner.available and not self._phase_done("nmap"):
            all_ips = set(targets)

            if _nmap_import or all_ips:
                nmap_output_dir = self._target_output_dir(label.replace("/", "_"))
                os.makedirs(nmap_output_dir, exist_ok=True)

                if _nmap_import:
                    nmap_results = self.nmap_scanner.load_from_file(_nmap_import)
                    _scan_ips = sorted(nmap_results.keys()) if not all_ips else sorted(all_ips)
                else:
                    nmap_results = self._safe_scan(
                        "nmap", self.nmap_scanner.scan,
                        all_ips, output_dir=nmap_output_dir,
                    )
                    _scan_ips = sorted(all_ips)

                if nmap_results is not None:
                    nmap_stats = self.nmap_scanner.stats

                    self.result.nmap_results = nmap_results
                    self.result.nmap_stats = nmap_stats.to_dict()
                    self.result.nmap_available = True
                    self.result.nmap_scanned_ips = _scan_ips
                    self._save_phase("nmap")

                    if nmap_stats.hosts_up > 0:
                        svc_str = ", ".join(
                            f"\033[96m{s['service']}\033[0m(\033[37m{s['count']}\033[0m)"
                            for s in nmap_stats.top_services[:5]
                        )
                        port_str = ", ".join(
                            f"\033[93m{p['port']}\033[0m(\033[37m{p['count']}\033[0m)"
                            for p in nmap_stats.top_ports[:5]
                        )
                        print(
                            f"\033[92m[+]\033[0m nmap: \033[92m{nmap_stats.hosts_up} hosts up\033[0m / "
                            f"{nmap_stats.total_ips_scanned} scanned | "
                            f"\033[92m{nmap_stats.total_open_ports} open ports\033[0m | "
                            f"{nmap_stats.unique_services} services "
                            f"\033[90m({nmap_stats.scan_time:.1f}s)\033[0m"
                        )
                        if svc_str:
                            print(f"\033[92m[+]\033[0m nmap: services = {svc_str}")
                        if port_str:
                            print(f"\033[92m[+]\033[0m nmap: top ports = {port_str}")
                        print()
                    else:
                        print(
                            f"\033[92m[+]\033[0m nmap: \033[37m0 hosts up\033[0m / "
                            f"{nmap_stats.total_ips_scanned} scanned "
                            f"\033[90m({nmap_stats.scan_time:.1f}s)\033[0m\n"
                        )
                else:
                    print(
                        f"\033[93m[!]\033[0m nmap: skipped by user\n"
                    )
        elif not self.nmap_scanner.available:
            print(
                f"\033[93m[!]\033[0m nmap not found – skipping port & service scan"
            )
            print(
                f"\033[90m    Install: https://nmap.org/download.html\033[0m\n"
            )

        # ── Enum4linux SMB/Windows enumeration (direct mode) ───────────────
        if (self.enum4linux_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("enum4linux")):
            # Only scan IPs that have SMB/NetBIOS ports open
            smb_ports = {445, 139, 137, 138}
            enum_ips = set()
            for ip, host_result in self.result.nmap_results.items():
                ports = host_result.ports if hasattr(host_result, 'ports') else []
                for p in ports:
                    port_num = p.port if hasattr(p, 'port') else p.get('port', 0)
                    state = p.state if hasattr(p, 'state') else p.get('state', '')
                    if port_num in smb_ports and state == "open":
                        enum_ips.add(ip)
                        break
            if enum_ips:
                enum_output_dir = self._target_output_dir(label.replace("/", "_"))
                os.makedirs(enum_output_dir, exist_ok=True)

                enum_results = self._safe_scan(
                    "enum4linux", self.enum4linux_scanner.scan,
                    enum_ips, output_dir=enum_output_dir,
                )

                if enum_results is not None:
                    enum_stats = self.enum4linux_scanner.stats

                    self.result.enum4linux_results = enum_results
                    self.result.enum4linux_stats = enum_stats.to_dict()
                    self.result.enum4linux_available = True
                    self._save_phase("enum4linux")

                    if enum_stats.hosts_responded > 0:
                        parts = [
                            f"\033[92m{enum_stats.hosts_responded} hosts responded\033[0m / "
                            f"{enum_stats.total_ips_scanned} scanned"
                        ]
                        if enum_stats.total_shares > 0:
                            parts.append(f"\033[96m{enum_stats.total_shares} shares\033[0m")
                        if enum_stats.total_users > 0:
                            parts.append(f"\033[96m{enum_stats.total_users} users\033[0m")
                        if enum_stats.total_groups > 0:
                            parts.append(f"\033[96m{enum_stats.total_groups} groups\033[0m")
                        if enum_stats.null_sessions > 0:
                            parts.append(
                                f"\033[91m{enum_stats.null_sessions} null session(s)\033[0m"
                            )
                        print(
                            f"\033[92m[+]\033[0m enum4linux: {' | '.join(parts)} "
                            f"\033[90m({enum_stats.scan_time:.1f}s)\033[0m"
                        )

                        null_hosts = self.enum4linux_scanner.get_null_session_hosts()
                        if null_hosts:
                            print(
                                f"\033[91m[!]\033[0m enum4linux: \033[91m{len(null_hosts)} host(s) "
                                f"allow null sessions\033[0m (anonymous access)"
                            )
                        print()
                    else:
                        print(
                            f"\033[92m[+]\033[0m enum4linux: \033[37m0 hosts responded\033[0m / "
                            f"{enum_stats.total_ips_scanned} scanned "
                            f"\033[90m({enum_stats.scan_time:.1f}s)\033[0m\n"
                        )
                else:
                    print(
                        f"\033[93m[!]\033[0m enum4linux: skipped by user\n"
                    )
        elif not self.enum4linux_scanner.available and self.result.nmap_available:
            print(
                f"\033[93m[!]\033[0m enum4linux not found – skipping SMB/Windows enumeration"
            )
            print(
                f"\033[90m    Install: sudo apt install enum4linux\033[0m\n"
            )

        # ── SMBClient null session detection (direct mode) ──────────────────
        if (self.smbclient_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("smbclient")):
            from .scanner.smbclient_scan import SMBClientScanner as _SMBC
            smb_hosts = _SMBC.get_smb_hosts(self.result.nmap_results)
            if smb_hosts:
                smb_output_dir = self._target_output_dir(label.replace("/", "_"))
                os.makedirs(smb_output_dir, exist_ok=True)

                smb_results = self._safe_scan(
                    "smbclient", self.smbclient_scanner.scan,
                    smb_hosts, output_dir=smb_output_dir,
                )

                if smb_results is not None:
                    smb_stats = self.smbclient_scanner.stats

                    self.result.smbclient_results = smb_results
                    self.result.smbclient_stats = smb_stats.to_dict()
                    self.result.smbclient_available = True
                    self._save_phase("smbclient")

                    if smb_stats.hosts_with_null_session > 0:
                        parts = [
                            f"\033[91m{smb_stats.hosts_with_null_session} null session(s)\033[0m / "
                            f"{smb_stats.total_hosts_scanned} scanned"
                        ]
                        if smb_stats.total_shares > 0:
                            parts.append(f"\033[96m{smb_stats.total_shares} shares\033[0m")
                        if smb_stats.accessible_shares > 0:
                            parts.append(
                                f"\033[91m{smb_stats.accessible_shares} accessible share(s)\033[0m"
                            )
                        if smb_stats.total_files_listed > 0:
                            parts.append(
                                f"\033[92m{smb_stats.total_files_listed} files listed\033[0m"
                            )
                        print(
                            f"\033[92m[+]\033[0m smbclient: {' | '.join(parts)} "
                            f"\033[90m({smb_stats.scan_time:.1f}s)\033[0m"
                        )

                        null_hosts = self.smbclient_scanner.get_null_session_hosts()
                        if null_hosts:
                            print(
                                f"\033[91m[!]\033[0m smbclient: \033[91m{len(null_hosts)} host(s) "
                                f"allow null sessions\033[0m (anonymous SMB access)"
                            )
                            for ip in null_hosts[:5]:
                                hr = smb_results[ip]
                                share_names = [s.name for s in hr.shares]
                                print(
                                    f"\033[91m[!]\033[0m smbclient: \033[96m{ip}\033[0m → "
                                    f"{', '.join(share_names[:6])}"
                                    f"{'...' if len(share_names) > 6 else ''}"
                                )
                        acc_hosts = self.smbclient_scanner.get_accessible_share_hosts()
                        if acc_hosts:
                            print(
                                f"\033[1;91m[!]\033[0m smbclient: \033[1;91m{len(acc_hosts)} host(s) "
                                f"with readable shares\033[0m (data exposure!)"
                            )
                        print()
                    else:
                        print(
                            f"\033[92m[+]\033[0m smbclient: \033[37m0 null sessions\033[0m / "
                            f"{smb_stats.total_hosts_scanned} scanned "
                            f"\033[90m({smb_stats.scan_time:.1f}s)\033[0m\n"
                        )
                else:
                    print(
                        f"\033[93m[!]\033[0m smbclient: skipped by user\n"
                    )
        elif not self.smbclient_scanner.available and self.result.nmap_available:
            from .scanner.smbclient_scan import SMBClientScanner as _SMBC2
            smb_check = _SMBC2.get_smb_hosts(self.result.nmap_results) if self.result.nmap_results else set()
            if smb_check:
                print(
                    f"\033[93m[!]\033[0m smbclient not found – skipping null session detection "
                    f"({len(smb_check)} SMB host(s) detected)"
                )
                print(
                    f"\033[90m    Install: sudo apt install smbclient\033[0m\n"
                )

        # ── SMB brute-force (direct mode) ──────────────────────────────────
        if (self.smb_brute_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("smb_brute")):
            smb_brute_output_dir = self._target_output_dir(label.replace("/", "_"))
            os.makedirs(smb_brute_output_dir, exist_ok=True)

            smb_brute_results = self._safe_scan(
                "smb-brute", self.smb_brute_scanner.scan,
                self.result.nmap_results, output_dir=smb_brute_output_dir,
            )

            if smb_brute_results:
                smb_brute_stats = self.smb_brute_scanner.stats

                self.result.smb_brute_results = smb_brute_results
                self.result.smb_brute_stats = smb_brute_stats.to_dict()
                self.result.smb_brute_available = True
                self._save_phase("smb_brute")

                if smb_brute_stats.credentials_found > 0:
                    pwn_str = ""
                    if smb_brute_stats.pwned_count > 0:
                        pwn_str = (
                            f" | \033[1;91m{smb_brute_stats.pwned_count} Pwn3d!\033[0m"
                        )
                    sam_str = ""
                    if smb_brute_stats.sam_hashes_dumped > 0:
                        sam_str = (
                            f" | \033[1;95m{smb_brute_stats.sam_hashes_dumped} SAM hashes\033[0m"
                        )
                    print(
                        f"\033[1;92m[+]\033[0m smb-brute: "
                        f"\033[1;92m{smb_brute_stats.credentials_found} credential(s) found!\033[0m | "
                        f"{smb_brute_stats.hosts_tested} hosts tested"
                        f"{pwn_str}{sam_str} "
                        f"\033[90m({smb_brute_stats.scan_time:.1f}s)\033[0m"
                    )
                    for cred in self.smb_brute_scanner.get_all_credentials():
                        domain_str = f"{cred.domain}\\" if cred.domain else ""
                        pwn_tag = " \033[1;91m(Pwn3d!)\033[0m" if cred.pwned else ""
                        anon_tag = " \033[1;93m(anonymous)\033[0m" if cred.anonymous else ""
                        print(
                            f"\033[1;92m[+]\033[0m smb-brute: "
                            f"\033[96m{cred.ip}\033[0m → "
                            f"\033[1;92m{domain_str}{cred.username}:{cred.password}\033[0m"
                            f"{pwn_tag}{anon_tag}"
                        )
                else:
                    print(
                        f"\033[92m[+]\033[0m smb-brute: "
                        f"\033[37mno valid credentials\033[0m | "
                        f"{smb_brute_stats.hosts_tested}/{smb_brute_stats.total_smb_hosts} hosts tested "
                        f"\033[90m({smb_brute_stats.scan_time:.1f}s)\033[0m"
                    )
                null_hosts = self.smb_brute_scanner.get_null_auth_hosts()
                if null_hosts:
                    print(
                        f"\033[1;91m[!]\033[0m smb-brute: \033[1;91m{len(null_hosts)} host(s) "
                        f"allow anonymous/null access\033[0m"
                    )
                pwned_hosts = self.smb_brute_scanner.get_pwned_hosts()
                if pwned_hosts:
                    print(
                        f"\033[1;91m[!]\033[0m smb-brute: \033[1;91m{len(pwned_hosts)} host(s) "
                        f"Pwn3d!\033[0m (admin access)"
                    )
                sam_hashes = self.smb_brute_scanner.get_all_sam_hashes()
                if sam_hashes:
                    print(
                        f"\033[1;95m[+]\033[0m smb-brute: \033[1;95m{len(sam_hashes)} SAM hash(es) "
                        f"dumped\033[0m"
                    )
                    for h in sam_hashes[:10]:
                        print(
                            f"\033[1;95m[+]\033[0m   {h.username}:{h.rid}:{h.lm_hash}:{h.nt_hash}"
                        )
                    if len(sam_hashes) > 10:
                        print(
                            f"\033[90m    ... and {len(sam_hashes) - 10} more (see smb_brute_sam_hashes.txt)\033[0m"
                        )
                if smb_brute_stats.hosts_skipped > 0:
                    print(
                        f"\033[93m[!]\033[0m smb-brute: "
                        f"{smb_brute_stats.hosts_skipped} host(s) skipped "
                        f"(lockout/connection errors)"
                    )
                print()
            elif smb_brute_results is None:
                print(
                    f"\033[93m[!]\033[0m smb-brute: skipped by user\n"
                )
        elif (not self.smb_brute_scanner.available
              and self.result.nmap_available
              and self.result.nmap_results):
            from .scanner.smb_brute import SMBBruteScanner as _SMBB3
            smb_b_check = _SMBB3(self.config.scanner)._get_smb_hosts(self.result.nmap_results)
            if smb_b_check:
                print(
                    f"\033[93m[!]\033[0m netexec (nxc) not found – skipping SMB brute-force "
                    f"({len(smb_b_check)} SMB host(s) detected)"
                )
                print(
                    f"\033[90m    Install: pip install netexec\033[0m\n"
                )

        # ── VNC brute-force (direct mode) ──────────────────────────────────
        if (self.vnc_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("vnc")):
            vnc_output_dir = self._target_output_dir(label.replace("/", "_"))
            os.makedirs(vnc_output_dir, exist_ok=True)

            vnc_results = self._safe_scan(
                "vnc-brute", self.vnc_scanner.scan,
                self.result.nmap_results, output_dir=vnc_output_dir,
            )

            if vnc_results:
                vnc_stats = self.vnc_scanner.stats

                self.result.vnc_results = vnc_results
                self.result.vnc_stats = vnc_stats.to_dict()
                self.result.vnc_available = True
                self._save_phase("vnc")

                if vnc_stats.credentials_found > 0:
                    no_auth_str = ""
                    if vnc_stats.hosts_no_auth > 0:
                        no_auth_str = (
                            f" | \033[1;91m{vnc_stats.hosts_no_auth} NO AUTH\033[0m"
                        )
                    print(
                        f"\033[1;92m[+]\033[0m vnc-brute: "
                        f"\033[1;92m{vnc_stats.credentials_found} credential(s) found!\033[0m | "
                        f"{vnc_stats.hosts_tested} hosts tested"
                        f"{no_auth_str} "
                        f"\033[90m({vnc_stats.scan_time:.1f}s)\033[0m"
                    )
                    for cred in self.vnc_scanner.get_all_credentials():
                        if cred.anonymous:
                            print(
                                f"\033[1;91m[!]\033[0m vnc-brute: "
                                f"\033[96m{cred.ip}:{cred.port}\033[0m → "
                                f"\033[1;91mNO AUTHENTICATION REQUIRED\033[0m"
                            )
                        else:
                            print(
                                f"\033[1;92m[+]\033[0m vnc-brute: "
                                f"\033[96m{cred.ip}:{cred.port}\033[0m → "
                                f"\033[1;92m:{cred.password}\033[0m"
                            )
                else:
                    print(
                        f"\033[92m[+]\033[0m vnc-brute: "
                        f"\033[37mno valid credentials\033[0m | "
                        f"{vnc_stats.hosts_tested}/{vnc_stats.total_vnc_hosts} hosts tested "
                        f"\033[90m({vnc_stats.scan_time:.1f}s)\033[0m"
                    )
                if vnc_stats.hosts_skipped > 0:
                    print(
                        f"\033[93m[!]\033[0m vnc-brute: "
                        f"{vnc_stats.hosts_skipped} host(s) skipped "
                        f"(lockout/connection errors)"
                    )
                no_auth = self.vnc_scanner.get_no_auth_hosts()
                if no_auth:
                    print(
                        f"\033[1;91m[!]\033[0m vnc-brute: \033[1;91m{len(no_auth)} host(s) "
                        f"with NO AUTHENTICATION\033[0m (open VNC access!)"
                    )
                print()
            elif vnc_results is None:
                print(
                    f"\033[93m[!]\033[0m vnc-brute: skipped by user\n"
                )
        elif (not self.vnc_scanner.available
              and self.result.nmap_available
              and self.result.nmap_results):
            from .scanner.vnc_brute import VNCBruteScanner as _VNC3
            vnc_check = _VNC3(self.config.scanner)._get_vnc_hosts(self.result.nmap_results)
            if vnc_check:
                print(
                    f"\033[93m[!]\033[0m msfconsole not found – skipping VNC brute-force "
                    f"({len(vnc_check)} VNC host(s) detected)"
                )
                print(
                    f"\033[90m    Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html\033[0m\n"
                )

        # ── SNMP login brute-force (direct mode) ──────────────────────────
        if (self.snmp_login_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("snmp_login")):
            snmp_output_dir = self._target_output_dir(label.replace("/", "_"))
            os.makedirs(snmp_output_dir, exist_ok=True)

            snmp_login_results = self._safe_scan(
                "snmp-login", self.snmp_login_scanner.scan,
                self.result.nmap_results, output_dir=snmp_output_dir,
            )

            if snmp_login_results:
                snmp_login_stats = self.snmp_login_scanner.stats

                self.result.snmp_login_results = snmp_login_results
                self.result.snmp_login_stats = snmp_login_stats.to_dict()
                self.result.snmp_login_available = True
                self._save_phase("snmp_login")

                if snmp_login_stats.credentials_found > 0:
                    rw_str = ""
                    if snmp_login_stats.read_write_found > 0:
                        rw_str = (
                            f" | \033[1;91m{snmp_login_stats.read_write_found} READ-WRITE\033[0m"
                        )
                    print(
                        f"\033[1;92m[+]\033[0m snmp-login: "
                        f"\033[1;92m{snmp_login_stats.credentials_found} community string(s) found!\033[0m | "
                        f"{snmp_login_stats.hosts_tested} hosts tested"
                        f"{rw_str} "
                        f"\033[90m({snmp_login_stats.scan_time:.1f}s)\033[0m"
                    )
                    for cred in self.snmp_login_scanner.get_all_credentials():
                        rw_tag = ""
                        if "write" in cred.access_level.lower():
                            rw_tag = " \033[1;91m[READ-WRITE!]\033[0m"
                        proof_str = f" — {cred.proof}" if cred.proof else ""
                        print(
                            f"\033[1;92m[+]\033[0m snmp-login: "
                            f"\033[96m{cred.ip}:{cred.port}\033[0m → "
                            f"\033[1;92m{cred.community}\033[0m "
                            f"(\033[93m{cred.access_level}\033[0m){rw_tag}"
                            f"\033[90m{proof_str}\033[0m"
                        )
                else:
                    print(
                        f"\033[92m[+]\033[0m snmp-login: "
                        f"\033[37mno valid community strings\033[0m | "
                        f"{snmp_login_stats.hosts_tested}/{snmp_login_stats.total_snmp_hosts} hosts tested "
                        f"\033[90m({snmp_login_stats.scan_time:.1f}s)\033[0m"
                    )
                if snmp_login_stats.hosts_skipped > 0:
                    print(
                        f"\033[93m[!]\033[0m snmp-login: "
                        f"{snmp_login_stats.hosts_skipped} host(s) skipped "
                        f"(rate limit/connection errors)"
                    )
                rw_hosts = self.snmp_login_scanner.get_read_write_hosts()
                if rw_hosts:
                    print(
                        f"\033[1;91m[!]\033[0m snmp-login: \033[1;91m{len(rw_hosts)} host(s) "
                        f"with READ-WRITE community\033[0m (config modification possible!)"
                    )
                print()

                # ── SNMP enumeration (direct mode) ─────────────────────────
                if (self.snmp_enum_scanner.available
                        and snmp_login_results):
                    community_map = self.snmp_login_scanner.get_community_strings()
                    if community_map:
                        snmp_enum_results = self._safe_scan(
                            "snmp-enum", self.snmp_enum_scanner.scan,
                            self.result.nmap_results,
                            community_map=community_map,
                            output_dir=snmp_output_dir,
                        )

                        if snmp_enum_results is not None:
                            snmp_enum_stats = self.snmp_enum_scanner.stats

                            self.result.snmp_enum_results = snmp_enum_results
                            self.result.snmp_enum_stats = snmp_enum_stats.to_dict()
                            self.result.snmp_enum_available = True
                            self._save_phase("snmp_enum")

                            if snmp_enum_stats.hosts_with_sysinfo > 0:
                                parts = [
                                    f"\033[92m{snmp_enum_stats.hosts_with_sysinfo} system(s)\033[0m"
                                ]
                                if snmp_enum_stats.hosts_with_netinfo > 0:
                                    parts.append(
                                        f"\033[96m{snmp_enum_stats.hosts_with_netinfo} network\033[0m"
                                    )
                                if snmp_enum_stats.hosts_with_users > 0:
                                    parts.append(
                                        f"\033[93m{snmp_enum_stats.hosts_with_users} users\033[0m"
                                    )
                                if snmp_enum_stats.hosts_with_processes > 0:
                                    parts.append(
                                        f"\033[36m{snmp_enum_stats.hosts_with_processes} processes\033[0m"
                                    )
                                print(
                                    f"\033[92m[+]\033[0m snmp-enum: "
                                    f"{' | '.join(parts)} enumerated "
                                    f"\033[90m({snmp_enum_stats.scan_time:.1f}s)\033[0m"
                                )
                                for si in self.snmp_enum_scanner.get_all_system_info():
                                    desc_str = f" — {si.description}" if si.description else ""
                                    print(
                                        f"\033[92m[+]\033[0m snmp-enum: "
                                        f"\033[96m{si.host_ip}\033[0m → "
                                        f"\033[1;92m{si.hostname}\033[0m"
                                        f"\033[90m{desc_str}\033[0m"
                                    )
                            else:
                                print(
                                    f"\033[92m[+]\033[0m snmp-enum: "
                                    f"\033[37mno data retrieved\033[0m | "
                                    f"{snmp_enum_stats.hosts_enumerated}/{snmp_enum_stats.total_snmp_hosts} hosts "
                                    f"\033[90m({snmp_enum_stats.scan_time:.1f}s)\033[0m"
                                )
                            fwd_hosts = self.snmp_enum_scanner.get_hosts_with_forwarding()
                            if fwd_hosts:
                                print(
                                    f"\033[93m[!]\033[0m snmp-enum: \033[93m{len(fwd_hosts)} host(s) "
                                    f"with IP forwarding enabled\033[0m (potential router/gateway)"
                                )
                            print()
                        else:
                            print(
                                f"\033[93m[!]\033[0m snmp-enum: skipped by user\n"
                            )
            elif snmp_login_results is None:
                print(
                    f"\033[93m[!]\033[0m snmp-login: skipped by user\n"
                )
        elif (not self.snmp_login_scanner.available
              and self.result.nmap_available
              and self.result.nmap_results):
            from .scanner.snmp_login import SNMPLoginScanner as _SNMP3
            snmp_check = _SNMP3(self.config.scanner)._get_snmp_hosts(self.result.nmap_results)
            if snmp_check:
                print(
                    f"\033[93m[!]\033[0m msfconsole not found – skipping SNMP login/enum "
                    f"({len(snmp_check)} SNMP host(s) detected)"
                )
                print(
                    f"\033[90m    Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html\033[0m\n"
                )

        # ── SSH login brute-force (direct mode) ───────────────────────────
        if (self.ssh_login_scanner.available
                and self.result.nmap_available
                and self.result.nmap_results
                and not self._phase_done("ssh_login")):
            ssh_output_dir = self._target_output_dir(label.replace("/", "_"))
            os.makedirs(ssh_output_dir, exist_ok=True)

            ssh_results = self._safe_scan(
                "ssh-login", self.ssh_login_scanner.scan,
                self.result.nmap_results, output_dir=ssh_output_dir,
            )

            if ssh_results:
                ssh_stats = self.ssh_login_scanner.stats

                self.result.ssh_login_results = ssh_results
                self.result.ssh_login_stats = ssh_stats.to_dict()
                self.result.ssh_login_available = True
                self._save_phase("ssh_login")

                if ssh_stats.credentials_found > 0:
                    print(
                        f"\033[1;92m[+]\033[0m ssh-login: "
                        f"\033[1;92m{ssh_stats.credentials_found} credential(s) found!\033[0m | "
                        f"{ssh_stats.hosts_tested} hosts tested | "
                        f"{ssh_stats.hosts_skipped} skipped "
                        f"\033[90m({ssh_stats.scan_time:.1f}s)\033[0m"
                    )
                    for cred in self.ssh_login_scanner.get_all_credentials():
                        print(
                            f"\033[1;92m[+]\033[0m ssh-login: "
                            f"\033[96m{cred.ip}:{cred.port}\033[0m → "
                            f"\033[1;92m{cred.username}:{cred.password}\033[0m"
                        )
                else:
                    print(
                        f"\033[37m[-]\033[0m ssh-login: no valid credentials | "
                        f"{ssh_stats.hosts_tested}/{ssh_stats.total_ssh_hosts} hosts tested | "
                        f"{ssh_stats.hosts_skipped} skipped "
                        f"\033[90m({ssh_stats.scan_time:.1f}s)\033[0m"
                    )
                print()
            elif ssh_results is None:
                print(
                    f"\033[93m[!]\033[0m ssh-login: skipped by user\n"
                )
        elif (not self.ssh_login_scanner.available
              and self.result.nmap_available
              and self.result.nmap_results):
            from .scanner.ssh_login import SSHLoginScanner as _SSH3
            ssh_check = _SSH3(self.config.scanner)._get_ssh_hosts(self.result.nmap_results)
            if ssh_check:
                print(
                    f"\033[93m[!]\033[0m msfconsole not found – skipping SSH login "
                    f"({len(ssh_check)} SSH host(s) detected)"
                )
                print(
                    f"\033[90m    Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html\033[0m\n"
                )

        # ── MongoDB login/info/enum (direct mode) ─────────────────────────
        if (self.mongodb_login_scanner.available
                and self.result.nmap_available
                and self.result.nmap_results
                and not self._phase_done("mongodb_login")):
            mongo_output_dir = self._target_output_dir(label.replace("/", "_"))
            os.makedirs(mongo_output_dir, exist_ok=True)

            mongo_results = self._safe_scan(
                "mongodb-login", self.mongodb_login_scanner.scan,
                self.result.nmap_results, output_dir=mongo_output_dir,
            )

            if mongo_results:
                mongo_stats = self.mongodb_login_scanner.stats

                self.result.mongodb_login_results = mongo_results
                self.result.mongodb_login_stats = mongo_stats.to_dict()
                self.result.mongodb_login_available = True
                self._save_phase("mongodb_login")

                parts = []
                if mongo_stats.credentials_found > 0:
                    parts.append(
                        f"\033[1;92m{mongo_stats.credentials_found} credential(s)\033[0m"
                    )
                if mongo_stats.hosts_with_info > 0:
                    parts.append(
                        f"{mongo_stats.hosts_with_info} server info"
                    )
                if mongo_stats.databases_found > 0:
                    parts.append(
                        f"\033[96m{mongo_stats.databases_found} database(s)\033[0m"
                    )
                if parts:
                    print(
                        f"\033[92m[+]\033[0m mongodb-login: "
                        f"{' | '.join(parts)} | "
                        f"{mongo_stats.hosts_tested}/{mongo_stats.total_mongodb_hosts} hosts "
                        f"\033[90m({mongo_stats.scan_time:.1f}s)\033[0m"
                    )
                    for cred in self.mongodb_login_scanner.get_all_credentials():
                        print(
                            f"\033[1;92m[+]\033[0m mongodb-login: "
                            f"\033[96m{cred.ip}:{cred.port}\033[0m → "
                            f"\033[1;92m{cred.username}:{cred.password}\033[0m"
                        )
                else:
                    print(
                        f"\033[37m[-]\033[0m mongodb-login: no data | "
                        f"{mongo_stats.hosts_tested}/{mongo_stats.total_mongodb_hosts} hosts | "
                        f"{mongo_stats.hosts_skipped} skipped "
                        f"\033[90m({mongo_stats.scan_time:.1f}s)\033[0m"
                    )
                print()
            elif mongo_results is None:
                print(
                    f"\033[93m[!]\033[0m mongodb-login: skipped by user\n"
                )
        elif (not self.mongodb_login_scanner.available
              and self.result.nmap_available
              and self.result.nmap_results):
            from .scanner.mongodb_login import MongoDBLoginScanner as _Mongo3
            mongo_check = _Mongo3(self.config.scanner)._get_mongodb_hosts(self.result.nmap_results)
            if mongo_check:
                print(
                    f"\033[93m[!]\033[0m msfconsole not found – skipping MongoDB login/info/enum "
                    f"({len(mongo_check)} MongoDB host(s) detected)"
                )
                print(
                    f"\033[90m    Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html\033[0m\n"
                )

        # ── FTP login brute-force (direct mode) ───────────────────────────
        if (self.ftp_login_scanner.available
                and self.result.nmap_available
                and self.result.nmap_results
                and not self._phase_done("ftp_login")):
            ftp_output_dir = self._target_output_dir(label.replace("/", "_"))
            os.makedirs(ftp_output_dir, exist_ok=True)

            ftp_results = self._safe_scan(
                "ftp-login", self.ftp_login_scanner.scan,
                self.result.nmap_results, output_dir=ftp_output_dir,
            )

            if ftp_results:
                ftp_stats = self.ftp_login_scanner.stats

                self.result.ftp_login_results = ftp_results
                self.result.ftp_login_stats = ftp_stats.to_dict()
                self.result.ftp_login_available = True
                self._save_phase("ftp_login")

                parts = []
                if ftp_stats.anonymous_hosts > 0:
                    parts.append(
                        f"\033[1;91m{ftp_stats.anonymous_hosts} anonymous access!\033[0m"
                    )
                if ftp_stats.credentials_found > 0:
                    parts.append(
                        f"\033[1;92m{ftp_stats.credentials_found} credential(s)\033[0m"
                    )
                if parts:
                    print(
                        f"\033[92m[+]\033[0m ftp-login: "
                        f"{' | '.join(parts)} | "
                        f"{ftp_stats.hosts_tested}/{ftp_stats.total_ftp_hosts} hosts "
                        f"\033[90m({ftp_stats.scan_time:.1f}s)\033[0m"
                    )
                    for cred in self.ftp_login_scanner.get_all_credentials():
                        anon_tag = " \033[1;91m[ANON]\033[0m" if cred.anonymous else ""
                        print(
                            f"\033[1;92m[+]\033[0m ftp-login: "
                            f"\033[96m{cred.ip}:{cred.port}\033[0m → "
                            f"\033[1;92m{cred.username}:{cred.password}\033[0m{anon_tag}"
                        )
                else:
                    print(
                        f"\033[37m[-]\033[0m ftp-login: no valid credentials | "
                        f"{ftp_stats.hosts_tested}/{ftp_stats.total_ftp_hosts} hosts tested | "
                        f"{ftp_stats.hosts_skipped} skipped "
                        f"\033[90m({ftp_stats.scan_time:.1f}s)\033[0m"
                    )
                print()
            elif ftp_results is None:
                print(
                    f"\033[93m[!]\033[0m ftp-login: skipped by user\n"
                )
        elif (not self.ftp_login_scanner.available
              and self.result.nmap_available
              and self.result.nmap_results):
            from .scanner.ftp_login import FTPLoginScanner as _FTP3
            ftp_check = _FTP3(self.config.scanner)._get_ftp_hosts(self.result.nmap_results)
            if ftp_check:
                print(
                    f"\033[93m[!]\033[0m msfconsole not found – skipping FTP login "
                    f"({len(ftp_check)} FTP host(s) detected)"
                )
                print(
                    f"\033[90m    Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html\033[0m\n"
                )

        # ── PostgreSQL login (direct mode) ─────────────────────────────────
        if (self.postgres_login_scanner.available
                and self.result.nmap_available
                and self.result.nmap_results
                and not self._phase_done("postgres_login")):
            pg_output_dir = self._target_output_dir(label.replace("/", "_"))
            os.makedirs(pg_output_dir, exist_ok=True)

            pg_results = self._safe_scan(
                "postgres-login", self.postgres_login_scanner.scan,
                self.result.nmap_results, output_dir=pg_output_dir,
            )

            if pg_results:
                pg_stats = self.postgres_login_scanner.stats

                self.result.postgres_login_results = pg_results
                self.result.postgres_login_stats = pg_stats.to_dict()
                self.result.postgres_login_available = True
                self._save_phase("postgres_login")

                if pg_stats.credentials_found > 0:
                    print(
                        f"\033[92m[+]\033[0m postgres-login: "
                        f"\033[1;92m{pg_stats.credentials_found} credential(s)\033[0m | "
                        f"{pg_stats.hosts_tested}/{pg_stats.total_postgres_hosts} hosts "
                        f"\033[90m({pg_stats.scan_time:.1f}s)\033[0m"
                    )
                    for cred in self.postgres_login_scanner.get_all_credentials():
                        pw = cred.password if cred.password else '(blank)'
                        print(
                            f"\033[1;92m[+]\033[0m postgres-login: "
                            f"\033[96m{cred.ip}:{cred.port}\033[0m → "
                            f"\033[1;92m{cred.username}:{pw}\033[0m"
                        )
                else:
                    print(
                        f"\033[37m[-]\033[0m postgres-login: no valid credentials | "
                        f"{pg_stats.hosts_tested}/{pg_stats.total_postgres_hosts} hosts tested | "
                        f"{pg_stats.hosts_skipped} skipped "
                        f"\033[90m({pg_stats.scan_time:.1f}s)\033[0m"
                    )
                print()
            elif pg_results is None:
                print(
                    f"\033[93m[!]\033[0m postgres-login: skipped by user\n"
                )
        elif (not self.postgres_login_scanner.available
              and self.result.nmap_available
              and self.result.nmap_results):
            from .scanner.postgres_login import PostgresLoginScanner as _PG3
            pg_check = _PG3(self.config.scanner)._get_postgres_hosts(self.result.nmap_results)
            if pg_check:
                print(
                    f"\033[93m[!]\033[0m msfconsole not found – skipping PostgreSQL login "
                    f"({len(pg_check)} PostgreSQL host(s) detected)"
                )
                print(
                    f"\033[90m    Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html\033[0m\n"
                )

        # ── RDP brute-force (direct mode) ──────────────────────────────────
        if (self.rdp_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("rdp")):
            rdp_output_dir = self._target_output_dir(label.replace("/", "_"))
            os.makedirs(rdp_output_dir, exist_ok=True)

            rdp_results = self._safe_scan(
                "rdp-brute", self.rdp_scanner.scan,
                self.result.nmap_results, output_dir=rdp_output_dir,
            )

            if rdp_results:
                rdp_stats = self.rdp_scanner.stats

                self.result.rdp_results = rdp_results
                self.result.rdp_stats = rdp_stats.to_dict()
                self.result.rdp_available = True
                self._save_phase("rdp")

                if rdp_stats.credentials_found > 0:
                    pwn_str = ""
                    if rdp_stats.pwned_count > 0:
                        pwn_str = (
                            f" | \033[1;91m{rdp_stats.pwned_count} Pwn3d!\033[0m"
                        )
                    print(
                        f"\033[1;92m[+]\033[0m rdp-brute: "
                        f"\033[1;92m{rdp_stats.credentials_found} credential(s) found!\033[0m | "
                        f"{rdp_stats.hosts_tested} hosts tested | "
                        f"{rdp_stats.total_users_tested} users tested"
                        f"{pwn_str} "
                        f"\033[90m({rdp_stats.scan_time:.1f}s)\033[0m"
                    )
                else:
                    print(
                        f"\033[92m[+]\033[0m rdp-brute: "
                        f"\033[37mno valid credentials\033[0m | "
                        f"{rdp_stats.hosts_tested}/{rdp_stats.total_rdp_hosts} hosts tested "
                        f"\033[90m({rdp_stats.scan_time:.1f}s)\033[0m"
                    )
                if rdp_stats.hosts_skipped > 0:
                    print(
                        f"\033[93m[!]\033[0m rdp-brute: "
                        f"{rdp_stats.hosts_skipped} host(s) skipped "
                        f"(lockout/connection errors)"
                    )
                print()
            elif rdp_results is None:
                print(
                    f"\033[93m[!]\033[0m rdp-brute: skipped by user\n"
                )
        elif (not self.rdp_scanner.available
              and self.result.nmap_available
              and self.result.nmap_results):
            rdp_check = self.rdp_scanner._get_rdp_hosts(self.result.nmap_results) if hasattr(self.rdp_scanner, '_get_rdp_hosts') else {}
            if rdp_check:
                print(
                    f"\033[93m[!]\033[0m netexec not found – skipping RDP brute-force "
                    f"({len(rdp_check)} RDP host(s) detected)"
                )
                print(
                    f"\033[90m    Install: pip install netexec\033[0m\n"
                )

        # ── MSF SMB brute-force (direct mode) ─────────────────────────────
        if (self.msf_scanner.available
                and self.result.enum4linux_available
                and self.result.enum4linux_results
                and not self._phase_done("msf")):
            enum_users = self.enum4linux_scanner.get_all_users()
            if enum_users:
                msf_output_dir = self._target_output_dir(label.replace("/", "_"))
                os.makedirs(msf_output_dir, exist_ok=True)

                msf_results = self._safe_scan(
                    "msf-brute", self.msf_scanner.scan,
                    enum_users, output_dir=msf_output_dir,
                )

                if msf_results is not None:
                    msf_stats = self.msf_scanner.stats

                    self.result.msf_results = msf_results
                    self.result.msf_stats = msf_stats.to_dict()
                    self.result.msf_available = True

                    if msf_stats.credentials_found > 0:
                        print(
                            f"\033[1;92m[+]\033[0m msf-brute: "
                            f"\033[1;92m{msf_stats.credentials_found} credential(s) found!\033[0m | "
                            f"{msf_stats.ips_tested} IPs tested | "
                            f"{msf_stats.total_users_tested} users tested "
                            f"\033[90m({msf_stats.scan_time:.1f}s)\033[0m"
                        )
                        for cred in self.msf_scanner.get_all_credentials():
                            domain_str = f"{cred.domain}\\" if cred.domain else ""
                            print(
                                f"\033[1;92m[+]\033[0m msf-brute: "
                                f"\033[96m{cred.ip}\033[0m → "
                                f"\033[1;92m{domain_str}{cred.username}:{cred.password}\033[0m"
                            )
                    else:
                        print(
                            f"\033[92m[+]\033[0m msf-brute: "
                            f"\033[37mno valid credentials\033[0m | "
                            f"{msf_stats.ips_tested} IPs tested | "
                            f"{msf_stats.total_users_tested} users tested "
                            f"\033[90m({msf_stats.scan_time:.1f}s)\033[0m"
                        )
                    if msf_stats.ips_skipped > 0:
                        print(
                            f"\033[93m[!]\033[0m msf-brute: "
                            f"{msf_stats.ips_skipped} IP(s) skipped "
                            f"(lockout/rate limit/timeout)"
                        )
                    print()
                else:
                    print(
                        f"\033[93m[!]\033[0m msf-brute: skipped by user\n"
                    )
        elif (not self.msf_scanner.available
              and self.result.enum4linux_available
              and self.enum4linux_scanner.get_all_users()):
            print(
                f"\033[93m[!]\033[0m msfconsole not found – skipping SMB brute-force"
            )
            print(
                f"\033[90m    Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html\033[0m\n"
            )

        # ── CrackMapExec protocol enumeration (direct mode) ────────────────
        if (self.cme_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("cme")):
            print(
                f"\033[36m[>]\033[0m CME: grouping hosts by protocol from nmap results ..."
            )
            cme_output_dir = self._target_output_dir(label.replace("/", "_"))
            os.makedirs(cme_output_dir, exist_ok=True)

            cme_results = self._safe_scan(
                "CME", self.cme_scanner.scan,
                self.result.nmap_results, output_dir=cme_output_dir,
            )

            if cme_results:
                cme_stats = self.cme_scanner.stats

                self.result.cme_results = cme_results
                self.result.cme_stats = cme_stats.to_dict()
                self.result.cme_available = True
                self._save_phase("cme")

                if cme_stats.protocols_scanned > 0:
                    proto_parts = []
                    for proto, count in sorted(cme_stats.protocol_summary.items()):
                        proto_parts.append(f"\033[96m{proto}\033[0m(\033[92m{count}\033[0m)")
                    proto_str = ", ".join(proto_parts)
                    print(
                        f"\033[92m[+]\033[0m CME: \033[92m{cme_stats.protocols_scanned} protocols\033[0m "
                        f"scanned | {cme_stats.total_hosts_discovered} hosts responded "
                        f"\033[90m({cme_stats.scan_time:.1f}s)\033[0m"
                    )
                    if proto_parts:
                        print(f"\033[92m[+]\033[0m CME: {proto_str}")

                    smb_nosign = self.cme_scanner.get_smb_signing_disabled()
                    if smb_nosign:
                        print(
                            f"\033[91m[!]\033[0m CME: \033[91m{len(smb_nosign)} hosts "
                            f"with SMB signing disabled\033[0m (relay targets)"
                        )
                    print()
                else:
                    print(
                        f"\033[92m[+]\033[0m CME: no matching protocols found in nmap results\n"
                    )
            elif cme_results is None:
                print(
                    f"\033[93m[!]\033[0m CME: skipped by user\n"
                )
        elif not self.cme_scanner.available and self.result.nmap_available:
            print(
                f"\033[93m[!]\033[0m crackmapexec/nxc not found – skipping protocol enumeration"
            )
            print(
                f"\033[90m    Install: pip install crackmapexec | or: https://github.com/byt3bl33d3r/CrackMapExec\033[0m\n"
            )

        # ── Nuclei vulnerability scanning (direct mode) ──────────────────
        # Attempt auto-install if nuclei is not available
        if not self.nuclei_scanner.available and self.result.nmap_available and self.result.nmap_results:
            print(
                f"\033[93m[!]\033[0m nuclei not found \u2013 attempting auto-install..."
            )
            self.nuclei_scanner.ensure_available()

        if (self.nuclei_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("nuclei")):
            # Build targets: bare IP + http://ip:port for HTTP + ip:port for non-HTTP
            HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8081, 8082, 3000, 5000, 9090, 9443, 3333, 5555}
            nuclei_targets: list = []
            seen: set = set()
            for ip, host_result in self.result.nmap_results.items():
                # Add bare IP (for javascript/network protocol templates like pgsql-*)
                if ip not in seen:
                    nuclei_targets.append(ip)
                    seen.add(ip)
                # Add ip:port for every open port
                if hasattr(host_result, 'ports'):
                    for port_obj in host_result.ports:
                        if port_obj.state == "open":
                            pnum = port_obj.port
                            # HTTP-like ports get http(s):// prefix for HTTP templates
                            if pnum in HTTP_PORTS or 'http' in (getattr(port_obj, 'service', '') or '').lower():
                                scheme = "https" if pnum in {443, 8443, 9443} else "http"
                                http_target = f"{scheme}://{ip}:{pnum}"
                                if http_target not in seen:
                                    nuclei_targets.append(http_target)
                                    seen.add(http_target)
                            else:
                                # Non-HTTP: bare ip:port for javascript/network templates
                                target = f"{ip}:{pnum}"
                                if target not in seen:
                                    nuclei_targets.append(target)
                                    seen.add(target)
            # Fallback: if no results at all
            if not nuclei_targets:
                for ip in sorted(self.result.nmap_results.keys()):
                    nuclei_targets.append(ip)
            if nuclei_targets:
                nuclei_output_dir = self._target_output_dir(label.replace("/", "_"))
                os.makedirs(nuclei_output_dir, exist_ok=True)

                try:
                    nuclei_results = self.nuclei_scanner.scan(
                        nuclei_targets, output_dir=nuclei_output_dir,
                    )
                except KeyboardInterrupt:
                    nuclei_results = None
                    print("\n\033[93m[!]\033[0m nuclei: interrupted by user\n")

                if nuclei_results is not None:
                    nuclei_stats = self.nuclei_scanner.stats

                    self.result.nuclei_results = nuclei_results
                    self.result.nuclei_stats = nuclei_stats.to_dict()
                    self.result.nuclei_available = True
                    self._save_phase("nuclei")

                    total = nuclei_stats.total_findings
                    if total > 0:
                        sev_parts = []
                        if nuclei_stats.critical > 0:
                            sev_parts.append(f"\033[1;91m{nuclei_stats.critical} critical\033[0m")
                        if nuclei_stats.high > 0:
                            sev_parts.append(f"\033[91m{nuclei_stats.high} high\033[0m")
                        if nuclei_stats.medium > 0:
                            sev_parts.append(f"\033[93m{nuclei_stats.medium} medium\033[0m")
                        if nuclei_stats.low > 0:
                            sev_parts.append(f"\033[36m{nuclei_stats.low} low\033[0m")
                        if nuclei_stats.info > 0:
                            sev_parts.append(f"\033[37m{nuclei_stats.info} info\033[0m")
                        print(
                            f"\033[92m[+]\033[0m nuclei: \033[92m{total} finding(s)\033[0m | "
                            f"{' | '.join(sev_parts)} "
                            f"\033[90m({nuclei_stats.scan_time:.1f}s)\033[0m"
                        )
                    else:
                        print(
                            f"\033[92m[+]\033[0m nuclei: \033[37m0 findings\033[0m "
                            f"on {nuclei_stats.hosts_scanned} hosts "
                            f"\033[90m({nuclei_stats.scan_time:.1f}s)\033[0m"
                        )
                    print()
                else:
                    print(
                        f"\033[93m[!]\033[0m nuclei: skipped by user\n"
                    )
        elif not self.nuclei_scanner.available and self.result.nmap_available:
            print(
                f"\033[91m[✗]\033[0m nuclei auto-install failed \u2013 skipping vulnerability scan"
            )
            print(
                f"\033[90m    Manual install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\033[0m\n"
            )

        # ── WPScan WordPress scanning (direct mode) ──────────────────────
        if self.wpscan_scanner.available and not self.wpscan_scanner.api_token:
            print(
                "\033[93m[!]\033[0m wpscan: \033[93mWPSCAN_API_TOKEN not set in .env\033[0m \u2013 skipping"
            )
            print(
                "\033[90m    Get a free token at: https://wpscan.com/api\033[0m\n"
            )
        elif (self.wpscan_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("wpscan")):
            from .scanner.wpscan import WPScanner as _WPS
            # In direct mode, detect WP from nmap HTTP/HTTPS services
            wp_targets: set[str] = set()
            for ip, host_result in self.result.nmap_results.items():
                ports = host_result.ports if hasattr(host_result, 'ports') else []
                for p in ports:
                    svc = (p.service if hasattr(p, 'service') else (p.get("service", "") if isinstance(p, dict) else "")) or ""
                    svc = svc.lower()
                    port_num = p.port if hasattr(p, 'port') else (p.get("port", 80) if isinstance(p, dict) else 80)
                    state = p.state if hasattr(p, 'state') else (p.get("state", "") if isinstance(p, dict) else "")
                    if state == "open" and svc in ("http", "https", "http-proxy", "https-alt"):
                        scheme = "https" if "https" in svc or port_num == 443 else "http"
                        wp_targets.add(f"{scheme}://{ip}:{port_num}")
            if wp_targets:
                wpscan_output_dir = self._target_output_dir(label.replace("/", "_"))
                os.makedirs(wpscan_output_dir, exist_ok=True)

                wpscan_results = self._safe_scan(
                    "wpscan", self.wpscan_scanner.scan,
                    sorted(wp_targets), output_dir=wpscan_output_dir,
                )

                if wpscan_results is not None:
                    wpscan_stats = self.wpscan_scanner.stats

                    self.result.wpscan_results = wpscan_results
                    self.result.wpscan_stats = wpscan_stats.to_dict()
                    self.result.wpscan_available = True
                    self._save_phase("wpscan")

                    total_vulns = wpscan_stats.total_vulns
                    if total_vulns > 0:
                        print(
                            f"\033[92m[+]\033[0m wpscan: \033[92m{total_vulns} vulnerability/ies\033[0m "
                            f"on \033[96m{wpscan_stats.targets_scanned}\033[0m WordPress target(s) "
                            f"\033[90m({wpscan_stats.scan_time:.1f}s)\033[0m"
                        )
                    else:
                        print(
                            f"\033[92m[+]\033[0m wpscan: \033[37m0 vulnerabilities\033[0m "
                            f"on {wpscan_stats.targets_scanned} WordPress target(s) "
                            f"\033[90m({wpscan_stats.scan_time:.1f}s)\033[0m"
                        )
                    print()
                else:
                    print(
                        f"\033[93m[!]\033[0m wpscan: skipped by user\n"
                    )
            else:
                print(
                    f"\033[90m[·]\033[0m wpscan: no HTTP/HTTPS services found for WordPress scan\n"
                )
        elif not self.wpscan_scanner.available and self.result.nmap_available:
            print(
                f"\033[93m[!]\033[0m wpscan not found – skipping WordPress scan"
            )
            print(
                f"\033[90m    Install: gem install wpscan | or: https://github.com/wpscanteam/wpscan\033[0m\n"
            )

        # ── Katana web crawling (direct mode) ────────────────────────────
        # Attempt auto-install if katana is not available
        if not self.katana_scanner.available and self.result.nmap_available and self.result.nmap_results:
            print(
                f"\033[93m[!]\033[0m katana not found \u2013 attempting auto-install..."
            )
            self.katana_scanner.ensure_available()

        if (self.katana_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("katana")):
            from .scanner.katana_scan import KatanaScanner as _KAT2
            katana_targets = _KAT2.get_http_targets_from_nmap(self.result.nmap_results)

            if katana_targets:
                katana_output_dir = self._target_output_dir(label.replace("/", "_"))
                os.makedirs(katana_output_dir, exist_ok=True)

                katana_results = self._safe_scan(
                    "katana", self.katana_scanner.scan,
                    sorted(katana_targets), output_dir=katana_output_dir,
                )

                if katana_results is not None:
                    katana_stats = self.katana_scanner.stats

                    self.result.katana_results = katana_results
                    self.result.katana_stats = katana_stats.to_dict()
                    self.result.katana_available = True
                    self._save_phase("katana")

                    total_urls = katana_stats.total_urls
                    if total_urls > 0:
                        parts = [f"\033[92m{total_urls} URLs\033[0m"]
                        if katana_stats.js_files > 0:
                            parts.append(f"\033[96m{katana_stats.js_files} JS\033[0m")
                        if katana_stats.api_endpoints > 0:
                            parts.append(f"\033[93m{katana_stats.api_endpoints} API\033[0m")
                        print(
                            f"\033[92m[+]\033[0m katana: {' | '.join(parts)} "
                            f"from \033[96m{katana_stats.targets_crawled}\033[0m target(s) "
                            f"\033[90m({katana_stats.scan_time:.1f}s)\033[0m"
                        )
                    else:
                        print(
                            f"\033[92m[+]\033[0m katana: \033[37m0 URLs\033[0m "
                            f"from {katana_stats.targets_crawled} target(s) "
                            f"\033[90m({katana_stats.scan_time:.1f}s)\033[0m"
                        )
                    print()

                    # Run httpx on katana URLs for enriched output
                    if total_urls > 0 and self.httpx_probe.available:
                        katana_urls_file = os.path.join(katana_output_dir, "txt", "katana_urls.txt")
                        if os.path.isfile(katana_urls_file):
                            katana_httpx_file = os.path.join(katana_output_dir, "txt", "katana_httpx.txt")
                            try:
                                line_count = self._run_katana_httpx_enrichment(
                                    katana_urls_file,
                                    katana_httpx_file,
                                    katana_stats.targets_crawled,
                                    total_urls,
                                )
                                if line_count is None:
                                    print()
                                elif line_count > 0:
                                    print(
                                        f"\033[92m[+]\033[0m katana+httpx: "
                                        f"\033[92m{line_count} alive URLs\033[0m "
                                        f"saved to \033[96mkatana_httpx.txt\033[0m"
                                    )
                                else:
                                    print(
                                        f"\033[37m[-]\033[0m katana+httpx: no alive URLs"
                                    )
                                print()
                            except Exception:
                                pass
                else:
                    print(
                        f"\033[93m[!]\033[0m katana: skipped by user\n"
                    )
            else:
                print(
                    f"\033[90m[\u00b7]\033[0m katana: no HTTP/HTTPS services found\n"
                )
        elif not self.katana_scanner.available and self.result.nmap_available:
            print(
                f"\033[91m[✗]\033[0m katana auto-install failed \u2013 skipping web crawling"
            )
            print(
                f"\033[90m    Manual install: go install github.com/projectdiscovery/katana/cmd/katana@latest\033[0m\n"
            )

        # ── Dirsearch directory brute-force (direct mode) ────────────────
        if (self.dirsearch_scanner.available and self.result.nmap_available and self.result.nmap_results
                and not self._phase_done("dirsearch")):
            from .scanner.katana_scan import KatanaScanner as _KAT2_D
            dirsearch_targets = _KAT2_D.get_http_targets_from_nmap(self.result.nmap_results)

            if dirsearch_targets:
                dirsearch_output_dir = self._target_output_dir(label.replace("/", "_"))
                os.makedirs(dirsearch_output_dir, exist_ok=True)

                dirsearch_results = self._safe_scan(
                    "dirsearch", self.dirsearch_scanner.scan,
                    sorted(dirsearch_targets), output_dir=dirsearch_output_dir,
                )

                if dirsearch_results is not None:
                    dirsearch_stats = self.dirsearch_scanner.stats
                    self.result.dirsearch_results = dirsearch_results
                    self.result.dirsearch_stats = dirsearch_stats.to_dict()
                    self.result.dirsearch_available = True
                    self._save_phase("dirsearch")

                    total = dirsearch_stats.total_findings
                    print(
                        f"\033[92m[+]\033[0m dirsearch: "
                        f"\033[92m{total} finding(s)\033[0m "
                        f"from \033[96m{dirsearch_stats.targets_scanned}\033[0m target(s) "
                        f"\033[90m({dirsearch_stats.scan_time:.1f}s)\033[0m\n"
                    )
                else:
                    print(
                        f"\033[93m[!]\033[0m dirsearch: skipped by user\n"
                    )
            else:
                print(
                    f"\033[90m[\u00b7]\033[0m dirsearch: no HTTP/HTTPS services found\n"
                )
        elif not self.dirsearch_scanner.available and self.result.nmap_available:
            print(
                f"\033[93m[!]\033[0m dirsearch not found \u2013 skipping directory brute-force"
            )
            print(
                f"\033[90m    Install: pip3 install dirsearch | or: apt install dirsearch\033[0m\n"
            )

        # ── Statistics & Output ────────────────────────────────────────────
        self.result.scan_time = time.time() - start_time

        # ── NetExec Module Scan (direct mode) ─────────────────────────────
        if (self.netexec_module_scanner.available
                and self.result.nmap_available
                and self.result.nmap_results
                and not self._phase_done("netexec_modules")):
            print(
                f"\033[36m[>]\033[0m netexec-modules: scanning all protocols with recon modules ..."
            )
            nxcmod_output_dir = self._target_output_dir(label.replace("/", "_"))
            os.makedirs(nxcmod_output_dir, exist_ok=True)

            nxcmod_results = self._safe_scan(
                "netexec-modules", self.netexec_module_scanner.scan,
                self.result.nmap_results, output_dir=nxcmod_output_dir,
            )

            if nxcmod_results:
                nxcmod_stats = self.netexec_module_scanner.stats
                self.result.netexec_module_results = {
                    p: r.to_dict() for p, r in nxcmod_results.items()
                }
                self.result.netexec_module_stats = nxcmod_stats.to_dict()
                self.result.netexec_module_available = True
                self._save_phase("netexec_modules")

                if nxcmod_stats.total_vulnerable > 0:
                    cve_map = self.netexec_module_scanner.get_cve_summary()
                    for module, hosts in sorted(cve_map.items()):
                        print(
                            f"\033[1;91m[!]\033[0m nxc-module \033[91m{module}\033[0m "
                            f"VULNERABLE on: \033[96m{', '.join(hosts[:10])}\033[0m"
                            + (" ..." if len(hosts) > 10 else "")
                        )
                print()
            elif nxcmod_results is None:
                print(f"\033[93m[!]\033[0m netexec-modules: skipped by user\n")

        elif not self.netexec_module_scanner.available and self.result.nmap_available:
            print(
                f"\033[93m[!]\033[0m nxc/netexec not found – skipping module scan"
            )
            print(
                f"\033[90m    Install: pip install netexec\033[0m\n"
            )

        # ── Service misconfiguration checks (direct mode) ──────────────────
        if (self.service_misconfig_scanner.available
                and self.result.nmap_available
                and self.result.nmap_results
                and not self._phase_done("service_misconfig")):
            service_output_dir = self._target_output_dir(label.replace("/", "_"))
            os.makedirs(service_output_dir, exist_ok=True)

            service_results = self._safe_scan(
                "service-misconfig", self.service_misconfig_scanner.scan,
                self.result.nmap_results, target_domain=self.result.target_domain,
                output_dir=service_output_dir,
            )

            if service_results:
                svc_stats = self.service_misconfig_scanner.stats
                self.result.service_misconfig_results = service_results
                self.result.service_misconfig_stats = svc_stats.to_dict()
                self.result.service_misconfig_available = True
                self._save_phase("service_misconfig")

                sev_parts = []
                if svc_stats.critical:
                    sev_parts.append(f"\033[1;91m{svc_stats.critical} critical\033[0m")
                if svc_stats.high:
                    sev_parts.append(f"\033[91m{svc_stats.high} high\033[0m")
                if svc_stats.medium:
                    sev_parts.append(f"\033[93m{svc_stats.medium} medium\033[0m")
                if svc_stats.low:
                    sev_parts.append(f"\033[36m{svc_stats.low} low\033[0m")
                if svc_stats.info:
                    sev_parts.append(f"\033[37m{svc_stats.info} info\033[0m")
                service_parts = []
                if svc_stats.smtp_hosts:
                    service_parts.append(f"smtp({svc_stats.smtp_hosts})")
                if svc_stats.pop3_hosts:
                    service_parts.append(f"pop3({svc_stats.pop3_hosts})")
                if svc_stats.mongodb_hosts:
                    service_parts.append(f"mongodb({svc_stats.mongodb_hosts})")
                if svc_stats.docker_hosts:
                    service_parts.append(f"docker({svc_stats.docker_hosts})")
                if svc_stats.elasticsearch_hosts:
                    service_parts.append(f"elasticsearch({svc_stats.elasticsearch_hosts})")
                if svc_stats.etcd_hosts:
                    service_parts.append(f"etcd({svc_stats.etcd_hosts})")
                if svc_stats.grafana_hosts:
                    service_parts.append(f"grafana({svc_stats.grafana_hosts})")
                if svc_stats.imap_hosts:
                    service_parts.append(f"imap({svc_stats.imap_hosts})")
                if svc_stats.jenkins_hosts:
                    service_parts.append(f"jenkins({svc_stats.jenkins_hosts})")
                if svc_stats.kafka_hosts:
                    service_parts.append(f"kafka({svc_stats.kafka_hosts})")
                if svc_stats.kerberos_hosts:
                    service_parts.append(f"kerberos({svc_stats.kerberos_hosts})")
                if svc_stats.kubernetes_hosts:
                    service_parts.append(f"kubernetes({svc_stats.kubernetes_hosts})")
                if svc_stats.ldap_hosts:
                    service_parts.append(f"ldap({svc_stats.ldap_hosts})")
                if svc_stats.memcached_hosts:
                    service_parts.append(f"memcached({svc_stats.memcached_hosts})")
                if svc_stats.mssql_hosts:
                    service_parts.append(f"mssql({svc_stats.mssql_hosts})")
                if svc_stats.netbios_hosts:
                    service_parts.append(f"netbios({svc_stats.netbios_hosts})")
                if svc_stats.nfs_hosts:
                    service_parts.append(f"nfs({svc_stats.nfs_hosts})")
                if svc_stats.ntp_hosts:
                    service_parts.append(f"ntp({svc_stats.ntp_hosts})")
                if svc_stats.oracle_hosts:
                    service_parts.append(f"oracle({svc_stats.oracle_hosts})")
                if svc_stats.postgresql_hosts:
                    service_parts.append(f"postgresql({svc_stats.postgresql_hosts})")
                if svc_stats.rabbitmq_hosts:
                    service_parts.append(f"rabbitmq({svc_stats.rabbitmq_hosts})")
                if svc_stats.rdp_hosts:
                    service_parts.append(f"rdp({svc_stats.rdp_hosts})")
                if svc_stats.redis_hosts:
                    service_parts.append(f"redis({svc_stats.redis_hosts})")
                if svc_stats.tftp_hosts:
                    service_parts.append(f"tftp({svc_stats.tftp_hosts})")
                if svc_stats.tomcat_hosts:
                    service_parts.append(f"tomcat({svc_stats.tomcat_hosts})")
                if svc_stats.vnc_hosts:
                    service_parts.append(f"vnc({svc_stats.vnc_hosts})")
                if svc_stats.webdav_hosts:
                    service_parts.append(f"webdav({svc_stats.webdav_hosts})")
                if svc_stats.winrm_hosts:
                    service_parts.append(f"winrm({svc_stats.winrm_hosts})")

                print(
                    f"\033[92m[+]\033[0m service-misconfig: "
                    f"\033[92m{svc_stats.findings_total} finding(s)\033[0m | "
                    f"{', '.join(sev_parts) if sev_parts else 'no findings'} | "
                    f"{', '.join(service_parts)} "
                    f"\033[90m({svc_stats.scan_time:.1f}s)\033[0m"
                )
                shown = 0
                for host_result in service_results.values():
                    for finding in host_result.findings:
                        print(
                            f"\033[91m[!]\033[0m {finding.service}:{finding.ip}:{finding.port} "
                            f"{finding.check} \033[90m({finding.severity})\033[0m"
                        )
                        shown += 1
                        if shown >= 10:
                            break
                    if shown >= 10:
                        break
                print()
            elif service_results is None:
                print(f"\033[93m[!]\033[0m service-misconfig: skipped by user\n")

        # ── AI Pentest Analysis (direct mode) ─────────────────────────────
        if self.ai_analyst.available and not self._phase_done("ai_analysis"):
            ai_report = self.ai_analyst.analyse(
                self.result.to_dict(),
                target=label,
            )
            if ai_report:
                self.result.ai_report = ai_report
                self.result.ai_available = True
                self._save_phase("ai_analysis")
                try:
                    ai_out_dir = self._target_output_dir(label.replace("/", "_"))
                    ai_report_file = os.path.join(ai_out_dir, "ai_pentest_report.txt")
                    self.ai_analyst.print_report(ai_report, output_file=ai_report_file)
                except Exception:
                    self.ai_analyst.print_report(ai_report)

        self._output()
        self._clear_checkpoint()

        return self.result

    def _run_demo(self) -> ScanResult:
        """
        Execute a demo scan with simulated data.
        Produces output that closely matches the reference image.
        """
        start_time = time.time()
        domain = self.config.target_domain

        # Simulate scanning delay for realism
        time.sleep(0.5)

        # ── Fetch demo data from all sources ───────────────────────────────
        all_subdomains = set()

        with ThreadPoolExecutor(max_workers=len(self.sources)) as executor:
            futures = {
                executor.submit(source.run, domain, True): key
                for key, source in self.sources.items()
            }
            for future in as_completed(futures):
                key = futures[future]
                try:
                    subs = future.result()
                    self.result.source_stats[key] = SourceStats(
                        name=self.sources[key].name,
                        count=len(subs),
                        subdomains=subs,
                    )
                    all_subdomains.update(subs)
                except Exception:
                    self.result.source_stats[key] = SourceStats(
                        name=self.sources[key].name, count=0,
                    )

        # Create subdomain objects
        for hostname in sorted(all_subdomains):
            sub = Subdomain(hostname=hostname)
            interesting, reason = is_interesting_subdomain(hostname)
            sub.interesting = interesting
            sub.interesting_reason = reason
            self.result.subdomains.append(sub)

        self.result.total_unique = len(all_subdomains)

        # ── Infrastructure stats (demo) ────────────────────────────────────
        self.result.infra = self.infra_scanner.scan_demo(len(all_subdomains))

        # ── CT Triage (demo) ───────────────────────────────────────────────
        ct_entries, stale, aged, no_date = self.ct_scanner.scan_demo(
            domain, len(all_subdomains)
        )
        self.result.ct_entries = ct_entries
        self.result.ct_stale = stale
        self.result.ct_aged = aged
        self.result.ct_no_date = no_date

        # ── Collapse (demo) ───────────────────────────────────────────────
        all_hostnames = [s.hostname for s in self.result.subdomains]
        collapsed_entries, pattern_groups = collapse_subdomains(
            all_hostnames, self.config.scanner.collapse_threshold
        )
        self.result.collapse = CollapseStats(
            total_entries=collapsed_entries,
            pattern_groups=pattern_groups,
            threshold=self.config.scanner.collapse_threshold,
        )

        # ── Takeover (demo) ───────────────────────────────────────────────
        self.result.takeover_results = self.takeover_scanner.scan_demo(domain)
        self.result.vulnerable_count = sum(
            1 for r in self.result.takeover_results
            if r.status == TakeoverStatus.VULNERABLE
        )
        self.result.dangling_count = sum(
            1 for r in self.result.takeover_results
            if r.status == TakeoverStatus.DANGLING
        )
        self.result.not_vulnerable_count = sum(
            1 for r in self.result.takeover_results
            if r.status == TakeoverStatus.NOT_VULNERABLE
        )
        self.result.takeover_provider = "Microsoft Azure"

        # ── Tech profiling (demo) ─────────────────────────────────────────
        matches, severity_groups = self.tech_profiler.scan_demo(domain)
        self.result.tech_matches = matches
        self.result.tech_severity_summary = severity_groups

        # ── Flagged interesting ────────────────────────────────────────────
        self.result.flagged_interesting = sum(
            1 for s in self.result.subdomains if s.interesting
        )

        # ── DB stats ──────────────────────────────────────────────────────
        self.result.takeover_db_services = self.takeover_scanner.db_service_count
        self.result.tech_db_signatures = self.tech_profiler.total_signatures

        # ── Timing ────────────────────────────────────────────────────────
        self.result.scan_time = time.time() - start_time

        # ── Render & Export ───────────────────────────────────────────────
        self._output()

        return self.result

    def _output(self):
        """Render results to terminal and optionally export to JSON."""
        # Terminal output
        self.renderer.print_summary(self.result)

        # JSON export
        filename = self.config.get_output_filename()
        saved_path = self.exporter.export(self.result, filename)
        self.renderer.print_saved(saved_path)

        # File export (separate files per category in domain folder)
        export_dir = self.file_exporter.export(self.result)
        if export_dir:
            print(f"\n  \033[38;5;75m📁 Results exported to: \033[1m{export_dir}\033[0m")

    def _reconcile_infra_from_httpx(self, subdomains):
        """
        Update infrastructure stats using httpx CDN and server header data.
        httpx detects CDN more reliably (via HTTP headers) than DNS-only approach.
        """
        from .models import InfraProvider

        # CDN name → provider mapping
        cdn_provider_map = {
            "cloudflare": "Cloudflare",
            "akamai": "Akamai",
            "amazon cloudfront": "AWS",
            "cloudfront": "AWS",
            "azure cdn": "Azure",
            "azure": "Azure",
            "fastly": "Other",
            "incapsula": "Other",
            "imperva": "Other",
            "sucuri": "Other",
        }

        # Server header → provider mapping
        server_provider_map = {
            "cloudflare": "Cloudflare",
            "amazons3": "AWS",
            "awselb": "AWS",
            "microsoft-azure": "Azure",
            "akamaighost": "Akamai",
        }

        # Recount from scratch using combined DNS + httpx data
        stats = self.result.infra
        stats.aws = 0
        stats.azure = 0
        stats.cloudflare = 0
        stats.akamai = 0
        stats.other = 0
        stats.ct_only = 0

        for sub in subdomains:
            provider_name = None

            # Priority 1: httpx CDN detection (most reliable)
            if sub.http_cdn and sub.http_cdn_name:
                cdn_lower = sub.http_cdn_name.lower().strip()
                for cdn_key, prov in cdn_provider_map.items():
                    if cdn_key in cdn_lower:
                        provider_name = prov
                        break

            # Priority 2: httpx server header
            if not provider_name and sub.http_server:
                srv_lower = sub.http_server.lower().replace(" ", "").replace("/", "")
                for srv_key, prov in server_provider_map.items():
                    if srv_key in srv_lower:
                        provider_name = prov
                        break

            # Priority 3: DNS-based classification (already set by infra scanner)
            if not provider_name and sub.provider:
                provider_name = sub.provider.value

            # Fallback
            if not provider_name:
                if not sub.is_alive and not sub.ip_addresses and not sub.cnames:
                    provider_name = "CT-only"
                else:
                    provider_name = "Other"

            # Update provider on subdomain object
            if provider_name == "AWS":
                stats.aws += 1
                sub.provider = InfraProvider.AWS
            elif provider_name == "Azure":
                stats.azure += 1
                sub.provider = InfraProvider.AZURE
            elif provider_name == "Cloudflare":
                stats.cloudflare += 1
                sub.provider = InfraProvider.CLOUDFLARE
            elif provider_name == "Akamai":
                stats.akamai += 1
                sub.provider = InfraProvider.AKAMAI
            elif provider_name == "CT-only":
                stats.ct_only += 1
                sub.provider = InfraProvider.CT_ONLY
            else:
                stats.other += 1
                sub.provider = InfraProvider.OTHER
