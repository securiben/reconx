"""
ReconX Engine - Main orchestrator.
Coordinates all data sources, scanners, and output rendering.
Manages concurrent execution and result aggregation.
"""

import os
import sys
import time
import random
import signal
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
)
from .sources.base import BaseSource
from .scanner import (
    InfrastructureScanner, CTLogScanner,
    TakeoverScanner, TechProfiler, HttpxProbe,
    NmapScanner, NucleiScanner, Enum4linuxScanner, CMEScanner,
    MSFSMBBruteScanner, RDPBruteScanner, VNCBruteScanner, SMBBruteScanner, WPScanner, SMBClientScanner,
)
from .output.terminal import TerminalRenderer
from .output.json_export import JSONExporter
from .output.file_export import FileExporter
from .utils import collapse_subdomains, is_interesting_subdomain


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
        self.file_exporter = FileExporter(base_dir=".")

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

        # Ctrl+C skip state
        self._skip_requested = False
        self._current_phase = ""

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
            elif phase == "summary":
                fe._export_summary(d, r)

            print(
                f"\033[38;5;75m    \U0001f4be {phase} → saved to {d}/\033[0m"
            )
        except Exception:
            pass  # Don't let a save failure crash the pipeline

    def run(self) -> ScanResult:
        """
        Execute the full reconnaissance pipeline.
        Returns the complete ScanResult.
        """
        start_time = time.time()
        domain = self.config.target_domain

        if self.config.demo_mode:
            return self._run_demo()

        # ── Direct mode: IP / CIDR / file-of-IPs → skip enum ──────────────
        if self.config.input_mode == "direct":
            return self._run_direct(start_time)

        # ── Phase 1: Fetch subdomains from all sources concurrently ────────
        all_subdomains_by_source: Dict[str, List[str]] = {}

        # Print source start messages
        max_name_len = max(len(s.name) for s in self.sources.values()) if self.sources else 7
        for key, source in self.sources.items():
            desc = getattr(source, 'SOURCE_DESC', source.config.description or f'querying {source.name}')
            print(f"\033[36m[>]\033[0m {source.name + ':':<{max_name_len + 1}} {desc} ...")

        with ThreadPoolExecutor(max_workers=len(self.sources)) as executor:
            futures = {
                executor.submit(source.run, domain, False): key
                for key, source in self.sources.items()
            }
            for future in as_completed(futures):
                key = futures[future]
                source = self.sources[key]
                try:
                    subs = future.result()
                    all_subdomains_by_source[key] = subs
                except Exception:
                    all_subdomains_by_source[key] = []

                # Print result message
                count = len(all_subdomains_by_source[key])
                elapsed_ms = int(source.elapsed * 1000)
                print(
                    f"\033[92m[+]\033[0m {source.name + ':':<{max_name_len + 1}} "
                    f"\033[92m{count:>4}\033[0m subdomains "
                    f"\033[90m({elapsed_ms}ms)\033[0m"
                )

        # ── Phase 2: Deduplicate and aggregate ─────────────────────────────
        unique_hostnames = set()
        for key, subs in all_subdomains_by_source.items():
            for sub in subs:
                unique_hostnames.add(sub.lower().strip())
            self.result.source_stats[key] = SourceStats(
                name=self.sources[key].name,
                count=len(subs),
                subdomains=subs,
            )

        # ── Phase 3: CT Log triage (before dedup so CT subs are included) ──
        ct_entries, ct_subs = self.ct_scanner.scan(domain)
        self.result.ct_entries = ct_entries
        stale, aged, no_date = self.ct_scanner.triage(ct_entries)
        self.result.ct_stale = stale
        self.result.ct_aged = aged
        self.result.ct_no_date = no_date

        # Merge CT-discovered subdomains into the main set
        ct_new_count = 0
        for sub_name in ct_subs:
            normalized = sub_name.lower().strip()
            if normalized not in unique_hostnames:
                ct_new_count += 1
            unique_hostnames.add(normalized)

        # Record CT as a source
        self.result.source_stats["crt.sh"] = SourceStats(
            name="crt.sh",
            count=len(ct_subs),
            subdomains=ct_subs,
        )

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

        # ── Phase 4: Infrastructure classification ─────────────────────────
        self.result.infra = self.infra_scanner.scan(subdomain_objects)
        self._save_phase("infrastructure")

        # ── Phase 5: HTTPX Probe ──────────────────────────────────────────
        httpx_start = time.time()
        if self.httpx_probe.available:
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
        else:
            # Fallback: count alive from infrastructure scan
            alive_count = sum(1 for s in subdomain_objects if s.is_alive)
            print(
                f"\033[93m[!]\033[0m ProjectDiscovery httpx not found \u2013 using basic DNS probe only "
                f"(\033[92m{alive_count} alive\033[0m)"
            )
            print(
                f"\033[90m    Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest\033[0m"
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

        # ── Phase 5c: Nuclei vulnerability scanning ───────────────────────
        if self.nuclei_scanner.available:
            # Collect alive hostnames for nuclei
            nuclei_targets = [s.hostname for s in subdomain_objects if s.is_alive]
            if not nuclei_targets:
                nuclei_targets = [s.hostname for s in subdomain_objects]

            if nuclei_targets:
                nuclei_output_dir = os.path.join(".", domain)
                os.makedirs(nuclei_output_dir, exist_ok=True)

                nuclei_results = self._safe_scan(
                    "nuclei", self.nuclei_scanner.scan,
                    nuclei_targets, output_dir=nuclei_output_dir,
                )

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
                f"\033[93m[!]\033[0m nuclei not found – skipping vulnerability scan"
            )
            print(
                f"\033[90m    Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\033[0m\n"
            )

        # ── Phase 5d: WPScan WordPress scanning ──────────────────────────
        if self.wpscan_scanner.available and self.result.nuclei_available and self.result.nuclei_results:
            from .scanner.wpscan import WPScanner as _WPS
            wp_targets = _WPS.detect_wordpress_targets(self.result.nuclei_results)
            if wp_targets:
                wpscan_output_dir = os.path.join(".", domain)
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

        # ── Phase 9: Nmap port & service scanning ──────────────────────────
        if self.nmap_scanner.available:
            # Collect all unique IP addresses from resolved subdomains
            all_ips = set()
            for sub in subdomain_objects:
                for ip in sub.ip_addresses:
                    all_ips.add(ip)

            if all_ips:
                # Run nmap with output directed to the domain results folder
                nmap_output_dir = os.path.join(".", domain)
                os.makedirs(nmap_output_dir, exist_ok=True)
                nmap_results = self._safe_scan(
                    "nmap", self.nmap_scanner.scan,
                    all_ips, output_dir=nmap_output_dir,
                )

                if nmap_results is not None:
                    nmap_stats = self.nmap_scanner.stats

                    self.result.nmap_results = nmap_results
                    self.result.nmap_stats = nmap_stats.to_dict()
                    self.result.nmap_available = True
                    self._save_phase("nmap")

                    # Print nmap summary
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
        else:
            print(
                f"\033[93m[!]\033[0m nmap not found – skipping port & service scan"
            )
            print(
                f"\033[90m    Install: https://nmap.org/download.html\033[0m\n"
            )

        # ── Phase 9a-2: SMBClient null session detection ─────────────────────
        if self.smbclient_scanner.available and self.result.nmap_available and self.result.nmap_results:
            from .scanner.smbclient_scan import SMBClientScanner as _SMBC
            smb_hosts = _SMBC.get_smb_hosts(self.result.nmap_results)
            if smb_hosts:
                smb_output_dir = os.path.join(".", domain)
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

        # ── Phase 9b: RDP brute-force (netexec) ─────────────────────────────
        if self.rdp_scanner.available and self.result.nmap_available and self.result.nmap_results:
            rdp_output_dir = os.path.join(".", domain)
            os.makedirs(rdp_output_dir, exist_ok=True)

            rdp_results = self._safe_scan(
                "rdp-brute", self.rdp_scanner.scan,
                self.result.nmap_results, output_dir=rdp_output_dir,
            )

            if rdp_results is not None:
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
            else:
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

        # ── Phase 9b-2: VNC brute-force (msfconsole) ────────────────────────
        if self.vnc_scanner.available and self.result.nmap_available and self.result.nmap_results:
            vnc_output_dir = os.path.join(".", domain)
            os.makedirs(vnc_output_dir, exist_ok=True)

            vnc_results = self._safe_scan(
                "vnc-brute", self.vnc_scanner.scan,
                self.result.nmap_results, output_dir=vnc_output_dir,
            )

            if vnc_results is not None:
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
            else:
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

        # ── Phase 9b-3: SMB brute-force (netexec / nxc) ───────────────────
        if self.smb_brute_scanner.available and self.result.nmap_available and self.result.nmap_results:
            smb_brute_output_dir = os.path.join(".", domain)
            os.makedirs(smb_brute_output_dir, exist_ok=True)

            smb_brute_results = self._safe_scan(
                "smb-brute", self.smb_brute_scanner.scan,
                self.result.nmap_results, output_dir=smb_brute_output_dir,
            )

            if smb_brute_results is not None:
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
            else:
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

        # ── Phase 9c-1: Enum4linux SMB/Windows enumeration ───────────────────
        if self.enum4linux_scanner.available and self.result.nmap_available and self.result.nmap_results:
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
                enum_output_dir = os.path.join(".", domain)
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
                f"\033[90m    Install: sudo apt install enum4linux\033[0m\n"
            )

        # ── Phase 9c-2: MSF SMB brute-force (after enum4linux finds users) ──
        if (self.msf_scanner.available
                and self.result.enum4linux_available
                and self.result.enum4linux_results):
            # Get users discovered by enum4linux
            enum_users = self.enum4linux_scanner.get_all_users()
            if enum_users:
                msf_output_dir = os.path.join(".", domain)
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
        if self.cme_scanner.available and self.result.nmap_available and self.result.nmap_results:
            print(
                f"\033[36m[>]\033[0m CME: grouping hosts by protocol from nmap results ..."
            )
            cme_output_dir = os.path.join(".", domain)
            os.makedirs(cme_output_dir, exist_ok=True)

            cme_results = self._safe_scan(
                "CME", self.cme_scanner.scan,
                self.result.nmap_results, output_dir=cme_output_dir,
            )

            if cme_results is not None:
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
            else:
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

        # ── Phase 10: Statistics ───────────────────────────────────────────
        self.result.flagged_interesting = sum(
            1 for s in subdomain_objects if s.interesting
        )
        self.result.takeover_db_services = self.takeover_scanner.db_service_count
        self.result.tech_db_signatures = self.tech_profiler.total_signatures
        self.result.scan_time = time.time() - start_time

        # ── Phase 11: Render & Export ──────────────────────────────────────
        self._output()

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

        print(
            f"\033[1;97m[»]\033[0m Direct mode: \033[1;96m{len(targets)}\033[0m "
            f"target(s) from \033[96m{label}\033[0m"
        )
        print(
            f"\033[1;97m[»]\033[0m Skipping subdomain enumeration — "
            f"jumping to nmap, smbclient, RDP-brute, enum4linux, MSF-brute, CME, Nuclei & WPScan\n"
        )

        # ── Nmap port & service scanning ───────────────────────────────────
        if self.nmap_scanner.available:
            all_ips = set(targets)

            if all_ips:
                nmap_output_dir = os.path.join(".", label.replace("/", "_"))
                os.makedirs(nmap_output_dir, exist_ok=True)
                nmap_results = self._safe_scan(
                    "nmap", self.nmap_scanner.scan,
                    all_ips, output_dir=nmap_output_dir,
                )

                if nmap_results is not None:
                    nmap_stats = self.nmap_scanner.stats

                    self.result.nmap_results = nmap_results
                    self.result.nmap_stats = nmap_stats.to_dict()
                    self.result.nmap_available = True
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
                f"\033[93m[!]\033[0m nmap not found – skipping port & service scan"
            )
            print(
                f"\033[90m    Install: https://nmap.org/download.html\033[0m\n"
            )

        # ── SMBClient null session detection (direct mode) ──────────────────
        if self.smbclient_scanner.available and self.result.nmap_available and self.result.nmap_results:
            from .scanner.smbclient_scan import SMBClientScanner as _SMBC
            smb_hosts = _SMBC.get_smb_hosts(self.result.nmap_results)
            if smb_hosts:
                smb_output_dir = os.path.join(".", label.replace("/", "_"))
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

        # ── RDP brute-force (direct mode) ──────────────────────────────────
        if self.rdp_scanner.available and self.result.nmap_available and self.result.nmap_results:
            rdp_output_dir = os.path.join(".", label.replace("/", "_"))
            os.makedirs(rdp_output_dir, exist_ok=True)

            rdp_results = self._safe_scan(
                "rdp-brute", self.rdp_scanner.scan,
                self.result.nmap_results, output_dir=rdp_output_dir,
            )

            if rdp_results is not None:
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
            else:
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

        # ── VNC brute-force (direct mode) ──────────────────────────────────
        if self.vnc_scanner.available and self.result.nmap_available and self.result.nmap_results:
            vnc_output_dir = os.path.join(".", label.replace("/", "_"))
            os.makedirs(vnc_output_dir, exist_ok=True)

            vnc_results = self._safe_scan(
                "vnc-brute", self.vnc_scanner.scan,
                self.result.nmap_results, output_dir=vnc_output_dir,
            )

            if vnc_results is not None:
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
            else:
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

        # ── SMB brute-force (direct mode) ──────────────────────────────────
        if self.smb_brute_scanner.available and self.result.nmap_available and self.result.nmap_results:
            smb_brute_output_dir = os.path.join(".", label.replace("/", "_"))
            os.makedirs(smb_brute_output_dir, exist_ok=True)

            smb_brute_results = self._safe_scan(
                "smb-brute", self.smb_brute_scanner.scan,
                self.result.nmap_results, output_dir=smb_brute_output_dir,
            )

            if smb_brute_results is not None:
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
            else:
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

        # ── Enum4linux SMB/Windows enumeration (direct mode) ───────────────
        if self.enum4linux_scanner.available and self.result.nmap_available and self.result.nmap_results:
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
                enum_output_dir = os.path.join(".", label.replace("/", "_"))
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

        # ── MSF SMB brute-force (direct mode) ─────────────────────────────
        if (self.msf_scanner.available
                and self.result.enum4linux_available
                and self.result.enum4linux_results):
            enum_users = self.enum4linux_scanner.get_all_users()
            if enum_users:
                msf_output_dir = os.path.join(".", label.replace("/", "_"))
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
        if self.cme_scanner.available and self.result.nmap_available and self.result.nmap_results:
            print(
                f"\033[36m[>]\033[0m CME: grouping hosts by protocol from nmap results ..."
            )
            cme_output_dir = os.path.join(".", label.replace("/", "_"))
            os.makedirs(cme_output_dir, exist_ok=True)

            cme_results = self._safe_scan(
                "CME", self.cme_scanner.scan,
                self.result.nmap_results, output_dir=cme_output_dir,
            )

            if cme_results is not None:
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
            else:
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
        if self.nuclei_scanner.available and self.result.nmap_available and self.result.nmap_results:
            # Use IPs from nmap results as nuclei targets
            nuclei_targets = sorted(self.result.nmap_results.keys())
            if nuclei_targets:
                nuclei_output_dir = os.path.join(".", label.replace("/", "_"))
                os.makedirs(nuclei_output_dir, exist_ok=True)

                nuclei_results = self._safe_scan(
                    "nuclei", self.nuclei_scanner.scan,
                    nuclei_targets, output_dir=nuclei_output_dir,
                )

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
                f"\033[93m[!]\033[0m nuclei not found – skipping vulnerability scan"
            )
            print(
                f"\033[90m    Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\033[0m\n"
            )

        # ── WPScan WordPress scanning (direct mode) ──────────────────────
        if self.wpscan_scanner.available and self.result.nuclei_available and self.result.nuclei_results:
            from .scanner.wpscan import WPScanner as _WPS
            wp_targets = _WPS.detect_wordpress_targets(self.result.nuclei_results)
            if wp_targets:
                wpscan_output_dir = os.path.join(".", label.replace("/", "_"))
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

        # ── Statistics & Output ────────────────────────────────────────────
        self.result.scan_time = time.time() - start_time
        self._output()

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
        self.exporter.export(self.result, filename)
        self.renderer.print_saved(filename)

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
