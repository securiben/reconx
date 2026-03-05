"""
File Exporter for ReconX.
Creates a domain-specific output folder with separate files
for each finding type: takeover, dangling, tech, flagged, IPs, etc.
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Optional

from ..models import (
    ScanResult, Subdomain, TakeoverResult, TakeoverStatus,
    TechMatch, Severity, CTEntry,
)


class FileExporter:
    """
    Exports scan findings into a per-domain output folder
    with separate files for each category.

    Output structure:
        results/<domain>/
        ├── scan_summary.json        # Full scan summary
        ├── all_subdomains.txt       # All unique subdomains
        ├── alive_subdomains.txt     # Only alive (resolvable) subdomains
        ├── ip_addresses.txt         # All discovered IP addresses
        ├── ip_subdomain_map.txt     # IP → subdomain mapping
        ├── takeover_vulnerable.txt  # Subdomain takeover vulnerabilities
        ├── dangling_cnames.txt      # Dangling CNAME records
        ├── tech_detected.txt        # Technology detections by severity
        ├── flagged_interesting.txt  # Interesting/flagged subdomains
        ├── ct_aged.txt              # Aged CT log entries (2yr+)
        ├── ct_stale.txt             # Stale CT log entries (1-2yr)
        ├── collapsed_patterns.txt   # Collapsed pattern groups
        ├── infrastructure.txt       # Infrastructure provider classification
        ├── sources_stats.txt        # Source statistics
        ├── httpx_probe.txt          # Full httpx probe results per host
        ├── httpx_technologies.txt   # Wappalyzer tech detection grouped
        ├── httpx_cdn.txt            # CDN-backed subdomains
        ├── httpx_favicon.txt        # Favicon hash → subdomain mapping
        ├── httpx_servers.txt        # Server header distribution
        ├── httpx_titles.txt         # HTTP page titles
        ├── httpx_redirects.txt      # Redirecting subdomains + locations
        └── nmap_summary.txt         # Nmap scan statistics
    """

    def __init__(self, base_dir: str = "results"):
        self.base_dir = base_dir

    def export(self, result: ScanResult) -> str:
        """
        Export all findings to the domain folder.
        Returns the output directory path.
        """
        # Create output directory: results/<domain>/
        domain_dir = os.path.join(self.base_dir, result.target_domain)
        os.makedirs(domain_dir, exist_ok=True)

        # Export each category
        self._export_summary(domain_dir, result)
        self._export_all_subdomains(domain_dir, result)
        self._export_alive_subdomains(domain_dir, result)
        self._export_ip_addresses(domain_dir, result)
        self._export_takeover(domain_dir, result)
        self._export_dangling(domain_dir, result)
        self._export_tech(domain_dir, result)
        self._export_flagged(domain_dir, result)
        self._export_ct_entries(domain_dir, result)
        self._export_collapsed(domain_dir, result)
        self._export_infrastructure(domain_dir, result)
        self._export_sources(domain_dir, result)
        self._export_httpx(domain_dir, result)
        self._export_nuclei(domain_dir, result)
        self._export_nmap(domain_dir, result)
        self._export_enum4linux(domain_dir, result)
        self._export_cme(domain_dir, result)
        self._export_msf(domain_dir, result)
        self._export_rdp(domain_dir, result)

        return os.path.abspath(domain_dir)

    def _write(self, filepath: str, content: str):
        """Write content to file."""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

    def _export_summary(self, outdir: str, result: ScanResult):
        """Export full scan summary as JSON."""
        data = {
            "meta": {
                "tool": "ReconX",
                "version": "1.0.0",
                "scan_date": datetime.utcnow().isoformat() + "Z",
                "target": result.target_domain,
                "scan_time_seconds": round(result.scan_time, 2),
            },
            "summary": {
                "total_unique_subdomains": result.total_unique,
                "infrastructure": result.infra.to_dict(),
                "ct_triage": {
                    "stale_1_2yr": result.ct_stale,
                    "aged_2yr_plus": result.ct_aged,
                    "no_date": result.ct_no_date,
                },
                "collapsed": result.collapse.to_dict(),
                "takeover": {
                    "vulnerable": result.vulnerable_count,
                    "dangling_cnames": result.dangling_count,
                    "not_vulnerable": result.not_vulnerable_count,
                    "primary_provider": result.takeover_provider,
                },
                "flagged_interesting": result.flagged_interesting,
                "databases": {
                    "takeover_services": result.takeover_db_services,
                    "tech_signatures": result.tech_db_signatures,
                },
            },
            "takeover_results": [r.to_dict() for r in result.takeover_results],
            "tech_matches": [m.to_dict() for m in result.tech_matches],
            "sources": {
                name: stats.to_dict()
                for name, stats in result.source_stats.items()
            },
            "subdomains": [s.to_dict() for s in result.subdomains],
        }
        filepath = os.path.join(outdir, "scan_summary.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    def _export_all_subdomains(self, outdir: str, result: ScanResult):
        """Export all unique subdomains, one per line."""
        subs = sorted(set(s.hostname for s in result.subdomains))
        filepath = os.path.join(outdir, "all_subdomains.txt")
        lines = [f"# ReconX - All Subdomains for {result.target_domain}"]
        lines.append(f"# Total: {len(subs)} unique subdomains")
        lines.append(f"# Scan date: {datetime.utcnow().isoformat()}Z")
        lines.append("")
        lines.extend(subs)
        self._write(filepath, "\n".join(lines) + "\n")

    def _export_alive_subdomains(self, outdir: str, result: ScanResult):
        """Export only alive (resolvable) subdomains."""
        alive = sorted(
            s.hostname for s in result.subdomains
            if s.is_alive or s.ip_addresses
        )
        filepath = os.path.join(outdir, "alive_subdomains.txt")
        lines = [f"# ReconX - Alive Subdomains for {result.target_domain}"]
        lines.append(f"# Total: {len(alive)} alive subdomains")
        lines.append("")
        lines.extend(alive)
        self._write(filepath, "\n".join(lines) + "\n")

    def _export_ip_addresses(self, outdir: str, result: ScanResult):
        """Export all discovered IP addresses with their subdomain mappings."""
        ip_to_subs: Dict[str, List[str]] = {}
        all_ips = set()

        for sub in result.subdomains:
            for ip in sub.ip_addresses:
                all_ips.add(ip)
                if ip not in ip_to_subs:
                    ip_to_subs[ip] = []
                ip_to_subs[ip].append(sub.hostname)

        # ip_addresses.txt - just IPs
        filepath_ips = os.path.join(outdir, "ip_addresses.txt")
        lines = [f"# ReconX - IP Addresses for {result.target_domain}"]
        lines.append(f"# Total: {len(all_ips)} unique IPs")
        lines.append("")
        lines.extend(sorted(all_ips))
        self._write(filepath_ips, "\n".join(lines) + "\n")

        # ip_subdomain_map.txt - IP → subdomain mapping
        filepath_map = os.path.join(outdir, "ip_subdomain_map.txt")
        lines = [f"# ReconX - IP to Subdomain Mapping for {result.target_domain}"]
        lines.append(f"# Total: {len(all_ips)} unique IPs")
        lines.append("")
        for ip in sorted(ip_to_subs.keys()):
            subs = sorted(ip_to_subs[ip])
            lines.append(f"{ip}")
            for sub in subs:
                lines.append(f"  └─ {sub}")
            lines.append("")
        self._write(filepath_map, "\n".join(lines) + "\n")

    def _export_takeover(self, outdir: str, result: ScanResult):
        """Export subdomain takeover vulnerabilities."""
        vulnerable = [
            r for r in result.takeover_results
            if r.status == TakeoverStatus.VULNERABLE
        ]
        if not vulnerable:
            return

        filepath = os.path.join(outdir, "takeover_vulnerable.txt")
        lines = [f"# ReconX - Subdomain Takeover Vulnerabilities for {result.target_domain}"]
        lines.append(f"# ⚠ {len(vulnerable)} VULNERABLE subdomain(s) detected!")
        lines.append(f"# Scan date: {datetime.utcnow().isoformat()}Z")
        lines.append("")
        for r in vulnerable:
            lines.append(f"[VULNERABLE] {r.subdomain}")
            lines.append(f"  Provider:   {r.provider}")
            lines.append(f"  CNAME:      {r.cname}")
            lines.append(f"  Evidence:   {r.evidence}")
            lines.append(f"  Match Type: {r.match_type}")
            lines.append("")
        self._write(filepath, "\n".join(lines) + "\n")

    def _export_dangling(self, outdir: str, result: ScanResult):
        """Export dangling CNAME records."""
        dangling = [
            r for r in result.takeover_results
            if r.status == TakeoverStatus.DANGLING
        ]
        if not dangling:
            return

        filepath = os.path.join(outdir, "dangling_cnames.txt")
        lines = [f"# ReconX - Dangling CNAME Records for {result.target_domain}"]
        lines.append(f"# {len(dangling)} dangling CNAME(s) detected")
        lines.append(f"# These may be potential takeover candidates")
        lines.append("")
        for r in dangling:
            lines.append(f"[DANGLING] {r.subdomain}")
            lines.append(f"  CNAME:      {r.cname}")
            lines.append(f"  Provider:   {r.provider}")
            if r.evidence:
                lines.append(f"  Evidence:   {r.evidence}")
            lines.append("")
        self._write(filepath, "\n".join(lines) + "\n")

    def _export_tech(self, outdir: str, result: ScanResult):
        """Export technology detections grouped by severity."""
        if not result.tech_matches:
            return

        filepath = os.path.join(outdir, "tech_detected.txt")
        lines = [f"# ReconX - Technology Detections for {result.target_domain}"]
        lines.append(f"# {len(result.tech_matches)} technology match(es)")
        lines.append("")

        # Group by severity
        by_severity: Dict[str, List[TechMatch]] = {}
        for m in result.tech_matches:
            sev = m.tech.severity.value
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(m)

        severity_order = ["CRITICAL", "high", "medium", "low", "info"]
        severity_icons = {
            "CRITICAL": "🔴", "high": "🟠", "medium": "🟡",
            "low": "🔵", "info": "⚪"
        }

        for sev in severity_order:
            if sev not in by_severity:
                continue
            matches = by_severity[sev]
            icon = severity_icons.get(sev, "")
            lines.append(f"{'='*60}")
            lines.append(f"{icon} [{sev.upper()}] - {len(matches)} match(es)")
            lines.append(f"{'='*60}")
            lines.append("")
            for m in matches:
                lines.append(f"  Subdomain:   {m.subdomain}")
                lines.append(f"  Technology:  {m.tech.name}")
                lines.append(f"  Category:    {m.tech.category}")
                lines.append(f"  Location:    {m.match_location}")
                lines.append(f"  Description: {m.tech.description}")
                if m.evidence:
                    evidence = m.evidence[:200]
                    lines.append(f"  Evidence:    {evidence}")
                lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

    def _export_flagged(self, outdir: str, result: ScanResult):
        """Export flagged/interesting subdomains."""
        flagged = [s for s in result.subdomains if s.interesting]
        if not flagged:
            return

        filepath = os.path.join(outdir, "flagged_interesting.txt")
        lines = [f"# ReconX - Flagged Interesting Subdomains for {result.target_domain}"]
        lines.append(f"# {len(flagged)} interesting subdomain(s)")
        lines.append(f"# These match patterns: admin, api, dev, staging, vpn, etc.")
        lines.append("")

        for sub in sorted(flagged, key=lambda s: s.hostname):
            ip_info = ", ".join(sub.ip_addresses) if sub.ip_addresses else "no IP"
            provider = sub.provider.value if sub.provider else "unknown"
            cname_info = " → ".join(sub.cnames) if sub.cnames else ""
            status = "ALIVE" if sub.is_alive else "dead"

            line = f"{sub.hostname}"
            line += f"  [{status}]"
            line += f"  {ip_info}"
            line += f"  [{provider}]"
            if cname_info:
                line += f"  CNAME: {cname_info}"
            lines.append(line)
            lines.append(f"  Reason: {sub.interesting_reason}")
            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

    def _export_ct_entries(self, outdir: str, result: ScanResult):
        """Export CT log entries grouped by age category."""
        if not result.ct_entries:
            return

        # Aged entries (2yr+)
        aged = [e for e in result.ct_entries if e.age_category == "aged"]
        if aged:
            filepath = os.path.join(outdir, "ct_aged.txt")
            lines = [f"# ReconX - Aged CT Log Entries (2yr+) for {result.target_domain}"]
            lines.append(f"# {len(aged)} aged entries")
            lines.append("")
            seen = set()
            for e in sorted(aged, key=lambda x: x.subdomain):
                if e.subdomain not in seen:
                    seen.add(e.subdomain)
                    date_str = e.not_before.strftime("%Y-%m-%d") if e.not_before else "unknown"
                    lines.append(f"{e.subdomain}  [{date_str}]  {e.issuer[:60]}")
            self._write(filepath, "\n".join(lines) + "\n")

        # Stale entries (1-2yr)
        stale = [e for e in result.ct_entries if e.age_category == "stale"]
        if stale:
            filepath = os.path.join(outdir, "ct_stale.txt")
            lines = [f"# ReconX - Stale CT Log Entries (1-2yr) for {result.target_domain}"]
            lines.append(f"# {len(stale)} stale entries")
            lines.append("")
            seen = set()
            for e in sorted(stale, key=lambda x: x.subdomain):
                if e.subdomain not in seen:
                    seen.add(e.subdomain)
                    date_str = e.not_before.strftime("%Y-%m-%d") if e.not_before else "unknown"
                    lines.append(f"{e.subdomain}  [{date_str}]  {e.issuer[:60]}")
            self._write(filepath, "\n".join(lines) + "\n")

    def _export_collapsed(self, outdir: str, result: ScanResult):
        """Export collapsed pattern groups with their members."""
        import re
        hostnames = [s.hostname for s in result.subdomains]
        threshold = result.collapse.threshold

        # Use same 4-strategy approach as utils.collapse_subdomains
        patterns: Dict[str, List[str]] = {}
        for hostname in hostnames:
            parts = hostname.split(".")
            if len(parts) < 2:
                continue

            keys = []
            # Strategy 1: Replace numeric sequences in first label
            pat1 = re.sub(r'\d+', '*', parts[0])
            pat1 = re.sub(r'\*+', '*', pat1)
            keys.append(pat1 + "." + ".".join(parts[1:]))

            # Strategy 2: Wildcard entire first label (group by parent)
            if len(parts) >= 3:
                keys.append("*." + ".".join(parts[1:]))

            # Strategy 3: Replace hex-like hashes (8+ hex chars)
            pat3 = re.sub(r'[0-9a-f]{8,}', '*', parts[0], flags=re.IGNORECASE)
            if pat3 != parts[0]:
                keys.append(pat3 + "." + ".".join(parts[1:]))

            # Strategy 4: Replace UUID patterns
            pat4 = re.sub(
                r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                '*', hostname, flags=re.IGNORECASE
            )
            if pat4 != hostname:
                keys.append(pat4)

            for key in keys:
                if key != hostname:
                    if key not in patterns:
                        patterns[key] = []
                    if hostname not in patterns[key]:
                        patterns[key].append(hostname)

        # Only keep groups above threshold
        groups = {
            p: members for p, members in patterns.items()
            if len(members) >= threshold
        }

        if not groups:
            return

        filepath = os.path.join(outdir, "collapsed_patterns.txt")
        lines = [f"# ReconX - Collapsed Pattern Groups for {result.target_domain}"]
        lines.append(f"# {len(groups)} pattern groups (threshold: {threshold}+)")
        total_entries = sum(len(m) for m in groups.values())
        lines.append(f"# {total_entries} total entries collapsed")
        lines.append("")

        for pattern, members in sorted(groups.items(), key=lambda x: -len(x[1])):
            lines.append(f"[{len(members)} entries] {pattern}")
            for member in sorted(members):
                lines.append(f"  {member}")
            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

    def _export_infrastructure(self, outdir: str, result: ScanResult):
        """Export infrastructure classification."""
        filepath = os.path.join(outdir, "infrastructure.txt")
        lines = [f"# ReconX - Infrastructure Classification for {result.target_domain}"]
        infra = result.infra
        lines.append(f"# AWS: {infra.aws} | Azure: {infra.azure} | Cloudflare: {infra.cloudflare}")
        lines.append(f"# Akamai: {infra.akamai} | Other: {infra.other} | CT-only: {infra.ct_only}")
        lines.append("")

        # Group subdomains by provider
        providers: Dict[str, List[Subdomain]] = {}
        for sub in result.subdomains:
            prov = sub.provider.value if sub.provider else "unknown"
            if prov not in providers:
                providers[prov] = []
            providers[prov].append(sub)

        for prov in ["AWS", "Azure", "Cloudflare", "Akamai", "Other", "CT-only"]:
            if prov not in providers:
                continue
            subs = providers[prov]
            lines.append(f"{'='*50}")
            lines.append(f"[{prov}] - {len(subs)} subdomain(s)")
            lines.append(f"{'='*50}")
            for sub in sorted(subs, key=lambda s: s.hostname):
                ip_str = ", ".join(sub.ip_addresses) if sub.ip_addresses else "-"
                cname_str = " → ".join(sub.cnames) if sub.cnames else ""
                line = f"  {sub.hostname}  [{ip_str}]"
                if cname_str:
                    line += f"  CNAME: {cname_str}"
                lines.append(line)
            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

    def _export_sources(self, outdir: str, result: ScanResult):
        """Export source statistics."""
        filepath = os.path.join(outdir, "sources_stats.txt")
        lines = [f"# ReconX - Source Statistics for {result.target_domain}"]
        lines.append(f"# Scan time: {result.scan_time:.1f}s")
        lines.append("")
        for name, stats in result.source_stats.items():
            lines.append(f"{stats.name:<12} {stats.count:>6} subdomains")
        lines.append(f"{'─'*30}")
        lines.append(f"{'Total unique':<12} {result.total_unique:>6}")
        self._write(filepath, "\n".join(lines) + "\n")

    def _export_httpx(self, outdir: str, result: ScanResult):
        """
        Export httpx probe results as multiple files:
          - httpx_probe.txt         Comprehensive probe results per alive host
          - httpx_technologies.txt  All detected technologies grouped
          - httpx_cdn.txt           CDN-backed subdomains
          - httpx_favicon.txt       Favicon hash → subdomain mapping
          - httpx_servers.txt       Server header summary
          - httpx_titles.txt        HTTP titles for all alive hosts
          - httpx_redirects.txt     Redirecting subdomains + locations
        """
        stats = getattr(result, 'httpx_stats', {})
        if not getattr(result, 'httpx_available', False) or not stats:
            return

        alive_subs = [s for s in result.subdomains if s.is_alive and getattr(s, 'http_url', '')]

        if not alive_subs:
            return

        # ── httpx_probe.txt ── comprehensive per-host results ─────────────
        filepath = os.path.join(outdir, "httpx_probe.txt")
        lines = [f"# ReconX - HTTPX Probe Results for {result.target_domain}"]
        lines.append(f"# {len(alive_subs)} alive hosts probed")
        lines.append(f"# Probed with: httpx -sc -title -td -favicon -cdn -server -efqdn")
        lines.append("")

        for sub in sorted(alive_subs, key=lambda s: s.hostname):
            sc = sub.http_status or 0
            title = getattr(sub, 'http_title', '') or ''
            server = getattr(sub, 'http_server', '') or ''
            url = getattr(sub, 'http_url', '') or ''
            cdn_name = getattr(sub, 'http_cdn_name', '') or ''
            is_cdn = getattr(sub, 'http_cdn', False)
            techs = getattr(sub, 'http_technologies', []) or []
            fav = getattr(sub, 'http_favicon_hash', '') or ''
            resp_time = getattr(sub, 'http_response_time', '') or ''
            location = getattr(sub, 'http_location', '') or ''
            final_url = getattr(sub, 'http_final_url', '') or ''
            cl = getattr(sub, 'http_content_length', 0) or 0

            lines.append(f"{'─'*70}")
            lines.append(f"  Host:        {sub.hostname}")
            lines.append(f"  URL:         {url}")
            lines.append(f"  Status:      {sc}")
            if title:
                lines.append(f"  Title:       {title}")
            if server:
                lines.append(f"  Server:      {server}")
            if is_cdn:
                lines.append(f"  CDN:         Yes ({cdn_name})" if cdn_name else f"  CDN:         Yes")
            if techs:
                lines.append(f"  Tech:        {', '.join(techs)}")
            if fav and fav != '0':
                lines.append(f"  Favicon:     {fav}")
            if location:
                lines.append(f"  Redirect:    {location}")
            if final_url and final_url != url:
                lines.append(f"  Final URL:   {final_url}")
            if resp_time:
                lines.append(f"  Resp Time:   {resp_time}")
            if cl:
                lines.append(f"  Content Len: {cl}")
            ips = ", ".join(sub.ip_addresses) if sub.ip_addresses else ""
            if ips:
                lines.append(f"  IPs:         {ips}")
            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── httpx_technologies.txt ── tech detection grouped ─────────────
        tech_map: Dict[str, List[str]] = {}
        for sub in alive_subs:
            for tech in getattr(sub, 'http_technologies', []) or []:
                if tech not in tech_map:
                    tech_map[tech] = []
                tech_map[tech].append(sub.hostname)

        if tech_map:
            filepath = os.path.join(outdir, "httpx_technologies.txt")
            lines = [f"# ReconX - HTTPX Technology Detection for {result.target_domain}"]
            lines.append(f"# {len(tech_map)} unique technologies detected across {sum(len(v) for v in tech_map.values())} hosts")
            lines.append("")
            for tech in sorted(tech_map.keys()):
                hosts = sorted(tech_map[tech])
                lines.append(f"[{tech}] ({len(hosts)} hosts)")
                for h in hosts:
                    lines.append(f"  {h}")
                lines.append("")
            self._write(filepath, "\n".join(lines) + "\n")

        # ── httpx_cdn.txt ── CDN-backed subdomains ───────────────────────
        cdn_subs = [s for s in alive_subs if getattr(s, 'http_cdn', False)]
        if cdn_subs:
            filepath = os.path.join(outdir, "httpx_cdn.txt")
            lines = [f"# ReconX - CDN Detection for {result.target_domain}"]
            lines.append(f"# {len(cdn_subs)} subdomains behind CDN")
            lines.append("")
            cdn_groups: Dict[str, List[str]] = {}
            for s in cdn_subs:
                name = getattr(s, 'http_cdn_name', 'Unknown') or 'Unknown'
                if name not in cdn_groups:
                    cdn_groups[name] = []
                cdn_groups[name].append(s.hostname)
            for provider in sorted(cdn_groups.keys()):
                hosts = sorted(cdn_groups[provider])
                lines.append(f"[{provider}] ({len(hosts)} hosts)")
                for h in hosts:
                    lines.append(f"  {h}")
                lines.append("")
            self._write(filepath, "\n".join(lines) + "\n")

        # ── httpx_favicon.txt ── favicon hashes ──────────────────────────
        fav_map: Dict[str, List[str]] = {}
        for sub in alive_subs:
            fav = getattr(sub, 'http_favicon_hash', '') or ''
            if fav and fav != '0' and fav != '':
                if fav not in fav_map:
                    fav_map[fav] = []
                fav_map[fav].append(sub.hostname)

        if fav_map:
            filepath = os.path.join(outdir, "httpx_favicon.txt")
            lines = [f"# ReconX - Favicon Hash Fingerprints for {result.target_domain}"]
            lines.append(f"# {len(fav_map)} unique favicon hashes")
            lines.append(f"# Use Shodan favicon search: http.favicon.hash:<hash>")
            lines.append("")
            for fhash in sorted(fav_map.keys(), key=lambda x: -len(fav_map[x])):
                hosts = sorted(fav_map[fhash])
                # Try to identify known service
                known = ""
                try:
                    from ..scanner.httpx_probe import identify_favicon
                    srv = identify_favicon(fhash)
                    if srv:
                        known = f" → {srv}"
                except Exception:
                    pass
                lines.append(f"[Favicon: {fhash}{known}] ({len(hosts)} hosts)")
                for h in hosts:
                    lines.append(f"  {h}")
                lines.append("")
            self._write(filepath, "\n".join(lines) + "\n")

        # ── httpx_servers.txt ── server header distribution ──────────────
        srv_map: Dict[str, List[str]] = {}
        for sub in alive_subs:
            server = getattr(sub, 'http_server', '') or ''
            if server:
                if server not in srv_map:
                    srv_map[server] = []
                srv_map[server].append(sub.hostname)

        if srv_map:
            filepath = os.path.join(outdir, "httpx_servers.txt")
            lines = [f"# ReconX - Server Headers for {result.target_domain}"]
            lines.append(f"# {len(srv_map)} unique server signatures")
            lines.append("")
            for server in sorted(srv_map.keys(), key=lambda x: -len(srv_map[x])):
                hosts = sorted(srv_map[server])
                lines.append(f"[{server}] ({len(hosts)} hosts)")
                for h in hosts:
                    lines.append(f"  {h}")
                lines.append("")
            self._write(filepath, "\n".join(lines) + "\n")

        # ── httpx_titles.txt ── page titles for all alive hosts ──────────
        titled_subs = [
            s for s in alive_subs
            if getattr(s, 'http_title', '')
        ]
        if titled_subs:
            filepath = os.path.join(outdir, "httpx_titles.txt")
            lines = [f"# ReconX - HTTP Page Titles for {result.target_domain}"]
            lines.append(f"# {len(titled_subs)} hosts with page titles")
            lines.append("")
            for sub in sorted(titled_subs, key=lambda s: s.hostname):
                sc = sub.http_status or 0
                title = getattr(sub, 'http_title', '')
                lines.append(f"[{sc}] {sub.hostname}  \"{title}\"")
            self._write(filepath, "\n".join(lines) + "\n")

        # ── httpx_redirects.txt ── redirecting subdomains ────────────────
        redirect_subs = [
            s for s in alive_subs
            if getattr(s, 'http_location', '')
        ]
        if redirect_subs:
            filepath = os.path.join(outdir, "httpx_redirects.txt")
            lines = [f"# ReconX - HTTP Redirects for {result.target_domain}"]
            lines.append(f"# {len(redirect_subs)} redirecting hosts")
            lines.append("")
            for sub in sorted(redirect_subs, key=lambda s: s.hostname):
                sc = sub.http_status or 0
                loc = getattr(sub, 'http_location', '')
                final = getattr(sub, 'http_final_url', '')
                lines.append(f"[{sc}] {sub.hostname}")
                lines.append(f"  → {loc}")
                if final and final != loc:
                    lines.append(f"  → (final) {final}")
                lines.append("")
            self._write(filepath, "\n".join(lines) + "\n")

    def _export_nuclei(self, outdir: str, result: ScanResult):
        """
        Export nuclei vulnerability scan results.
        Note: nuclei_results.txt is already written by the scanner directly.
        This exports a structured summary and JSON.
        """
        nuclei_stats = getattr(result, 'nuclei_stats', {})
        nuclei_results = getattr(result, 'nuclei_results', [])
        if not getattr(result, 'nuclei_available', False) or not nuclei_results:
            return

        domain = result.target_domain

        # ── nuclei_summary.txt ── Human-readable summary ─────────────
        filepath = os.path.join(outdir, "nuclei_summary.txt")
        lines = [f"# ReconX - Nuclei Vulnerability Scan for {domain}"]
        lines.append(f"# Total findings: {nuclei_stats.get('total_findings', 0)}")
        lines.append(f"# Critical: {nuclei_stats.get('critical', 0)}")
        lines.append(f"# High: {nuclei_stats.get('high', 0)}")
        lines.append(f"# Medium: {nuclei_stats.get('medium', 0)}")
        lines.append(f"# Low: {nuclei_stats.get('low', 0)}")
        lines.append(f"# Hosts scanned: {nuclei_stats.get('hosts_scanned', 0)}")
        lines.append(f"# Scan time: {nuclei_stats.get('scan_time', 0.0):.1f}s")
        lines.append("")

        # Group by severity
        for sev in ["critical", "high", "medium", "low"]:
            sev_findings = [
                f for f in nuclei_results
                if (f.severity if hasattr(f, 'severity') else f.get('severity', '')) == sev
            ]
            if not sev_findings:
                continue
            lines.append(f"── {sev.upper()} ({len(sev_findings)}) ──")
            for finding in sev_findings:
                tid = finding.template_id if hasattr(finding, 'template_id') else finding.get('template_id', '')
                tname = finding.template_name if hasattr(finding, 'template_name') else finding.get('template_name', tid)
                host = finding.host if hasattr(finding, 'host') else finding.get('host', '')
                matched = finding.matched_at if hasattr(finding, 'matched_at') else finding.get('matched_at', host)
                lines.append(f"  [{tid}] {tname}")
                lines.append(f"    Host: {host}")
                if matched and matched != host:
                    lines.append(f"    Matched: {matched}")
            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── nuclei_summary.json ── Structured JSON ───────────────────
        filepath_json = os.path.join(outdir, "nuclei_summary.json")
        json_data = {
            "domain": domain,
            "stats": nuclei_stats,
            "findings": [
                r.to_dict() if hasattr(r, 'to_dict') else r
                for r in nuclei_results
            ],
        }
        self._write(filepath_json, json.dumps(json_data, indent=2, ensure_ascii=False) + "\n")

    def _export_nmap(self, outdir: str, result: ScanResult):
        """
        Export nmap scan results as summary text file.
        The raw nmap output files (.nmap, .xml, .gnmap) are already
        written directly by the nmap scanner to the output directory.
        This method creates an additional human-readable summary.
        """
        nmap_stats = getattr(result, 'nmap_stats', {})
        nmap_results = getattr(result, 'nmap_results', {})
        if not getattr(result, 'nmap_available', False) or not nmap_results:
            return

        domain = result.target_domain

        # ── nmap_summary.txt ── Human-readable summary ────────────────
        filepath = os.path.join(outdir, "nmap_summary.txt")
        lines = [f"# ReconX - Nmap Port Scan Summary for {domain}"]
        lines.append(f"# Command: nmap -iL ip_addresses.txt -sCV --top-ports 1000 -T3 -oA nmap_scan")
        lines.append(f"# Hosts scanned: {nmap_stats.get('total_ips_scanned', 0)}")
        lines.append(f"# Hosts up: {nmap_stats.get('hosts_up', 0)}")
        lines.append(f"# Total open ports: {nmap_stats.get('total_open_ports', 0)}")
        lines.append(f"# Unique services: {nmap_stats.get('unique_services', 0)}")
        lines.append(f"# Scan time: {nmap_stats.get('scan_time', 0.0):.1f}s")
        lines.append("")

        # Top services
        top_services = nmap_stats.get("top_services", [])
        if top_services:
            lines.append("── Top Services ──")
            for s in top_services:
                lines.append(f"  {s['service']:<20} {s['count']} host(s)")
            lines.append("")

        # Top ports
        top_ports = nmap_stats.get("top_ports", [])
        if top_ports:
            lines.append("── Top Ports ──")
            for p in top_ports:
                lines.append(f"  {p['port']:<8} {p['count']} host(s)")
            lines.append("")

        # Per-host results
        lines.append("── Per-Host Results ──")
        for ip in sorted(nmap_results.keys()):
            host = nmap_results[ip]
            hostname_str = f" ({host.hostname})" if hasattr(host, 'hostname') and host.hostname else ""
            ports = host.ports if hasattr(host, 'ports') else []
            lines.append(f"{'─'*60}")
            lines.append(f"  Host: {ip}{hostname_str}")
            lines.append(f"  Open ports: {len(ports)}")
            if ports:
                for p in sorted(ports, key=lambda x: x.port if hasattr(x, 'port') else 0):
                    port_num = p.port if hasattr(p, 'port') else p.get('port', 0)
                    proto = p.protocol if hasattr(p, 'protocol') else p.get('protocol', 'tcp')
                    service = p.service if hasattr(p, 'service') else p.get('service', '')
                    version = p.version if hasattr(p, 'version') else p.get('version', '')
                    ver_str = f" ({version})" if version else ""
                    lines.append(f"    {port_num}/{proto:<5} {service}{ver_str}")
            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── nmap_summary.json ── Structured JSON ──────────────────────
        filepath_json = os.path.join(outdir, "nmap_summary.json")
        json_data = {
            "domain": domain,
            "stats": nmap_stats,
            "hosts": {
                ip: h.to_dict() if hasattr(h, 'to_dict') else h
                for ip, h in nmap_results.items()
            },
        }
        self._write(filepath_json, json.dumps(json_data, indent=2, ensure_ascii=False) + "\n")

    def _export_enum4linux(self, outdir: str, result: ScanResult):
        """
        Export enum4linux scan results.
        Creates a human-readable summary and a structured JSON file.
        Raw per-host output files are already written by the scanner.
        """
        enum_stats = getattr(result, 'enum4linux_stats', {})
        enum_results = getattr(result, 'enum4linux_results', {})
        if not getattr(result, 'enum4linux_available', False) or not enum_results:
            return

        domain = result.target_domain

        # ── enum4linux_summary.txt ── Human-readable summary ──────────
        filepath = os.path.join(outdir, "enum4linux_summary.txt")
        lines = [f"# ReconX - Enum4linux SMB/Windows Enumeration for {domain}"]
        lines.append(f"# Command: enum4linux -a <ip>")
        lines.append(f"# Hosts scanned: {enum_stats.get('total_ips_scanned', 0)}")
        lines.append(f"# Hosts responded: {enum_stats.get('hosts_responded', 0)}")
        lines.append(f"# Null sessions: {enum_stats.get('null_sessions', 0)}")
        lines.append(f"# Total shares: {enum_stats.get('total_shares', 0)}")
        lines.append(f"# Total users: {enum_stats.get('total_users', 0)}")
        lines.append(f"# Total groups: {enum_stats.get('total_groups', 0)}")
        lines.append(f"# Scan time: {enum_stats.get('scan_time', 0.0):.1f}s")
        lines.append("")

        # Per-host results
        for ip in sorted(enum_results.keys()):
            host = enum_results[ip]
            success = host.success if hasattr(host, 'success') else host.get('success', False)
            if not success:
                continue

            lines.append(f"{'─'*60}")
            lines.append(f"  Host: {ip}")

            workgroup = host.workgroup if hasattr(host, 'workgroup') else host.get('workgroup', '')
            domain_name = host.domain if hasattr(host, 'domain') else host.get('domain', '')
            os_info = host.os_info if hasattr(host, 'os_info') else host.get('os_info', '')
            null_session = host.null_session if hasattr(host, 'null_session') else host.get('null_session', False)

            if workgroup:
                lines.append(f"  Workgroup: {workgroup}")
            if domain_name:
                lines.append(f"  Domain: {domain_name}")
            if os_info:
                lines.append(f"  OS: {os_info}")
            if null_session:
                lines.append(f"  ⚠ NULL SESSION ALLOWED")

            # Shares
            shares = host.shares if hasattr(host, 'shares') else host.get('shares', [])
            if shares:
                lines.append(f"  Shares ({len(shares)}):")
                for s in shares:
                    name = s.name if hasattr(s, 'name') else s.get('name', '')
                    stype = s.share_type if hasattr(s, 'share_type') else s.get('type', '')
                    comment = s.comment if hasattr(s, 'comment') else s.get('comment', '')
                    access = s.access if hasattr(s, 'access') else s.get('access', '')
                    parts = [f"    {name}"]
                    if stype:
                        parts.append(f"[{stype}]")
                    if access:
                        parts.append(f"({access})")
                    if comment:
                        parts.append(f"- {comment}")
                    lines.append(" ".join(parts))

            # Users
            users = host.users if hasattr(host, 'users') else host.get('users', [])
            if users:
                lines.append(f"  Users ({len(users)}):")
                for u in users:
                    username = u.username if hasattr(u, 'username') else u.get('username', '')
                    rid = u.rid if hasattr(u, 'rid') else u.get('rid', '')
                    rid_str = f" (RID: {rid})" if rid else ""
                    lines.append(f"    {username}{rid_str}")

            # Groups
            groups = host.groups if hasattr(host, 'groups') else host.get('groups', [])
            if groups:
                lines.append(f"  Groups ({len(groups)}):")
                for g in groups:
                    name = g.name if hasattr(g, 'name') else g.get('name', '')
                    rid = g.rid if hasattr(g, 'rid') else g.get('rid', '')
                    rid_str = f" (RID: {rid})" if rid else ""
                    lines.append(f"    {name}{rid_str}")

            # Password policy
            policy = host.password_policy if hasattr(host, 'password_policy') else host.get('password_policy', {})
            if policy:
                lines.append(f"  Password Policy:")
                for key, value in policy.items():
                    lines.append(f"    {key}: {value}")

            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── enum4linux_users.txt ── All discovered usernames ──────────
        all_users = set()
        for ip, host in enum_results.items():
            users = host.users if hasattr(host, 'users') else host.get('users', [])
            for u in users:
                username = u.username if hasattr(u, 'username') else u.get('username', '')
                if username:
                    all_users.add(username)
            rid_users = host.rid_cycling_users if hasattr(host, 'rid_cycling_users') else host.get('rid_cycling_users', [])
            for u in rid_users:
                if u:
                    all_users.add(u)

        if all_users:
            filepath_users = os.path.join(outdir, "enum4linux_users.txt")
            user_lines = [f"# ReconX - Enum4linux Discovered Users for {domain}"]
            user_lines.append(f"# Total: {len(all_users)} unique users")
            user_lines.append("")
            user_lines.extend(sorted(all_users))
            self._write(filepath_users, "\n".join(user_lines) + "\n")

        # ── enum4linux_shares.txt ── All discovered shares ────────────
        all_shares_info = []
        for ip, host in enum_results.items():
            shares = host.shares if hasattr(host, 'shares') else host.get('shares', [])
            for s in shares:
                name = s.name if hasattr(s, 'name') else s.get('name', '')
                if name:
                    all_shares_info.append(f"{ip}  {name}")

        if all_shares_info:
            filepath_shares = os.path.join(outdir, "enum4linux_shares.txt")
            share_lines = [f"# ReconX - Enum4linux Discovered Shares for {domain}"]
            share_lines.append(f"# Format: IP  ShareName")
            share_lines.append("")
            share_lines.extend(sorted(all_shares_info))
            self._write(filepath_shares, "\n".join(share_lines) + "\n")

        # ── enum4linux_null_sessions.txt ── Hosts with null sessions ──
        null_hosts = [
            ip for ip, h in enum_results.items()
            if (h.null_session if hasattr(h, 'null_session') else h.get('null_session', False))
        ]
        if null_hosts:
            filepath_null = os.path.join(outdir, "enum4linux_null_sessions.txt")
            null_lines = [f"# ReconX - Enum4linux Null Session Hosts for {domain}"]
            null_lines.append(f"# ⚠ {len(null_hosts)} host(s) allow anonymous/null sessions")
            null_lines.append("")
            null_lines.extend(sorted(null_hosts))
            self._write(filepath_null, "\n".join(null_lines) + "\n")

        # ── enum4linux_summary.json ── Structured JSON ────────────────
        filepath_json = os.path.join(outdir, "enum4linux_summary.json")
        json_data = {
            "domain": domain,
            "stats": enum_stats,
            "hosts": {
                ip: h.to_dict() if hasattr(h, 'to_dict') else h
                for ip, h in enum_results.items()
            },
        }
        self._write(filepath_json, json.dumps(json_data, indent=2, ensure_ascii=False) + "\n")

    def _export_cme(self, outdir: str, result: ScanResult):
        """
        Export CrackMapExec scan results.
        Creates per-protocol target files and a summary.
        """
        cme_stats = getattr(result, 'cme_stats', {})
        cme_results = getattr(result, 'cme_results', {})
        if not getattr(result, 'cme_available', False) or not cme_results:
            return

        domain = result.target_domain

        # ── cme_summary.txt ── Human-readable summary ─────────────────
        filepath = os.path.join(outdir, "cme_summary.txt")
        lines = [f"# ReconX - CrackMapExec Protocol Enumeration for {domain}"]
        lines.append(f"# Protocols scanned: {cme_stats.get('protocols_scanned', 0)}")
        lines.append(f"# Total hosts discovered: {cme_stats.get('total_hosts_discovered', 0)}")
        lines.append(f"# Scan time: {cme_stats.get('scan_time', 0.0):.1f}s")
        lines.append("")

        protocol_summary = cme_stats.get('protocol_summary', {})
        if protocol_summary:
            lines.append("── Protocol Summary ──")
            for proto, count in sorted(protocol_summary.items()):
                lines.append(f"  {proto:<12} {count} host(s)")
            lines.append("")

        # Per-protocol results
        for proto in ["smb", "ssh", "rdp", "winrm", "mssql", "ldap", "wmi", "vnc", "ftp"]:
            proto_result = cme_results.get(proto)
            if not proto_result:
                continue

            host_results = []
            if hasattr(proto_result, 'host_results'):
                host_results = proto_result.host_results
            elif isinstance(proto_result, dict):
                host_results = proto_result.get('host_results', [])

            if not host_results:
                continue

            lines.append(f"── {proto.upper()} ──")
            for h in host_results:
                ip = h.ip if hasattr(h, 'ip') else h.get('ip', '')
                hostname = h.hostname if hasattr(h, 'hostname') else h.get('hostname', '')
                port_num = h.port if hasattr(h, 'port') else h.get('port', 0)
                os_info = h.os_info if hasattr(h, 'os_info') else h.get('os_info', '')
                signing = h.signing if hasattr(h, 'signing') else h.get('signing', '')
                domain_name = h.domain if hasattr(h, 'domain') else h.get('domain', '')

                parts = [f"  {ip}:{port_num}"]
                if hostname:
                    parts.append(f"({hostname})")
                if os_info:
                    parts.append(f"[{os_info}]")
                if signing:
                    parts.append(f"signing:{signing}")
                if domain_name:
                    parts.append(f"domain:{domain_name}")
                lines.append(" ".join(parts))
            lines.append("")

            # Write per-protocol target file: cme_<protocol>_targets.txt
            targets_file = os.path.join(outdir, f"cme_{proto}_targets.txt")
            target_lines = []
            for h in host_results:
                ip = h.ip if hasattr(h, 'ip') else h.get('ip', '')
                if ip:
                    target_lines.append(ip)
            if target_lines:
                self._write(targets_file, "\n".join(sorted(set(target_lines))) + "\n")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── cme_summary.json ── Structured JSON ───────────────────────
        filepath_json = os.path.join(outdir, "cme_summary.json")
        json_data = {
            "domain": domain,
            "stats": cme_stats,
            "protocols": {
                proto: r.to_dict() if hasattr(r, 'to_dict') else r
                for proto, r in cme_results.items()
            },
        }
        self._write(filepath_json, json.dumps(json_data, indent=2, ensure_ascii=False) + "\n")

    def _export_msf(self, outdir: str, result: ScanResult):
        """
        Export MSF SMB brute-force results.
        Creates credentials file and structured JSON summary.
        """
        msf_stats = getattr(result, 'msf_stats', {})
        msf_results = getattr(result, 'msf_results', {})
        if not getattr(result, 'msf_available', False) or not msf_results:
            return

        domain = result.target_domain

        # ── msf_smb_credentials.txt ── Human-readable credential list ─
        filepath = os.path.join(outdir, "msf_smb_credentials.txt")
        lines = [f"# ReconX - MSF SMB Brute-force Results for {domain}"]
        lines.append(f"# IPs tested: {msf_stats.get('ips_tested', 0)}/{msf_stats.get('total_ips', 0)}")
        lines.append(f"# IPs skipped: {msf_stats.get('ips_skipped', 0)}")
        lines.append(f"# Total users tested: {msf_stats.get('total_users_tested', 0)}")
        lines.append(f"# Credentials found: {msf_stats.get('credentials_found', 0)}")
        lines.append(f"# Scan time: {msf_stats.get('scan_time', 0.0):.1f}s")
        lines.append("")

        for ip in sorted(msf_results.keys()):
            host_result = msf_results[ip]
            creds = []
            if hasattr(host_result, 'credentials'):
                creds = host_result.credentials
            elif isinstance(host_result, dict):
                creds = host_result.get('credentials', [])

            skipped = host_result.skipped if hasattr(host_result, 'skipped') else host_result.get('skipped', False)
            skip_reason = host_result.skip_reason if hasattr(host_result, 'skip_reason') else host_result.get('skip_reason', '')
            users_tested = host_result.users_tested if hasattr(host_result, 'users_tested') else host_result.get('users_tested', 0)

            lines.append(f"── {ip} ──")
            lines.append(f"  Users tested: {users_tested}")
            if skipped:
                lines.append(f"  SKIPPED: {skip_reason}")

            if creds:
                for cred in creds:
                    user = cred.username if hasattr(cred, 'username') else cred.get('username', '')
                    pwd = cred.password if hasattr(cred, 'password') else cred.get('password', '')
                    cred_domain = cred.domain if hasattr(cred, 'domain') else cred.get('domain', '')
                    port = cred.port if hasattr(cred, 'port') else cred.get('port', 445)
                    domain_str = f"{cred_domain}\\" if cred_domain else ""
                    lines.append(f"  [+] {domain_str}{user}:{pwd} (port {port})")
            else:
                lines.append("  No valid credentials found")
            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── msf_smb_summary.json ── Structured JSON ──────────────────
        filepath_json = os.path.join(outdir, "msf_smb_summary.json")
        json_data = {
            "domain": domain,
            "stats": msf_stats,
            "hosts": {
                ip: r.to_dict() if hasattr(r, 'to_dict') else r
                for ip, r in msf_results.items()
            },
        }
        self._write(filepath_json, json.dumps(json_data, indent=2, ensure_ascii=False) + "\n")

    def _export_rdp(self, outdir: str, result: ScanResult):
        """
        Export RDP brute-force results.
        Creates credentials file and structured JSON summary.
        """
        rdp_stats = getattr(result, 'rdp_stats', {})
        rdp_results = getattr(result, 'rdp_results', {})
        if not getattr(result, 'rdp_available', False) or not rdp_results:
            return

        domain = result.target_domain

        # ── rdp_credentials.txt ── Human-readable credential list ─────
        filepath = os.path.join(outdir, "rdp_credentials.txt")
        lines = [f"# ReconX - RDP Brute-force Results for {domain}"]
        lines.append(f"# Hosts tested: {rdp_stats.get('hosts_tested', 0)}/{rdp_stats.get('total_rdp_hosts', 0)}")
        lines.append(f"# Hosts skipped: {rdp_stats.get('hosts_skipped', 0)}")
        lines.append(f"# Total users tested: {rdp_stats.get('total_users_tested', 0)}")
        lines.append(f"# Credentials found: {rdp_stats.get('credentials_found', 0)}")
        lines.append(f"# Pwn3d: {rdp_stats.get('pwned_count', 0)}")
        lines.append(f"# Scan time: {rdp_stats.get('scan_time', 0.0):.1f}s")
        lines.append("")

        for ip in sorted(rdp_results.keys()):
            host_result = rdp_results[ip]
            creds = []
            if hasattr(host_result, 'credentials'):
                creds = host_result.credentials
            elif isinstance(host_result, dict):
                creds = host_result.get('credentials', [])

            port = host_result.port if hasattr(host_result, 'port') else host_result.get('port', 3389)
            hostname = host_result.hostname if hasattr(host_result, 'hostname') else host_result.get('hostname', '')
            os_info = host_result.os_info if hasattr(host_result, 'os_info') else host_result.get('os_info', '')
            skipped = host_result.skipped if hasattr(host_result, 'skipped') else host_result.get('skipped', False)
            skip_reason = host_result.skip_reason if hasattr(host_result, 'skip_reason') else host_result.get('skip_reason', '')
            users_tested = host_result.users_tested if hasattr(host_result, 'users_tested') else host_result.get('users_tested', [])

            lines.append(f"── {ip}:{port} ──")
            if hostname:
                lines.append(f"  Hostname: {hostname}")
            if os_info:
                lines.append(f"  OS: {os_info}")
            lines.append(f"  Users tested: {', '.join(users_tested) if isinstance(users_tested, list) else users_tested}")
            if skipped:
                lines.append(f"  SKIPPED: {skip_reason}")

            if creds:
                for cred in creds:
                    user = cred.username if hasattr(cred, 'username') else cred.get('username', '')
                    pwd = cred.password if hasattr(cred, 'password') else cred.get('password', '')
                    cred_domain = cred.domain if hasattr(cred, 'domain') else cred.get('domain', '')
                    pwned = cred.pwned if hasattr(cred, 'pwned') else cred.get('pwned', False)
                    domain_str = f"{cred_domain}\\" if cred_domain else ""
                    pwn_str = " (Pwn3d!)" if pwned else ""
                    lines.append(f"  [+] {domain_str}{user}:{pwd}{pwn_str}")
            else:
                lines.append("  No valid credentials found")
            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── rdp_brute_summary.json ── Structured JSON ─────────────────
        filepath_json = os.path.join(outdir, "rdp_brute_summary.json")
        json_data = {
            "domain": domain,
            "stats": rdp_stats,
            "hosts": {
                ip: r.to_dict() if hasattr(r, 'to_dict') else r
                for ip, r in rdp_results.items()
            },
        }
        self._write(filepath_json, json.dumps(json_data, indent=2, ensure_ascii=False) + "\n")

    def _export_wpscan(self, outdir: str, result: ScanResult):
        """
        Export WPScan results.
        Creates human-readable summary and structured JSON.
        """
        wpscan_stats = getattr(result, 'wpscan_stats', {})
        wpscan_results = getattr(result, 'wpscan_results', {})
        if not getattr(result, 'wpscan_available', False) or not wpscan_results:
            return

        domain = result.target_domain

        # ── wpscan_summary.txt ── Human-readable summary ─────────────
        filepath = os.path.join(outdir, "wpscan_summary.txt")
        lines = [f"# ReconX - WPScan Results for {domain}"]
        lines.append(f"# Targets scanned: {wpscan_stats.get('targets_scanned', 0)}")
        lines.append(f"# Targets with vulns: {wpscan_stats.get('targets_with_vulns', 0)}")
        lines.append(f"# Total vulnerabilities: {wpscan_stats.get('total_vulns', 0)}")
        lines.append(f"# Total plugins: {wpscan_stats.get('total_plugins', 0)}")
        lines.append(f"# Total themes: {wpscan_stats.get('total_themes', 0)}")
        lines.append(f"# Total users: {wpscan_stats.get('total_users', 0)}")
        lines.append(f"# Outdated plugins: {wpscan_stats.get('outdated_plugins', 0)}")
        lines.append(f"# Config backups: {wpscan_stats.get('config_backups', 0)}")
        lines.append(f"# DB exports: {wpscan_stats.get('db_exports', 0)}")
        lines.append(f"# Scan time: {wpscan_stats.get('scan_time', 0.0):.1f}s")
        lines.append("")

        for url in sorted(wpscan_results.keys()):
            host_result = wpscan_results[url]
            wp_ver = host_result.wp_version if hasattr(host_result, 'wp_version') else host_result.get('wp_version', '')
            wp_status = host_result.wp_version_status if hasattr(host_result, 'wp_version_status') else host_result.get('wp_version_status', '')
            plugins = host_result.plugins if hasattr(host_result, 'plugins') else host_result.get('plugins', [])
            themes = host_result.themes if hasattr(host_result, 'themes') else host_result.get('themes', [])
            users = host_result.users if hasattr(host_result, 'users') else host_result.get('users', [])
            vulns = host_result.vulnerabilities if hasattr(host_result, 'vulnerabilities') else host_result.get('vulnerabilities', [])
            total_v = host_result.total_vulns if hasattr(host_result, 'total_vulns') else host_result.get('total_vulns', 0)

            lines.append(f"── {url} ──")
            if wp_ver:
                lines.append(f"  WordPress: {wp_ver} ({wp_status})")
            lines.append(f"  Plugins: {len(plugins)}  |  Themes: {len(themes)}  |  Users: {len(users)}")
            lines.append(f"  Vulnerabilities: {total_v}")

            if vulns:
                lines.append("  Core vulnerabilities:")
                for v in vulns:
                    title = v.title if hasattr(v, 'title') else v.get('title', '')
                    lines.append(f"    - {title}")

            for p in plugins:
                p_slug = p.slug if hasattr(p, 'slug') else p.get('slug', '')
                p_ver = p.version if hasattr(p, 'version') else p.get('version', '')
                p_outdated = p.outdated if hasattr(p, 'outdated') else p.get('outdated', False)
                p_vulns = p.vulnerabilities if hasattr(p, 'vulnerabilities') else p.get('vulnerabilities', [])
                outdated_str = " [OUTDATED]" if p_outdated else ""
                lines.append(f"  Plugin: {p_slug} {p_ver}{outdated_str}")
                for v in p_vulns:
                    title = v.title if hasattr(v, 'title') else v.get('title', '')
                    lines.append(f"    - {title}")

            for u in users:
                uname = u.username if hasattr(u, 'username') else u.get('username', '')
                lines.append(f"  User: {uname}")

            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── wpscan_summary.json ── Structured JSON ────────────────────
        filepath_json = os.path.join(outdir, "wpscan_summary.json")
        json_data = {
            "domain": domain,
            "stats": wpscan_stats,
            "targets": {
                url: r.to_dict() if hasattr(r, 'to_dict') else r
                for url, r in wpscan_results.items()
            },
        }
        self._write(filepath_json, json.dumps(json_data, indent=2, ensure_ascii=False) + "\n")