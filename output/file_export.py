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
    Files are auto-routed to txt/ and json/ subfolders.
    Empty results are skipped (no file created).

    Output structure:
        results/<domain>/
        ├── txt/
        │   ├── all_subdomains.txt
        │   ├── alive_subdomains.txt
        │   ├── ip_addresses.txt
        │   ├── ip_subdomain_map.txt
        │   ├── takeover_vulnerable.txt
        │   ├── dangling_cnames.txt
        │   ├── tech_detected.txt
        │   ├── flagged_interesting.txt
        │   ├── ct_aged.txt
        │   ├── ct_stale.txt
        │   ├── collapsed_patterns.txt
        │   ├── infrastructure.txt
        │   ├── sources_stats.txt
        │   ├── httpx_probe.txt
        │   ├── httpx_technologies.txt
        │   ├── httpx_cdn.txt
        │   ├── httpx_favicon.txt
        │   ├── httpx_servers.txt
        │   ├── httpx_titles.txt
        │   ├── httpx_redirects.txt
        │   ├── nmap_summary.txt
        │   └── ...
        └── json/
            ├── scan_summary.json
            ├── nuclei_summary.json
            ├── nmap_summary.json
            └── ...
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
        self._export_vnc(domain_dir, result)
        self._export_smb_brute(domain_dir, result)
        self._export_smbclient(domain_dir, result)
        self._export_chameleon(domain_dir, result)
        self._export_dirsearch(domain_dir, result)
        self._export_snmp_login(domain_dir, result)
        self._export_snmp_enum(domain_dir, result)
        self._export_ssh_login(domain_dir, result)
        self._export_mongodb_login(domain_dir, result)
        self._export_ftp_login(domain_dir, result)

        return os.path.abspath(domain_dir)

    def _write(self, filepath: str, content: str):
        """Write content to file, auto-routing to txt/ or json/ subfolder."""
        dirpath = os.path.dirname(filepath)
        filename = os.path.basename(filepath)
        ext = os.path.splitext(filename)[1].lower()
        if ext == '.json':
            subdir = os.path.join(dirpath, 'json')
        elif ext == '.txt':
            subdir = os.path.join(dirpath, 'txt')
        else:
            subdir = dirpath
        os.makedirs(subdir, exist_ok=True)
        final_path = os.path.join(subdir, filename)
        with open(final_path, "w", encoding="utf-8") as f:
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
        self._write(filepath, json.dumps(data, indent=2, ensure_ascii=False, default=str))

    def _export_all_subdomains(self, outdir: str, result: ScanResult):
        """Export all unique subdomains, one per line."""
        subs = sorted(set(s.hostname for s in result.subdomains))
        if not subs:
            return
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
        if not alive:
            return
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

        if not all_ips:
            return

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
        if not result.subdomains:
            return
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
        if not result.source_stats:
            return
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
        The raw nmap output file (nmap_scan.txt) is already
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

        # ── host-up.txt ── IPs that responded ─────────────────────────
        up_ips = sorted(nmap_results.keys())
        if up_ips:
            filepath_up = os.path.join(outdir, "host-up.txt")
            lines_up = [
                f"# ReconX — Hosts Up for {domain}",
                f"# Total: {len(up_ips)} host(s) up",
                "",
            ]
            lines_up.extend(up_ips)
            self._write(filepath_up, "\n".join(lines_up) + "\n")

        # ── host-down.txt ── IPs that did not respond ─────────────────
        scanned_ips = set(getattr(result, 'nmap_scanned_ips', []))
        down_ips = sorted(scanned_ips - set(nmap_results.keys()))
        if down_ips:
            filepath_down = os.path.join(outdir, "host-down.txt")
            lines_down = [
                f"# ReconX — Hosts Down for {domain}",
                f"# Total: {len(down_ips)} host(s) down",
                "",
            ]
            lines_down.extend(down_ips)
            self._write(filepath_down, "\n".join(lines_down) + "\n")

    def _export_enum4linux(self, outdir: str, result: ScanResult):
        """
        Export enum4linux scan results.
        Creates a human-readable summary and a structured JSON file.
        Raw per-host output files are already written by the scanner.
        Only exports when at least one host responded successfully.
        """
        enum_stats = getattr(result, 'enum4linux_stats', {})
        enum_results = getattr(result, 'enum4linux_results', {})
        if not getattr(result, 'enum4linux_available', False) or not enum_results:
            return

        # Only save if at least one host responded
        has_success = any(
            (h.success if hasattr(h, 'success') else h.get('success', False))
            for h in enum_results.values()
        )
        if not has_success:
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
        Only writes files when there are actual discovered hosts.
        """
        cme_stats = getattr(result, 'cme_stats', {})
        cme_results = getattr(result, 'cme_results', {})
        if not getattr(result, 'cme_available', False) or not cme_results:
            return

        # Check if any protocol actually has host results
        has_any_hosts = False
        for proto, proto_result in cme_results.items():
            host_results = []
            if hasattr(proto_result, 'host_results'):
                host_results = proto_result.host_results
            elif isinstance(proto_result, dict):
                host_results = proto_result.get('host_results', [])
            if host_results:
                has_any_hosts = True
                break

        if not has_any_hosts:
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

    def _export_vnc(self, outdir: str, result: ScanResult):
        """
        Export VNC brute-force results.
        Creates credentials file, no-auth list, and structured JSON summary.
        Only exports when valid credentials are found.
        """
        vnc_stats = getattr(result, 'vnc_stats', {})
        vnc_results = getattr(result, 'vnc_results', {})
        if not getattr(result, 'vnc_available', False) or not vnc_results:
            return

        # Only save if credentials were found
        if vnc_stats.get('credentials_found', 0) == 0:
            return

        domain = result.target_domain

        # ── vnc_credentials.txt ── Human-readable credential list ─────
        filepath = os.path.join(outdir, "vnc_credentials.txt")
        lines = [f"# ReconX - VNC Brute-force Results for {domain}"]
        lines.append(f"# Hosts tested: {vnc_stats.get('hosts_tested', 0)}/{vnc_stats.get('total_vnc_hosts', 0)}")
        lines.append(f"# Hosts skipped: {vnc_stats.get('hosts_skipped', 0)}")
        lines.append(f"# Hosts no-auth: {vnc_stats.get('hosts_no_auth', 0)}")
        lines.append(f"# Credentials found: {vnc_stats.get('credentials_found', 0)}")
        lines.append(f"# Scan time: {vnc_stats.get('scan_time', 0.0):.1f}s")
        lines.append("")

        for key in sorted(vnc_results.keys()):
            host_result = vnc_results[key]
            creds = []
            if hasattr(host_result, 'credentials'):
                creds = host_result.credentials
            elif isinstance(host_result, dict):
                creds = host_result.get('credentials', [])

            host_ip = host_result.ip if hasattr(host_result, 'ip') else host_result.get('ip', key)
            port = host_result.port if hasattr(host_result, 'port') else host_result.get('port', 5900)
            no_auth = host_result.no_auth if hasattr(host_result, 'no_auth') else host_result.get('no_auth', False)
            skipped = host_result.skipped if hasattr(host_result, 'skipped') else host_result.get('skipped', False)
            skip_reason = host_result.skip_reason if hasattr(host_result, 'skip_reason') else host_result.get('skip_reason', '')

            lines.append(f"── {host_ip}:{port} ──")
            if no_auth:
                lines.append("  [!] NO AUTHENTICATION REQUIRED")
            if skipped:
                lines.append(f"  SKIPPED: {skip_reason}")

            if creds:
                for cred in creds:
                    pwd = cred.password if hasattr(cred, 'password') else cred.get('password', '')
                    anon = cred.anonymous if hasattr(cred, 'anonymous') else cred.get('anonymous', False)
                    if anon:
                        lines.append(f"  [!] NO AUTH (anonymous access)")
                    else:
                        lines.append(f"  [+] :{pwd}")
            else:
                lines.append("  No valid credentials found")
            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── vnc_no_auth.txt ── Hosts with no authentication ──────────
        no_auth_hosts = []
        for key in sorted(vnc_results.keys()):
            host_result = vnc_results[key]
            na = host_result.no_auth if hasattr(host_result, 'no_auth') else host_result.get('no_auth', False)
            host_ip = host_result.ip if hasattr(host_result, 'ip') else host_result.get('ip', key)
            port = host_result.port if hasattr(host_result, 'port') else host_result.get('port', 5900)
            if na:
                no_auth_hosts.append(f"{host_ip}:{port}")

        if no_auth_hosts:
            na_filepath = os.path.join(outdir, "vnc_no_auth.txt")
            na_lines = [f"# ReconX - VNC Hosts with No Authentication for {domain}"]
            na_lines.append(f"# Total: {len(no_auth_hosts)} host(s)")
            na_lines.append("")
            na_lines.extend(no_auth_hosts)
            self._write(na_filepath, "\n".join(na_lines) + "\n")

        # ── vnc_brute_summary.json ── Structured JSON ─────────────────
        filepath_json = os.path.join(outdir, "vnc_brute_summary.json")
        json_data = {
            "domain": domain,
            "stats": vnc_stats,
            "hosts": {
                ip: r.to_dict() if hasattr(r, 'to_dict') else r
                for ip, r in vnc_results.items()
            },
        }
        self._write(filepath_json, json.dumps(json_data, indent=2, ensure_ascii=False) + "\n")

    def _export_smb_brute(self, outdir: str, result: ScanResult):
        """
        Export SMB brute-force results (nxc).
        Creates credentials file, SAM hashes file, and structured JSON summary.
        Only exports when valid credentials are found.
        """
        smb_stats = getattr(result, 'smb_brute_stats', {})
        smb_results = getattr(result, 'smb_brute_results', {})
        if not getattr(result, 'smb_brute_available', False) or not smb_results:
            return

        # Only save if credentials were found
        if smb_stats.get('credentials_found', 0) == 0:
            return

        domain = result.target_domain

        # ── smb_brute_credentials.txt ── Human-readable credential list ───
        filepath = os.path.join(outdir, "smb_brute_credentials.txt")
        lines = [f"# ReconX - SMB Brute-force Results for {domain}"]
        lines.append(f"# Hosts tested: {smb_stats.get('hosts_tested', 0)}/{smb_stats.get('total_smb_hosts', 0)}")
        lines.append(f"# Hosts skipped: {smb_stats.get('hosts_skipped', 0)}")
        lines.append(f"# Null auth hosts: {smb_stats.get('null_auth_hosts', 0)}")
        lines.append(f"# Credentials found: {smb_stats.get('credentials_found', 0)}")
        lines.append(f"# Pwn3d hosts: {smb_stats.get('pwned_count', 0)}")
        lines.append(f"# SAM hashes dumped: {smb_stats.get('sam_hashes_dumped', 0)}")
        lines.append(f"# Scan time: {smb_stats.get('scan_time', 0.0):.1f}s")
        lines.append("")

        for ip in sorted(smb_results.keys()):
            host_result = smb_results[ip]
            creds = []
            if hasattr(host_result, 'credentials'):
                creds = host_result.credentials
            elif isinstance(host_result, dict):
                creds = host_result.get('credentials', [])

            port = host_result.port if hasattr(host_result, 'port') else host_result.get('port', 445)
            null_auth = host_result.null_auth if hasattr(host_result, 'null_auth') else host_result.get('null_auth', False)
            hostname = host_result.hostname if hasattr(host_result, 'hostname') else host_result.get('hostname', '')
            os_info = host_result.os_info if hasattr(host_result, 'os_info') else host_result.get('os_info', '')
            skipped = host_result.skipped if hasattr(host_result, 'skipped') else host_result.get('skipped', False)
            skip_reason = host_result.skip_reason if hasattr(host_result, 'skip_reason') else host_result.get('skip_reason', '')

            lines.append(f"── {ip}:{port} ──")
            if hostname:
                lines.append(f"  Hostname: {hostname}")
            if os_info:
                lines.append(f"  OS: {os_info}")
            if null_auth:
                lines.append("  [!] ANONYMOUS/NULL ACCESS ALLOWED")
            if skipped:
                lines.append(f"  SKIPPED: {skip_reason}")

            if creds:
                for cred in creds:
                    username = cred.username if hasattr(cred, 'username') else cred.get('username', '')
                    password = cred.password if hasattr(cred, 'password') else cred.get('password', '')
                    cred_domain = cred.domain if hasattr(cred, 'domain') else cred.get('domain', '')
                    pwned = cred.pwned if hasattr(cred, 'pwned') else cred.get('pwned', False)
                    anonymous = cred.anonymous if hasattr(cred, 'anonymous') else cred.get('anonymous', False)
                    domain_str = f"{cred_domain}\\" if cred_domain else ""
                    pwn_tag = " (Pwn3d!)" if pwned else ""
                    anon_tag = " (anonymous)" if anonymous else ""
                    lines.append(f"  [+] {domain_str}{username}:{password}{pwn_tag}{anon_tag}")
            else:
                lines.append("  No valid credentials found")

            # Shares
            shares = []
            if hasattr(host_result, 'shares'):
                shares = host_result.shares
            elif isinstance(host_result, dict):
                shares = host_result.get('shares', [])
            if shares:
                lines.append("  Shares:")
                for share in shares:
                    name = share.name if hasattr(share, 'name') else share.get('name', '')
                    access = share.access if hasattr(share, 'access') else share.get('access', '')
                    comment = share.comment if hasattr(share, 'comment') else share.get('comment', '')
                    comment_str = f" ({comment})" if comment else ""
                    lines.append(f"    {name} [{access}]{comment_str}")

            # SAM hashes
            sam_hashes = []
            if hasattr(host_result, 'sam_hashes'):
                sam_hashes = host_result.sam_hashes
            elif isinstance(host_result, dict):
                sam_hashes = host_result.get('sam_hashes', [])
            if sam_hashes:
                lines.append("  SAM Hashes:")
                for h in sam_hashes:
                    username = h.username if hasattr(h, 'username') else h.get('username', '')
                    rid = h.rid if hasattr(h, 'rid') else h.get('rid', '')
                    lm_hash = h.lm_hash if hasattr(h, 'lm_hash') else h.get('lm_hash', '')
                    nt_hash = h.nt_hash if hasattr(h, 'nt_hash') else h.get('nt_hash', '')
                    lines.append(f"    {username}:{rid}:{lm_hash}:{nt_hash}:::")

            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── smb_brute_sam_hashes.txt ── All SAM hashes (hashcat/john format) ─
        all_hashes = []
        for ip in sorted(smb_results.keys()):
            host_result = smb_results[ip]
            sam_hashes = []
            if hasattr(host_result, 'sam_hashes'):
                sam_hashes = host_result.sam_hashes
            elif isinstance(host_result, dict):
                sam_hashes = host_result.get('sam_hashes', [])
            for h in sam_hashes:
                username = h.username if hasattr(h, 'username') else h.get('username', '')
                rid = h.rid if hasattr(h, 'rid') else h.get('rid', '')
                lm_hash = h.lm_hash if hasattr(h, 'lm_hash') else h.get('lm_hash', '')
                nt_hash = h.nt_hash if hasattr(h, 'nt_hash') else h.get('nt_hash', '')
                all_hashes.append(f"{username}:{rid}:{lm_hash}:{nt_hash}:::")

        if all_hashes:
            hash_filepath = os.path.join(outdir, "smb_brute_sam_hashes.txt")
            hash_lines = [f"# ReconX - SAM Hashes dumped via SMB Brute-force for {domain}"]
            hash_lines.append(f"# Total: {len(all_hashes)} hash(es)")
            hash_lines.append(f"# Format: username:rid:lm_hash:nt_hash:::")
            hash_lines.append(f"# Crack with: hashcat -m 1000 smb_brute_sam_hashes.txt wordlist.txt")
            hash_lines.append("")
            hash_lines.extend(all_hashes)
            self._write(hash_filepath, "\n".join(hash_lines) + "\n")

        # ── smb_brute_summary.json ── Structured JSON ─────────────────
        filepath_json = os.path.join(outdir, "smb_brute_summary.json")
        json_data = {
            "domain": domain,
            "stats": smb_stats,
            "hosts": {
                ip: r.to_dict() if hasattr(r, 'to_dict') else r
                for ip, r in smb_results.items()
            },
        }
        self._write(filepath_json, json.dumps(json_data, indent=2, ensure_ascii=False) + "\n")

    def _export_rdp(self, outdir: str, result: ScanResult):
        """
        Export RDP brute-force results.
        Creates credentials file and structured JSON summary.
        Only exports when valid credentials are found.
        """
        rdp_stats = getattr(result, 'rdp_stats', {})
        rdp_results = getattr(result, 'rdp_results', {})
        if not getattr(result, 'rdp_available', False) or not rdp_results:
            return

        # Only save if credentials were found
        if rdp_stats.get('credentials_found', 0) == 0:
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

    def _export_smbclient(self, outdir: str, result: ScanResult):
        """
        Export SMBClient null session results.
        Creates human-readable summary and structured JSON.
        Only exports when null sessions are found.
        """
        smb_stats = getattr(result, 'smbclient_stats', {})
        smb_results = getattr(result, 'smbclient_results', {})
        if not getattr(result, 'smbclient_available', False) or not smb_results:
            return

        # Only save if null sessions were found
        if smb_stats.get('hosts_with_null_session', 0) == 0:
            return

        domain = result.target_domain

        # ── smbclient_nullsession.txt ── Human-readable summary ───────
        filepath = os.path.join(outdir, "smbclient_nullsession.txt")
        lines = [f"# ReconX - SMBClient Null Session Results for {domain}"]
        lines.append(f"# Hosts scanned: {smb_stats.get('total_hosts_scanned', 0)}")
        lines.append(f"# Hosts with null session: {smb_stats.get('hosts_with_null_session', 0)}")
        lines.append(f"# Total shares: {smb_stats.get('total_shares', 0)}")
        lines.append(f"# Accessible shares: {smb_stats.get('accessible_shares', 0)}")
        lines.append(f"# Total files listed: {smb_stats.get('total_files_listed', 0)}")
        lines.append(f"# Hosts with accessible shares: {smb_stats.get('hosts_with_accessible_shares', 0)}")
        lines.append(f"# Scan time: {smb_stats.get('scan_time', 0.0):.1f}s")
        lines.append("")

        for ip in sorted(smb_results.keys()):
            host_result = smb_results[ip]
            null_session = host_result.null_session if hasattr(host_result, 'null_session') else host_result.get('null_session', False)
            shares = host_result.shares if hasattr(host_result, 'shares') else host_result.get('shares', [])
            workgroup = host_result.workgroup if hasattr(host_result, 'workgroup') else host_result.get('workgroup', '')
            error = host_result.error if hasattr(host_result, 'error') else host_result.get('error', '')
            acc_shares = host_result.accessible_shares if hasattr(host_result, 'accessible_shares') else host_result.get('accessible_shares', 0)
            total_files = host_result.total_files_listed if hasattr(host_result, 'total_files_listed') else host_result.get('total_files_listed', 0)

            null_str = "NULL SESSION" if null_session else "no null session"
            lines.append(f"── {ip} ({null_str}) ──")
            if workgroup:
                lines.append(f"  Workgroup: {workgroup}")
            if error and not null_session:
                lines.append(f"  Error: {error}")

            if shares:
                lines.append(f"  Shares ({len(shares)}):")
                lines.append(f"  {'Sharename':<40s} {'Type':<10s} Comment")
                lines.append(f"  {'-' * 40} {'-' * 10} {'-' * 30}")
                for share in shares:
                    s_name = share.name if hasattr(share, 'name') else share.get('name', '')
                    s_type = share.share_type if hasattr(share, 'share_type') else share.get('type', '')
                    s_comment = share.comment if hasattr(share, 'comment') else share.get('comment', '')
                    s_accessible = share.accessible if hasattr(share, 'accessible') else share.get('accessible', False)
                    s_files = share.files if hasattr(share, 'files') else share.get('files', [])

                    acc_marker = " [ACCESSIBLE]" if s_accessible else ""
                    lines.append(f"  {s_name:<40s} {s_type:<10s} {s_comment}{acc_marker}")

                    if s_accessible and s_files:
                        lines.append(f"    Files ({len(s_files)}):")
                        for f_entry in s_files[:50]:
                            lines.append(f"      {f_entry}")
                        if len(s_files) > 50:
                            lines.append(f"      ... and {len(s_files) - 50} more")

            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── smbclient_nullsession.json ── Structured JSON ────────────
        filepath_json = os.path.join(outdir, "smbclient_nullsession.json")
        json_data = {
            "domain": domain,
            "stats": smb_stats,
            "hosts": {
                ip: r.to_dict() if hasattr(r, 'to_dict') else r
                for ip, r in smb_results.items()
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

    def _export_katana(self, outdir: str, result: ScanResult):
        """
        Export katana web crawl results.
        The katana_urls.txt is already written by the scanner directly.
        This exports a structured summary.
        """
        katana_stats = getattr(result, 'katana_stats', {})
        katana_results = getattr(result, 'katana_results', [])
        if not getattr(result, 'katana_available', False) or not katana_results:
            return

        domain = result.target_domain

        # ── katana_summary.txt ── Human-readable summary ─────────────
        filepath = os.path.join(outdir, "katana_summary.txt")
        lines = [f"# ReconX - Katana Web Crawl for {domain}"]
        lines.append(f"# Total URLs: {katana_stats.get('total_urls', 0)}")
        lines.append(f"# Unique endpoints: {katana_stats.get('unique_endpoints', 0)}")
        lines.append(f"# Targets crawled: {katana_stats.get('targets_crawled', 0)}")
        lines.append(f"# JS files: {katana_stats.get('js_files', 0)}")
        lines.append(f"# API endpoints: {katana_stats.get('api_endpoints', 0)}")
        lines.append(f"# Scan time: {katana_stats.get('scan_time', 0.0):.1f}s")
        lines.append("")

        # Extensions breakdown
        extensions = katana_stats.get('extensions', {})
        if extensions:
            lines.append("── Extensions ──")
            for ext, count in sorted(extensions.items(), key=lambda x: -x[1]):
                lines.append(f"  .{ext}: {count}")
            lines.append("")

        # All URLs
        lines.append(f"── All URLs ({len(katana_results)}) ──")
        for url in katana_results:
            lines.append(f"  {url}")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── katana_summary.json ── Structured JSON ────────────────────
        filepath_json = os.path.join(outdir, "katana_summary.json")
        json_data = {
            "domain": domain,
            "stats": katana_stats,
            "total_urls": len(katana_results),
            "urls": katana_results,
        }
        self._write(filepath_json, json.dumps(json_data, indent=2, ensure_ascii=False) + "\n")

    def _export_chameleon(self, outdir: str, result: ScanResult):
        """Export chameleon web content discovery results."""
        chameleon_stats = getattr(result, 'chameleon_stats', {})
        chameleon_results = getattr(result, 'chameleon_results', [])
        if not getattr(result, 'chameleon_available', False) or not chameleon_results:
            return

        domain = result.target_domain

        # ── chameleon_summary.txt ─────────────────────────────────────
        filepath = os.path.join(outdir, "chameleon_summary.txt")
        lines = [f"# ReconX - Chameleon Content Discovery for {domain}"]
        lines.append(f"# Total findings: {chameleon_stats.get('total_findings', 0)}")
        lines.append(f"# Targets scanned: {chameleon_stats.get('targets_scanned', 0)}")
        lines.append(f"# Scan time: {chameleon_stats.get('scan_time', 0.0):.1f}s")
        lines.append("")
        lines.append(f"── Results ({len(chameleon_results)}) ──")
        for r in chameleon_results:
            lines.append(f"  {r}")
        self._write(filepath, "\n".join(lines) + "\n")

        # ── chameleon_summary.json ────────────────────────────────────
        filepath_json = os.path.join(outdir, "chameleon_summary.json")
        json_data = {
            "domain": domain,
            "stats": chameleon_stats,
            "total_findings": len(chameleon_results),
            "results": chameleon_results,
        }
        self._write(filepath_json, json.dumps(json_data, indent=2, ensure_ascii=False) + "\n")

    def _export_dirsearch(self, outdir: str, result: ScanResult):
        """Export dirsearch directory brute-force results."""
        dirsearch_stats = getattr(result, 'dirsearch_stats', {})
        dirsearch_results = getattr(result, 'dirsearch_results', [])
        if not getattr(result, 'dirsearch_available', False) or not dirsearch_results:
            return

        domain = result.target_domain

        # ── dirsearch_summary.txt ─────────────────────────────────────
        filepath = os.path.join(outdir, "dirsearch_summary.txt")
        lines = [f"# ReconX - Dirsearch Directory Discovery for {domain}"]
        lines.append(f"# Total findings: {dirsearch_stats.get('total_findings', 0)}")
        lines.append(f"# Targets scanned: {dirsearch_stats.get('targets_scanned', 0)}")
        lines.append(f"# Scan time: {dirsearch_stats.get('scan_time', 0.0):.1f}s")
        lines.append("")
        lines.append(f"── Results ({len(dirsearch_results)}) ──")
        for r in dirsearch_results:
            lines.append(f"  {r}")
        self._write(filepath, "\n".join(lines) + "\n")

        # ── dirsearch_summary.json ────────────────────────────────────
        filepath_json = os.path.join(outdir, "dirsearch_summary.json")
        json_data = {
            "domain": domain,
            "stats": dirsearch_stats,
            "total_findings": len(dirsearch_results),
            "results": dirsearch_results,
        }
        self._write(filepath_json, json.dumps(json_data, indent=2, ensure_ascii=False) + "\n")

    def _export_snmp_login(self, outdir: str, result: ScanResult):
        """
        Export SNMP login brute-force results.
        Creates community strings file and structured JSON summary.
        Only exports when valid community strings are found.
        """
        snmp_login_stats = getattr(result, 'snmp_login_stats', {})
        snmp_login_results = getattr(result, 'snmp_login_results', {})
        if not getattr(result, 'snmp_login_available', False) or not snmp_login_results:
            return

        # Only save if community strings were found
        if snmp_login_stats.get('credentials_found', 0) == 0:
            return

        domain = result.target_domain

        # ── snmp_communities.txt ── Human-readable community list ─────
        filepath = os.path.join(outdir, "snmp_communities.txt")
        lines = [f"# ReconX - SNMP Login Results for {domain}"]
        lines.append(f"# Hosts tested: {snmp_login_stats.get('hosts_tested', 0)}/{snmp_login_stats.get('total_snmp_hosts', 0)}")
        lines.append(f"# Hosts skipped: {snmp_login_stats.get('hosts_skipped', 0)}")
        lines.append(f"# Community strings found: {snmp_login_stats.get('credentials_found', 0)}")
        lines.append(f"# Read-write found: {snmp_login_stats.get('read_write_found', 0)}")
        lines.append(f"# Scan time: {snmp_login_stats.get('scan_time', 0.0):.1f}s")
        lines.append("")

        for key in sorted(snmp_login_results.keys()):
            host_result = snmp_login_results[key]
            creds = []
            if hasattr(host_result, 'credentials'):
                creds = host_result.credentials
            elif isinstance(host_result, dict):
                creds = host_result.get('credentials', [])

            host_ip = host_result.ip if hasattr(host_result, 'ip') else host_result.get('ip', key)
            port = host_result.port if hasattr(host_result, 'port') else host_result.get('port', 161)
            skipped = host_result.skipped if hasattr(host_result, 'skipped') else host_result.get('skipped', False)
            skip_reason = host_result.skip_reason if hasattr(host_result, 'skip_reason') else host_result.get('skip_reason', '')

            lines.append(f"── {host_ip}:{port} ──")
            if skipped:
                lines.append(f"  SKIPPED: {skip_reason}")

            if creds:
                for cred in creds:
                    community = cred.community if hasattr(cred, 'community') else cred.get('community', '')
                    access = cred.access_level if hasattr(cred, 'access_level') else cred.get('access_level', '')
                    proof = cred.proof if hasattr(cred, 'proof') else cred.get('proof', '')
                    proof_str = f" — {proof}" if proof else ""
                    lines.append(f"  [+] {community} ({access}){proof_str}")
            else:
                lines.append("  No valid community strings found")
            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── snmp_read_write.txt ── Hosts with read-write access ───────
        rw_hosts = []
        for key in sorted(snmp_login_results.keys()):
            host_result = snmp_login_results[key]
            creds = host_result.credentials if hasattr(host_result, 'credentials') else host_result.get('credentials', [])
            host_ip = host_result.ip if hasattr(host_result, 'ip') else host_result.get('ip', key)
            port = host_result.port if hasattr(host_result, 'port') else host_result.get('port', 161)
            for cred in creds:
                access = cred.access_level if hasattr(cred, 'access_level') else cred.get('access_level', '')
                community = cred.community if hasattr(cred, 'community') else cred.get('community', '')
                if "write" in access.lower():
                    rw_hosts.append(f"{host_ip}:{port} → {community}")

        if rw_hosts:
            rw_filepath = os.path.join(outdir, "snmp_read_write.txt")
            rw_lines = [f"# ReconX - SNMP Hosts with Read-Write Community Strings for {domain}"]
            rw_lines.append(f"# Total: {len(rw_hosts)} host(s)")
            rw_lines.append("")
            rw_lines.extend(rw_hosts)
            self._write(rw_filepath, "\n".join(rw_lines) + "\n")

        # ── snmp_login_summary.json ── Structured JSON ────────────────
        filepath_json = os.path.join(outdir, "snmp_login_summary.json")
        json_data = {
            "domain": domain,
            "stats": snmp_login_stats,
            "hosts": {
                ip: r.to_dict() if hasattr(r, 'to_dict') else r
                for ip, r in snmp_login_results.items()
            },
        }
        self._write(filepath_json, json.dumps(json_data, indent=2, ensure_ascii=False) + "\n")

    def _export_snmp_enum(self, outdir: str, result: ScanResult):
        """
        Export SNMP enumeration results.
        Creates system info summary and structured JSON.
        """
        snmp_enum_stats = getattr(result, 'snmp_enum_stats', {})
        snmp_enum_results = getattr(result, 'snmp_enum_results', {})
        if not getattr(result, 'snmp_enum_available', False) or not snmp_enum_results:
            return

        domain = result.target_domain

        # ── snmp_enum_systems.txt ── Human-readable system info ───────
        filepath = os.path.join(outdir, "snmp_enum_systems.txt")
        lines = [f"# ReconX - SNMP Enumeration Results for {domain}"]
        lines.append(f"# Hosts enumerated: {snmp_enum_stats.get('hosts_enumerated', 0)}/{snmp_enum_stats.get('total_snmp_hosts', 0)}")
        lines.append(f"# Hosts with sysinfo: {snmp_enum_stats.get('hosts_with_sysinfo', 0)}")
        lines.append(f"# Hosts with netinfo: {snmp_enum_stats.get('hosts_with_netinfo', 0)}")
        lines.append(f"# Hosts with users: {snmp_enum_stats.get('hosts_with_users', 0)}")
        lines.append(f"# Scan time: {snmp_enum_stats.get('scan_time', 0.0):.1f}s")
        lines.append("")

        for key in sorted(snmp_enum_results.keys()):
            r = snmp_enum_results[key]
            host_ip = r.ip if hasattr(r, 'ip') else r.get('ip', key)
            port = r.port if hasattr(r, 'port') else r.get('port', 161)
            community = r.community if hasattr(r, 'community') else r.get('community', '')

            lines.append(f"── {host_ip}:{port} (community: {community}) ──")

            # System info
            si = r.system_info if hasattr(r, 'system_info') else r.get('system_info')
            if si:
                hostname = si.hostname if hasattr(si, 'hostname') else si.get('hostname', '')
                description = si.description if hasattr(si, 'description') else si.get('description', '')
                contact = si.contact if hasattr(si, 'contact') else si.get('contact', '')
                location = si.location if hasattr(si, 'location') else si.get('location', '')
                uptime = si.uptime_snmp if hasattr(si, 'uptime_snmp') else si.get('uptime_snmp', '')
                sysdate = si.system_date if hasattr(si, 'system_date') else si.get('system_date', '')

                if hostname:
                    lines.append(f"  Hostname    : {hostname}")
                if description:
                    lines.append(f"  Description : {description}")
                if contact:
                    lines.append(f"  Contact     : {contact}")
                if location:
                    lines.append(f"  Location    : {location}")
                if uptime:
                    lines.append(f"  Uptime SNMP : {uptime}")
                if sysdate:
                    lines.append(f"  System Date : {sysdate}")

            # Network info
            ni = r.network_info if hasattr(r, 'network_info') else r.get('network_info')
            if ni:
                ip_fwd = ni.ip_forwarding if hasattr(ni, 'ip_forwarding') else ni.get('ip_forwarding', '')
                if ip_fwd:
                    lines.append(f"  IP Fwd      : {ip_fwd}")

            # User accounts
            users = r.user_accounts if hasattr(r, 'user_accounts') else r.get('user_accounts', [])
            if users:
                lines.append(f"  Users ({len(users)}):")
                for u in users[:20]:
                    lines.append(f"    - {u}")
                if len(users) > 20:
                    lines.append(f"    ... and {len(users) - 20} more")

            # Processes count
            procs = r.processes if hasattr(r, 'processes') else r.get('processes', [])
            if procs:
                lines.append(f"  Processes   : {len(procs)}")

            # Software
            sw = r.software if hasattr(r, 'software') else r.get('software', [])
            if sw:
                lines.append(f"  Software ({len(sw)}):")
                for s in sw[:10]:
                    lines.append(f"    - {s}")
                if len(sw) > 10:
                    lines.append(f"    ... and {len(sw) - 10} more")

            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── snmp_enum_summary.json ── Structured JSON ─────────────────
        filepath_json = os.path.join(outdir, "snmp_enum_summary.json")
        json_data = {
            "domain": domain,
            "stats": snmp_enum_stats,
            "hosts": {
                ip: r.to_dict() if hasattr(r, 'to_dict') else r
                for ip, r in snmp_enum_results.items()
            },
        }
        self._write(filepath_json, json.dumps(json_data, indent=2, ensure_ascii=False) + "\n")

    def _export_ssh_login(self, outdir: str, result: ScanResult):
        """Export SSH login brute-force results. Only exports when valid credentials are found."""
        ssh_login_stats = getattr(result, 'ssh_login_stats', {})
        ssh_login_results = getattr(result, 'ssh_login_results', {})
        if not getattr(result, 'ssh_login_available', False) or not ssh_login_results:
            return

        # Only save if credentials were found
        if ssh_login_stats.get('credentials_found', 0) == 0:
            return

        domain = result.target_domain

        # ── ssh_login.txt ── Human-readable report ────────────────────
        filepath = os.path.join(outdir, "ssh_login.txt")
        lines = [
            f"# SSH Login Brute-Force — {domain}",
            f"# Hosts tested: {ssh_login_stats.get('hosts_tested', 0)}/{ssh_login_stats.get('total_ssh_hosts', 0)}",
            f"# Hosts skipped: {ssh_login_stats.get('hosts_skipped', 0)}",
            f"# Credentials found: {ssh_login_stats.get('credentials_found', 0)}",
            f"# Scan time: {ssh_login_stats.get('scan_time', 0.0):.1f}s",
            "",
        ]

        # Valid credentials section
        all_creds = []
        for key in sorted(ssh_login_results.keys()):
            host_result = ssh_login_results[key]
            creds = host_result.credentials if hasattr(host_result, 'credentials') else host_result.get('credentials', [])
            for cred in creds:
                if hasattr(cred, 'to_dict'):
                    all_creds.append(cred.to_dict())
                elif isinstance(cred, dict):
                    all_creds.append(cred)

        if all_creds:
            lines.append("## Valid Credentials")
            lines.append("")
            for cred in all_creds:
                ip = cred.get('ip', '?')
                port = cred.get('port', 22)
                user = cred.get('username', '?')
                passwd = cred.get('password', '?')
                lines.append(f"  {ip}:{port} → {user}:{passwd}")
            lines.append("")

        # Per-host summary
        lines.append("## Per-Host Summary")
        lines.append("")
        for key in sorted(ssh_login_results.keys()):
            host_result = ssh_login_results[key]
            ip = host_result.ip if hasattr(host_result, 'ip') else host_result.get('ip', key)
            port = host_result.port if hasattr(host_result, 'port') else host_result.get('port', 22)
            skipped = host_result.skipped if hasattr(host_result, 'skipped') else host_result.get('skipped', False)
            skip_reason = host_result.skip_reason if hasattr(host_result, 'skip_reason') else host_result.get('skip_reason', '')
            creds = host_result.credentials if hasattr(host_result, 'credentials') else host_result.get('credentials', [])
            scan_time = host_result.scan_time if hasattr(host_result, 'scan_time') else host_result.get('scan_time', 0)

            status = "SKIPPED" if skipped else f"{len(creds)} credential(s)"
            lines.append(f"  [{ip}:{port}] {status}")
            if skipped and skip_reason:
                lines.append(f"    Reason: {skip_reason}")
            for cred in creds:
                if hasattr(cred, 'username'):
                    lines.append(f"    → {cred.username}:{cred.password}")
                elif isinstance(cred, dict):
                    lines.append(f"    → {cred.get('username', '?')}:{cred.get('password', '?')}")
            lines.append(f"    Time: {scan_time:.1f}s")
            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

    def _export_mongodb_login(self, outdir: str, result: ScanResult):
        """Export MongoDB login/info/enum results."""
        mongo_stats = getattr(result, 'mongodb_login_stats', {})
        mongo_results = getattr(result, 'mongodb_login_results', {})
        if not getattr(result, 'mongodb_login_available', False) or not mongo_results:
            return

        domain = result.target_domain

        # ── mongodb_login.txt ── Human-readable report ────────────────
        filepath = os.path.join(outdir, "mongodb_login.txt")
        lines = [
            f"# MongoDB Login / Info / Enum — {domain}",
            f"# Hosts tested: {mongo_stats.get('hosts_tested', 0)}/{mongo_stats.get('total_mongodb_hosts', 0)}",
            f"# Hosts skipped: {mongo_stats.get('hosts_skipped', 0)}",
            f"# Credentials found: {mongo_stats.get('credentials_found', 0)}",
            f"# Hosts with info: {mongo_stats.get('hosts_with_info', 0)}",
            f"# Databases found: {mongo_stats.get('databases_found', 0)}",
            f"# Scan time: {mongo_stats.get('scan_time', 0.0):.1f}s",
            "",
        ]

        # Valid credentials section
        all_creds = []
        for key in sorted(mongo_results.keys()):
            host_result = mongo_results[key]
            creds = host_result.credentials if hasattr(host_result, 'credentials') else host_result.get('credentials', [])
            for cred in creds:
                if hasattr(cred, 'to_dict'):
                    all_creds.append(cred.to_dict())
                elif isinstance(cred, dict):
                    all_creds.append(cred)

        if all_creds:
            lines.append("## Valid Credentials")
            lines.append("")
            for cred in all_creds:
                ip = cred.get('ip', '?')
                port = cred.get('port', 27017)
                user = cred.get('username', '?')
                passwd = cred.get('password', '?')
                lines.append(f"  {ip}:{port} → {user}:{passwd}")
            lines.append("")

        # Per-host summary
        lines.append("## Per-Host Summary")
        lines.append("")
        for key in sorted(mongo_results.keys()):
            host_result = mongo_results[key]
            ip = host_result.ip if hasattr(host_result, 'ip') else host_result.get('ip', key)
            port = host_result.port if hasattr(host_result, 'port') else host_result.get('port', 27017)
            skipped = host_result.skipped if hasattr(host_result, 'skipped') else host_result.get('skipped', False)
            skip_reason = host_result.skip_reason if hasattr(host_result, 'skip_reason') else host_result.get('skip_reason', '')
            creds = host_result.credentials if hasattr(host_result, 'credentials') else host_result.get('credentials', [])
            scan_time = host_result.scan_time if hasattr(host_result, 'scan_time') else host_result.get('scan_time', 0)

            status = "SKIPPED" if skipped else f"{len(creds)} credential(s)"
            lines.append(f"  [{ip}:{port}] {status}")
            if skipped and skip_reason:
                lines.append(f"    Reason: {skip_reason}")
            for cred in creds:
                if hasattr(cred, 'username'):
                    lines.append(f"    → {cred.username}:{cred.password}")
                elif isinstance(cred, dict):
                    lines.append(f"    → {cred.get('username', '?')}:{cred.get('password', '?')}")

            # Server info
            server_info = host_result.server_info if hasattr(host_result, 'server_info') else host_result.get('server_info')
            if server_info:
                ver = server_info.version if hasattr(server_info, 'version') else server_info.get('version', '')
                os_name = server_info.os_name if hasattr(server_info, 'os_name') else server_info.get('os_name', '')
                if ver:
                    lines.append(f"    Version: {ver}")
                if os_name:
                    lines.append(f"    OS: {os_name}")

            # Enum info
            enum_info = host_result.enum_info if hasattr(host_result, 'enum_info') else host_result.get('enum_info')
            if enum_info:
                dbs = enum_info.databases if hasattr(enum_info, 'databases') else enum_info.get('databases', [])
                if dbs:
                    lines.append(f"    Databases: {', '.join(dbs)}")
                users = enum_info.users if hasattr(enum_info, 'users') else enum_info.get('users', [])
                if users:
                    lines.append(f"    Users: {', '.join(users)}")

            lines.append(f"    Time: {scan_time:.1f}s")
            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── mongodb_login_summary.json ── Structured JSON ─────────────
        filepath_json = os.path.join(outdir, "mongodb_login_summary.json")
        json_data = {
            "domain": domain,
            "stats": mongo_stats,
            "hosts": {
                key: r.to_dict() if hasattr(r, 'to_dict') else r
                for key, r in mongo_results.items()
            },
        }
        self._write(filepath_json, json.dumps(json_data, indent=2, ensure_ascii=False) + "\n")

    def _export_ftp_login(self, outdir: str, result: ScanResult):
        """Export FTP login brute-force results (anonymous + credentials). Only exports when valid credentials or anonymous access found."""
        ftp_stats = getattr(result, 'ftp_login_stats', {})
        ftp_results = getattr(result, 'ftp_login_results', {})
        if not getattr(result, 'ftp_login_available', False) or not ftp_results:
            return

        # Only save if credentials or anonymous access found
        if ftp_stats.get('credentials_found', 0) == 0 and ftp_stats.get('anonymous_hosts', 0) == 0:
            return

        domain = result.target_domain

        # ── ftp_login.txt ── Human-readable report ────────────────────
        filepath = os.path.join(outdir, "ftp_login.txt")
        lines = [
            f"# FTP Login Brute-Force — {domain}",
            f"# Hosts tested: {ftp_stats.get('hosts_tested', 0)}/{ftp_stats.get('total_ftp_hosts', 0)}",
            f"# Hosts skipped: {ftp_stats.get('hosts_skipped', 0)}",
            f"# Anonymous hosts: {ftp_stats.get('anonymous_hosts', 0)}",
            f"# Credentials found: {ftp_stats.get('credentials_found', 0)}",
            f"# Scan time: {ftp_stats.get('scan_time', 0.0):.1f}s",
            "",
        ]

        # Anonymous access section
        anon_hosts = []
        for key in sorted(ftp_results.keys()):
            host_result = ftp_results[key]
            anon = host_result.anonymous_access if hasattr(host_result, 'anonymous_access') else host_result.get('anonymous_access', False)
            if anon:
                ip = host_result.ip if hasattr(host_result, 'ip') else host_result.get('ip', key)
                port = host_result.port if hasattr(host_result, 'port') else host_result.get('port', 21)
                anon_hosts.append(f"  {ip}:{port}")

        if anon_hosts:
            lines.append("## Anonymous Access")
            lines.append("")
            for h in anon_hosts:
                lines.append(h)
            lines.append("")

        # Valid credentials section
        all_creds = []
        for key in sorted(ftp_results.keys()):
            host_result = ftp_results[key]
            creds = host_result.credentials if hasattr(host_result, 'credentials') else host_result.get('credentials', [])
            for cred in creds:
                if hasattr(cred, 'to_dict'):
                    all_creds.append(cred.to_dict())
                elif isinstance(cred, dict):
                    all_creds.append(cred)

        if all_creds:
            lines.append("## Valid Credentials")
            lines.append("")
            for cred in all_creds:
                ip = cred.get('ip', '?')
                port = cred.get('port', 21)
                user = cred.get('username', '?')
                passwd = cred.get('password', '?')
                anon_tag = " [ANONYMOUS]" if cred.get('anonymous', False) else ""
                lines.append(f"  {ip}:{port} → {user}:{passwd}{anon_tag}")
            lines.append("")

        # Per-host summary
        lines.append("## Per-Host Summary")
        lines.append("")
        for key in sorted(ftp_results.keys()):
            host_result = ftp_results[key]
            ip = host_result.ip if hasattr(host_result, 'ip') else host_result.get('ip', key)
            port = host_result.port if hasattr(host_result, 'port') else host_result.get('port', 21)
            skipped = host_result.skipped if hasattr(host_result, 'skipped') else host_result.get('skipped', False)
            skip_reason = host_result.skip_reason if hasattr(host_result, 'skip_reason') else host_result.get('skip_reason', '')
            creds = host_result.credentials if hasattr(host_result, 'credentials') else host_result.get('credentials', [])
            scan_time = host_result.scan_time if hasattr(host_result, 'scan_time') else host_result.get('scan_time', 0)
            anon = host_result.anonymous_access if hasattr(host_result, 'anonymous_access') else host_result.get('anonymous_access', False)

            status = "SKIPPED" if skipped else f"{len(creds)} credential(s)"
            anon_str = " [ANON]" if anon else ""
            lines.append(f"  [{ip}:{port}] {status}{anon_str}")
            if skipped and skip_reason:
                lines.append(f"    Reason: {skip_reason}")
            for cred in creds:
                if hasattr(cred, 'username'):
                    a = " [ANONYMOUS]" if getattr(cred, 'anonymous', False) else ""
                    lines.append(f"    → {cred.username}:{cred.password}{a}")
                elif isinstance(cred, dict):
                    a = " [ANONYMOUS]" if cred.get('anonymous', False) else ""
                    lines.append(f"    → {cred.get('username', '?')}:{cred.get('password', '?')}{a}")
            lines.append(f"    Time: {scan_time:.1f}s")
            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── ftp_login_summary.json ── Structured JSON ─────────────────
        filepath_json = os.path.join(outdir, "ftp_login_summary.json")
        json_data = {
            "domain": domain,
            "stats": ftp_stats,
            "hosts": {
                key: r.to_dict() if hasattr(r, 'to_dict') else r
                for key, r in ftp_results.items()
            },
        }
        self._write(filepath_json, json.dumps(json_data, indent=2, ensure_ascii=False) + "\n")