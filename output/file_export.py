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
        ├── nuclei_findings.txt      # All nuclei vulnerability findings
        ├── nuclei_critical.txt      # Critical severity findings only
        ├── nuclei_high.txt          # High severity findings only
        └── nuclei_summary.json      # Nuclei scan statistics
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
        """Export nuclei vulnerability scan results."""
        nuclei_results = getattr(result, 'nuclei_results', [])
        nuclei_stats = getattr(result, 'nuclei_stats', {})
        nuclei_available = getattr(result, 'nuclei_available', False)

        if not nuclei_available or not nuclei_results:
            return

        domain = result.target_domain

        # ── nuclei_findings.txt ── All findings ──────────────────────────
        filepath = os.path.join(outdir, "nuclei_findings.txt")
        lines = [f"# ReconX - Nuclei Vulnerability Findings for {domain}"]
        lines.append(f"# {len(nuclei_results)} total findings")
        tags_used = nuclei_stats.get("tags_used", [])
        if tags_used:
            lines.append(f"# Tags: {', '.join(tags_used)}")
        lines.append("")

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_results = sorted(
            nuclei_results,
            key=lambda r: (sev_order.get(r.severity, 5), r.template_id)
        )

        for r in sorted_results:
            host = r.host.replace("https://", "").replace("http://", "").rstrip("/")
            lines.append(f"[{r.severity.upper()}] {r.template_name}")
            lines.append(f"  Template: {r.template_id}")
            lines.append(f"  Host: {host}")
            if r.matched_at and r.matched_at != r.host:
                lines.append(f"  Matched: {r.matched_at}")
            if r.description:
                lines.append(f"  Description: {r.description[:200]}")
            if r.reference:
                for ref in r.reference[:3]:
                    lines.append(f"  Reference: {ref}")
            if r.matcher_name:
                lines.append(f"  Matcher: {r.matcher_name}")
            if r.extracted_results:
                for ext in r.extracted_results[:3]:
                    lines.append(f"  Extracted: {ext}")
            lines.append("")

        self._write(filepath, "\n".join(lines) + "\n")

        # ── nuclei_critical.txt ── Critical only ─────────────────────────
        critical = [r for r in nuclei_results if r.severity == "critical"]
        if critical:
            filepath = os.path.join(outdir, "nuclei_critical.txt")
            lines = [f"# ReconX - CRITICAL Nuclei Findings for {domain}"]
            lines.append(f"# {len(critical)} critical findings")
            lines.append("")
            for r in critical:
                host = r.host.replace("https://", "").replace("http://", "").rstrip("/")
                lines.append(f"[CRITICAL] {r.template_name}")
                lines.append(f"  Template: {r.template_id}")
                lines.append(f"  Host: {host}")
                if r.matched_at and r.matched_at != r.host:
                    lines.append(f"  Matched: {r.matched_at}")
                if r.description:
                    lines.append(f"  Description: {r.description[:300]}")
                if r.reference:
                    for ref in r.reference:
                        lines.append(f"  Reference: {ref}")
                if r.curl_command:
                    lines.append(f"  Curl: {r.curl_command}")
                lines.append("")
            self._write(filepath, "\n".join(lines) + "\n")

        # ── nuclei_high.txt ── High only ─────────────────────────────────
        high = [r for r in nuclei_results if r.severity == "high"]
        if high:
            filepath = os.path.join(outdir, "nuclei_high.txt")
            lines = [f"# ReconX - HIGH Nuclei Findings for {domain}"]
            lines.append(f"# {len(high)} high findings")
            lines.append("")
            for r in high:
                host = r.host.replace("https://", "").replace("http://", "").rstrip("/")
                lines.append(f"[HIGH] {r.template_name}")
                lines.append(f"  Template: {r.template_id}")
                lines.append(f"  Host: {host}")
                if r.matched_at and r.matched_at != r.host:
                    lines.append(f"  Matched: {r.matched_at}")
                if r.description:
                    lines.append(f"  Description: {r.description[:300]}")
                if r.reference:
                    for ref in r.reference[:5]:
                        lines.append(f"  Reference: {ref}")
                lines.append("")
            self._write(filepath, "\n".join(lines) + "\n")

        # ── nuclei_summary.json ── Stats JSON ────────────────────────────
        filepath = os.path.join(outdir, "nuclei_summary.json")
        summary = {
            "domain": domain,
            "total_findings": nuclei_stats.get("total_findings", 0),
            "severity": {
                "critical": nuclei_stats.get("critical", 0),
                "high": nuclei_stats.get("high", 0),
                "medium": nuclei_stats.get("medium", 0),
                "low": nuclei_stats.get("low", 0),
                "info": nuclei_stats.get("info", 0),
            },
            "hosts_scanned": nuclei_stats.get("hosts_scanned", 0),
            "templates_used": nuclei_stats.get("templates_used", 0),
            "tags_used": tags_used,
            "scan_time": nuclei_stats.get("scan_time", 0.0),
            "findings": [
                r.to_dict() if hasattr(r, 'to_dict') else r
                for r in sorted_results
            ],
        }
        self._write(filepath, json.dumps(summary, indent=2, ensure_ascii=False) + "\n")