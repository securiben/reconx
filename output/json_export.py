"""
JSON Export module for ReconX.
Saves scan results to structured JSON files.
"""

import json
import os
from datetime import datetime
from typing import Optional

from ..models import ScanResult
from ..utils import routed_path


class JSONExporter:
    """
    Exports ReconX scan results to JSON format.
    Produces a comprehensive, structured JSON file
    containing all scan data.
    """

    def __init__(self, pretty: bool = True):
        self.pretty = pretty

    def export(self, result: ScanResult, filename: str) -> str:
        """
        Export scan result to a JSON file.
        Returns the absolute path of the saved file.
        """
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

        # Route to json/ subfolder
        dirname = os.path.dirname(filename)
        basename = os.path.basename(filename)
        final_path = routed_path(dirname, basename) if dirname else filename

        # Write JSON
        with open(final_path, "w", encoding="utf-8") as f:
            if self.pretty:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            else:
                json.dump(data, f, ensure_ascii=False, default=str)

        return os.path.abspath(final_path)
