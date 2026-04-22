#!/usr/bin/env python3
"""
ReconX - Automated Reconnaissance & Intelligence Gathering Tool

Usage:
    python main.py <target> [options]

Examples:
    python main.py example.com              # Domain → full recon pipeline
    python main.py targets.txt              # File of targets (IPs/domains)
    python main.py 10.10.0.5                # Single IP → nmap + CME
    python main.py 10.10.0.0/24             # CIDR range → nmap + CME
    python main.py 'a.txt,"file 2.txt",c.txt'  # Multiple files (comma-separated)
    python main.py example.com --Pn         # Skip host discovery (ICMP dead)
    python main.py example.com --script=vuln  # Run nmap with --script=vuln
    python main.py example.com -o results.json
"""

import sys
import os
import argparse
import time
import platform

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconx.config import ReconConfig
from reconx.engine import ReconEngine
from reconx.utils import resolve_targets, parse_multi_files


# ─── Banner ───────────────────────────────────────────────────────────────────

BANNER_TOP = """\
{cyan}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   {bold_white}██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗{cyan}        ║
║   {bold_white}██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝{cyan}        ║
║   {bold_white}██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝{cyan}         ║
║   {bold_white}██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗{cyan}         ║
║   {bold_white}██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗{cyan}        ║
║   {bold_white}╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝{cyan}        ║
║                                                              ║
║   {dim}Automated Reconnaissance & Intelligence Gathering{cyan}          ║
║   {dim}v1.0.0 | Multi-Source Subdomain Enumeration Engine{cyan}         ║
║                                                              ║"""

BANNER_BOTTOM = """\
{cyan}╚══════════════════════════════════════════════════════════════╝{reset}
"""

# Inner width between the two ║ chars (count the spaces in the banner → 62)
_BOX_W = 62


def _fetch_ipinfo() -> dict:
    """Fetch network identity from ipinfo.io. Returns empty dict on failure."""
    try:
        import requests
        resp = requests.get("https://ipinfo.io/json", timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return {}


def _ipinfo_rows(data: dict) -> list:
    """Build coloured row strings for each ipinfo field."""
    white = "\033[1;97m"
    dim = "\033[2;37m"
    green = "\033[32m"
    yellow = "\033[33m"

    fields = [
        ("IP",       white,  data.get("ip", "N/A")),
        ("Hostname", white,  data.get("hostname", "N/A")),
        ("ASN/Org",  yellow, data.get("org", "N/A")),
        ("City",     green,  data.get("city", "N/A")),
        ("Region",   green,  data.get("region", "N/A")),
        ("Country",  green,  data.get("country", "N/A")),
        ("Location", dim,    data.get("loc", "N/A")),
        ("Postal",   dim,    data.get("postal", "N/A")),
        ("Timezone", dim,    data.get("timezone", "N/A")),
    ]

    rows = []
    cyan = "\033[36m"
    reset = "\033[0m"
    for label, color, value in fields:
        # "   IP       : 103.130.18.239"
        visible = f"   {label:<9s}: {value}"
        pad = _BOX_W - len(visible)
        rows.append(
            f"{cyan}║{reset}{cyan}   {label:<9s}{dim}: {color}{value}{reset}"
            f"{' ' * max(pad, 1)}{cyan}║{reset}"
        )
    return rows


def print_banner():
    """Print the ReconX ASCII banner with embedded network identity."""
    cyan = "\033[36m"
    bold_white = "\033[1;97m"
    dim = "\033[2;37m"
    reset = "\033[0m"

    # Top part (logo + tagline)
    print(BANNER_TOP.format(cyan=cyan, bold_white=bold_white, dim=dim, reset=reset))

    # Fetch ipinfo (may silently fail)
    data = _fetch_ipinfo()
    if data:
        # Separator
        print(f"{cyan}╠══════════════════════════════════════════════════════════════╣{reset}")
        # Title
        title = "Network Identity"
        pad = _BOX_W - len(title) - 4  # 4 = leading spaces
        print(f"{cyan}║{reset}  {bold_white}{title}{reset}{' ' * max(pad, 1)}{cyan}  ║{reset}")
        print(f"{cyan}╠══════════════════════════════════════════════════════════════╣{reset}")
        # Rows
        for row in _ipinfo_rows(data):
            print(row)
        print(f"{cyan}║{' ' * _BOX_W}║{reset}")

    # Bottom border
    print(BANNER_BOTTOM.format(cyan=cyan, reset=reset))


def print_scan_start(label: str, direct: bool = False):
    """Print scan initialization info."""
    print(f"\033[1;97m[»]\033[0m Target: \033[1;96m{label}\033[0m")
    if direct:
        print(f"\033[1;97m[»]\033[0m Mode: \033[93mDirect scan\033[0m (IP/CIDR — skipping subdomain enumeration)")
        print(f"\033[1;97m[»]\033[0m Initializing nmap, smbclient, RDP-brute, enum4linux, MSF-brute, CME, Nuclei & WPScan ...\n")
    else:
        print(f"\033[1;97m[»]\033[0m Initializing sources & scanners...")
        print(f"\033[1;97m[»]\033[0m Launching concurrent enumeration...\n")


# ─── CLI Argument Parser ─────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX - Automated Reconnaissance & Intelligence Gathering Tool",
        epilog="Example: python main.py example.com --Pn",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "target",
        help="Target: domain, IP address, CIDR range, or file of targets",
    )

    parser.add_argument(
        "-o", "--output",
        help="Output JSON filename (default: <domain>.json)",
        default=None,
    )

    parser.add_argument(
        "--Pn",
        action="store_true",
        help="Nmap: skip host discovery (treat all hosts as online)",
    )

    parser.add_argument(
        "--script",
        type=str,
        default=None,
        help="Nmap: run NSE script (e.g. --script=vuln)",
    )

    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="Show full subdomain names (don't redact)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=50,
        help="Max concurrent workers (default: 50)",
    )

    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=10,
        help="Per-request timeout in seconds (default: 10)",
    )

    parser.add_argument(
        "--nmap-import",
        action="store_true",
        help="Treat <target> as an existing nmap -oN output file and skip scanning",
    )

    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip printing the banner",
    )

    parser.add_argument(
        "--collapse-threshold",
        type=int,
        default=5,
        help="Minimum entries to collapse into a pattern group (default: 5)",
    )

    return parser


# ─── Kali Linux Check ─────────────────────────────────────────────────────────

def _is_kali_linux() -> bool:
    """Check if the current OS is Kali Linux (native, VM, or WSL)."""
    if platform.system() != "Linux":
        return False
    # Check /etc/os-release for Kali
    try:
        with open("/etc/os-release", "r") as f:
            content = f.read().lower()
            return "kali" in content
    except FileNotFoundError:
        pass
    # Fallback: check /etc/issue
    try:
        with open("/etc/issue", "r") as f:
            return "kali" in f.read().lower()
    except FileNotFoundError:
        pass
    return False


# ─── Main Entry Point ────────────────────────────────────────────────────────

def main():
    """Main entry point for ReconX CLI."""
    # ── Enforce Kali Linux ─────────────────────────────────────────────
    if not _is_kali_linux():
        print(
            "\033[91m[✗] ReconX hanya bisa dijalankan di Kali Linux.\033[0m\n"
            "\033[90m    Gunakan Kali Linux (VM, bare-metal, atau WSL).\n"
            "    WSL: wsl --install kali-linux\n"
            "    VM : https://www.kali.org/get-kali/#kali-virtual-machines\033[0m"
        )
        sys.exit(1)

    parser = build_parser()
    args = parser.parse_args()

    # Banner
    if not args.no_banner:
        print_banner()

    # ── Check for multi-file input ─────────────────────────────────────
    multi_files = parse_multi_files(args.target)
    if multi_files:
        print(
            f"\033[1;97m[»]\033[0m Multi-file input: "
            f"\033[92m{len(multi_files)}\033[0m files → "
            f"\033[90m{', '.join(os.path.basename(f) for f in multi_files)}\033[0m\n"
        )
        for idx, filepath in enumerate(multi_files, 1):
            print(
                f"\033[1;97m{'═' * 80}\033[0m"
            )
            print(
                f"\033[1;97m[»]\033[0m File \033[92m{idx}/{len(multi_files)}\033[0m: "
                f"\033[1;96m{filepath}\033[0m"
            )
            print(
                f"\033[1;97m{'═' * 80}\033[0m\n"
            )
            _run_single_target(filepath, args)
            if idx < len(multi_files):
                print()  # Separator between scans
    else:
        _run_single_target(args.target, args)

    print()  # Final newline


def _run_single_target(target: str, args):
    """Run a single scan for one target (file, IP, CIDR, or domain)."""
    # ── Detect input type ──────────────────────────────────────────────
    if getattr(args, 'nmap_import', False):
        # target IS the nmap -oN output file — don't parse it as a targets list
        label = os.path.splitext(os.path.basename(target))[0]
        targets = []
        is_direct = True
    else:
        label, targets, is_direct = resolve_targets(target)

    # Build configuration
    config = ReconConfig(
        target_domain=target if not is_direct else label,
        output_file=args.output,
        verbose=args.verbose,
    )
    if is_direct:
        config.input_mode = "direct"
        config.direct_targets = targets
        config.input_label = label

    config.scanner.concurrency = args.concurrency
    config.scanner.timeout = args.timeout
    config.scanner.collapse_threshold = args.collapse_threshold
    config.scanner.nmap_pn = args.Pn
    config.scanner.nmap_script = args.script or ""
    config.scanner.nmap_import_file = target if getattr(args, 'nmap_import', False) else ""

    # Print scan start info
    print_scan_start(label, direct=is_direct)

    # Create and run engine
    engine = ReconEngine(config)

    # Override redaction if requested
    if args.no_redact:
        engine.renderer.redact = False

    # Execute scan
    try:
        result = engine.run()
    except KeyboardInterrupt:
        print(f"\n\033[93m[!]\033[0m Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\033[91m[!]\033[0m Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
