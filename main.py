#!/usr/bin/env python3
"""
ReconX - Automated Reconnaissance & Intelligence Gathering Tool

Usage:
    python main.py <domain> [options]

Examples:
    python main.py example.com
    python main.py example.com --demo
    python main.py example.com -o results.json
    python main.py example.com --no-redact --verbose
"""

import sys
import os
import argparse
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from recon.config import ReconConfig
from recon.engine import ReconEngine


# ─── Banner ───────────────────────────────────────────────────────────────────

BANNER = r"""
{cyan}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   {bold_white}██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗{cyan}       ║
║   {bold_white}██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝{cyan}       ║
║   {bold_white}██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝{cyan}        ║
║   {bold_white}██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗{cyan}        ║
║   {bold_white}██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗{cyan}       ║
║   {bold_white}╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝{cyan}       ║
║                                                              ║
║   {dim}Automated Reconnaissance & Intelligence Gathering{cyan}          ║
║   {dim}v1.0.0 | Multi-Source Subdomain Enumeration Engine{cyan}         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{reset}
"""


def print_banner():
    """Print the ReconX ASCII banner."""
    print(BANNER.format(
        cyan="\033[36m",
        bold_white="\033[1;97m",
        dim="\033[2;37m",
        reset="\033[0m",
    ))


def print_scan_start(domain: str, demo: bool):
    """Print scan initialization info."""
    mode = "\033[93m[DEMO MODE]\033[0m " if demo else ""
    print(f"\033[1;97m[»]\033[0m {mode}Target: \033[1;96m{domain}\033[0m")
    print(f"\033[1;97m[»]\033[0m Initializing sources & scanners...")
    print(f"\033[1;97m[»]\033[0m Launching concurrent enumeration...\n")


# ─── CLI Argument Parser ─────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX - Automated Reconnaissance & Intelligence Gathering Tool",
        epilog="Example: python main.py example.com --demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "domain",
        help="Target domain to scan (e.g., example.com)",
    )

    parser.add_argument(
        "-o", "--output",
        help="Output JSON filename (default: <domain>.json)",
        default=None,
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run in demo mode with simulated data",
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


# ─── Main Entry Point ────────────────────────────────────────────────────────

def main():
    """Main entry point for ReconX CLI."""
    parser = build_parser()
    args = parser.parse_args()

    # Enable Windows ANSI support
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(
                kernel32.GetStdHandle(-11), 0x0001 | 0x0002 | 0x0004
            )
        except Exception:
            os.system("")  # Fallback: triggers ANSI support on Win10+

    # Banner
    if not args.no_banner:
        print_banner()

    # Build configuration
    config = ReconConfig(
        target_domain=args.domain,
        output_file=args.output,
        demo_mode=args.demo,
        verbose=args.verbose,
    )
    config.scanner.concurrency = args.concurrency
    config.scanner.timeout = args.timeout
    config.scanner.collapse_threshold = args.collapse_threshold

    # Print scan start info
    print_scan_start(args.domain, args.demo)

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

    print()  # Final newline


if __name__ == "__main__":
    main()
