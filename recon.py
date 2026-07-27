#!/usr/bin/env python3
"""web-timeline — tiered web-application offensive-security pipeline.

Usage:
    python recon.py example.com                                  # passive
    python recon.py example.com sub.example.com --active         # + scanning
    python recon.py -f domains.txt -o output --config config.yaml --exploit

Three gated tiers, each opt-in:
  passive   (default)  — subdomains, DNS, HTTP probe, crawl, screenshots.
  active    (--active) — port scan, nuclei vuln scan, SQLi/XSS detection.
  offensive (--exploit)— exploitation, credential attacks, data extraction.

Active and offensive stages send intrusive traffic and are only appropriate
against systems you own or are explicitly authorized to test. --exploit
additionally requires written authorization.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pipeline import __version__
from pipeline.config import load_config
from pipeline.orchestrator import Orchestrator
from pipeline import runner

REQUIRED_TOOLS = ["subfinder", "dnsx", "httpx", "naabu", "nmap", "nuclei",
                  "katana", "gowitness", "assetfinder", "waybackurls", "gau", "amass",
                  "searchsploit", "sqlmap", "dalfox", "john", "hydra", "msfconsole"]

BANNER = r"""
  web-timeline  ·  tiered web-app offensive-security pipeline  v{ver}
""".format(ver=__version__)


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="recon.py",
        description="Staged domain reconnaissance: domains in → JSON + HTML report out.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("domains", nargs="*", help="Target root domain(s), e.g. example.com")
    p.add_argument("-f", "--file", help="File with one domain per line")
    p.add_argument("-c", "--config", help="YAML config file (overrides defaults)")
    p.add_argument("-o", "--output", help="Output directory (default: output/)")
    p.add_argument("--active", action="store_true",
                   help="Enable ACTIVE stages (scanning + enumeration). Authorization required.")
    p.add_argument("--exploit", action="store_true",
                   help="Enable OFFENSIVE stages (exploitation). Implies --active. Written authorization required.")
    p.add_argument("--yes", action="store_true",
                   help="Skip the active/offensive confirmation prompt (for automation).")
    p.add_argument("-q", "--quiet", action="store_true", help="Reduce console output")
    p.add_argument("--list-tools", action="store_true",
                   help="Show which recon tools are installed and exit")
    return p.parse_args(argv)


def list_tools() -> int:
    print("Tool availability:")
    missing = 0
    for t in REQUIRED_TOOLS:
        path = runner.tool_path(t)
        mark = "✓" if path else "✗"
        print(f"  {mark} {t:<14} {path or 'MISSING — run scripts/install_tools.sh'}")
        missing += 0 if path else 1
    print(f"\n{len(REQUIRED_TOOLS) - missing}/{len(REQUIRED_TOOLS)} tools installed.")
    return 0 if missing == 0 else 1


def gather_domains(args: argparse.Namespace) -> list[str]:
    domains = list(args.domains)
    if args.file:
        text = Path(args.file).read_text()
        domains += [ln.strip() for ln in text.splitlines()
                    if ln.strip() and not ln.startswith("#")]
    return domains


def confirm_active(domains: list[str], offensive: bool = False) -> bool:
    if offensive:
        print("\n  ⚠  OFFENSIVE mode actively EXPLOITS the following targets")
        print("     (data extraction, credential attacks, exploit execution):\n")
    else:
        print("\n  ⚠  ACTIVE mode sends real scan traffic (enumeration + vulnerability probes)")
        print("     to the following targets:\n")
    for d in domains:
        print(f"       · {d}")
    if offensive:
        print("\n     Proceed ONLY against systems you own or hold WRITTEN authorization to test.")
    else:
        print("\n     Only proceed if you own these systems or have written authorization.")
    try:
        answer = input("     Type 'yes' to continue: ").strip().lower()
    except EOFError:
        return False
    return answer == "yes"


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    print(BANNER)

    if args.list_tools:
        return list_tools()

    domains = gather_domains(args)
    if not domains:
        print("error: no target domains given. Provide domains or -f <file>.\n")
        print("       python recon.py example.com --active")
        return 2

    config = load_config(args.config)
    if args.output:
        config.output_dir = args.output
    if args.active:
        config.active = True
    if args.exploit:
        config.active = True       # offensive tier implies active
        config.offensive = True

    if config.active and not args.yes and sys.stdin.isatty():
        if not confirm_active(domains, offensive=config.offensive):
            print("\n  Aborted. (Run without --active/--exploit for passive-only recon.)")
            return 1

    orch = Orchestrator(domains, config, verbose=not args.quiet)
    try:
        orch.run()
    except KeyboardInterrupt:
        print("\n  Interrupted — partial results were written to the run directory.")
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
