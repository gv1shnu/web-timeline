"""Run configuration: defaults + optional YAML overrides.

Everything the pipeline needs to tune scan breadth, rate limits and per-stage
behaviour lives here so the stages themselves stay declarative.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - yaml is a listed dependency
    yaml = None


@dataclass
class Config:
    # --- global -----------------------------------------------------------
    output_dir: str = "output"
    active: bool = False           # gate for active scanning (opt-in)
    offensive: bool = False        # gate for exploitation tier (opt-in; implies active)
    threads: int = 40
    rate_limit: int = 150          # requests/sec cap for tools that support it
    resolvers: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])

    # --- stage toggles ----------------------------------------------------
    stages: dict[str, bool] = field(default_factory=lambda: {
        "subdomains": True,
        "resolve": True,
        "ports": True,        # active
        "http_probe": True,
        "crawl": True,
        "screenshots": True,
        "vulns": True,        # active
        "sqli_detect": True,  # active
        "xss_detect": True,   # active
        "exploits": True,     # passive enrichment of vuln findings
        "sqli_exploit": True, # offensive
        "xss_confirm": True,  # offensive
        "auth_attack": True,  # offensive
        "exploit_run": True,  # offensive
        "crack": True,        # offensive
    })

    # --- per-stage tuning -------------------------------------------------
    subfinder_all_sources: bool = True
    amass_enabled: bool = False    # amass passive is slow; off by default
    include_crtsh: bool = True

    ports: str = "top-1000"        # naabu -top-ports value, or "1-65535", or CSV
    port_scan_tool: str = "naabu"  # naabu | nmap
    nmap_service_scan: bool = True # run nmap -sV on naabu-found ports

    nuclei_severity: str = "low,medium,high,critical"
    nuclei_tags: str = ""          # optional template tag filter
    nuclei_rate_limit: int = 150

    # --- sql injection (sqlmap) ------------------------------------------
    sqli_max_urls: int = 50        # cap parameterized URLs tested per run
    sqlmap_level: int = 1          # sqlmap --level (1-5): test depth
    sqlmap_risk: int = 1           # sqlmap --risk (1-3): payload aggressiveness
    sqlmap_dump: bool = True       # OFFENSIVE: extract data from injectable params
    sqlmap_dump_max_rows: int = 100  # --stop cap per table (bounds extraction)
    sqlmap_os_shell: bool = False  # OFFENSIVE (opt-in): attempt OS command execution

    # --- cross-site scripting (dalfox) -----------------------------------
    xss_max_urls: int = 100        # cap parameterized URLs tested per run
    dalfox_workers: int = 40       # dalfox concurrency (-w)
    xss_blind_callback: str = ""   # OFFENSIVE (opt-in): out-of-band host for blind XSS

    # --- password cracking (john) ----------------------------------------
    crack_wordlist: str = ""       # wordlist path; empty = john's default mode
    crack_max_hashes: int = 500    # cap hashes fed to the cracker per run
    crack_format: str = ""         # force a john --format (empty = auto-detect)

    # --- credential attacks (hydra) --------------------------------------
    auth_userlist: str = ""        # usernames file; empty = small built-in common set
    auth_passlist: str = ""        # passwords file; empty = small built-in common set
    auth_max_targets: int = 10     # cap login surfaces attacked per run
    auth_form: str = ""            # optional hydra http-post-form spec for form logins
    auth_stop_on_success: bool = True  # hydra -f: stop a target after first valid pair

    # --- CVE exploitation (exploit_run) ----------------------------------
    # Auto-execution runs ONLY through vetted engines (nuclei templates). Third-
    # party PoCs are fetched/staged for manual review, never auto-executed.
    exploit_run_engines: list[str] = field(default_factory=lambda: ["nuclei"])
    exploit_run_max_cves: int = 25     # cap CVEs fired per run
    exploit_run_stage_pocs: bool = True   # write per-CVE PoC pointer manifest
    exploit_run_msf_script: bool = True   # emit an MSF resource script (staged, not run)

    # --- exploit enrichment -----------------------------------------------
    exploit_sources: list[str] = field(default_factory=lambda: ["searchsploit", "github"])
    exploits_per_finding: int = 15     # cap exploits attached per finding
    exploit_github_base: str = "https://raw.githubusercontent.com/trickest/cve/main"

    crawl_depth: int = 2
    crawl_tools: list[str] = field(default_factory=lambda: ["katana", "waybackurls", "gau"])

    screenshot_timeout: int = 15

    # --- timeouts (seconds) ----------------------------------------------
    timeouts: dict[str, int] = field(default_factory=lambda: {
        "subdomains": 600,
        "resolve": 300,
        "ports": 1800,
        "http_probe": 600,
        "crawl": 900,
        "screenshots": 900,
        "vulns": 3600,
        "sqli_detect": 1800,
        "xss_detect": 1800,
        "exploits": 600,
        "sqli_exploit": 3600,
        "xss_confirm": 1800,
        "auth_attack": 1800,
        "exploit_run": 3600,
        "crack": 3600,
    })

    def timeout_for(self, stage: str) -> int:
        return self.timeouts.get(stage, 900)

    def stage_enabled(self, stage: str, active_stage: bool = False) -> bool:
        if active_stage and not self.active:
            return False
        return self.stages.get(stage, True)

    # --- tier gating (passive < active < offensive) -----------------------
    _TIER_ORDER = ("passive", "active", "offensive")

    def tier_ceiling(self) -> str:
        """Highest tier this run is permitted to reach."""
        if self.offensive:
            return "offensive"
        if self.active:
            return "active"
        return "passive"

    def stage_allowed(self, stage_tier: str) -> bool:
        """True if a stage of ``stage_tier`` may run under the current ceiling."""
        order = self._TIER_ORDER
        try:
            return order.index(stage_tier) <= order.index(self.tier_ceiling())
        except ValueError:
            return True  # unknown tier: don't silently gate it out


def load_config(path: str | None) -> Config:
    """Load config from YAML, layering it over the dataclass defaults."""
    cfg = Config()
    if not path:
        return cfg
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    if yaml is None:
        raise RuntimeError("PyYAML is required to load a config file (pip install pyyaml)")
    data: dict[str, Any] = yaml.safe_load(p.read_text()) or {}

    valid = {f.name for f in fields(Config)}
    for key, value in data.items():
        if key not in valid:
            continue
        if isinstance(value, dict) and isinstance(getattr(cfg, key), dict):
            merged = dict(getattr(cfg, key))
            merged.update(value)
            setattr(cfg, key, merged)
        else:
            setattr(cfg, key, value)
    return cfg
