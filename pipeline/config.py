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
    active: bool = False           # gate for port/vuln scanning (opt-in)
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
        "exploits": True,     # passive enrichment of vuln findings
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
        "exploits": 600,
    })

    def timeout_for(self, stage: str) -> int:
        return self.timeouts.get(stage, 900)

    def stage_enabled(self, stage: str, active_stage: bool = False) -> bool:
        if active_stage and not self.active:
            return False
        return self.stages.get(stage, True)


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
