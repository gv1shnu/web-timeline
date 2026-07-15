"""Pipeline stages, executed in order by the orchestrator."""

from .base import Stage, StageContext
from .subdomains import SubdomainStage
from .resolve import ResolveStage
from .ports import PortScanStage
from .http_probe import HttpProbeStage
from .crawl import CrawlStage
from .screenshots import ScreenshotStage
from .vulns import VulnStage
from .exploits import ExploitStage

# Canonical execution order. Active stages are gated by config at runtime.
STAGE_CLASSES = [
    SubdomainStage,
    ResolveStage,
    PortScanStage,
    HttpProbeStage,
    CrawlStage,
    ScreenshotStage,
    VulnStage,
    ExploitStage,
]

__all__ = ["Stage", "StageContext", "STAGE_CLASSES"]
