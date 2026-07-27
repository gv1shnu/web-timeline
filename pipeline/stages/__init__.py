"""Pipeline stages, executed in order by the orchestrator."""

from .base import Stage, StageContext
from .subdomains import SubdomainStage
from .resolve import ResolveStage
from .ports import PortScanStage
from .http_probe import HttpProbeStage
from .crawl import CrawlStage
from .screenshots import ScreenshotStage
from .vulns import VulnStage
from .sqli import SqliDetectStage, SqliExploitStage
from .xss import XssDetectStage, XssConfirmStage
from .auth import AuthAttackStage
from .crack import CrackStage
from .exploits import ExploitStage
from .exploit_run import ExploitRunStage

# Canonical execution order. Each stage is gated by its tier (passive < active <
# offensive) at runtime, so higher-tier stages self-skip unless unlocked.
STAGE_CLASSES = [
    SubdomainStage,      # passive
    ResolveStage,        # passive
    PortScanStage,       # active
    HttpProbeStage,      # passive
    CrawlStage,          # passive
    ScreenshotStage,     # passive
    VulnStage,           # active
    SqliDetectStage,     # active
    XssDetectStage,      # active
    ExploitStage,        # passive
    SqliExploitStage,    # offensive
    XssConfirmStage,     # offensive
    AuthAttackStage,     # offensive
    ExploitRunStage,     # offensive
    CrackStage,          # offensive
]

__all__ = ["Stage", "StageContext", "STAGE_CLASSES"]
