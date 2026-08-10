"""Normalized data schema shared across every pipeline stage.

Each stage parses a tool's native output into these dataclasses, so the
aggregator and report never have to care which tool produced a given fact.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, value: str | None) -> "Severity":
        try:
            return cls((value or "unknown").strip().lower())
        except ValueError:
            return cls.UNKNOWN


@dataclass
class Host:
    """A discovered hostname/subdomain and its resolution state."""
    name: str
    sources: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    cname: str | None = None
    resolved: bool = False

    def merge(self, other: "Host") -> None:
        self.sources |= other.sources
        self.ips |= other.ips
        self.cname = self.cname or other.cname
        self.resolved = self.resolved or other.resolved


@dataclass
class Service:
    """An open port and (optionally) the service/version behind it."""
    host: str
    port: int
    protocol: str = "tcp"
    ip: str | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    state: str = "open"


@dataclass
class HttpEndpoint:
    """A live HTTP(S) endpoint with fingerprint data."""
    url: str
    host: str | None = None
    port: int | None = None
    scheme: str | None = None
    status: int | None = None
    title: str | None = None
    webserver: str | None = None
    tech: list[str] = field(default_factory=list)
    content_length: int | None = None
    content_type: str | None = None
    cdn: str | None = None
    ip: str | None = None
    tls: dict[str, Any] | None = None
    screenshot: str | None = None  # relative path to screenshot file


@dataclass
class CrawlUrl:
    url: str
    source: str  # katana | waybackurls | gau


@dataclass
class Exploit:
    """A public exploit or proof-of-concept for a CVE behind a Finding."""
    source: str          # exploit-db | github
    title: str
    url: str
    cve: str | None = None
    local_path: str | None = None  # on-disk path (searchsploit / Exploit-DB)


@dataclass
class Finding:
    """A nuclei (or equivalent) match: vuln, misconfig, exposure, tech, etc."""
    template_id: str
    name: str
    severity: str = "unknown"
    host: str | None = None
    matched_at: str | None = None
    description: str | None = None
    tags: list[str] = field(default_factory=list)
    reference: list[str] = field(default_factory=list)
    type: str | None = None
    cves: list[str] = field(default_factory=list)
    exploits: list[Exploit] = field(default_factory=list)


@dataclass
class Credential:
    """A username/password pair recovered during the offensive tier."""
    host: str
    service: str = "http"
    username: str = ""
    password: str | None = None
    source: str = ""            # sqli-dump | auth_attack | crack
    validated: bool = False


@dataclass
class Secret:
    """A leaked key/token/credential string found in client-side content."""
    url: str
    kind: str                   # api-key | token | aws | jwt | ...
    value: str
    source: str = "js_recon"


@dataclass
class Loot:
    """A reference to data extracted during the offensive tier."""
    kind: str                   # db-dump | file | hash-set
    source: str                 # producing stage name
    summary: str = ""
    path: str | None = None     # path (relative to run dir) to the extracted artifact


@dataclass
class Insight:
    """A cross-stage correlation: a compound/chained risk synthesized from
    otherwise-isolated facts (a dangling CNAME, an exposed management port, a
    cluster of CVEs on one host, ...). This is pre-exploitation intelligence
    for a human operator to verify and act on manually — the pipeline never
    treats an Insight as a trigger for further automated action."""
    id: str
    title: str
    category: str                 # takeover | exposure | injection-surface | infra | shadow-it | vuln-rollup
    severity: str = "unknown"
    confidence: str = "medium"    # low | medium | high
    hosts: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    rationale: str = ""
    next_step: str = ""           # what a human tester should verify/do manually


@dataclass
class StageRun:
    """Metadata about one stage execution — surfaced in the report."""
    name: str
    tool: str
    status: str  # ok | skipped | error
    started: str = ""
    finished: str = ""
    duration_s: float = 0.0
    produced: int = 0
    note: str = ""


@dataclass
class ReconResults:
    """The single aggregated result object for a whole run."""
    targets: list[str] = field(default_factory=list)
    active: bool = False
    offensive: bool = False
    started: str = field(default_factory=utcnow)
    finished: str | None = None
    hosts: dict[str, Host] = field(default_factory=dict)
    services: list[Service] = field(default_factory=list)
    endpoints: list[HttpEndpoint] = field(default_factory=list)
    crawl_urls: list[CrawlUrl] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    insights: list[Insight] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    secrets: list[Secret] = field(default_factory=list)
    loot: list[Loot] = field(default_factory=list)
    stages: list[StageRun] = field(default_factory=list)

    # -- mutation helpers ---------------------------------------------------
    def add_host(self, host: Host) -> None:
        existing = self.hosts.get(host.name)
        if existing:
            existing.merge(host)
        else:
            self.hosts[host.name] = host

    # -- summary ------------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        sev_counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            sev_counts[Severity.parse(f.severity).value] += 1
        insight_sev_counts = {s: 0 for s in SEVERITY_ORDER}
        for i in self.insights:
            insight_sev_counts[Severity.parse(i.severity).value] += 1
        return {
            "hosts": len(self.hosts),
            "resolved_hosts": sum(1 for h in self.hosts.values() if h.resolved),
            "services": len(self.services),
            "http_endpoints": len(self.endpoints),
            "crawl_urls": len(self.crawl_urls),
            "findings": len(self.findings),
            "findings_by_severity": sev_counts,
            "findings_with_exploits": sum(1 for f in self.findings if f.exploits),
            "exploits": sum(len(f.exploits) for f in self.findings),
            "insights": len(self.insights),
            "insights_by_severity": insight_sev_counts,
            "credentials": len(self.credentials),
            "secrets": len(self.secrets),
            "loot": len(self.loot),
        }

    # -- serialization ------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "targets": self.targets,
            "active": self.active,
            "offensive": self.offensive,
            "started": self.started,
            "finished": self.finished,
            "summary": self.summary(),
            "hosts": [asdict(h) for h in self.hosts.values()],
            "services": [asdict(s) for s in self.services],
            "endpoints": [asdict(e) for e in self.endpoints],
            "crawl_urls": [asdict(c) for c in self.crawl_urls],
            "findings": [asdict(f) for f in self.findings],
            "insights": [asdict(i) for i in self.insights],
            "credentials": [asdict(c) for c in self.credentials],
            "secrets": [asdict(s) for s in self.secrets],
            "loot": [asdict(l) for l in self.loot],
            "stages": [asdict(s) for s in self.stages],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=_json_default)


def _json_default(obj: Any) -> Any:
    if isinstance(obj, set):
        return sorted(obj)
    if isinstance(obj, Enum):
        return obj.value
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
