"""Stage 7 (ACTIVE) — vulnerability / misconfiguration scanning with nuclei.

Runs community + custom nuclei templates against every live HTTP endpoint and
normalises each match into a Finding.

ACTIVE: nuclei sends crafted probes to the target. Gated behind --active.
"""

from __future__ import annotations

import re

from ..models import Finding, Severity, StageRun, SEVERITY_ORDER
from ..util import iter_json_lines, write_lines
from .. import runner
from .base import Stage, StageContext

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cves(obj: dict, info: dict) -> list[str]:
    """Pull CVE IDs from a nuclei finding (template-id, tags, classification)."""
    found: set[str] = set()
    haystack = " ".join(str(x) for x in [
        obj.get("template-id", ""), obj.get("templateID", ""),
        info.get("name", ""), " ".join(info.get("tags") or []
            if isinstance(info.get("tags"), list) else [str(info.get("tags") or "")]),
    ])
    found.update(m.upper() for m in CVE_RE.findall(haystack))
    classification = info.get("classification") or {}
    cve_ids = classification.get("cve-id") or classification.get("cveid") or []
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]
    found.update(c.upper() for c in cve_ids if c)
    return sorted(found)


class VulnStage(Stage):
    name = "vulns"
    tools = ["nuclei"]
    active = True

    def execute(self, ctx: StageContext, record: StageRun) -> str:
        targets = [e.url for e in ctx.results.endpoints if e.status]
        if not targets:
            return "no live endpoints to scan"

        sdir = ctx.stage_dir(self.name)
        in_file = sdir / "targets.txt"
        write_lines(in_file, targets)
        jsonl = sdir / "nuclei.jsonl"

        cmd = [
            "nuclei", "-silent", "-jsonl", "-o", str(jsonl),
            "-l", str(in_file),
            "-severity", ctx.config.nuclei_severity,
            "-rate-limit", str(ctx.config.nuclei_rate_limit),
            "-c", str(ctx.config.threads),
            "-no-color",
        ]
        if ctx.config.nuclei_tags:
            cmd += ["-tags", ctx.config.nuclei_tags]

        res = runner.run(cmd, timeout=ctx.config.timeout_for(self.name),
                         log_dir=sdir, log_name="nuclei")

        raw = jsonl.read_text() if jsonl.exists() else res.stdout
        for obj in iter_json_lines(raw):
            ctx.results.findings.append(self._parse(obj))

        # Sort by severity (critical first).
        ctx.results.findings.sort(
            key=lambda f: SEVERITY_ORDER.index(Severity.parse(f.severity).value))

        record.produced = len(ctx.results.findings)
        crit = sum(1 for f in ctx.results.findings
                   if f.severity in ("critical", "high"))
        return f"{len(ctx.results.findings)} findings ({crit} high/critical)"

    @staticmethod
    def _parse(obj: dict) -> Finding:
        info = obj.get("info") or {}
        return Finding(
            template_id=obj.get("template-id") or obj.get("templateID") or "unknown",
            name=info.get("name") or obj.get("template-id") or "unknown",
            severity=Severity.parse(info.get("severity")).value,
            host=obj.get("host") or obj.get("matched-at"),
            matched_at=obj.get("matched-at") or obj.get("matched_at"),
            description=info.get("description"),
            tags=info.get("tags") if isinstance(info.get("tags"), list)
                else ([info["tags"]] if info.get("tags") else []),
            reference=info.get("reference") if isinstance(info.get("reference"), list)
                else ([info["reference"]] if info.get("reference") else []),
            type=obj.get("type"),
            cves=extract_cves(obj, info),
        )
