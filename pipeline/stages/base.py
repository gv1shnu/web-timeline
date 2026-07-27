"""Base class + shared context for pipeline stages."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from ..models import ReconResults, StageRun, utcnow
from .. import runner


@dataclass
class StageContext:
    """Everything a stage needs to do its work and record results."""
    config: Config
    results: ReconResults
    run_dir: Path                # output/<target>/<timestamp>/
    targets: list[str]
    log: "Logger"

    def stage_dir(self, name: str) -> Path:
        d = self.run_dir / name
        d.mkdir(parents=True, exist_ok=True)
        return d


class Logger:
    """Minimal timestamped console logger (kept dependency-free)."""

    def __init__(self, verbose: bool = True) -> None:
        self.verbose = verbose

    def _emit(self, symbol: str, msg: str) -> None:
        if self.verbose:
            print(f"[{time.strftime('%H:%M:%S')}] {symbol} {msg}", flush=True)

    def info(self, msg: str) -> None:
        self._emit("·", msg)

    def stage(self, msg: str) -> None:
        self._emit("▶", msg)

    def ok(self, msg: str) -> None:
        self._emit("✓", msg)

    def warn(self, msg: str) -> None:
        self._emit("!", msg)


class Stage(ABC):
    """A single pipeline step.

    Subclasses set ``name``, ``tools`` (external binaries they rely on) and
    ``active`` (whether the stage sends intrusive traffic), then implement
    :meth:`execute`. The base class handles enable/skip logic, timing, tool
    availability checks and StageRun bookkeeping.
    """

    name: str = "stage"
    tools: list[str] = []
    active: bool = False           # active == intrusive; gated by config.active
    requires_any_tool: bool = True  # skip if none of `tools` are installed
    tier: str = ""                 # "" derives from `active`; or set explicitly
    depends_on: list[str] = []     # stage names this stage consumes (for the DAG)

    def effective_tier(self) -> str:
        """Resolve this stage's tier: explicit ``tier`` wins, else from ``active``."""
        if self.tier:
            return self.tier
        return "active" if self.active else "passive"

    @abstractmethod
    def execute(self, ctx: StageContext, record: StageRun) -> str:
        """Do the work; mutate ``ctx.results``.

        Set ``record.produced`` to the count of items this stage generated and
        return a short human-readable note for the log/report.
        """

    # -- orchestration entrypoint ------------------------------------------
    def run(self, ctx: StageContext) -> StageRun:
        record = StageRun(name=self.name, tool=",".join(self.tools), status="ok",
                          started=utcnow())
        start = time.time()

        enabled = ctx.config.stages.get(self.name, True)
        tier = self.effective_tier()
        if not enabled or not ctx.config.stage_allowed(tier):
            if not enabled:
                reason = "disabled in config"
            elif tier == "offensive":
                reason = "offensive stage — skipped (run with --exploit to enable)"
            else:
                reason = "active stage — skipped (run with --active to enable)"
            record.status = "skipped"
            record.note = reason
            ctx.log.warn(f"{self.name}: {reason}")
            return self._finalize(record, start, ctx)

        available = [t for t in self.tools if runner.have(t)]
        if self.requires_any_tool and self.tools and not available:
            record.status = "skipped"
            record.note = f"missing tool(s): {', '.join(self.tools)}"
            ctx.log.warn(f"{self.name}: {record.note}")
            return self._finalize(record, start, ctx)

        ctx.log.stage(f"{self.name} (tools: {', '.join(available) or 'builtin'})")
        try:
            note = self.execute(ctx, record)
            record.note = note or ""
        except Exception as exc:  # noqa: BLE001 - one stage must not kill the run
            record.status = "error"
            record.note = f"{type(exc).__name__}: {exc}"
            ctx.log.warn(f"{self.name} errored: {record.note}")

        return self._finalize(record, start, ctx)

    def _finalize(self, record: StageRun, start: float, ctx: StageContext) -> StageRun:
        record.finished = utcnow()
        record.duration_s = round(time.time() - start, 1)
        if record.status == "ok":
            ctx.log.ok(f"{self.name} done in {record.duration_s}s — {record.note}")
        return record
