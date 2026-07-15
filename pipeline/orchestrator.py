"""Drive the full recon pipeline for a set of target domains."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from .config import Config
from .models import ReconResults, utcnow
from .report import render_html
from .stages import STAGE_CLASSES, StageContext
from .stages.base import Logger
from .util import clean_host


def _slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", text)[:60] or "scan"


class Orchestrator:
    def __init__(self, targets: list[str], config: Config, verbose: bool = True) -> None:
        self.targets = [clean_host(t) for t in targets if clean_host(t)]
        self.config = config
        self.log = Logger(verbose=verbose)

    def _make_run_dir(self) -> Path:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        label = _slug(self.targets[0]) if self.targets else "scan"
        run_dir = Path(self.config.output_dir) / label / stamp
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir

    def run(self) -> tuple[ReconResults, Path]:
        if not self.targets:
            raise ValueError("No valid target domains provided.")

        run_dir = self._make_run_dir()
        results = ReconResults(targets=self.targets, active=self.config.active,
                               started=utcnow())
        ctx = StageContext(config=self.config, results=results, run_dir=run_dir,
                           targets=self.targets, log=self.log)

        self.log.info(f"Targets: {', '.join(self.targets)}")
        self.log.info(f"Mode: {'ACTIVE' if self.config.active else 'passive'}  ·  "
                      f"Output: {run_dir}")

        for stage_cls in STAGE_CLASSES:
            stage = stage_cls()
            record = stage.run(ctx)
            results.stages.append(record)
            # Persist incrementally so a long run is inspectable / crash-safe.
            self._write_json(results, run_dir)

        results.finished = utcnow()
        self._write_json(results, run_dir)
        report_path = render_html(results, run_dir / "report.html")

        self._print_summary(results, run_dir, report_path)
        return results, report_path

    @staticmethod
    def _write_json(results: ReconResults, run_dir: Path) -> None:
        (run_dir / "results.json").write_text(results.to_json(), encoding="utf-8")

    def _print_summary(self, results: ReconResults, run_dir: Path, report: Path) -> None:
        s = results.summary()
        sev = s["findings_by_severity"]
        self.log.ok("Scan complete.")
        print("\n" + "=" * 56)
        print(f"  Hosts discovered : {s['hosts']}  ({s['resolved_hosts']} resolved)")
        print(f"  Open ports       : {s['services']}")
        print(f"  HTTP endpoints   : {s['http_endpoints']}")
        print(f"  URLs harvested   : {s['crawl_urls']}")
        print(f"  Findings         : {s['findings']}  "
              f"(crit {sev['critical']}, high {sev['high']}, "
              f"med {sev['medium']}, low {sev['low']}, info {sev['info']})")
        print(f"  Exploits found   : {s['exploits']}  "
              f"(for {s['findings_with_exploits']} finding(s))")
        print("-" * 56)
        print(f"  JSON   : {run_dir / 'results.json'}")
        print(f"  Report : {report}")
        print("=" * 56 + "\n")
