"""Flask app: browse past runs, launch new scans, watch them live.

The pipeline core is untouched — this layer just wraps ``Orchestrator`` in a
background thread and reads the ``output/`` directory the CLI already writes.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from flask import (Flask, Response, abort, redirect, render_template, request,
                   send_from_directory, url_for)

from ..config import Config
from ..models import SEVERITY_ORDER
from ..orchestrator import Orchestrator
from ..stages.base import Logger

# In-memory registry of live/finished web-launched runs: id -> state dict.
LIVE_RUNS: dict[str, dict] = {}


class WebLogger(Logger):
    """Logger that appends formatted lines to a shared buffer for SSE."""

    def __init__(self, buffer: list[str]) -> None:
        super().__init__(verbose=False)
        self.buffer = buffer

    def _emit(self, symbol: str, msg: str) -> None:
        self.buffer.append(f"{time.strftime('%H:%M:%S')} {symbol} {msg}")


def create_app(output_dir: str = "output") -> Flask:
    app = Flask(__name__)
    out_root = Path(output_dir).resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    # -- helpers -----------------------------------------------------------
    def list_runs() -> list[dict]:
        runs = []
        for results_file in out_root.glob("*/*/results.json"):
            try:
                data = json.loads(results_file.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            run_dir = results_file.parent
            runs.append({
                "id": str(run_dir.relative_to(out_root)),
                "target": ", ".join(data.get("targets", [])) or run_dir.parent.name,
                "started": data.get("started"),
                "finished": data.get("finished"),
                "active": data.get("active", False),
                "summary": data.get("summary", {}),
                "has_report": (run_dir / "report.html").exists(),
            })
        runs.sort(key=lambda r: r["started"] or "", reverse=True)
        return runs

    def run_scan(run_id: str, domains: list[str], config: Config) -> None:
        entry = LIVE_RUNS[run_id]
        try:
            orch = Orchestrator(domains, config, verbose=False)
            orch.log = WebLogger(entry["lines"])
            _results, report = orch.run()
            entry["run_rel"] = str(report.parent.relative_to(out_root))
            entry["status"] = "done"
        except Exception as exc:  # noqa: BLE001 - report failure to the UI
            entry["lines"].append(f"ERROR: {type(exc).__name__}: {exc}")
            entry["status"] = "error"

    # -- routes ------------------------------------------------------------
    @app.route("/")
    def dashboard():
        return render_template("dashboard.html", runs=list_runs(),
                               severity_order=SEVERITY_ORDER)

    @app.route("/run/<path:run_id>")
    def run_detail(run_id):
        run_dir = (out_root / run_id).resolve()
        if out_root not in run_dir.parents or not (run_dir / "report.html").exists():
            abort(404)
        meta = next((r for r in list_runs() if r["id"] == run_id), None)
        return render_template("run.html", run_id=run_id, meta=meta)

    @app.route("/runs/<path:relpath>")
    def run_files(relpath):
        # Static file server scoped to the output dir (report.html, screenshots).
        return send_from_directory(out_root, relpath)

    @app.route("/new")
    def new_scan():
        return render_template("new_scan.html")

    @app.route("/scan", methods=["POST"])
    def scan():
        raw = request.form.get("domains", "")
        domains = [d.strip() for d in raw.replace(",", " ").split() if d.strip()]
        if not domains:
            return redirect(url_for("new_scan"))
        config = Config()
        config.output_dir = str(out_root)
        config.active = request.form.get("active") == "on"

        run_id = str(int(time.time() * 1000))
        LIVE_RUNS[run_id] = {"lines": [], "status": "running", "run_rel": None,
                             "domains": domains, "active": config.active}
        threading.Thread(target=run_scan, args=(run_id, domains, config),
                         daemon=True).start()
        return redirect(url_for("live", run_id=run_id))

    @app.route("/live/<run_id>")
    def live(run_id):
        entry = LIVE_RUNS.get(run_id)
        if not entry:
            abort(404)
        return render_template("live.html", run_id=run_id, entry=entry)

    @app.route("/stream/<run_id>")
    def stream(run_id):
        def gen():
            idx = 0
            while True:
                entry = LIVE_RUNS.get(run_id)
                if not entry:
                    return
                lines = entry["lines"]
                while idx < len(lines):
                    yield f"data: {lines[idx]}\n\n"
                    idx += 1
                if entry["status"] != "running":
                    yield f"event: {entry['status']}\ndata: {entry.get('run_rel') or ''}\n\n"
                    return
                time.sleep(0.4)
        return Response(gen(), mimetype="text/event-stream")

    return app
