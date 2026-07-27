"""Stage 6 — screenshots of live web endpoints with gowitness.

gowitness v3 headlessly renders each URL (auto-fetching a Chrome build if none
is configured) and emits a JSONL mapping of URL -> screenshot file, which we
attach back onto the matching HttpEndpoint for the report.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit, urlunsplit

from ..models import StageRun
from ..util import iter_json_lines, write_lines
from .. import runner
from .base import Stage, StageContext

MAX_SHOTS = 200  # bound render time on large scopes


def _norm_url(url: str) -> str:
    """Canonicalise a URL for matching (drop default ports + trailing slash).

    httpx emits ``http://host`` while gowitness records ``http://host:80``;
    normalising both sides lets us line screenshots up with their endpoints.
    """
    try:
        p = urlsplit(url.strip())
    except ValueError:
        return url.strip().rstrip("/")
    host = (p.hostname or "").lower()
    port = p.port
    default = (p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443)
    netloc = host if (port is None or default) else f"{host}:{port}"
    return urlunsplit((p.scheme, netloc, p.path.rstrip("/"), p.query, ""))


class ScreenshotStage(Stage):
    name = "screenshots"
    tools = ["gowitness"]
    active = False

    def execute(self, ctx: StageContext, record: StageRun) -> str:
        live = [e for e in ctx.results.endpoints if e.status]
        if not live:
            return "no live endpoints to screenshot"
        live = live[:MAX_SHOTS]

        sdir = ctx.stage_dir(self.name)
        shots_dir = sdir / "images"
        shots_dir.mkdir(parents=True, exist_ok=True)
        urls_file = sdir / "urls.txt"
        write_lines(urls_file, [e.url for e in live])
        jsonl = sdir / "gowitness.jsonl"

        cmd = [
            "gowitness", "scan", "file", "-f", str(urls_file),
            "-s", str(shots_dir),
            "--screenshot-format", "png",
            "--threads", str(min(ctx.config.threads, 10)),
            "--timeout", str(ctx.config.screenshot_timeout),
            "--write-jsonl", "--write-jsonl-file", str(jsonl),
        ]
        res = runner.run(cmd, timeout=ctx.config.timeout_for(self.name),
                         log_dir=sdir, log_name="gowitness")

        # Map normalized URL -> screenshot filename from the JSONL.
        url_to_file: dict[str, str] = {}
        if jsonl.exists():
            for obj in iter_json_lines(jsonl.read_text()):
                url = obj.get("url")
                fname = obj.get("file_name") or obj.get("filename")
                if url and fname:
                    url_to_file[_norm_url(url)] = os.path.basename(fname)

        count = 0
        for ep in ctx.results.endpoints:
            fname = url_to_file.get(_norm_url(ep.url))
            if fname:
                ep.screenshot = f"screenshots/images/{fname}"
                count += 1

        record.produced = count
        if count == 0 and not res.ok:
            return "gowitness produced no screenshots (see stage log; Chrome may still be downloading)"
        return f"{count} screenshots captured"
