"""Stage 4 — HTTP(S) probing + fingerprinting with httpx.

Turns resolved hosts (and any discovered host:port pairs) into live HTTP
endpoints with status, title, tech stack, server, TLS and CDN metadata.
"""

from __future__ import annotations

from ..models import HttpEndpoint, StageRun
from ..util import dedupe, iter_json_lines, write_lines
from .. import runner
from .base import Stage, StageContext


class HttpProbeStage(Stage):
    name = "http_probe"
    tools = ["httpx"]
    active = False  # standard HTTP requests; not treated as intrusive scanning

    def execute(self, ctx: StageContext, record: StageRun) -> str:
        # Prefer resolved hosts; fall back to all known hosts.
        hosts = [h.name for h in ctx.results.hosts.values() if h.resolved] \
            or list(ctx.results.hosts.keys())

        # Add host:port targets from the port scan (non-standard web ports).
        targets = list(hosts)
        for svc in ctx.results.services:
            if svc.port not in (80, 443):
                targets.append(f"{svc.host}:{svc.port}")
        targets = dedupe(targets)
        if not targets:
            return "no hosts to probe"

        sdir = ctx.stage_dir(self.name)
        in_file = sdir / "targets.txt"
        write_lines(in_file, targets)

        cmd = [
            "httpx", "-silent", "-json", "-l", str(in_file),
            "-title", "-status-code", "-tech-detect", "-web-server",
            "-content-length", "-content-type", "-cdn", "-tls-grab",
            "-follow-redirects", "-no-color",
            "-threads", str(ctx.config.threads),
            "-rate-limit", str(ctx.config.rate_limit),
        ]
        res = runner.run(cmd, timeout=ctx.config.timeout_for(self.name),
                         log_dir=sdir, log_name="httpx")

        for obj in iter_json_lines(res.stdout):
            ctx.results.endpoints.append(self._parse(obj))

        # Sort: interesting statuses first, then by url.
        ctx.results.endpoints.sort(key=lambda e: (e.status or 999, e.url))
        record.produced = len(ctx.results.endpoints)
        live = sum(1 for e in ctx.results.endpoints if e.status)
        return f"{live} live HTTP endpoints"

    @staticmethod
    def _parse(obj: dict) -> HttpEndpoint:
        tech = obj.get("tech") or obj.get("technologies") or []
        if isinstance(tech, str):
            tech = [tech]
        tls = obj.get("tls")
        tls_summary = None
        if isinstance(tls, dict):
            tls_summary = {
                "subject_cn": tls.get("subject_cn") or tls.get("host"),
                "issuer": tls.get("issuer_org") or tls.get("issuer_cn"),
                "not_after": tls.get("not_after"),
                "tls_version": tls.get("tls_version") or tls.get("version"),
            }
        a_records = obj.get("a") or []
        return HttpEndpoint(
            url=obj.get("url", ""),
            host=obj.get("input") or obj.get("host"),
            port=int(obj["port"]) if str(obj.get("port", "")).isdigit() else None,
            scheme=obj.get("scheme"),
            status=obj.get("status_code"),
            title=obj.get("title"),
            webserver=obj.get("webserver"),
            tech=list(tech),
            content_length=obj.get("content_length"),
            content_type=obj.get("content_type"),
            cdn=obj.get("cdn_name") or (obj.get("cdn") if isinstance(obj.get("cdn"), str) else None),
            ip=a_records[0] if a_records else obj.get("host"),
            tls=tls_summary,
        )
