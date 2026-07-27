"""Stage 2 — DNS resolution with dnsx.

Filters the (often noisy) subdomain list down to hosts that actually resolve,
and records their A records + CNAME chain for downstream active stages.
"""

from __future__ import annotations

from ..models import StageRun
from ..util import iter_json_lines, write_lines
from .. import runner
from .base import Stage, StageContext


class ResolveStage(Stage):
    name = "resolve"
    tools = ["dnsx"]
    active = False

    def execute(self, ctx: StageContext, record: StageRun) -> str:
        if not ctx.results.hosts:
            return "no hosts to resolve"

        sdir = ctx.stage_dir(self.name)
        hosts_file = sdir / "hosts_in.txt"
        write_lines(hosts_file, ctx.results.hosts.keys())

        cmd = [
            "dnsx", "-silent", "-json", "-a", "-cname", "-resp",
            "-l", str(hosts_file),
            "-r", ",".join(ctx.config.resolvers),
            "-t", str(ctx.config.threads),
        ]
        res = runner.run(cmd, timeout=ctx.config.timeout_for(self.name),
                         log_dir=sdir, log_name="dnsx")

        resolved = 0
        for obj in iter_json_lines(res.stdout):
            name = (obj.get("host") or "").lower()
            host = ctx.results.hosts.get(name)
            if not host:
                continue
            a_records = obj.get("a") or []
            cname = obj.get("cname") or []
            if a_records:
                host.ips |= set(a_records)
            if cname:
                host.cname = cname[0] if isinstance(cname, list) else cname
            if a_records or cname:
                host.resolved = True
                resolved += 1

        record.produced = resolved
        return f"{resolved}/{len(ctx.results.hosts)} hosts resolved"
