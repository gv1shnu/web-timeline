"""Stage 1 — passive subdomain / asset discovery.

Sources: subfinder, assetfinder, amass (optional), and crt.sh certificate
transparency logs. All passive — no traffic is sent to the target itself.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.parse

from ..models import Host, StageRun
from ..util import clean_host, in_scope
from .. import runner
from .base import Stage, StageContext


class SubdomainStage(Stage):
    name = "subdomains"
    tools = ["subfinder", "assetfinder", "amass"]
    active = False
    requires_any_tool = False  # crt.sh works even with no local tools

    def execute(self, ctx: StageContext, record: StageRun) -> str:
        sdir = ctx.stage_dir(self.name)
        found: dict[str, set[str]] = {}

        def add(name: str, source: str) -> None:
            h = clean_host(name)
            if h and in_scope(h, ctx.targets):
                found.setdefault(h, set()).add(source)

        # Seed the root domains themselves.
        for t in ctx.targets:
            add(t, "seed")

        for domain in ctx.targets:
            if runner.have("subfinder"):
                cmd = ["subfinder", "-d", domain, "-silent"]
                if ctx.config.subfinder_all_sources:
                    cmd.append("-all")
                res = runner.run(cmd, timeout=ctx.config.timeout_for(self.name),
                                 log_dir=sdir, log_name=f"subfinder_{domain}")
                for line in res.lines():
                    add(line, "subfinder")

            if runner.have("assetfinder"):
                res = runner.run(["assetfinder", "--subs-only", domain],
                                 timeout=ctx.config.timeout_for(self.name),
                                 log_dir=sdir, log_name=f"assetfinder_{domain}")
                for line in res.lines():
                    add(line, "assetfinder")

            if ctx.config.amass_enabled and runner.have("amass"):
                res = runner.run(["amass", "enum", "-passive", "-d", domain, "-silent"],
                                 timeout=ctx.config.timeout_for(self.name),
                                 log_dir=sdir, log_name=f"amass_{domain}")
                for line in res.lines():
                    add(line, "amass")

            if ctx.config.include_crtsh:
                for name in self._crtsh(domain, ctx):
                    add(name, "crt.sh")

        for name, sources in found.items():
            ctx.results.add_host(Host(name=name, sources=set(sources)))

        record.produced = len(found)
        return f"{len(found)} unique hosts"

    def _crtsh(self, domain: str, ctx: StageContext) -> list[str]:
        """Query crt.sh certificate transparency logs (best-effort)."""
        url = "https://crt.sh/?q=" + urllib.parse.quote(f"%.{domain}") + "&output=json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ceh-automation/0.1"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except Exception as exc:  # noqa: BLE001 - crt.sh is flaky; degrade quietly
            ctx.log.warn(f"crt.sh query failed for {domain}: {exc}")
            return []
        names: list[str] = []
        for entry in data if isinstance(data, list) else []:
            value = entry.get("name_value", "")
            names.extend(value.split("\n"))
        return names
