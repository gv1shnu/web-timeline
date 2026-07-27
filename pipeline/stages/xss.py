"""Cross-site scripting — detection (ACTIVE) and confirmation (OFFENSIVE).

  * ``xss_detect``  (ACTIVE)    — dalfox scans parameterized URLs from the crawl
                                  stage and records reflected/verified XSS as
                                  Findings.
  * ``xss_confirm`` (OFFENSIVE) — re-tests the same surface with headless
                                  verification (and optional blind-XSS callback),
                                  recording each triggered payload as proof Loot.

dalfox marks each PoC with a ``type``: ``V`` = verified (triggered via headless),
``R`` = reflected, ``G`` = grep-only. Detection keeps R/V; confirmation promotes
the ones that actually fire.
"""

from __future__ import annotations

import json

from ..models import Finding, Loot, Severity, StageRun
from ..util import clean_host, dedupe, iter_json_lines, write_lines
from .. import runner
from .base import Stage, StageContext


def _param_urls(ctx: StageContext) -> list[str]:
    return dedupe(u.url for u in ctx.results.crawl_urls if "?" in u.url and "=" in u.url)


def _host_of(url: str) -> str | None:
    try:
        return clean_host(url) or None
    except Exception:  # noqa: BLE001
        return None


def _dalfox_objs(text: str) -> list[dict]:
    """Parse dalfox --format json output (a JSON array or JSONL, tolerantly)."""
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass
    return list(iter_json_lines(text))


def _run_dalfox(ctx: StageContext, sdir, urls: list[str], stage_name: str,
                blind: str = "") -> list[dict]:
    urlfile = sdir / "targets.txt"
    write_lines(urlfile, urls)
    cmd = [
        "dalfox", "file", str(urlfile), "--format", "json",
        "--silence", "--no-color", "--no-spinner",
        "-w", str(ctx.config.dalfox_workers),
    ]
    if blind:
        cmd += ["-b", blind]
    res = runner.run(cmd, timeout=ctx.config.timeout_for(stage_name),
                     log_dir=sdir, log_name=stage_name)
    return _dalfox_objs(res.stdout)


class XssDetectStage(Stage):
    name = "xss_detect"
    tools = ["dalfox"]
    active = True                       # tier: active
    depends_on = ["crawl"]

    def execute(self, ctx: StageContext, record: StageRun) -> str:
        candidates = _param_urls(ctx)[: ctx.config.xss_max_urls]
        if not candidates:
            return "no parameterized URLs to test"

        sdir = ctx.stage_dir(self.name)
        objs = _run_dalfox(ctx, sdir, candidates, "xss_detect")

        seen: set[tuple] = set()
        found = 0
        for o in objs:
            typ = (o.get("type") or "").upper()
            if typ == "G":              # grep-only signal, not an XSS injection
                continue
            param = o.get("param") or ""
            poc = o.get("data") or o.get("poc") or ""
            key = (param, poc)
            if not poc or key in seen:
                continue
            seen.add(key)
            found += 1
            state = "verified" if typ == "V" else "reflected"
            ctx.results.findings.append(Finding(
                template_id="xss",
                name=f"Cross-site scripting ({o.get('inject_type') or state}) — param: {param or '?'}",
                severity=Severity.parse(o.get("severity")).value,
                host=_host_of(poc),
                matched_at=poc,
                type="xss",
                tags=["xss", state] + ([param] if param else []),
                description=o.get("message_str") or "dalfox reflected an injected payload.",
            ))

        record.produced = found
        return f"{found} XSS candidate(s) across {len(candidates)} URL(s)"


class XssConfirmStage(Stage):
    name = "xss_confirm"
    tools = ["dalfox"]
    tier = "offensive"                  # gated behind --exploit
    depends_on = ["xss_detect"]

    def execute(self, ctx: StageContext, record: StageRun) -> str:
        xss = [f for f in ctx.results.findings if f.template_id == "xss"]
        if not xss:
            return "no detected XSS to confirm"

        candidates = _param_urls(ctx)[: ctx.config.xss_max_urls]
        if not candidates:
            return "no parameterized URLs to confirm"

        sdir = ctx.stage_dir(self.name)
        blind = ctx.config.xss_blind_callback
        objs = _run_dalfox(ctx, sdir, candidates, "xss_confirm", blind=blind)

        verified = [o for o in objs if (o.get("type") or "").upper() == "V"]
        proofs = dedupe(o.get("data") or "" for o in verified if o.get("data"))
        if proofs:
            proof_file = sdir / "verified_xss.txt"
            write_lines(proof_file, proofs)
            for o in verified:
                if not o.get("data"):
                    continue
                ctx.results.loot.append(Loot(
                    kind="xss-poc",
                    source=self.name,
                    summary=f"triggered {o.get('inject_type') or 'XSS'} in param "
                            f"{o.get('param') or '?'}",
                    path=self._rel(ctx, proof_file),
                ))
            # Promote matching findings to a verified state.
            proven = set(proofs)
            for f in xss:
                if f.matched_at in proven and "verified" not in f.tags:
                    f.tags = [t for t in f.tags if t != "reflected"] + ["verified"]

        record.produced = len(proofs)
        extra = f" (blind callback: {blind})" if blind else ""
        return f"{len(proofs)} XSS payload(s) triggered/confirmed{extra}"

    @staticmethod
    def _rel(ctx: StageContext, path) -> str:
        try:
            return str(path.relative_to(ctx.run_dir))
        except ValueError:
            return str(path)
