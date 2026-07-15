"""Stage 5 — content discovery / URL harvesting.

katana actively crawls live endpoints; waybackurls and gau pull historical URLs
from public archives (passive). Results are capped to keep the report usable.
"""

from __future__ import annotations

from ..models import CrawlUrl, StageRun
from ..util import dedupe, write_lines
from .. import runner
from .base import Stage, StageContext

MAX_URLS = 5000  # hard cap so a noisy target can't bloat the report


class CrawlStage(Stage):
    name = "crawl"
    tools = ["katana", "waybackurls", "gau"]
    active = False  # katana crawling is light; archive sources are passive
    requires_any_tool = True

    def execute(self, ctx: StageContext, record: StageRun) -> str:
        sdir = ctx.stage_dir(self.name)
        collected: dict[str, str] = {}  # url -> first source

        def add(url: str, source: str) -> None:
            url = url.strip()
            if url and url not in collected and len(collected) < MAX_URLS:
                collected[url] = source

        live_urls = [e.url for e in ctx.results.endpoints if e.status]

        if "katana" in ctx.config.crawl_tools and runner.have("katana") and live_urls:
            urls_file = sdir / "seed_urls.txt"
            write_lines(urls_file, live_urls)
            res = runner.run(
                ["katana", "-silent", "-jc", "-d", str(ctx.config.crawl_depth),
                 "-list", str(urls_file), "-c", str(ctx.config.threads),
                 "-rl", str(ctx.config.rate_limit)],
                timeout=ctx.config.timeout_for(self.name),
                log_dir=sdir, log_name="katana")
            for line in res.lines():
                add(line, "katana")

        for domain in ctx.targets:
            if "waybackurls" in ctx.config.crawl_tools and runner.have("waybackurls"):
                res = runner.run(["waybackurls", domain], stdin_data=domain + "\n",
                                 timeout=ctx.config.timeout_for(self.name),
                                 log_dir=sdir, log_name=f"waybackurls_{domain}")
                for line in res.lines():
                    add(line, "waybackurls")

            if "gau" in ctx.config.crawl_tools and runner.have("gau"):
                res = runner.run(["gau", "--subs", domain],
                                 timeout=ctx.config.timeout_for(self.name),
                                 log_dir=sdir, log_name=f"gau_{domain}")
                for line in res.lines():
                    add(line, "gau")

        for url, source in collected.items():
            ctx.results.crawl_urls.append(CrawlUrl(url=url, source=source))

        write_lines(sdir / "all_urls.txt", dedupe(collected.keys()))
        record.produced = len(collected)
        capped = " (capped)" if len(collected) >= MAX_URLS else ""
        return f"{len(collected)} unique URLs{capped}"
