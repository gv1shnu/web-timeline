"""Small shared helpers used across stages."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Iterator


def iter_json_lines(text: str) -> Iterator[dict]:
    """Yield parsed JSON objects from JSONL/NDJSON tool output, skipping junk."""
    for line in text.splitlines():
        line = line.strip()
        if not line or not (line.startswith("{") or line.startswith("[")):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    yield item


def write_lines(path: Path, lines: Iterable[str]) -> int:
    """Write iterable of lines to a file; return count written."""
    items = [str(x).strip() for x in lines if str(x).strip()]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(items) + ("\n" if items else ""))
    return len(items)


def in_scope(host: str, targets: Iterable[str]) -> bool:
    """True if host is one of, or a subdomain of, any target root domain."""
    host = host.strip().lower().rstrip(".")
    for t in targets:
        t = t.strip().lower().rstrip(".")
        if host == t or host.endswith("." + t):
            return True
    return False


def clean_host(raw: str) -> str:
    """Normalise a hostname line (strip wildcards, ports, protocols)."""
    h = raw.strip().lower().lstrip("*.").rstrip(".")
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0].split(":", 1)[0]
    return h


def dedupe(seq: Iterable[str]) -> list[str]:
    """Order-preserving de-duplication."""
    seen: set[str] = set()
    out: list[str] = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
