"""Render a ReconResults object to a self-contained HTML report."""

from __future__ import annotations

from pathlib import Path

from ..models import ReconResults, SEVERITY_ORDER

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except ImportError:  # pragma: no cover - jinja2 is a listed dependency
    Environment = None  # type: ignore

TEMPLATE_DIR = Path(__file__).parent / "templates"

SEVERITY_COLORS = {
    "critical": "#7c1d1d",
    "high": "#b91c1c",
    "medium": "#c2740c",
    "low": "#2563eb",
    "info": "#4b5563",
    "unknown": "#6b7280",
}


def render_html(results: ReconResults, out_path: Path) -> Path:
    if Environment is None:
        raise RuntimeError("Jinja2 is required to render HTML reports (pip install jinja2)")

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.html.j2")
    html = template.render(
        r=results,
        data=results.to_dict(),
        severity_order=SEVERITY_ORDER,
        severity_colors=SEVERITY_COLORS,
    )
    out_path.write_text(html, encoding="utf-8")
    return out_path
