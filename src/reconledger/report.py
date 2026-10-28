"""Markdown report: ranked ledger with the "why" for each finding."""
from __future__ import annotations

from .models import Finding


def to_markdown(findings: list[Finding], title: str = "ReconLedger report") -> str:
    lines = [f"# {title}", "", "| # | Score | Target | Finding | Sources |", "|---|---|---|---|---|"]
    for i, f in enumerate(findings, 1):
        lines.append(f"| {i} | {f.score:.1f} | {f.target} | {f.title} | {f.source} |")
    lines.append("")
    lines.append("## Why each finding ranks where it does")
    for i, f in enumerate(findings, 1):
        lines.append(f"\n**{i}. {f.title}** ({f.score:.1f})")
        for r in f.reasons:
            lines.append(f"- {r}")
    return "\n".join(lines) + "\n"
