"""Markdown report: ranked ledger with the "why" for each finding."""
from __future__ import annotations

from typing import Any

from .models import Finding


def to_markdown(findings: list[Finding], title: str = "ReconLedger report",
                meta: dict[str, Any] | None = None) -> str:
    lines = [f"# {title}", ""]
    if meta:
        lines.append("## Run summary")
        for k, v in meta.items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")
    lines += ["## Ranked findings", "",
              "| # | Score | Target | Finding | Sources |", "|---|---|---|---|---|"]
    for i, f in enumerate(findings, 1):
        lines.append(f"| {i} | {f.score:.1f} | {f.target} | {f.title} | {f.source} |")
    lines.append("")
    lines.append("## Why each finding ranks where it does")
    for i, f in enumerate(findings, 1):
        lines.append(f"\n**{i}. {f.title}** ({f.score:.1f})")
        for r in f.reasons:
            lines.append(f"- {r}")
        fix = f.evidence.get("fix") if isinstance(f.evidence, dict) else None
        if fix:
            lines.append(f"- **fix:** {fix}")
    return "\n".join(lines) + "\n"
