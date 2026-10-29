"""Cross-stage correlation: link findings that share a host:port."""
from __future__ import annotations

from collections import defaultdict

from .models import Finding


def correlate(findings: list[Finding]) -> list[Finding]:
    by_target: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_target[f.target.lower()].append(f)
    for target, group in by_target.items():
        sources = {s for f in group for s in f.source.split("+")}
        if "nmap" in sources and len(sources) > 1:
            for f in group:
                if f.source != "nmap" and "confirmed-open" not in f.tags:
                    f.tags.append("confirmed-open")
                    f.reasons.append(f"correlated: nmap confirms {target} is open and reachable")
        # An open port with N weaknesses behind it matters more than an empty one.
        weak = [f for f in group if "misconfig" in f.tags]
        for f in group:
            if f.source == "nmap" and weak:
                f.evidence["weaknesses_behind_port"] = len(weak)
                if "has-weaknesses" not in f.tags:
                    f.tags.append("has-weaknesses")
                    f.reasons.append(f"correlated: {len(weak)} web weaknesses found behind this port")
    return findings
