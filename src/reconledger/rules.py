"""Config-driven rules engine for context-aware risk scoring.

Rules live in a JSON file so they can be re-scoped after the problem statement
without code changes. Each rule matches a finding and adjusts its score, and
leaves a human-readable reason (the "explain why").
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .models import Finding


class RulesEngine(Protocol):
    def score(self, finding: Finding) -> Finding: ...


@dataclass
class Rule:
    id: str
    when: dict[str, Any]   # {"tag": "x"} | {"source": "x"} | {"title_contains": "x"} | {"min_severity": n}
    add: float = 0.0
    multiply: float = 1.0
    reason: str = ""

    def matches(self, f: Finding) -> bool:
        w = self.when
        if "tag" in w and w["tag"] not in f.tags:
            return False
        if "source" in w and w["source"] != f.source:
            return False
        if "title_contains" in w and w["title_contains"].lower() not in f.title.lower():
            return False
        if "source_count_min" in w and len(f.source.split("+")) < int(w["source_count_min"]):
            return False
        if "min_severity" in w and f.severity < float(w["min_severity"]):
            return False
        return True


class JsonRulesEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    @classmethod
    def from_file(cls, path: str | Path) -> "JsonRulesEngine":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls([Rule(**r) for r in data["rules"]])

    def score(self, finding: Finding) -> Finding:
        s = finding.severity
        finding.reasons.append(f"base severity {finding.severity:.1f}")
        for rule in self.rules:
            if rule.matches(finding):
                s = s * rule.multiply + rule.add
                finding.reasons.append(f"{rule.id}: {rule.reason or 'matched'}")
        finding.score = round(max(0.0, min(10.0, s)), 2)
        return finding
