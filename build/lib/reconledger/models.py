"""Core data types shared by every module."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class ActionKind(str, Enum):
    PASSIVE = "passive"  # reads existing data; runs without approval
    ACTIVE = "active"    # touches a target (scan, fuzz, check); needs human approval


@dataclass
class Finding:
    id: str
    source: str            # which stage/tool produced it, e.g. "nmap", "headers"
    target: str            # host or URL inside the lab scope
    title: str
    severity: float = 0.0  # base score 0-10 (e.g. CVSS) before context
    tags: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    score: float = 0.0     # final context-adjusted score (set by the rules engine)
    reasons: list[str] = field(default_factory=list)  # "explain why" trail

    def key(self) -> tuple[str, str]:
        """Dedup key: same target + same normalised title = same issue."""
        return (self.target.lower(), self.title.strip().lower())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlannedAction:
    name: str
    kind: ActionKind
    target: str
    reason: str       # why the agent wants to do this
    risk_note: str = ""  # what could go wrong, shown to the approver
    params: dict[str, Any] = field(default_factory=dict)
