"""Agent loop: plan -> (approve) -> act -> correlate -> rank -> report.

Passive steps run on their own. Active steps are checked against the scope
guard and then stopped for human approval. Everything is audited. The planner
is pluggable: a deterministic mock planner by default (no API keys), with an
LLM planner to be added behind the same interface.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol

from .approval import Approver, deny_all
from .audit import AuditLog
from .ingest import dedupe
from .models import ActionKind, Finding, PlannedAction
from .rules import RulesEngine
from .scope import OutOfScopeError, ScopeGuard


class Planner(Protocol):
    def plan(self, findings: list[Finding]) -> list[PlannedAction]: ...


class MockPlanner:
    """Deterministic planner used offline and in tests."""

    def __init__(self, actions: list[PlannedAction] | None = None):
        self.actions = actions or []

    def plan(self, findings: list[Finding]) -> list[PlannedAction]:
        return list(self.actions)


Tool = Callable[[PlannedAction], list[Finding]]


@dataclass
class RunResult:
    findings: list[Finding]
    executed: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)


class Agent:
    def __init__(
        self,
        rules: RulesEngine,
        scope: ScopeGuard | None = None,
        planner: Planner | None = None,
        approver: Approver = deny_all,
        tools: dict[str, Tool] | None = None,
        audit: AuditLog | None = None,
    ):
        self.rules = rules
        self.scope = scope or ScopeGuard()
        self.planner = planner or MockPlanner()
        self.approver = approver
        self.tools = tools or {}
        self.audit = audit or AuditLog()

    def run(self, initial: list[Finding]) -> RunResult:
        findings = list(initial)
        result = RunResult(findings=[])
        self.audit.record("run_start", initial=len(findings))

        for action in self.planner.plan(findings):
            self.audit.record("planned", action=action.name, kind=action.kind.value,
                              target=action.target, reason=action.reason)
            try:
                self.scope.check(action.target)
            except OutOfScopeError as exc:
                self.audit.record("blocked_scope", action=action.name, error=str(exc))
                result.blocked.append(action.name)
                continue
            if action.kind is ActionKind.ACTIVE:
                ok, who = self.approver(action)
                self.audit.record("approval", action=action.name, approved=ok, by=who,
                                  risk_note=action.risk_note)
                if not ok:
                    result.skipped.append(action.name)
                    continue
            tool = self.tools.get(action.name)
            if tool is None:
                self.audit.record("no_tool", action=action.name)
                result.skipped.append(action.name)
                continue
            new = tool(action)
            self.audit.record("executed", action=action.name, new_findings=len(new))
            result.executed.append(action.name)
            findings.extend(new)

        merged = dedupe(findings)
        for f in merged:
            self.rules.score(f)
        merged.sort(key=lambda f: f.score, reverse=True)
        self.audit.record("ranked", count=len(merged),
                          top=[(f.id, f.score) for f in merged[:5]])
        result.findings = merged
        return result
