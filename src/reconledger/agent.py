"""Agent loop: plan -> scope check -> (approve) -> act -> correlate -> rank.

The loop runs in rounds: after each round the planner sees every finding so far
and may propose follow-up actions (e.g. header checks on ports nmap found open).
Passive steps run on their own. Every action is scope-checked first, and every
ACTIVE action stops for human approval. Everything is audited. The planner is
pluggable: deterministic planners by default (no API keys); an LLM planner can
sit behind the same interface.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol

from .approval import Approver, deny_all
from .audit import AuditLog
from .correlate import correlate
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


class LabPlanner:
    """Rule-based planner for the localhost lab.

    Round 1: port scan the lab host (active).
    Round 2+: for every open web port: HTTP security-header check (cheap, one GET)
    and a Nikto web scan (heavier, safe tuning only). Both need approval.
    """

    def __init__(self, host: str, ports: str, nikto: bool = True):
        self.host, self.ports, self.nikto = host, ports, nikto

    def plan(self, findings: list[Finding]) -> list[PlannedAction]:
        actions = [PlannedAction(
            "nmap_scan", ActionKind.ACTIVE, self.host,
            reason=f"discover which lab services listen on ports {self.ports}",
            risk_note="TCP connect scan; sends connection attempts to the lab host only",
            params={"ports": self.ports})]
        for f in findings:
            if f.source.startswith("nmap") and "web" in f.tags:
                actions.append(PlannedAction(
                    "header_check", ActionKind.ACTIVE, f"http://{f.target}/",
                    reason=f"{f.title} looks like a web app; check its HTTP security headers",
                    risk_note="one HTTP GET to the lab app; no payloads"))
                if self.nikto:
                    actions.append(PlannedAction(
                        "nikto_scan", ActionKind.ACTIVE, f"http://{f.target}/",
                        reason=(f"{f.title} is a web service; header checks only see one response, "
                                "so run Nikto to look for exposed files, directories and known-bad "
                                "components, then validate its hits against a soft-404 baseline"),
                        risk_note=("~5,000 HTTP requests to the lab app over up to 3 minutes; safe "
                                   "tuning 0123b (no injection or DoS checks)")))
        return actions


Tool = Callable[[PlannedAction], list[Finding]]


@dataclass
class RunResult:
    findings: list[Finding]
    executed: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class Agent:
    def __init__(
        self,
        rules: RulesEngine,
        scope: ScopeGuard | None = None,
        planner: Planner | None = None,
        approver: Approver = deny_all,
        tools: dict[str, Tool] | None = None,
        audit: AuditLog | None = None,
        max_rounds: int = 5,
    ):
        self.rules = rules
        self.scope = scope or ScopeGuard()
        self.planner = planner or MockPlanner()
        self.approver = approver
        self.tools = tools or {}
        self.audit = audit or AuditLog()
        self.max_rounds = max_rounds

    def _step(self, action: PlannedAction, result: RunResult) -> list[Finding]:
        self.audit.record("planned", action=action.name, kind=action.kind.value,
                          target=action.target, reason=action.reason)
        try:
            self.scope.check(action.target)
        except OutOfScopeError as exc:
            self.audit.record("blocked_scope", action=action.name, target=action.target, error=str(exc))
            result.blocked.append(action.name)
            return []
        if action.kind is ActionKind.ACTIVE:
            ok, who = self.approver(action)
            self.audit.record("approval", action=action.name, target=action.target,
                              approved=ok, by=who, risk_note=action.risk_note)
            if not ok:
                result.skipped.append(action.name)
                return []
        tool = self.tools.get(action.name)
        if tool is None:
            self.audit.record("no_tool", action=action.name)
            result.skipped.append(action.name)
            return []
        try:
            new = tool(action)
        except Exception as exc:  # a failing tool must not kill the run
            self.audit.record("tool_error", action=action.name, error=repr(exc))
            result.errors.append(f"{action.name}: {exc}")
            return []
        self.audit.record("executed", action=action.name, target=action.target,
                          new_findings=len(new))
        result.executed.append(action.name)
        return new

    def run(self, initial: list[Finding]) -> RunResult:
        findings = list(initial)
        result = RunResult(findings=[])
        seen: set[tuple[str, str]] = set()
        self.audit.record("run_start", initial=len(findings))

        for rnd in range(1, self.max_rounds + 1):
            todo = [a for a in self.planner.plan(findings) if (a.name, a.target) not in seen]
            if not todo:
                break
            self.audit.record("round", n=rnd, actions=[a.name for a in todo])
            for action in todo:
                seen.add((action.name, action.target))
                findings.extend(self._step(action, result))

        merged = correlate(dedupe(findings))
        for f in merged:
            self.rules.score(f)
        merged.sort(key=lambda f: f.score, reverse=True)
        self.audit.record("ranked", count=len(merged),
                          top=[(f.id, f.score) for f in merged[:5]])
        result.findings = merged
        return result
