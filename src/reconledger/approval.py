"""Human-approval gate. Every ACTIVE action must pass through here."""
from __future__ import annotations

from typing import Callable, Protocol

from .models import PlannedAction


class Approver(Protocol):
    def __call__(self, action: PlannedAction) -> tuple[bool, str]:
        """Return (approved, who/why)."""


def cli_approver(input_fn: Callable[[str], str] = input) -> Approver:
    def _ask(action: PlannedAction) -> tuple[bool, str]:
        print(f"\n[APPROVAL NEEDED] {action.name} -> {action.target}")
        print(f"  reason: {action.reason}")
        if action.risk_note:
            print(f"  risk:   {action.risk_note}")
        answer = input_fn("  approve? [y/N] ").strip().lower()
        return answer in {"y", "yes"}, "cli-operator"
    return _ask


def deny_all(action: PlannedAction) -> tuple[bool, str]:
    """Safe default for non-interactive runs: never auto-approve active steps."""
    return False, "auto-deny (non-interactive)"


def approve_all_for_tests(action: PlannedAction) -> tuple[bool, str]:
    return True, "test-approver"


def plan_file_approver(path: str) -> Approver:
    """Pre-approved plan for unattended runs: the analyst signs a JSON file listing
    exactly which (action, target-pattern) pairs may run. Anything else is denied.

    {"analyst": "name", "approved": [{"action": "nmap_scan", "target": "127.0.0.1",
                                      "reason": "why the analyst allows it"}]}
    """
    import fnmatch
    import json
    from pathlib import Path

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    who = f"plan-file:{data.get('analyst', 'unknown')}"
    allowed = [(a["action"], a["target"]) for a in data.get("approved", [])]

    def _check(action: PlannedAction) -> tuple[bool, str]:
        ok = any(action.name == n and fnmatch.fnmatch(action.target, pat) for n, pat in allowed)
        print(f"[APPROVAL {'GRANTED' if ok else 'DENIED'} by {who}] {action.name} -> {action.target}")
        return ok, who
    return _check
