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
