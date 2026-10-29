"""Bind real tools to agent action names."""
from __future__ import annotations

from .agent import Tool
from .models import Finding, PlannedAction
from .scope import ScopeGuard
from .tools import headers, nmap


def lab_tools(scope: ScopeGuard) -> dict[str, Tool]:
    def nmap_scan(a: PlannedAction) -> list[Finding]:
        return nmap.parse_xml(nmap.run(a.target, a.params.get("ports", "3000"), scope))

    def header_check(a: PlannedAction) -> list[Finding]:
        _status, hdrs = headers.fetch(a.target, scope)
        return headers.parse(a.target, hdrs)

    return {"nmap_scan": nmap_scan, "header_check": header_check}
