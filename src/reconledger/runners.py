"""Bind real tools to agent action names."""
from __future__ import annotations

from .agent import Tool
from .models import Finding, PlannedAction
from .scope import ScopeGuard
from .tools import headers, nikto, nmap


def lab_tools(scope: ScopeGuard) -> dict[str, Tool]:
    def nmap_scan(a: PlannedAction) -> list[Finding]:
        return nmap.parse_xml(nmap.run(a.target, a.params.get("ports", "3000"), scope))

    def header_check(a: PlannedAction) -> list[Finding]:
        _status, hdrs = headers.fetch(a.target, scope)
        return headers.parse(a.target, hdrs)

    def nikto_scan(a: PlannedAction) -> list[Finding]:
        found = nikto.parse_json(nikto.run(a.target, scope))
        return nikto.validate_soft404(a.target, found, scope)

    return {"nmap_scan": nmap_scan, "header_check": header_check, "nikto_scan": nikto_scan}
