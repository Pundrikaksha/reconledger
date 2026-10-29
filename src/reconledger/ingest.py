"""Ingestion: turn tool outputs into Findings.

Stub stage. Real parsers (nmap XML, nuclei JSON, header/TLS checks, SBOM) plug
in here after the problem statement is known. Every parser is a pure function
(text -> list[Finding]) so it can be unit-tested on saved sample files.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from .models import Finding

Parser = Callable[[str], list[Finding]]
PARSERS: dict[str, Parser] = {}


def parser(name: str) -> Callable[[Parser], Parser]:
    def deco(fn: Parser) -> Parser:
        PARSERS[name] = fn
        return fn
    return deco


@parser("generic-json")
def parse_generic_json(text: str) -> list[Finding]:
    """A neutral format: {"findings": [{id, source, target, title, severity, tags}]}"""
    data = json.loads(text)
    return [Finding(**item) for item in data.get("findings", [])]


def load(path: str | Path, fmt: str = "generic-json") -> list[Finding]:
    if fmt not in PARSERS:
        raise ValueError(f"no parser for {fmt!r}; known: {sorted(PARSERS)}")
    return PARSERS[fmt](Path(path).read_text(encoding="utf-8"))


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge duplicates across stages; keep the highest severity, union tags/sources."""
    merged: dict[tuple[str, str], Finding] = {}
    for f in findings:
        k = f.key()
        if k not in merged:
            merged[k] = f
            continue
        m = merged[k]
        m.severity = max(m.severity, f.severity)
        m.tags = sorted(set(m.tags) | set(f.tags))
        if f.source not in m.source.split("+"):
            m.source = f"{m.source}+{f.source}"
    return list(merged.values())


@parser("nmap-xml")
def parse_nmap_xml(text: str) -> list[Finding]:
    from .tools.nmap import parse_xml
    return parse_xml(text)
