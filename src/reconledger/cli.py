"""Command line: `reconledger triage samples/findings.json --rules rules/default.json`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .agent import Agent
from .audit import AuditLog
from .ingest import load
from .report import to_markdown
from .rules import JsonRulesEngine

ROOT = Path(__file__).resolve().parents[2]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="reconledger")
    sub = p.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("triage", help="ingest findings, score, rank and report (passive only)")
    t.add_argument("input")
    t.add_argument("--format", default="generic-json")
    t.add_argument("--rules", default=str(ROOT / "rules" / "default.json"))
    t.add_argument("--audit", default=None, help="path to write JSONL audit trail")
    t.add_argument("--out", default=None, help="write Markdown report here (default stdout)")
    args = p.parse_args(argv)

    agent = Agent(rules=JsonRulesEngine.from_file(args.rules), audit=AuditLog(args.audit))
    result = agent.run(load(args.input, args.format))
    md = to_markdown(result.findings)
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
    else:
        sys.stdout.write(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
