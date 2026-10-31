"""Command line.

  reconledger triage samples/findings.json            # passive: score + rank existing findings
  reconledger assess --target 127.0.0.1 --ports 3000  # lab loop: plan -> approve -> scan -> rank
  reconledger assess ... --non-interactive --approve-plan approved-plan.json --pdf out/report.pdf
"""
from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .agent import Agent, LabPlanner
from .approval import cli_approver, deny_all, plan_file_approver
from .audit import AuditLog
from .ingest import load
from .report import to_markdown, to_pdf
from .rules import JsonRulesEngine
from .runners import lab_tools
from .scope import OutOfScopeError, ScopeGuard

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULES = str(ROOT / "rules" / "default.json")


def _emit(md: str, out: str | None) -> None:
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(md, encoding="utf-8")
        print(f"report written to {out}")
    else:
        sys.stdout.write(md)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="reconledger")
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("triage", help="ingest findings, score, rank and report (passive only)")
    t.add_argument("input")
    t.add_argument("--format", default="generic-json", help="generic-json | nmap-xml | nikto-json")
    t.add_argument("--pdf", default=None, help="also write a PDF report here")
    t.add_argument("--rules", default=DEFAULT_RULES)
    t.add_argument("--audit", default=None, help="path to write JSONL audit trail")
    t.add_argument("--out", default=None, help="write Markdown report here (default stdout)")

    a = sub.add_parser("assess", help="run the agent loop against the localhost lab")
    a.add_argument("--target", default="127.0.0.1", help="lab host (must be in scope)")
    a.add_argument("--ports", default="3000", help="nmap port spec, e.g. 3000,4280")
    a.add_argument("--scope", action="append", default=None,
                   help="extra loopback/private lab range (repeatable); public ranges refused")
    a.add_argument("--extra-target", action="append", default=[],
                   help="(demo) also plan a header check on this URL to show the scope guard")
    a.add_argument("--rules", default=DEFAULT_RULES)
    a.add_argument("--audit", default=None)
    a.add_argument("--out", default=None)
    a.add_argument("--non-interactive", action="store_true",
                   help="no prompts: deny every active step unless --approve-plan pre-approves it")
    a.add_argument("--approve-plan", default=None,
                   help="analyst-signed JSON of (action, target-pattern) pairs allowed to run")
    a.add_argument("--pdf", default=None, help="also write the PDF VAPT report here")
    a.add_argument("--sign-off", default=None,
                   help="analyst name approving the final report (otherwise it stays DRAFT)")
    a.add_argument("--no-nikto", action="store_true", help="do not plan Nikto scans")
    args = p.parse_args(argv)

    rules = JsonRulesEngine.from_file(args.rules)
    if args.cmd == "triage":
        agent = Agent(rules=rules, audit=AuditLog(args.audit))
        result = agent.run(load(args.input, args.format))
        _emit(to_markdown(result.findings, events=agent.audit.events), args.out)
        if args.pdf:
            to_pdf(result.findings, args.pdf, "ReconLedger triage report", None, agent.audit.events)
        return 0

    scope = ScopeGuard((args.scope or []) + ["127.0.0.0/8", "localhost", "::1/128"])
    try:
        scope.check(args.target)
    except OutOfScopeError as exc:
        print(f"refusing to run: {exc}", file=sys.stderr)
        return 2

    base = LabPlanner(args.target, args.ports, nikto=not args.no_nikto)
    if args.extra_target:
        from .models import ActionKind, PlannedAction

        class _Planner:
            def plan(self, findings):
                return base.plan(findings) + [PlannedAction(
                    "header_check", ActionKind.ACTIVE, u, reason="operator-supplied extra target",
                    risk_note="one HTTP GET") for u in args.extra_target]
        planner = _Planner()
    else:
        planner = base

    if args.approve_plan:
        approver = plan_file_approver(args.approve_plan)
    elif args.non_interactive:
        approver = deny_all
    else:
        approver = cli_approver()
    audit = AuditLog(args.audit)
    agent = Agent(rules, scope=scope, planner=planner, approver=approver,
                  tools=lab_tools(scope), audit=audit,
                  progress=lambda m: print(m, flush=True))
    started = datetime.now(timezone.utc).astimezone()
    t0 = time.monotonic()
    res = agent.run([])
    elapsed = time.monotonic() - t0
    finished = datetime.now(timezone.utc).astimezone()
    approvals = [e for e in audit.events if e["event"] == "approval"]
    meta = {
        "report status": (f"APPROVED by analyst {args.sign_off} at {finished:%d %b %Y %H:%M %Z}"
                          if args.sign_off else "DRAFT - pending analyst review"),
        "started": started.strftime("%d %b %Y %H:%M:%S %Z"),
        "finished": finished.strftime("%d %b %Y %H:%M:%S %Z"),
        "run time": f"{elapsed:.1f} s",
        "target": f"{args.target} ports {args.ports} (localhost lab)",
        "scope allow-list": ", ".join(str(n) for n in scope.nets) + ", localhost",
        "active steps approved / asked": f"{sum(e['approved'] for e in approvals)} / {len(approvals)}",
        "executed": ", ".join(res.executed) or "none",
        "skipped (denied/no tool)": ", ".join(res.skipped) or "none",
        "blocked by scope guard": ", ".join(
            f"{e['action']} -> {e['target']}" for e in audit.events
            if e["event"] == "blocked_scope") or "none",
        "tool errors": "; ".join(res.errors) or "none",
        "findings": len(res.findings),
    }
    _emit(to_markdown(res.findings, "ReconLedger lab assessment", meta, audit.events), args.out)
    if args.pdf:
        Path(args.pdf).parent.mkdir(parents=True, exist_ok=True)
        to_pdf(res.findings, args.pdf, "ReconLedger VAPT report", meta, audit.events)
        print(f"PDF report written to {args.pdf}")
    print(f"{len(res.findings)} findings | executed {len(res.executed)} | "
          f"skipped {len(res.skipped)} | blocked {len(res.blocked)} | errors {len(res.errors)}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
