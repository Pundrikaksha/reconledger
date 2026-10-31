from pathlib import Path

from reconledger.agent import Agent, MockPlanner
from reconledger.approval import approve_all_for_tests, deny_all
from reconledger.audit import AuditLog
from reconledger.ingest import load
from reconledger.models import ActionKind, Finding, PlannedAction
from reconledger.report import to_markdown
from reconledger.rules import JsonRulesEngine

ROOT = Path(__file__).parents[1]
RULES = JsonRulesEngine.from_file(ROOT / "rules" / "default.json")


def _scan_tool(action):
    return [Finding(id="N1", source="scan", target=action.target, title="Open admin panel", severity=8.0)]


def _plan():
    return MockPlanner([
        PlannedAction("passive_lookup", ActionKind.PASSIVE, "127.0.0.1", "read banner cache"),
        PlannedAction("active_scan", ActionKind.ACTIVE, "127.0.0.1:3000", "probe web app", "may load the app"),
        PlannedAction("active_scan", ActionKind.ACTIVE, "8.8.8.8", "out of scope test"),
    ])


def test_active_step_denied_by_default():
    audit = AuditLog()
    agent = Agent(RULES, planner=_plan(), tools={"active_scan": _scan_tool}, audit=audit)
    res = agent.run([])
    assert "active_scan" in res.skipped
    assert res.executed == []
    assert "active_scan" in res.blocked  # 8.8.8.8 never reaches approval
    approvals = [e for e in audit.events if e["event"] == "approval"]
    assert len(approvals) == 1 and approvals[0]["approved"] is False


def test_active_step_runs_when_approved(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    agent = Agent(RULES, planner=_plan(), approver=approve_all_for_tests,
                  tools={"active_scan": _scan_tool}, audit=audit)
    res = agent.run([])
    assert res.executed == ["active_scan"]
    assert res.findings[0].title == "Open admin panel"
    assert (tmp_path / "audit.jsonl").read_text().count("\n") == len(audit.events)


def test_sample_dedup_and_rank():
    findings = load(ROOT / "samples" / "findings.json")
    res = Agent(RULES, approver=deny_all).run(findings)
    titles = [f.title for f in res.findings]
    assert titles.count("Outdated web framework") == 1  # merged across portscan + depscan
    assert res.findings[0].title == "Outdated web framework"
    assert res.findings[-1].title == "SSH banner disclosed"
    md = to_markdown(res.findings)
    assert "Detailed findings (with explain-why)" in md and "Exploitability:" in md
