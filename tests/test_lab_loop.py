"""Full loop with real header runner against a local stub and a fake nmap."""
import http.server
import threading
from pathlib import Path

import pytest

from reconledger.agent import Agent, LabPlanner
from reconledger.approval import approve_all_for_tests, cli_approver, deny_all
from reconledger.audit import AuditLog
from reconledger.models import Finding
from reconledger.rules import JsonRulesEngine
from reconledger.scope import ScopeGuard
from reconledger.tools import headers

ROOT = Path(__file__).parents[1]
RULES = JsonRulesEngine.from_file(ROOT / "rules" / "default.json")


class _Stub(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def port():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def _tools(port, scope):
    def fake_nmap(a):
        return [Finding(id="n", source="nmap", target=f"127.0.0.1:{port}",
                        title=f"Open port {port}/tcp (http)", severity=3.0,
                        tags=["open-port", "exposed", "web"])]

    def header_check(a):
        return headers.parse(a.target, headers.fetch(a.target, scope)[1])
    return {"nmap_scan": fake_nmap, "header_check": header_check}


def test_full_loop_plans_followups_correlates_and_ranks(port):
    scope, audit = ScopeGuard(), AuditLog()
    agent = Agent(RULES, scope=scope, planner=LabPlanner("127.0.0.1", str(port)),
                  approver=approve_all_for_tests, tools=_tools(port, scope), audit=audit)
    res = agent.run([])
    assert res.executed == ["nmap_scan", "header_check"]  # header check planned in round 2
    top = res.findings[0]
    assert top.title == "Missing Content-Security-Policy"
    assert "confirmed-open" in top.tags
    assert any(r.startswith("correlated:") for r in top.reasons)
    rounds = [e for e in audit.events if e["event"] == "round"]
    assert len(rounds) == 2


def test_denied_scan_means_no_followups(port):
    scope = ScopeGuard()
    res = Agent(RULES, scope=scope, planner=LabPlanner("127.0.0.1", str(port)),
                approver=deny_all, tools=_tools(port, scope)).run([])
    assert res.executed == [] and res.skipped == ["nmap_scan"] and res.findings == []


def test_cli_prompt_controls_each_step(port, capsys):
    answers = iter(["y", "n"])  # approve the scan, deny the header check
    scope = ScopeGuard()
    res = Agent(RULES, scope=scope, planner=LabPlanner("127.0.0.1", str(port)),
                approver=cli_approver(lambda _p: next(answers)), tools=_tools(port, scope)).run([])
    assert res.executed == ["nmap_scan"] and res.skipped == ["header_check"]
    assert capsys.readouterr().out.count("[APPROVAL NEEDED]") == 2
