import json
import shutil
import subprocess
from pathlib import Path

from reconledger.agent import Agent
from reconledger.approval import deny_all, plan_file_approver
from reconledger.audit import AuditLog
from reconledger.explain import explain
from reconledger.models import ActionKind, Finding, PlannedAction
from reconledger.report import to_markdown, to_pdf
from reconledger.rules import JsonRulesEngine
from reconledger.tools import nikto

ROOT = Path(__file__).parents[1]
RULES = JsonRulesEngine.from_file(ROOT / "rules" / "default.json")
DATA = ROOT / "tests" / "data" / "nikto-juice.json"


def _ranked():
    nmap = Finding(id="n", source="nmap", target="127.0.0.1:3000", title="Open port 3000/tcp",
                   severity=3.0, tags=["open-port", "exposed", "web"])
    hdr = Finding(id="h", source="headers", target="127.0.0.1:3000",
                  title="Missing Content-Security-Policy", severity=5.0,
                  tags=["web", "misconfig", "xss-risk"])
    fs = nikto.parse_json(DATA.read_text())
    nikto.validate_soft404("http://127.0.0.1:3000/", fs, __import__("reconledger.scope").scope.ScopeGuard(),
                           lambda u: (200, b"dir") if u.endswith("/ftp/") else (200, b"spa"))
    return Agent(RULES, approver=deny_all).run([nmap, hdr, *fs]).findings


def test_explain_is_deterministic_and_uses_run_data():
    fs = _ranked()
    a = [explain(f).summary for f in fs]
    b = [explain(f).summary for f in _ranked()]
    assert a == b
    csp = next(f for f in fs if f.title == "Missing Content-Security-Policy")
    x = explain(csp, "planned because port 3000 is web")
    assert csp.source == "headers+nikto" and x.confidence.startswith("High (independently")
    assert "multi-tool-agreement" in x.context and "nmap" in x.exposure
    assert "script-injection" in x.exploitability and x.why_planned


def test_soft404_hits_rank_below_real_findings():
    fs = _ranked()
    hist = next(f for f in fs if f.evidence.get("url") == "/.bash_history")
    csp = next(f for f in fs if f.title == "Missing Content-Security-Policy")
    assert hist.score < 2.0 < csp.score
    assert explain(hist).confidence.startswith("Low")


def test_llm_hook_optional_and_failsafe():
    f = _ranked()[0]
    assert explain(f, llm=lambda p: "REWRITTEN").summary == "REWRITTEN"
    base = explain(f).summary

    def boom(p):
        raise RuntimeError("no key")
    assert explain(f, llm=boom).summary == base


def test_markdown_has_ps1_section_7_parts():
    md = to_markdown(_ranked(), "t", {"started": "s", "finished": "f", "run time": "1 s"}, [])
    for s in ("1. Executive summary", "2. Assessment methodology", "Rules of engagement",
              "Tool execution summary", "3. Severity distribution", "4. Detailed findings",
              "Confidence:", "Validation status:", "CWE / OWASP", "5. Impact and remediation",
              "6. Assessment limitations", "Human approvals", "Appendix A"):
        assert s in md, s


def test_pdf_written(tmp_path):
    out = tmp_path / "r.pdf"
    audit = AuditLog()
    audit.record("planned", action="nmap_scan", target="127.0.0.1", reason="discover ports")
    audit.record("approval", action="nmap_scan", target="127.0.0.1", approved=True, by="analyst")
    to_pdf(_ranked(), str(out), "ReconLedger VAPT report", {"report status": "DRAFT"}, audit.events)
    raw = out.read_bytes()
    assert raw.startswith(b"%PDF") and len(raw) > 5000
    if shutil.which("pdftotext"):
        text = subprocess.run(["pdftotext", str(out), "-"], capture_output=True, text=True).stdout
        for s in ("Executive summary", "Assessment methodology", "Severity distribution",
                  "Detailed vulnerability findings", "Impact and remediation",
                  "Assessment limitations", "approval and audit trail", "Explain why"):
            assert s in text, s


def test_plan_file_approver_only_allows_listed_steps(tmp_path):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"analyst": "A. Analyst", "approved": [
        {"action": "nmap_scan", "target": "127.0.0.1"},
        {"action": "header_check", "target": "http://127.0.0.1:*"}]}))
    ap = plan_file_approver(str(plan))
    assert ap(PlannedAction("nmap_scan", ActionKind.ACTIVE, "127.0.0.1", "r")) == (True, "plan-file:A. Analyst")
    assert ap(PlannedAction("header_check", ActionKind.ACTIVE, "http://127.0.0.1:3000/", "r"))[0]
    assert not ap(PlannedAction("nikto_scan", ActionKind.ACTIVE, "http://127.0.0.1:3000/", "r"))[0]
    assert not ap(PlannedAction("nmap_scan", ActionKind.ACTIVE, "127.0.0.2", "r"))[0]
