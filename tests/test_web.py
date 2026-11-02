import base64
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from fake_docker import FakeDocker  # noqa: E402
from reconledger.audit import LedgerLog  # noqa: E402
from reconledger.sandbox import ExecResult  # noqa: E402
from reconledger.web.app import create_app  # noqa: E402
from test_sandbox import NMAP_XML  # noqa: E402

HEADER_DUMP = "HTTP/1.1 200 OK\r\nServer: lab\r\nAccess-Control-Allow-Origin: *\r\n\r\n"
BASE = "http://127.0.0.1"


def handler(command):
    return ExecResult(0, NMAP_XML if command[0] == "nmap" else HEADER_DUMP)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("WEB_BASIC_AUTH_USER", "WEB_BASIC_AUTH_PASS", "LLM_PROVIDER", "LLM_API_KEY", "LLM_MODEL",
                 "WEB_RATE_LIMIT_PER_MIN", "WEB_MAX_ACTIVE_ASSESSMENTS", "WEB_TRUST_PROXY"):
        monkeypatch.delenv(name, raising=False)


def make(fake=None, **kw):
    fake = fake or FakeDocker(handler)
    app = create_app(executor=fake, **kw)
    return TestClient(app, base_url=BASE, follow_redirects=False), app, fake


def start(client, target="juice-shop"):
    resp = client.post("/assessments", data={"target": target})
    assert resp.status_code == 303
    return resp.headers["location"].rsplit("/", 1)[1]


def wait(client, aid, pred, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        state = client.get(f"/api/assessments/{aid}").json()
        if pred(state):
            return state
        time.sleep(0.01)
    raise AssertionError(f"timed out; last state {state}")


def awaiting(state):
    return next((s for s in state["steps"] if s["status"] == "awaiting_approval"), None)


def decide(client, aid, decision, reason="looks fine"):
    step = awaiting(wait(client, aid, awaiting))
    resp = client.post(f"/assessments/{aid}/steps/{step['id']}/decision",
                       data={"decision": decision, "reason": reason})
    assert resp.status_code == 303
    return step


def done(state):
    return state["status"] != "running"


def test_approve_and_reject_flow():
    client, app, fake = make()
    aid = start(client)

    wait(client, aid, awaiting)
    page = client.get(f"/assessments/{aid}").text
    for text in ("Approve", "Reject", "nmap_scan", "TCP connect scan", "required"):
        assert text in page
    assert fake.runs() == []  # nothing runs before a human approves

    assert decide(client, aid, "approve", "in scope for the lab")["name"] == "nmap_scan"
    step = decide(client, aid, "approve", "one GET is fine")
    assert step["name"] == "header_check" and step["target"] == "http://172.30.0.10:3000/"
    state = wait(client, aid, done)
    assert state["status"] == "complete" and state["findings"] > 1
    assert all(s["status"] == "done" and s["sandbox"]["destroyed"] for s in state["steps"])
    assert [r[r.index("reconledger-sandbox:latest") + 1] for r in fake.runs()] == ["nmap", "curl"]

    page = client.get(f"/assessments/{aid}").text
    for text in ("Missing Content-Security-Policy", "in scope for the lab", "Output SHA-256", "report.md"):
        assert text in page
    events = [e["event"] for e in app.state.ledger.events]
    for event in ("assessment_start", "planned", "approval_decision", "approval", "sandbox_run",
                  "executed", "ranked"):
        assert event in events
    assert app.state.ledger.verify() == (True, None)
    assert "intact" in client.get("/ledger").text


def test_reject_means_no_container_and_no_followups():
    client, _, fake = make()
    aid = start(client)
    decide(client, aid, "reject", "not today")
    state = wait(client, aid, done)
    assert state["status"] == "complete" and state["findings"] == 0
    assert state["steps"][0]["status"] == "rejected" and state["summary"]["skipped"] == ["nmap_scan"]
    assert fake.runs() == [] and fake.calls == []


def test_mixed_decisions_run_only_what_was_approved():
    client, _, fake = make()
    aid = start(client)
    decide(client, aid, "approve")
    decide(client, aid, "reject", "enough for now")
    wait(client, aid, done)
    assert len(fake.runs()) == 1
    assert "nmap" in fake.runs()[0]


@pytest.mark.parametrize("target", ["127.0.0.1", "172.30.0.10", "http://example.com/", "8.8.8.8", "", "JUICE-SHOP"])
def test_unlisted_target_is_rejected_and_audited(target):
    client, app, fake = make()
    resp = client.post("/assessments", data={"target": target})
    assert resp.status_code == 400
    last = app.state.ledger.events[-1]
    assert last["event"] == "scope_blocked" and last["target"] == target
    assert fake.calls == [] and app.state.assessments == {}


def test_target_is_a_fixed_choice_with_no_free_text_box():
    client, _, _ = make()
    page = client.get("/").text
    assert '<select id="target" name="target">' in page and "juice-shop" in page
    assert "<input" not in page


def test_reason_is_required():
    client, app, fake = make()
    aid = start(client)
    step = awaiting(wait(client, aid, awaiting))
    url = f"/assessments/{aid}/steps/{step['id']}/decision"
    for data in ({"decision": "approve"}, {"decision": "approve", "reason": "   "}):
        assert client.post(url, data=data).status_code == 400
    assert client.post(url, data={"decision": "maybe", "reason": "x"}).status_code == 400
    assert awaiting(client.get(f"/api/assessments/{aid}").json()) and fake.runs() == []


def test_decision_cannot_be_replayed_or_aimed_at_a_later_step():
    client, _, _ = make()
    aid = start(client)
    step = decide(client, aid, "approve")
    url = f"/assessments/{aid}/steps/{step['id']}/decision"
    second = awaiting(wait(client, aid, lambda s: (a := awaiting(s)) and a["id"] != step["id"]))
    assert client.post(url, data={"decision": "reject", "reason": "changed my mind"}).status_code == 409
    assert client.post(f"/assessments/{aid}/steps/99/decision",
                       data={"decision": "approve", "reason": "x"}).status_code == 404
    assert second["name"] == "header_check"


def test_unanswered_step_is_denied_on_timeout():
    client, app, fake = make(approval_timeout=0.05)
    aid = start(client)
    state = wait(client, aid, done)
    assert state["steps"][0]["status"] == "rejected" and fake.runs() == []
    assert any(e["event"] == "approval_decision" and e["by"] == "timeout" for e in app.state.ledger.events)


def test_report_download_only_after_the_run():
    client, _, _ = make()
    aid = start(client)
    wait(client, aid, awaiting)
    assert client.get(f"/assessments/{aid}/report.md").status_code == 409
    decide(client, aid, "approve")
    decide(client, aid, "approve")
    wait(client, aid, done)
    resp = client.get(f"/assessments/{aid}/report.md")
    assert resp.status_code == 200 and "attachment" in resp.headers["content-disposition"]
    text = resp.text
    assert "Missing Content-Security-Policy" in text and "verified intact" in text
    assert "ledger head hash" in text and "DRAFT" in text
    assert "Nikto was not run" in text and "and a Nikto scan" not in text


def test_failed_sandbox_step_is_shown_and_does_not_kill_the_run():
    client, _, _ = make(FakeDocker(lambda c: ExecResult(125, "", "image not found")))
    aid = start(client)
    decide(client, aid, "approve")
    state = wait(client, aid, done)
    assert state["status"] == "complete" and state["steps"][0]["status"] == "error"
    assert "image not found" in state["steps"][0]["error"]
    assert "image not found" in client.get(f"/assessments/{aid}").text


def test_html_is_escaped():
    client, _, _ = make()
    aid = start(client)
    decide(client, aid, "reject", "<script>alert(1)</script>")
    wait(client, aid, done)
    page = client.get(f"/assessments/{aid}").text
    assert "<script>alert(1)" not in page and "&lt;script&gt;" in page


def test_concurrent_assessments_are_capped():
    # unset WEB_MAX_ACTIVE_ASSESSMENTS defaults to MAX_ACTIVE = 3
    client, _, _ = make()
    for _ in range(3):
        start(client)
    assert client.post("/assessments", data={"target": "juice-shop"}).status_code == 429


def test_concurrent_assessments_invalid_env_defaults_to_cap(monkeypatch):
    monkeypatch.setenv("WEB_MAX_ACTIVE_ASSESSMENTS", "invalid_value")
    client, _, _ = make()
    for _ in range(3):
        start(client)
    assert client.post("/assessments", data={"target": "juice-shop"}).status_code == 429


def test_concurrent_assessments_unlimited(monkeypatch):
    monkeypatch.setenv("WEB_MAX_ACTIVE_ASSESSMENTS", "0")
    client, _, _ = make()
    for _ in range(4):
        start(client)
    assert len(client.app.state.assessments) == 4


def test_post_rate_limiting(monkeypatch):
    monkeypatch.setenv("WEB_RATE_LIMIT_PER_MIN", "2")
    client, _, _ = make()
    # 2 POST requests succeed
    assert client.post("/assessments", data={"target": "juice-shop"}).status_code == 303
    assert client.post("/assessments", data={"target": "juice-shop"}).status_code == 303
    # 3rd POST request is rate limited
    resp = client.post("/assessments", data={"target": "juice-shop"})
    assert resp.status_code == 429
    assert "rate limit exceeded" in resp.text
    # GET requests are not rate limited
    assert client.get("/").status_code == 200
    assert client.get("/").status_code == 200


def test_rate_limiting_trusted_proxy_uses_leftmost_xff(monkeypatch):
    monkeypatch.setenv("WEB_RATE_LIMIT_PER_MIN", "2")
    monkeypatch.setenv("WEB_TRUST_PROXY", "1")
    client, _, _ = make()
    headers_client1 = {"X-Forwarded-For": "203.0.113.10, 10.0.0.1"}
    headers_client2 = {"X-Forwarded-For": "203.0.113.20, 10.0.0.1"}

    assert client.post("/assessments", data={"target": "juice-shop"}, headers=headers_client1).status_code == 303
    assert client.post("/assessments", data={"target": "juice-shop"}, headers=headers_client1).status_code == 303
    # 3rd request from client 1 hits rate limit
    assert client.post("/assessments", data={"target": "juice-shop"}, headers=headers_client1).status_code == 429

    # client 2 has its own quota
    assert client.post("/assessments", data={"target": "juice-shop"}, headers=headers_client2).status_code == 303


def test_rate_limiting_untrusted_proxy_ignores_xff(monkeypatch):
    monkeypatch.setenv("WEB_RATE_LIMIT_PER_MIN", "2")
    # WEB_TRUST_PROXY is not set
    client, _, _ = make()
    headers_client1 = {"X-Forwarded-For": "203.0.113.10"}
    headers_client2 = {"X-Forwarded-For": "203.0.113.20"}

    assert client.post("/assessments", data={"target": "juice-shop"}, headers=headers_client1).status_code == 303
    assert client.post("/assessments", data={"target": "juice-shop"}, headers=headers_client2).status_code == 303
    # Since proxy is not trusted, client host is used for both, so 3rd POST returns 429
    assert client.post("/assessments", data={"target": "juice-shop"}, headers=headers_client2).status_code == 429


def test_rate_limiter_prunes_expired_entries(monkeypatch):
    monkeypatch.setenv("WEB_RATE_LIMIT_PER_MIN", "10")
    monkeypatch.setenv("WEB_MAX_ACTIVE_ASSESSMENTS", "0")
    client, app, _ = make()
    old_ts = time.monotonic() - 100.0
    # Seed post_history with > 10,000 stale entries
    for i in range(10_005):
        app.state.post_history[f"stale-{i}"] = [old_ts]
    app.state.post_history["active-client"] = [time.monotonic() - 5.0]

    assert len(app.state.post_history) == 10_006
    # POST request should trigger pruning since len > 10,000
    resp = client.post("/assessments", data={"target": "juice-shop"})
    assert resp.status_code == 303
    # Expired entries removed, active-client and current request client remain
    assert "stale-0" not in app.state.post_history
    assert "active-client" in app.state.post_history
    assert len(app.state.post_history) == 2


def test_cross_site_post_is_refused():
    client, _, fake = make()
    resp = client.post("/assessments", data={"target": "juice-shop"},
                       headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403
    resp = client.post("/assessments", data={"target": "juice-shop"},
                       headers={"Sec-Fetch-Site": "cross-site"})
    assert resp.status_code == 403
    assert client.post("/assessments", data={"target": "juice-shop"},
                       headers={"Origin": BASE}).status_code == 303


def test_unauthenticated_mode_serves_loopback_names_only():
    client, _, _ = make()
    assert client.get("/").status_code == 200
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400


def _basic(user, password):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


def test_basic_auth_when_configured(monkeypatch):
    monkeypatch.setenv("WEB_BASIC_AUTH_USER", "analyst")
    monkeypatch.setenv("WEB_BASIC_AUTH_PASS", "placeholder-pass")
    client, app, _ = make(bind_host="0.0.0.0")
    resp = client.get("/")
    assert resp.status_code == 401 and "Basic" in resp.headers["www-authenticate"]
    assert client.get("/", headers=_basic("analyst", "wrong")).status_code == 401
    assert client.get("/", headers={"Authorization": "Basic !!!"}).status_code == 401
    auth = _basic("analyst", "placeholder-pass")
    assert client.get("/", headers=auth).status_code == 200
    resp = client.post("/assessments", data={"target": "juice-shop"}, headers=auth)
    assert resp.status_code == 303
    assert "placeholder-pass" not in str(app.state.ledger.events)
    assert any(e.get("by") == "web:analyst" for e in app.state.ledger.events)


@pytest.mark.parametrize("host", ["0.0.0.0", "203.0.113.5", "::"])
def test_refuses_public_bind_without_auth(host):
    with pytest.raises(ValueError, match="refusing to bind"):
        create_app(executor=FakeDocker(), bind_host=host)


def test_half_configured_auth_is_refused(monkeypatch):
    monkeypatch.setenv("WEB_BASIC_AUTH_USER", "analyst")
    with pytest.raises(ValueError, match="both"):
        create_app(executor=FakeDocker())


def test_mock_llm_plan_rejection_shows_in_ledger_and_step_list(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    client, app, _ = make()
    aid = start(client)
    state = wait(client, aid, awaiting)
    assert "shell_exec" not in {s["name"] for s in state["steps"]}
    assert awaiting(state)["name"] == "nmap_scan"
    rejected = [e for e in app.state.ledger.events if e["event"] == "llm_plan_rejected"]
    assert rejected and rejected[0]["action"] == "shell_exec"
    assert "LLM (mock)" in client.get("/").text


def test_llm_key_stays_out_of_ui_and_ledger(monkeypatch):
    key = "placeholder-key-for-tests"
    monkeypatch.setenv("LLM_PROVIDER", "vultr")
    monkeypatch.setenv("LLM_API_KEY", key)
    monkeypatch.setenv("LLM_MODEL", "test-model")

    def fail(req, timeout=None):
        raise OSError(f"failed with {req.get_header('Authorization')}")
    monkeypatch.setattr("urllib.request.urlopen", fail)
    client, app, fake = make()
    aid = start(client)
    decide(client, aid, "approve")
    decide(client, aid, "approve")
    wait(client, aid, done)
    pages = (client.get("/").text + client.get("/ledger").text + client.get(f"/assessments/{aid}").text
             + client.get(f"/assessments/{aid}/report.md").text)
    assert key not in pages and key not in str(app.state.ledger.events)
    assert any(e["event"] == "llm_plan_failed" for e in app.state.ledger.events)
    assert not any(key in str(env) or key in str(argv) for env, argv in zip(fake.envs, fake.calls))


def test_ledger_file_is_written_when_configured(tmp_path):
    path = tmp_path / "ledger.jsonl"
    client, _, _ = make(ledger=LedgerLog(path))
    assert client.post("/assessments", data={"target": "nope"}).status_code == 400
    assert "scope_blocked" in path.read_text()
