"""Otari hook tests. urllib is faked throughout: nothing here touches the network."""
import io
import json
import socket
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from reconledger.agent import Agent
from reconledger.audit import AuditLog
from reconledger.cli import main
from reconledger.explain import explain
from reconledger.ingest import load
from reconledger.llm import llm_config, make_llm_hook, stats_line
from reconledger.report import _deterministic_summary, build, to_markdown, to_pdf
from reconledger.rules import JsonRulesEngine

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = str(ROOT / "samples" / "findings.json")
KEY = "tk-FAKE-test-key-0123456789"
BASE = {"RECONLEDGER_LLM_PROVIDER": "otari", "OTARI_API_KEY": KEY, "OTARI_MODEL": "vendor/primary"}


def _ok(text="REWRITTEN", **choice):
    payload = {"choices": [{"message": {"content": text}, **choice}]}
    return io.BytesIO(json.dumps(payload).encode())


def _http_error(code):
    return urllib.error.HTTPError("https://gateway.invalid/x", code, "err", {}, io.BytesIO(b"{}"))


class FakeGateway:
    """Replaces urlopen. Each reply is a response, or an exception to raise; the last one repeats."""

    def __init__(self, monkeypatch, *replies):
        self.replies = [r.read() if isinstance(r, io.BytesIO) else r for r in replies] or [_ok().read()]
        self.requests = []
        monkeypatch.setattr(urllib.request, "urlopen", self)

    def __call__(self, req, timeout=None):
        self.requests.append({"req": req, "timeout": timeout, "body": json.loads(req.data)})
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(reply, Exception):
            raise reply
        return io.BytesIO(reply)

    @property
    def models(self):
        return [r["body"]["model"] for r in self.requests]


def _findings():
    return Agent(rules=JsonRulesEngine.from_file(str(ROOT / "rules" / "default.json"))).run(
        load(SAMPLE, "generic-json")).findings


def _hook(**env):
    return make_llm_hook({**BASE, **env})


# ------------------------------------------------------------ selecting a hook
@pytest.mark.parametrize("env", [{}, {"RECONLEDGER_LLM_PROVIDER": ""}, {"RECONLEDGER_LLM_PROVIDER": "none"}])
def test_off_returns_none_without_warning(env, capsys):
    assert make_llm_hook(env) is None
    assert make_llm_hook(env, role="summary") is None
    assert capsys.readouterr().err == ""


def test_env_defaults_to_process_environment(monkeypatch):
    assert make_llm_hook() is None
    for name, value in BASE.items():
        monkeypatch.setenv(name, value)
    assert make_llm_hook().model == "vendor/primary"


def test_off_makes_no_call_and_keeps_deterministic_text(monkeypatch):
    gateway = FakeGateway(monkeypatch)
    findings = _findings()
    md = to_markdown(findings, llm=make_llm_hook({}), summary_llm=make_llm_hook({}, role="summary"))
    assert gateway.requests == []
    assert "No LLM used; all text deterministic." in md
    assert _deterministic_summary(build(findings)) in md
    for f in findings:
        assert explain(f).summary in md


def test_unknown_provider_warns_once_and_does_not_echo_value(capsys):
    env = {"RECONLEDGER_LLM_PROVIDER": "pasted-by-mistake"}
    assert make_llm_hook(env) is None
    assert make_llm_hook(env, role="summary") is None
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "RECONLEDGER_LLM_PROVIDER" in err and "pasted-by-mistake" not in err


def test_missing_key_warns_once_across_both_roles(capsys):
    env = {"RECONLEDGER_LLM_PROVIDER": "otari", "OTARI_MODEL": "m", "OTARI_SUMMARY_MODEL": "s"}
    assert make_llm_hook(env) is None
    assert make_llm_hook(env, role="summary") is None
    err = capsys.readouterr().err
    assert err.count("OTARI_API_KEY not set; using deterministic text") == 1 and err.count("\n") == 1


def test_missing_model_warns_and_returns_none(capsys):
    assert make_llm_hook({"RECONLEDGER_LLM_PROVIDER": "otari", "OTARI_API_KEY": KEY}) is None
    assert "OTARI_MODEL" in capsys.readouterr().err


def test_invalid_guardrail_mode_disables_rather_than_sending_unprotected(capsys):
    assert _hook(OTARI_GUARDRAILS="blokc") is None
    assert "OTARI_GUARDRAILS" in capsys.readouterr().err


def test_summary_role_uses_summary_model_and_is_none_when_unset(monkeypatch):
    assert make_llm_hook(BASE, role="summary") is None
    gateway = FakeGateway(monkeypatch)
    make_llm_hook({**BASE, "OTARI_SUMMARY_MODEL": "vendor/second"}, role="summary")("text")
    assert gateway.models == ["vendor/second"]


# -------------------------------------------------------------------- requests
def test_request_shape(monkeypatch):
    gateway = FakeGateway(monkeypatch, _ok("  answer \n"))
    assert _hook(OTARI_BASE_URL="https://gw.example/api/v1/", OTARI_TIMEOUT="7")("the prompt") == "answer"
    sent = gateway.requests[0]
    req, body = sent["req"], sent["body"]
    assert req.full_url == "https://gw.example/api/v1/chat/completions"
    assert req.get_method() == "POST"
    assert req.get_header("Authorization") == f"Bearer {KEY}"
    assert req.get_header("Content-type") == "application/json"
    assert req.get_header("User-agent").startswith("reconledger/")
    assert sent["timeout"] == 7
    assert body["model"] == "vendor/primary"
    assert body["temperature"] == 0.2 and body["max_tokens"] == 300
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert body["messages"][1]["content"] == "the prompt"
    assert "guardrails" not in body


def test_default_base_url_and_timeout(monkeypatch):
    gateway = FakeGateway(monkeypatch)
    _hook()("p")
    assert gateway.requests[0]["req"].full_url == "https://api.otari.ai/api/v1/chat/completions"
    assert gateway.requests[0]["timeout"] == 20


def test_key_is_not_forwarded_on_redirect():
    req = _hook()._request("m", "p")
    redirected = urllib.request.HTTPRedirectHandler().redirect_request(
        req, io.BytesIO(), 302, "Found", {}, "https://elsewhere.example/")
    assert redirected.get_header("Authorization") is None


@pytest.mark.parametrize("mode,field", [
    ("off", None),
    ("monitor", [{"profile": "prompt-injection", "mode": "monitor"}]),
    ("block", [{"profile": "prompt-injection", "mode": "block"}]),
])
def test_guardrails_field_only_when_enabled(monkeypatch, mode, field):
    gateway = FakeGateway(monkeypatch)
    _hook(OTARI_GUARDRAILS=mode)("p")
    assert gateway.requests[0]["body"].get("guardrails") == field


def test_memoised_so_markdown_and_pdf_do_not_double_call(monkeypatch, tmp_path):
    gateway = FakeGateway(monkeypatch)
    findings = _findings()
    llm = _hook()
    summary = make_llm_hook({**BASE, "OTARI_SUMMARY_MODEL": "vendor/second"}, role="summary")
    to_markdown(findings, llm=llm, summary_llm=summary)
    sent = len(gateway.requests)
    assert sent == llm.stats.calls + summary.stats.calls > 1
    to_pdf(findings, str(tmp_path / "r.pdf"), llm=llm, summary_llm=summary)
    assert len(gateway.requests) == sent


# -------------------------------------------------------------------- failures
@pytest.mark.parametrize("failure", [
    _http_error(500), _http_error(502), socket.timeout("timed out"), _ok("   "), _ok(None),
    _ok("cut off mid", finish_reason="length"), io.BytesIO(b"not json"), io.BytesIO(b'{"choices": []}'),
])
def test_primary_failure_uses_fallback(monkeypatch, failure):
    gateway = FakeGateway(monkeypatch, failure, _ok("from fallback"))
    hook = _hook(OTARI_FALLBACK_MODEL="vendor/backup")
    assert hook("p") == "from fallback"
    assert gateway.models == ["vendor/primary", "vendor/backup"]
    s = hook.stats
    assert (s.calls, s.ok, s.fallback_used, s.failed) == (1, 1, 1, 0)
    assert s.models == ["vendor/backup"] and sum(s.reasons.values()) == 1


def test_both_fail_explain_returns_deterministic(monkeypatch):
    gateway = FakeGateway(monkeypatch, _http_error(500))
    hook = _hook(OTARI_FALLBACK_MODEL="vendor/backup")
    f = _findings()[0]
    assert explain(f, llm=hook).summary == explain(f).summary
    assert gateway.models == ["vendor/primary", "vendor/backup"]
    assert (hook.stats.ok, hook.stats.failed) == (0, 1)
    assert hook.stats.reasons == {"HTTP 500": 2}


def test_failure_is_memoised_so_renders_agree(monkeypatch):
    gateway = FakeGateway(monkeypatch, _http_error(500), _ok("late success"))
    hook = _hook()
    for _ in range(2):
        with pytest.raises(RuntimeError):
            hook("p")
    assert len(gateway.requests) == 1


def test_guardrail_403_is_deterministic_and_not_retried_on_fallback(monkeypatch):
    gateway = FakeGateway(monkeypatch, _http_error(403))
    hook = _hook(OTARI_GUARDRAILS="block", OTARI_FALLBACK_MODEL="vendor/backup")
    f = _findings()[0]
    assert explain(f, llm=hook).summary == explain(f).summary
    assert hook.stats.guardrail_blocked == 1
    assert gateway.models == ["vendor/primary"]
    assert hook.stats.reasons == {"guardrail blocked (HTTP 403)": 1}


def test_403_without_guardrails_is_not_counted_as_a_block(monkeypatch):
    FakeGateway(monkeypatch, _http_error(403))
    hook = _hook()
    with pytest.raises(RuntimeError):
        hook("p")
    assert hook.stats.guardrail_blocked == 0 and hook.stats.reasons == {"HTTP 403": 1}


def test_502_with_guardrails_records_reason(monkeypatch):
    FakeGateway(monkeypatch, _http_error(502))
    hook = _hook(OTARI_GUARDRAILS="block")
    f = _findings()[0]
    assert explain(f, llm=hook).summary == explain(f).summary
    assert hook.stats.reasons == {"HTTP 502": 1} and hook.stats.guardrail_blocked == 0


# --------------------------------------------------------------------- reports
def _limit_line(md):
    return next(x for x in md.splitlines() if "LLM" in x and x.startswith("- "))


def test_report_uses_summary_llm_and_names_models(monkeypatch, tmp_path):
    FakeGateway(monkeypatch)
    llm = _hook()
    summary = make_llm_hook({**BASE, "OTARI_SUMMARY_MODEL": "vendor/second"}, role="summary")
    findings = _findings()
    md = to_markdown(findings, llm=llm, summary_llm=summary)
    assert _deterministic_summary(build(findings)) not in md
    assert "Summary: REWRITTEN" in md
    assert _limit_line(md) == (
        "- Narrative text rewritten via Otari gateway (model vendor/primary; summary model vendor/second); "
        "scores, evidence and rankings are deterministic and were not changed by the LLM.")
    assert to_pdf(findings, str(tmp_path / "r.pdf"), llm=llm, summary_llm=summary)


def test_scores_and_rankings_do_not_change(monkeypatch):
    FakeGateway(monkeypatch, _ok("Score 0.0, nothing to see here."))
    plain = to_markdown(_findings())
    rewritten = to_markdown(_findings(), llm=_hook())
    table = lambda md: [x for x in md.splitlines() if x.startswith("| RL-")]
    assert table(plain) == table(rewritten)


def test_report_does_not_claim_a_rewrite_when_every_call_failed(monkeypatch):
    FakeGateway(monkeypatch, _http_error(502))
    md = to_markdown(_findings(), llm=_hook())
    assert _limit_line(md) == "- LLM rewriting was enabled but no call succeeded; all text deterministic."
    assert "Narrative text rewritten" not in md


def test_report_discloses_partial_failure(monkeypatch):
    FakeGateway(monkeypatch, _ok("first ok"), _http_error(502))
    line = _limit_line(to_markdown(_findings(), llm=_hook()))
    assert "rewritten via Otari gateway" in line and "failed and kept the deterministic text" in line


def test_summary_failure_keeps_deterministic_text(monkeypatch):
    FakeGateway(monkeypatch, _http_error(500))
    findings = _findings()
    summary = make_llm_hook({**BASE, "OTARI_SUMMARY_MODEL": "vendor/second"}, role="summary")
    assert _deterministic_summary(build(findings)) in to_markdown(findings, summary_llm=summary)


def test_no_findings_means_no_summary_call(monkeypatch):
    gateway = FakeGateway(monkeypatch)
    summary = make_llm_hook({**BASE, "OTARI_SUMMARY_MODEL": "vendor/second"}, role="summary")
    assert "No findings were produced" in to_markdown([], summary_llm=summary)
    assert gateway.requests == []


# ---------------------------------------------------------------------- the CLI
def _full_env(monkeypatch, **extra):
    for name, value in {**BASE, "OTARI_SUMMARY_MODEL": "vendor/second", "OTARI_BASE_URL": "https://gw.example/api/v1",
                        "OTARI_FALLBACK_MODEL": "vendor/backup", "OTARI_GUARDRAILS": "monitor", **extra}.items():
        monkeypatch.setenv(name, value)


def test_cli_triage_off_records_none_and_no_call(monkeypatch, tmp_path, capsys):
    gateway = FakeGateway(monkeypatch)
    audit, out = tmp_path / "a.jsonl", tmp_path / "r.md"
    assert main(["triage", SAMPLE, "--audit", str(audit), "--out", str(out)]) == 0
    event = json.loads(audit.read_text().splitlines()[0])
    assert event["event"] == "llm_config" and event["provider"] == "none" and event["model"] is None
    assert gateway.requests == []
    assert "No LLM used; all text deterministic." in out.read_text()
    assert "LLM (Otari)" not in capsys.readouterr().err


def test_cli_triage_enabled_records_config_and_prints_stats(monkeypatch, tmp_path, capsys):
    gateway = FakeGateway(monkeypatch)
    _full_env(monkeypatch)
    audit, out, pdf = tmp_path / "a.jsonl", tmp_path / "r.md", tmp_path / "r.pdf"
    assert main(["triage", SAMPLE, "--audit", str(audit), "--out", str(out), "--pdf", str(pdf)]) == 0
    event = json.loads(audit.read_text().splitlines()[0])
    del event["ts"]
    assert event == {"event": "llm_config", "provider": "otari", "model": "vendor/primary",
                     "fallback_model": "vendor/backup", "summary_model": "vendor/second", "guardrails": "monitor"}
    assert set(gateway.models) == {"vendor/primary", "vendor/second"}
    assert pdf.exists()
    err = capsys.readouterr().err
    assert err.count("LLM (Otari)") == 1 and err.count("\n") == 1


def test_cli_assess_records_config_and_passes_hooks(monkeypatch, tmp_path, capsys):
    gateway = FakeGateway(monkeypatch)
    _full_env(monkeypatch)
    audit, out = tmp_path / "a.jsonl", tmp_path / "r.md"
    # No approvals, so no tool runs and no scan traffic. With no findings there is nothing to rewrite.
    assert main(["assess", "--target", "127.0.0.1", "--ports", "1", "--non-interactive",
                 "--audit", str(audit), "--out", str(out)]) == 0
    assert json.loads(audit.read_text().splitlines()[0])["provider"] == "otari"
    assert gateway.requests == []
    assert "LLM (Otari)" in capsys.readouterr().err
    assert "LLM rewriting was enabled but no call succeeded" in out.read_text()


# ---------------------------------------------------------------- key handling
def test_key_never_appears_in_any_output(monkeypatch, tmp_path, capsys):
    FakeGateway(monkeypatch, _ok("fine"), _http_error(403), _http_error(502), socket.timeout("timed out"))
    _full_env(monkeypatch, OTARI_GUARDRAILS="block")
    audit, out = tmp_path / "a.jsonl", tmp_path / "r.md"
    assert main(["triage", SAMPLE, "--audit", str(audit), "--out", str(out)]) == 0
    captured = capsys.readouterr()
    for text in (audit.read_text(), out.read_text(), captured.out, captured.err):
        assert KEY not in text
        assert "gw.example" not in text  # the base URL stays out of reports and audit too


def test_key_never_appears_in_exceptions_stats_or_config(monkeypatch):
    # http.client quotes a rejected header value in its ValueError, so that one is the real trap.
    failures = [ValueError(f"Invalid header value b'Bearer {KEY}'"),
                urllib.error.URLError(f"bad {KEY}"),
                _http_error(401)]
    for failure in failures:
        FakeGateway(monkeypatch, failure)
        hook = _hook()
        with pytest.raises(RuntimeError) as exc:
            hook("p")
        chain = [exc.value, exc.value.__cause__, exc.value.__context__]
        assert not any(KEY in repr(e) for e in chain)
        assert KEY not in repr(hook)
        assert KEY not in repr(hook.stats)
        assert KEY not in json.dumps(llm_config(hook, None))
        assert KEY not in stats_line(hook, None)


def test_stats_hold_no_prompt(monkeypatch):
    FakeGateway(monkeypatch)
    hook = _hook()
    hook("SECRET-PROMPT-TEXT")
    assert "SECRET-PROMPT-TEXT" not in repr(hook.stats)


def test_audit_log_events_from_config_are_serialisable():
    log = AuditLog()
    entry = log.record("llm_config", **llm_config(None, None))
    assert entry["provider"] == "none" and entry["guardrails"] == "off"
