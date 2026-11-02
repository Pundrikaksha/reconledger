import io

import pytest

from fake_docker import FakeDocker
from reconledger.cli import main
from reconledger.containment_demo import CANARY_NAME, CANARY_VALUE, run_demo
from reconledger.sandbox import ExecResult


def contained(command):
    """A container behaving as it should: no egress, killed by caps, clean env."""
    if command[0] == "curl":
        return ExecResult(0 if "172.30.0.10" in command[-1] else 7, "", "curl: (7) failed")
    if command[0] == "sleep":
        return ExecResult(None, timed_out=True)
    if command[0] == "sh":
        return ExecResult(137)
    assert command == ["env"]
    return ExecResult(0, "PATH=/usr/bin\nHOSTNAME=abc\n")


def run(handler, **kw):
    out = io.StringIO()
    code = run_demo(executor=FakeDocker(handler, **kw), out=out)
    return code, out.getvalue()


def test_all_checks_pass_on_a_contained_sandbox():
    code, text = run(contained)
    assert code == 0 and "FAIL" not in text and "Result: PASS" in text
    assert "scope_blocked is recorded" in text and "hash chain intact" in text


def _override(**by_tool):
    def handler(command):
        if command[0] in by_tool:
            return by_tool[command[0]](command)
        return contained(command)
    return handler


@pytest.mark.parametrize("result", [
    ExecResult(0),                 # the request got out
    ExecResult(127, "", "curl: not found"),  # curl never ran, which proves nothing
    ExecResult(125, "", "no such image"),
])
def test_egress_check_fails_unless_the_network_blocked_it(result):
    code, text = run(_override(curl=lambda c: result))
    assert code == 1 and "NOT shown to be blocked" in text


def test_runaway_check_fails_when_nothing_killed_it():
    code, text = run(_override(sleep=lambda c: ExecResult(0)))
    assert code == 1 and "[FAIL] sleep 999" in text


def test_memory_check_requires_the_oom_exit_code():
    code, text = run(_override(sh=lambda c: ExecResult(2)))
    assert code == 1 and "[FAIL] memory hog" in text


def test_surviving_container_is_a_failure():
    code, text = run(contained, still_listed=True)
    assert code == 1 and "is gone" in text.split("[FAIL]", 1)[1]


def test_env_check_fails_on_secret_name_and_hides_its_value():
    code, text = run(_override(env=lambda c: ExecResult(0, "PATH=/bin\nVULTR_API_KEY=real-looking-value\n")))
    assert code == 1 and "VULTR_API_KEY" in text and "real-looking-value" not in text


def test_env_check_fails_when_env_did_not_run():
    code, text = run(_override(env=lambda c: ExecResult(125, "", "docker error")))
    assert code == 1 and "[FAIL] env ran inside" in text


def test_canary_is_detected_under_any_name():
    code, text = run(_override(env=lambda c: ExecResult(0, f"PATH=/bin\nHARMLESS={CANARY_VALUE}\n")))
    assert code == 1 and "[FAIL] the parent's canary" in text


def test_canary_is_removed_from_the_parent_afterwards(monkeypatch):
    import os
    monkeypatch.delenv(CANARY_NAME, raising=False)
    run(contained)
    assert CANARY_NAME not in os.environ


def test_dry_run_says_it_proved_commands_only(monkeypatch):
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("subprocess started"))
    out = io.StringIO()
    assert run_demo(dry_run=True, out=out) == 0
    text = out.getvalue()
    assert "DRY RUN (nothing executed)" in text and "PASS (dry-run, command only" in text
    assert "not runtime containment" in text
    # What dry-run really can prove (the scope guard ran for real) stays a plain PASS.
    assert "[PASS] scope guard refused" in text


def test_falls_back_to_dry_run_without_docker(monkeypatch, capsys):
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert main(["demo-containment"]) == 0
    assert "falling back to --dry-run" in capsys.readouterr().out


def test_cli_dry_run_flag(capsys):
    assert main(["demo-containment", "--dry-run"]) == 0
    assert "Result: PASS" in capsys.readouterr().out
