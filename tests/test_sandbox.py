import hashlib
import sys

import pytest

from fake_docker import FakeDocker
from reconledger.audit import AuditLog
from reconledger.models import ActionKind, PlannedAction
from reconledger.sandbox import (DEFAULT_IMAGE, ExecResult, LAB_SUBNET, SandboxCaps, SandboxError,
                                 SandboxRunner, output_hash, parse_header_dump, sandbox_tools,
                                 subprocess_executor)
from reconledger.scope import OutOfScopeError, ScopeGuard

LAB_URL = "http://172.30.0.10:3000/"


def make(fake=None, **kw):
    audit = AuditLog()
    fake = fake or FakeDocker()
    return SandboxRunner(ScopeGuard([LAB_SUBNET]), audit=audit, executor=fake, **kw), fake, audit


def docker_opts(argv):
    return argv[:argv.index(DEFAULT_IMAGE)]


def test_argv_has_every_cap_and_isolation_flag():
    runner, _, _ = make()
    argv = runner.build_argv("rl-sbx-x", ["nmap", "-sT", "172.30.0.10"])
    opts = docker_opts(argv)
    pairs = {"--name": "rl-sbx-x", "--network": "reconledger-lab", "--memory": "256m",
             "--memory-swap": "256m", "--cpus": "0.5", "--pids-limit": "128", "--cap-drop": "ALL",
             "--security-opt": "no-new-privileges", "--user": "65534:65534", "--pull": "never"}
    for flag, value in pairs.items():
        assert opts[opts.index(flag) + 1] == value, flag
    assert {"--rm", "--read-only"} <= set(opts)
    assert opts[opts.index("--tmpfs") + 1].startswith("/tmp:")
    assert argv[-3:] == ["nmap", "-sT", "172.30.0.10"]


def test_argv_has_no_mounts_env_or_privileges():
    runner, _, _ = make()
    # -e and -v after the image belong to the tool, so they are allowed there.
    opts = docker_opts(runner.build_argv("c", ["curl", "-e", "x", "-v"]))
    forbidden = {"-v", "--volume", "--mount", "--volumes-from", "-e", "--env", "--env-file",
                 "--privileged", "--cap-add", "-p", "--publish"}
    assert not forbidden & {o.split("=", 1)[0] for o in opts}


@pytest.mark.parametrize("network", ["host", "bridge", "default", "container:rl-juice"])
def test_host_style_networks_are_refused(network):
    with pytest.raises(ValueError):
        make(network=network)


def test_refuses_a_network_that_is_not_internal():
    runner, fake, audit = make(FakeDocker(internal="false"))
    with pytest.raises(SandboxError, match="not internal"):
        runner.run(["true"], target=LAB_URL, action="x")
    assert fake.runs() == []
    assert audit.events[-1]["event"] == "sandbox_refused"


def test_secrets_in_parent_env_never_reach_the_sandbox_or_cli(monkeypatch):
    secret = "placeholder-secret-value"
    for name in ("LLM_API_KEY", "VULTR_TOKEN", "DB_PASSWORD", "MY_SECRET"):
        monkeypatch.setenv(name, secret)
    runner, fake, audit = make()
    res = runner.run(["env"], target=LAB_URL, action="x")
    for argv in fake.calls:
        assert not any(secret in tok for tok in argv)
    for env in fake.envs:
        assert not [k for k in env if any(m in k.upper() for m in ("KEY", "TOKEN", "SECRET", "PASSWORD"))]
        assert secret not in env.values()
    assert secret not in str(audit.events) and secret not in str(res)


def test_teardown_on_success():
    runner, fake, _ = make()
    res = runner.run(["true"], target=LAB_URL, action="x")
    assert res.outcome == "ok" and res.exit_code == 0 and not res.killed_by_timeout
    assert fake.verbs() == ["network", "run", "kill", "rm", "ps"]
    assert fake.calls[3][:3] == ["docker", "rm", "-f"] and fake.calls[3][3] == res.container
    assert res.destroyed


def test_teardown_on_error():
    def boom(command):
        raise OSError("docker went away")
    runner, fake, _ = make(FakeDocker(boom))
    res = runner.run(["true"], target=LAB_URL, action="x")
    assert res.outcome == "error" and res.exit_code is None and "docker went away" in res.stderr
    assert fake.verbs()[-3:] == ["kill", "rm", "ps"] and res.destroyed


def test_teardown_on_timeout():
    runner, fake, audit = make(FakeDocker(lambda c: ExecResult(None, "partial", timed_out=True)))
    res = runner.run(["sleep", "999"], target=LAB_URL, action="x", timeout=3)
    assert res.killed_by_timeout and res.outcome == "timeout" and res.exit_code is None
    assert fake.verbs()[-3:] == ["kill", "rm", "ps"] and res.destroyed
    assert fake.timeouts[1] == 3 and res.caps["timeout"] == 3
    assert audit.events[-1]["killed_by_timeout"] is True


def test_teardown_runs_even_when_the_executor_raises_non_exception():
    def stop(command):
        raise KeyboardInterrupt
    runner, fake, _ = make(FakeDocker(stop))
    with pytest.raises(KeyboardInterrupt):
        runner.run(["true"], target=LAB_URL, action="x")
    assert fake.verbs()[-3:] == ["kill", "rm", "ps"]


def test_destroyed_is_false_when_the_container_survives():
    runner, _, audit = make(FakeDocker(still_listed=True))
    res = runner.run(["true"], target=LAB_URL, action="x")
    assert res.destroyed is False and audit.events[-1]["destroyed"] is False


def test_out_of_scope_target_never_reaches_docker():
    runner, fake, audit = make()
    with pytest.raises(OutOfScopeError):
        runner.run(["curl", "http://example.com/"], target="http://example.com/", action="header_check")
    assert fake.calls == []
    assert audit.events[-1]["event"] == "scope_blocked"


def test_audit_event_and_hash_are_verifiable():
    runner, _, audit = make(FakeDocker(lambda c: ExecResult(0, "out-secretly-long", "err")))
    res = runner.run(["true"], target=LAB_URL, action="nmap_scan", task_id="t1")
    expected = hashlib.sha256("out-secretly-long\0err".encode()).hexdigest()
    assert res.output_sha256 == expected == output_hash(res.stdout, res.stderr)
    e = audit.events[-1]
    assert e["event"] == "sandbox_run" and e["output_sha256"] == expected
    assert e["container"] == res.container and e["image"] == DEFAULT_IMAGE and e["caps"]["memory"] == "256m"
    assert e["outcome"] == "ok" and "duration_s" in e
    assert "out-secretly-long" not in str(e)  # hash only; output stays out of the ledger


def test_each_run_gets_a_unique_container():
    runner, _, _ = make()
    names = {runner.run(["true"], target=LAB_URL, task_id="same").container for _ in range(5)}
    assert len(names) == 5


def test_dry_run_builds_the_command_but_runs_nothing(monkeypatch):
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("subprocess started"))
    runner = SandboxRunner(ScopeGuard([LAB_SUBNET]), dry_run=True)
    res = runner.run(["true"], target=LAB_URL)
    assert res.dry_run and res.outcome == "dry_run"


def test_subprocess_executor_enforces_the_wall_clock():
    res = subprocess_executor([sys.executable, "-c", "import time; print('hi', flush=True); time.sleep(60)"],
                              0.5, {}, 1024)
    assert res.timed_out and res.returncode is None and "hi" in res.stdout


def test_subprocess_executor_bounds_captured_output():
    res = subprocess_executor([sys.executable, "-c", "print('x' * 5_000_000)"], 30, {}, 1000)
    assert res.returncode == 0 and res.truncated and len(res.stdout) == 1000


def test_parse_header_dump_keeps_repeated_headers():
    hdrs = parse_header_dump("HTTP/1.1 200 OK\r\nServer: x:1\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n")
    assert hdrs == {"server": "x:1", "set-cookie": "a=1\nb=2"}


NMAP_XML = ('<nmaprun><host><address addr="172.30.0.10"/><ports><port protocol="tcp" portid="3000">'
            '<state state="open"/><service name="http"/></port></ports></host></nmaprun>')


def _action(name, target, **params):
    return PlannedAction(name, ActionKind.ACTIVE, target, "why", "risk", params)


def test_sandbox_tools_parse_real_shaped_output():
    def handler(command):
        if command[0] == "nmap":
            assert command[-1] == "172.30.0.10" and "-sT" in command
            return ExecResult(0, NMAP_XML)
        assert command[0] == "curl" and command[-1] == LAB_URL
        return ExecResult(0, "HTTP/1.1 200 OK\r\nServer: lab\r\n\r\n")
    runner, _, _ = make(FakeDocker(handler))
    tools = sandbox_tools(runner, "t")
    assert [f.target for f in tools["nmap_scan"](_action("nmap_scan", "172.30.0.10", ports="3000"))] == ["172.30.0.10:3000"]
    titles = [f.title for f in tools["header_check"](_action("header_check", LAB_URL))]
    assert "Missing Content-Security-Policy" in titles
    assert set(tools) == {"nmap_scan", "header_check"}


@pytest.mark.parametrize("result", [ExecResult(1, "", "boom"), ExecResult(None, timed_out=True),
                                    ExecResult(0, "<nmaprun", truncated=True)])
def test_sandbox_tools_raise_instead_of_reporting_nothing_found(result):
    runner, _, _ = make(FakeDocker(lambda c: result))
    with pytest.raises(SandboxError):
        sandbox_tools(runner)["nmap_scan"](_action("nmap_scan", "172.30.0.10", ports="3000"))


def test_caps_are_configurable():
    runner, _, _ = make(caps=SandboxCaps(memory="64m", cpus="0.25", pids=32))
    opts = docker_opts(runner.build_argv("c", ["true"]))
    assert opts[opts.index("--memory") + 1] == "64m" and opts[opts.index("--pids-limit") + 1] == "32"
