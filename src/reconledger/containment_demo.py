"""Containment demo: four checks against the real SandboxRunner, with PASS/FAIL lines.

A check passes only on positive evidence. A failure to start (bad image, docker error)
is a FAIL, never a PASS. Dry-run checks the commands only and says so on every line,
because it proves nothing about what a running container can do.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import replace

from .audit import LedgerLog
from .sandbox import (DEFAULT_IMAGE, DEFAULT_NETWORK, LAB_SUBNET, LAB_TARGETS, SECRET_MARKERS,
                      SandboxCaps, SandboxRunner)
from .scope import OutOfScopeError, ScopeGuard

# curl exit codes that mean "the network said no": no DNS, connection refused or
# unreachable, timed out. 125-127 mean the container or curl never ran, which proves nothing.
CURL_BLOCKED = {6: "could not resolve host", 7: "could not connect", 28: "timed out"}
EGRESS_PROBES = (("public internet IP", "http://1.1.1.1/"),
                 ("public hostname", "http://example.com/"),
                 ("cloud metadata service", "http://169.254.169.254/"))
CANARY_NAME = "RECONLEDGER_DEMO_API_KEY"
CANARY_VALUE = "demo-canary-not-a-real-secret"
SECRET_NAME_RE = re.compile("|".join(SECRET_MARKERS), re.I)


class Report:
    def __init__(self, dry_run: bool, out=None):
        self.dry_run, self.failed, self.out = dry_run, 0, out or sys.stdout

    def say(self, msg: str) -> None:
        print(msg, file=self.out, flush=True)

    def check(self, ok: bool, msg: str, proven_in_dry_run: bool = False) -> None:
        self.failed += not ok
        label = "PASS" if ok else "FAIL"
        if self.dry_run and ok and not proven_in_dry_run:
            label = "PASS (dry-run, command only, nothing executed)"
        self.say(f"[{label}] {msg}")


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _prerequisites(image: str, network: str) -> list[str]:
    missing = []
    if subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode != 0:
        missing.append(f"image {image}: docker build -t {image} -f deploy/sandbox/Dockerfile.sandbox deploy/sandbox")
    if subprocess.run(["docker", "network", "inspect", network], capture_output=True).returncode != 0:
        missing.append(f"network {network}: docker compose -f lab/docker-compose.yml up -d")
    return missing


class _Counting:
    """Counts docker invocations, to show a scope block never reached docker."""

    def __init__(self, inner):
        self.inner, self.calls = inner, []

    def __call__(self, argv, timeout, env, max_bytes):
        self.calls.append(argv)
        return self.inner(argv, timeout, env, max_bytes)


def check_scope_block(rep: Report, runner: SandboxRunner, ledger: LedgerLog, counter: _Counting) -> None:
    rep.say("\n(a) Out-of-scope target is blocked before any container starts")
    target = "http://example.com/"
    before = len(counter.calls)
    try:
        runner.run(["curl", target], target=target, action="header_check", task_id="demo-a")
        blocked = False
    except OutOfScopeError:
        blocked = True
    rep.check(blocked, f"scope guard refused {target}", proven_in_dry_run=True)
    rep.check(len(counter.calls) == before, "docker was never called for it", proven_in_dry_run=True)
    rep.check(any(e["event"] == "scope_blocked" and e["target"] == target for e in ledger.events),
              "scope_blocked is recorded in the ledger", proven_in_dry_run=True)


def check_egress(rep: Report, runner: SandboxRunner) -> None:
    rep.say("\n(b) No outbound internet from inside the sandbox")
    argv = runner.build_argv("preview", ["true"])
    rep.check(argv[argv.index("--network") + 1] == runner.network and "host" not in argv,
              f"sandbox joins only network {runner.network}", proven_in_dry_run=True)
    for label, url in EGRESS_PROBES:
        res = runner.run(["curl", "-sS", "--max-time", "5", "-o", "/dev/null", url], target=None,
                         action="egress_probe", task_id="demo-b", timeout=20)
        if rep.dry_run:
            rep.check(True, f"would curl {url} ({label})")
        else:
            why = CURL_BLOCKED.get(res.exit_code)
            rep.check(why is not None, f"{label} {url}: " + (
                f"blocked, curl exit {res.exit_code} ({why})" if why
                else f"NOT shown to be blocked, exit {res.exit_code}: {res.stderr.strip()[:120]}"))
    if not rep.dry_run:
        # Control: the same network can reach the lab, so the failures above are not just a broken container.
        t = LAB_TARGETS[0]
        url = f"http://{t.host}:{t.ports}/"
        res = runner.run(["curl", "-sS", "--max-time", "5", "-o", "/dev/null", url], target=url,
                         action="lab_control", task_id="demo-b", timeout=20)
        rep.say(f"[INFO] control, lab target {url}: exit {res.exit_code} "
                f"({'reachable' if res.exit_code == 0 else 'not reachable; is the lab up?'})")


def check_runaway(rep: Report, runner: SandboxRunner) -> None:
    rep.say("\n(c) Runaway tasks are killed and the container is destroyed")
    res = runner.run(["sleep", "999"], target=None, action="runaway_sleep", task_id="demo-c", timeout=3)
    if rep.dry_run:
        rep.check(True, f"would run sleep 999 under a {res.caps['timeout']:g} s wall clock")
    else:
        rep.check(res.killed_by_timeout, f"sleep 999 killed by the wall clock after {res.duration_s:.1f} s")
    rep.check(res.destroyed, f"container {res.container} is gone")

    caps = replace(runner.caps, memory="32m")
    hog = ["sh", "-c", "x=aaaaaaaa; while :; do x=$x$x; done"]
    res = runner.run(hog, target=None, action="runaway_memory", task_id="demo-c", timeout=30, caps=caps)
    if rep.dry_run:
        rep.check(True, f"would run a memory hog under a {caps.memory} cap with no swap")
    else:
        # 137 = SIGKILL from the OOM killer. A shell that dies on a failed allocation
        # also exits non-zero, so the code is printed and only 137 counts as the cap firing.
        rep.check(res.exit_code == 137, f"memory hog under {caps.memory}: exit {res.exit_code}, "
                                        f"{res.duration_s:.1f} s (137 = killed by the memory cap)")
    rep.check(res.destroyed, f"container {res.container} is gone")


def check_env(rep: Report, runner: SandboxRunner) -> None:
    rep.say("\n(d) No secrets in the sandbox environment")
    os.environ[CANARY_NAME] = CANARY_VALUE  # present in the parent, must not cross over
    try:
        rep.say(f"parent process has {CANARY_NAME} set (a harmless canary)")
        res = runner.run(["env"], target=None, action="env_probe", task_id="demo-d", timeout=20)
    finally:
        del os.environ[CANARY_NAME]
    argv = runner.build_argv("preview", ["env"])
    opts = argv[:argv.index(runner.image)]
    rep.check(not {"-e", "--env", "--env-file"} & set(opts), "docker run has no -e or --env-file",
              proven_in_dry_run=True)
    if rep.dry_run:
        rep.check(True, "would print env inside the sandbox and check its names")
        return
    names = [line.split("=", 1)[0] for line in res.stdout.splitlines() if "=" in line]
    for line in res.stdout.splitlines():
        name = line.split("=", 1)[0]
        rep.say(f"  {name}=<hidden>" if SECRET_NAME_RE.search(name) else f"  {line}")
    rep.check(res.exit_code == 0 and bool(names), f"env ran inside the sandbox ({len(names)} variables)")
    bad = [n for n in names if SECRET_NAME_RE.search(n)]
    rep.check(not bad, "no KEY/TOKEN/SECRET/PASSWORD names" + (f"; found {bad}" if bad else ""))
    rep.check(CANARY_VALUE not in res.stdout, "the parent's canary did not cross over")


def run_demo(dry_run: bool = False, executor=None, out=None) -> int:
    """Exit 0 when every check passed, 1 on a FAIL, 2 when the lab is not set up."""
    image = os.environ.get("RECONLEDGER_SANDBOX_IMAGE") or DEFAULT_IMAGE
    network = os.environ.get("RECONLEDGER_SANDBOX_NETWORK") or DEFAULT_NETWORK
    rep = Report(dry_run, out)
    if not dry_run and executor is None:
        if not _docker_available():
            rep.dry_run = dry_run = True
            rep.say("Docker is not available, so falling back to --dry-run.")
        else:
            missing = _prerequisites(image, network)
            if missing:
                rep.say("Not ready. Set these up first:\n  " + "\n  ".join(missing))
                return 2
    rep.say(f"ReconLedger containment demo | mode: {'DRY RUN (nothing executed)' if dry_run else 'LIVE docker'}"
            f" | image {image} | network {network}")

    ledger = LedgerLog()
    runner = SandboxRunner(ScopeGuard([LAB_SUBNET]), audit=ledger, image=image, network=network,
                           caps=SandboxCaps(), executor=executor, dry_run=dry_run)
    counter = _Counting(runner.executor)
    runner.executor = counter
    for check in (lambda: check_scope_block(rep, runner, ledger, counter),
                  lambda: check_egress(rep, runner),
                  lambda: check_runaway(rep, runner),
                  lambda: check_env(rep, runner)):
        try:
            check()
        except Exception as exc:  # e.g. the network was removed mid-run
            rep.check(False, f"check could not run: {type(exc).__name__}: {str(exc)[:160]}")

    intact, bad = ledger.verify()
    rep.say("\nLedger")
    rep.check(intact, f"hash chain intact over {len(ledger.events)} entries"
              + ("" if intact else f" (broken at seq {bad})"), proven_in_dry_run=True)
    rep.check(not any(CANARY_VALUE in str(e) for e in ledger.events), "the canary is not in the ledger",
              proven_in_dry_run=True)
    rep.say(f"\nResult: {'FAIL' if rep.failed else 'PASS'} ({rep.failed} failed)"
            + (" | DRY RUN: this checked commands only, not runtime containment." if dry_run else ""))
    return 1 if rep.failed else 0
