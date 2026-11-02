"""Docker sandbox: every tool step runs in its own capped, throwaway container.

Guarantees and where they are enforced:
  isolation    build_argv + _assert_contained (no host network, mounts, env or privileges)
               and _check_network (refuses any network that is not Docker-internal).
  no secrets   no -e/--env-file is ever built; the docker CLI itself gets _cli_env only.
  limits       SandboxCaps (memory, swap, CPU, PIDs, tmpfs, wall clock, captured output).
  destruction  _teardown in a `finally`: docker kill, docker rm -f, then confirm it is gone.

The scope check happens before anything reaches docker. Tests and --dry-run inject
an executor, so nothing here needs docker to be tested.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field, replace
from typing import Callable

from .agent import Tool
from .audit import AuditLog
from .models import Finding, PlannedAction
from .scope import OutOfScopeError, ScopeGuard
from .tools import headers, nmap

DEFAULT_IMAGE = "reconledger-sandbox:latest"
DEFAULT_NETWORK = "reconledger-lab"  # lab/docker-compose.yml, network sandbox-lab
SECRET_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD")
# The docker CLI needs these to find the daemon. Nothing else reaches the subprocess.
CLI_ENV_ALLOW = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG",
                 "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "XDG_RUNTIME_DIR")
FORBIDDEN_NETWORKS = {"host", "bridge", "default"}
FORBIDDEN_FLAGS = {"-v", "--volume", "--volumes-from", "--mount", "-e", "--env", "--env-file",
                   "--privileged", "--device", "--cap-add", "-p", "--publish", "-P",
                   "--publish-all", "--pid", "--ipc", "--uts", "--userns", "--add-host"}
TEARDOWN_TIMEOUT = 15


@dataclass(frozen=True)
class LabTarget:
    id: str
    host: str  # fixed address on the internal lab network
    ports: str
    label: str


LAB_SUBNET = "172.30.0.0/24"
LAB_TARGETS = (
    LabTarget("juice-shop", "172.30.0.10", "3000", "OWASP Juice Shop (lab)"),
    LabTarget("dvwa", "172.30.0.20", "80", "DVWA (lab, compose profile dvwa)"),
)


class SandboxError(RuntimeError):
    """The sandbox refused to start, or a step inside it failed."""


@dataclass(frozen=True)
class SandboxCaps:
    memory: str = "256m"
    cpus: str = "0.5"
    pids: int = 128
    tmpfs_size: str = "16m"
    user: str = "65534:65534"
    timeout: float = 120.0
    max_output_bytes: int = 1_048_576  # per stream; the rest is drained and discarded


@dataclass
class ExecResult:
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    truncated: bool = False


Executor = Callable[[list[str], float, dict[str, str], int], ExecResult]


@dataclass
class SandboxResult:
    exit_code: int | None
    stdout: str
    stderr: str
    duration_s: float
    killed_by_timeout: bool
    caps: dict
    image: str
    network: str
    container: str
    output_sha256: str  # over exactly the stdout/stderr above, so anyone can recompute it
    outcome: str        # ok | nonzero_exit | timeout | error | dry_run
    destroyed: bool     # docker confirmed the container no longer exists
    truncated: bool = False
    dry_run: bool = False
    command: list[str] = field(default_factory=list)


def output_hash(stdout: str, stderr: str) -> str:
    return hashlib.sha256(f"{stdout}\0{stderr}".encode("utf-8", "replace")).hexdigest()


def _cli_env() -> dict[str, str]:
    env = {k: os.environ[k] for k in CLI_ENV_ALLOW if k in os.environ}
    leaked = [k for k in env if any(m in k.upper() for m in SECRET_MARKERS)]
    assert not leaked, f"secret-named variable in docker CLI env: {leaked}"
    return env


def subprocess_executor(argv: list[str], timeout: float, env: dict[str, str],
                        max_bytes: int) -> ExecResult:
    """Run argv with a wall clock and bounded capture, so a sandbox that floods
    stdout cannot exhaust the control layer's memory."""
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env)
    kept: dict[str, bytes] = {"out": b"", "err": b""}
    over = {"out": False, "err": False}

    def drain(name: str, stream) -> None:
        buf = bytearray()
        while chunk := stream.read(65536):
            room = max_bytes - len(buf)
            buf += chunk[:max(room, 0)]
            over[name] = over[name] or len(chunk) > room
        kept[name] = bytes(buf)

    threads = [threading.Thread(target=drain, args=a, daemon=True)
               for a in (("out", proc.stdout), ("err", proc.stderr))]
    for t in threads:
        t.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True  # this only stops the client; _teardown stops the container
        proc.kill()
        proc.wait()
    for t in threads:
        t.join(timeout=2)
    return ExecResult(None if timed_out else proc.returncode,
                      kept["out"].decode("utf-8", "replace"),
                      kept["err"].decode("utf-8", "replace"),
                      timed_out, any(over.values()))


def dry_run_executor(argv: list[str], timeout: float, env: dict[str, str],
                     max_bytes: int) -> ExecResult:
    return ExecResult(0)


def _assert_contained(argv: list[str], image: str, network: str) -> None:
    """Last check on the final argv. Only options before the image are docker's;
    whatever follows it (curl -e, nmap -v) belongs to the tool inside."""
    opts = argv[:argv.index(image)]
    for tok in opts:
        name = tok.split("=", 1)[0]
        if name in FORBIDDEN_FLAGS:
            raise SandboxError(f"refusing docker flag {name}")
    if opts[opts.index("--network") + 1] != network or network in FORBIDDEN_NETWORKS:
        raise SandboxError(f"refusing network {network!r}")
    for required in ("--rm", "--memory", "--cpus", "--pids-limit", "--read-only", "--tmpfs",
                     "--cap-drop", "--security-opt", "--user"):
        if required not in opts:
            raise SandboxError(f"missing isolation flag {required}")


class SandboxRunner:
    def __init__(self, scope: ScopeGuard, audit: AuditLog | None = None,
                 caps: SandboxCaps | None = None, image: str | None = None,
                 network: str | None = None, executor: Executor | None = None,
                 dry_run: bool = False):
        self.scope = scope
        self.audit = audit or AuditLog()
        self.caps = caps or SandboxCaps()
        self.image = image or os.environ.get("RECONLEDGER_SANDBOX_IMAGE") or DEFAULT_IMAGE
        self.network = network or os.environ.get("RECONLEDGER_SANDBOX_NETWORK") or DEFAULT_NETWORK
        if self.network in FORBIDDEN_NETWORKS or self.network.startswith("container:"):
            raise ValueError(f"sandbox network may not be {self.network!r}")
        self.dry_run = dry_run
        self.executor = dry_run_executor if dry_run else (executor or subprocess_executor)

    def build_argv(self, container: str, command: list[str],
                   caps: SandboxCaps | None = None) -> list[str]:
        caps = caps or self.caps
        argv = ["docker", "run", "--rm", "--pull", "never", "--name", container,
                "--network", self.network,
                "--memory", caps.memory, "--memory-swap", caps.memory,  # equal: no swap
                "--cpus", caps.cpus, "--pids-limit", str(caps.pids),
                "--read-only", "--tmpfs", f"/tmp:rw,noexec,nosuid,size={caps.tmpfs_size}",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", caps.user,
                "--log-driver", "none",  # output is captured here, not left on the host disk
                self.image, *command]
        _assert_contained(argv, self.image, self.network)
        return argv

    def _docker(self, argv: list[str], timeout: float = TEARDOWN_TIMEOUT) -> ExecResult:
        return self.executor(argv, timeout, _cli_env(), 65536)

    def _check_network(self) -> None:
        """Fail closed: a network with a gateway would give the sandbox internet access."""
        if self.dry_run:
            return
        res = self._docker(["docker", "network", "inspect", "--format", "{{.Internal}}", self.network])
        if res.returncode != 0 or res.stdout.strip() != "true":
            raise SandboxError(f"network {self.network!r} is missing or not internal; "
                               "start lab/docker-compose.yml first")

    def _teardown(self, container: str) -> bool:
        """Always runs. Returns True only when docker confirms the container is gone."""
        for argv in (["docker", "kill", container], ["docker", "rm", "-f", container]):
            try:  # after --rm these normally fail with "no such container", which is fine
                self._docker(argv)
            except Exception:  # keep going: the check below decides what is reported
                pass
        if self.dry_run:
            return True
        try:
            res = self._docker(["docker", "ps", "-aq", "--filter", f"name=^/{container}$"])
        except Exception:
            return False
        return res.returncode == 0 and not res.stdout.strip()

    def run(self, command: list[str], target: str | None, action: str = "", task_id: str = "",
            timeout: float | None = None, caps: SandboxCaps | None = None) -> SandboxResult:
        """Run one command in one fresh container.

        target is what the command will touch, checked against scope before docker is
        involved. Only the containment self-test passes None (its probes are meant to fail).
        """
        if target is not None:
            try:
                self.scope.check(target)
            except OutOfScopeError as exc:
                self.audit.record("scope_blocked", action=action, target=target, error=str(exc))
                raise
        caps = caps or self.caps
        if timeout is not None:
            caps = replace(caps, timeout=timeout)
        container = f"rl-sbx-{(task_id or 'task')[:12]}-{uuid.uuid4().hex[:8]}"
        argv = self.build_argv(container, command, caps)
        try:
            self._check_network()
        except (SandboxError, OSError) as exc:
            self.audit.record("sandbox_refused", action=action, target=target, container=container,
                              network=self.network, error=str(exc)[:200])
            raise SandboxError(str(exc)) from None

        exec_res = ExecResult(None)
        error = ""
        t0 = time.monotonic()
        try:
            exec_res = self.executor(argv, caps.timeout, _cli_env(), caps.max_output_bytes)
        except Exception as exc:  # e.g. docker binary missing; reported in the result
            error = f"{type(exc).__name__}: {exc}"[:200]
        finally:
            destroyed = self._teardown(container)
        duration = round(time.monotonic() - t0, 3)

        if error:
            outcome = "error"
        elif exec_res.timed_out:
            outcome = "timeout"
        elif self.dry_run:
            outcome = "dry_run"
        else:
            outcome = "ok" if exec_res.returncode == 0 else "nonzero_exit"
        result = SandboxResult(
            exit_code=exec_res.returncode, stdout=exec_res.stdout,
            stderr=exec_res.stderr or error, duration_s=duration,
            killed_by_timeout=exec_res.timed_out, caps=asdict(caps), image=self.image,
            network=self.network, container=container,
            output_sha256=output_hash(exec_res.stdout, exec_res.stderr or error),
            outcome=outcome, destroyed=destroyed, truncated=exec_res.truncated,
            dry_run=self.dry_run, command=list(command))
        self.audit.record("sandbox_run", action=action, target=target, task=task_id,
                          container=container, image=self.image, network=self.network,
                          caps=result.caps, command=result.command, duration_s=duration,
                          exit_code=result.exit_code, outcome=outcome,
                          killed_by_timeout=result.killed_by_timeout, destroyed=destroyed,
                          truncated=result.truncated, output_sha256=result.output_sha256)
        return result


def _require_ok(result: SandboxResult, tool: str) -> SandboxResult:
    if result.outcome not in {"ok", "dry_run"}:
        raise SandboxError(f"{tool} in sandbox: {result.outcome} (exit {result.exit_code}): "
                           f"{result.stderr.strip()[:150]}")
    if result.truncated:  # parsing half an answer would misreport what the tool saw
        raise SandboxError(f"{tool} in sandbox: output exceeded the capture cap")
    return result


def nmap_command(host: str, ports: str) -> list[str]:
    if not nmap.PORTS_RE.match(ports):
        raise ValueError(f"bad port spec {ports!r}")
    return ["nmap", "-sT", "-Pn", "-n", "-p", ports, "-oX", "-", host]


def curl_headers_command(url: str) -> list[str]:
    return ["curl", "-sS", "--proto", "=http,https", "--max-time", "10", "--max-redirs", "0",
            "-A", "ReconLedger-lab/0.4", "-D", "-", "-o", "/dev/null", url]


def parse_header_dump(text: str) -> dict[str, str]:
    """curl -D - output -> the dict shape headers.parse expects (repeats joined by newline)."""
    hdrs: dict[str, str] = {}
    for line in text.replace("\r\n", "\n").split("\n"):
        if ":" not in line or line.startswith("HTTP/"):
            continue
        k, v = line.split(":", 1)
        key = k.strip().lower()
        hdrs[key] = f"{hdrs[key]}\n{v.strip()}" if key in hdrs else v.strip()
    return hdrs


def sandbox_tools(runner: SandboxRunner, task_id: str = "",
                  on_result: Callable[[PlannedAction, SandboxResult], None] | None = None,
                  ) -> dict[str, Tool]:
    """The same action names as runners.lab_tools, but each runs inside a container.
    Nikto is not bound: the sandbox image only ships nmap and curl."""
    def _exec(a: PlannedAction, command: list[str], timeout: float) -> SandboxResult:
        res = runner.run(command, target=a.target, action=a.name, task_id=task_id, timeout=timeout)
        if on_result:
            on_result(a, res)
        return _require_ok(res, a.name)

    def nmap_scan(a: PlannedAction) -> list[Finding]:
        res = _exec(a, nmap_command(a.target, a.params.get("ports", "3000")), 120)
        return nmap.parse_xml(res.stdout) if res.stdout else []

    def header_check(a: PlannedAction) -> list[Finding]:
        res = _exec(a, curl_headers_command(a.target), 30)
        return headers.parse(a.target, parse_header_dump(res.stdout)) if res.stdout else []

    return {"nmap_scan": nmap_scan, "header_check": header_check}
