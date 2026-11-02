"""A stand-in for the docker CLI, so no test ever starts a container."""
from reconledger.sandbox import DEFAULT_IMAGE, ExecResult


class FakeDocker:
    """Answers network inspect and teardown calls; `handler` answers the tool command."""

    def __init__(self, handler=None, internal="true", still_listed=False):
        self.handler = handler or (lambda command: ExecResult(0, "output"))
        self.internal, self.still_listed = internal, still_listed
        self.calls: list[list[str]] = []
        self.envs: list[dict] = []
        self.timeouts: list[float] = []

    def __call__(self, argv, timeout, env, max_bytes):
        self.calls.append(argv)
        self.envs.append(env)
        self.timeouts.append(timeout)
        verb = argv[1]
        if verb == "network":
            return ExecResult(0, f"{self.internal}\n")
        if verb == "ps":
            return ExecResult(0, "abc123\n" if self.still_listed else "")
        if verb in {"kill", "rm"}:
            return ExecResult(1, "", "Error: No such container")
        assert verb == "run", argv
        return self.handler(argv[argv.index(DEFAULT_IMAGE) + 1:])

    def verbs(self) -> list[str]:
        return [c[1] for c in self.calls]

    def runs(self) -> list[list[str]]:
        return [c for c in self.calls if c[1] == "run"]
