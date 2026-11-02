"""FastAPI control layer, built around the existing Agent loop.

Each assessment runs Agent.run in a background thread. The approver blocks that thread
until a human decides in the browser, so scope checks, approvals and ranking stay in
agent.py. Approved steps run through SandboxRunner. Targets are picked by id from a
fixed list: no request can name a host.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import os
import secrets
import sys
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import jinja2
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response

from ..agent import Agent, LabPlanner
from ..audit import LedgerLog
from ..cli import DEFAULT_RULES
from ..kb import severity_label
from ..llm_vultr import LLMAdvisedPlanner, get_llm, lab_menu, limited
from ..models import Finding, PlannedAction
from ..report import _detail, to_markdown
from ..rules import JsonRulesEngine
from ..sandbox import LAB_TARGETS, Executor, LabTarget, SandboxResult, SandboxRunner, sandbox_tools
from ..scope import ScopeGuard

MAX_ACTIVE = 3             # assessments running at once
APPROVAL_TIMEOUT = 1800.0  # an unanswered step is denied, never left to run later
MAX_REASON = 500
MAX_BODY = 16_384
MAX_NARRATED_FINDINGS = 8

_templates = jinja2.Environment(
    loader=jinja2.FileSystemLoader(Path(__file__).parent / "templates"), autoescape=True)
_templates.filters["detail"] = _detail
_templates.filters["severity"] = severity_label
_templates.filters["clock"] = lambda ts: datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else ""


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return host == "localhost"


class _AssessmentLog:
    """One assessment's view of the shared ledger; the single chain covers them all."""

    def __init__(self, ledger: LedgerLog, assessment_id: str):
        self.ledger, self.assessment_id = ledger, assessment_id

    def record(self, event: str, **data):
        return self.ledger.record(event, assessment=self.assessment_id, **data)

    @property
    def events(self) -> list[dict]:
        return [e for e in self.ledger.events if e.get("assessment") == self.assessment_id]


@dataclass
class Step:
    id: int
    name: str
    target: str
    reason: str
    risk_note: str
    status: str = "planned"  # planned awaiting_approval running done rejected error blocked not_run
    decision: bool | None = None
    decided_by: str = ""
    decision_reason: str = ""
    new_findings: int | None = None
    error: str = ""
    sandbox: dict = field(default_factory=dict)


class Assessment:
    def __init__(self, target: LabTarget, ledger: LedgerLog, rules, llm, executor: Executor | None,
                 dry_run: bool, approval_timeout: float):
        self.id = uuid.uuid4().hex[:12]
        self.target = target
        self.audit = _AssessmentLog(ledger, self.id)
        self.ledger = ledger
        self.rules = rules
        self.llm = llm
        self.executor = executor
        self.dry_run = dry_run
        self.approval_timeout = approval_timeout
        self.status = "running"
        self.steps: list[Step] = []
        self.findings: list[Finding] = []
        self.summary: dict = {}
        self.started = datetime.now(timezone.utc).astimezone()
        self.finished: datetime | None = None
        self._cond = threading.Condition()
        self.scope = ScopeGuard([f"{target.host}/32"])  # this one host, not the whole subnet
        self.thread = threading.Thread(target=self._run, daemon=True, name=f"assess-{self.id}")

    def _step_for(self, action: PlannedAction) -> Step:
        return next(s for s in self.steps if (s.name, s.target) == (action.name, action.target))

    def plan_recorder(self, base):
        """Publish each round's plan to the UI as soon as the planner proposes it."""
        outer = self

        class _Recording:
            def plan(self, findings):
                actions = base.plan(findings)
                with outer._cond:
                    known = {(s.name, s.target) for s in outer.steps}
                    for a in actions:
                        if (a.name, a.target) not in known:
                            known.add((a.name, a.target))
                            outer.steps.append(Step(
                                len(outer.steps) + 1, a.name, a.target, a.reason, a.risk_note,
                                status="planned" if outer.scope.allowed(a.target) else "blocked"))
                return actions
        return _Recording()

    def approver(self, action: PlannedAction) -> tuple[bool, str]:
        step = self._step_for(action)
        with self._cond:
            step.status = "awaiting_approval"
            answered = self._cond.wait_for(lambda: step.decision is not None, self.approval_timeout)
            if not answered:
                step.decision, step.status = False, "rejected"
                step.decided_by, step.decision_reason = "timeout", "no decision in time"
                self.audit.record("approval_decision", action=step.name, target=step.target,
                                  step=step.id, approved=False, by="timeout",
                                  reason=step.decision_reason)
            return bool(step.decision), step.decided_by

    def decide(self, step_id: int, approved: bool, reason: str, who: str) -> None:
        with self._cond:
            step = next((s for s in self.steps if s.id == step_id), None)
            if step is None:
                raise HTTPException(404, "no such step")
            if step.status != "awaiting_approval":
                raise HTTPException(409, f"step is {step.status}, not awaiting approval")
            step.decision, step.decided_by, step.decision_reason = approved, who, reason
            step.status = "running" if approved else "rejected"
            self.audit.record("approval_decision", action=step.name, target=step.target,
                              step=step.id, approved=approved, by=who, reason=reason)
            self._cond.notify_all()

    def _tools(self, runner: SandboxRunner):
        def on_result(action: PlannedAction, res: SandboxResult) -> None:
            self._step_for(action).sandbox = {
                k: getattr(res, k) for k in ("container", "image", "network", "caps", "exit_code",
                                             "outcome", "duration_s", "killed_by_timeout",
                                             "destroyed", "output_sha256", "dry_run")}

        def wrap(tool):
            def run(action: PlannedAction) -> list[Finding]:
                step = self._step_for(action)
                step.status = "running"
                try:
                    found = tool(action)
                except Exception as exc:
                    step.status, step.error = "error", str(exc)[:300]
                    raise
                step.status, step.new_findings = "done", len(found)
                return found
            return run

        tools = sandbox_tools(runner, self.id, on_result)
        return {name: wrap(tool) for name, tool in tools.items()}

    def _run(self) -> None:
        t = self.target
        runner = SandboxRunner(self.scope, audit=self.audit, executor=self.executor,
                               dry_run=self.dry_run)
        planner = LabPlanner(t.host, t.ports, nikto=False)
        if self.llm:
            planner = LLMAdvisedPlanner(planner, lambda: lab_menu(t.host, t.ports), self.llm,
                                        self.scope, self.audit)
        agent = Agent(self.rules, scope=self.scope, planner=self.plan_recorder(planner),
                      approver=self.approver, tools=self._tools(runner), audit=self.audit)
        try:
            res = agent.run([])
            self.findings = res.findings
            self.summary = {"executed": res.executed, "skipped": res.skipped,
                            "blocked": res.blocked, "errors": res.errors}
            self.status = "complete"
        except Exception as exc:
            self.audit.record("assessment_error", error=f"{type(exc).__name__}: {exc}"[:200])
            self.status = "failed"
        for s in self.steps:
            if s.status == "planned":
                s.status = "not_run"
        self.finished = datetime.now(timezone.utc).astimezone()

    def report(self) -> str:
        events = self.audit.events
        approvals = [e for e in events if e["event"] == "approval"]
        intact, bad = self.ledger.verify()
        head = self.ledger.events[-1]["hash"] if self.ledger.events else ""
        meta = {
            "report status": "DRAFT - pending analyst review",
            "started": self.started.strftime("%d %b %Y %H:%M:%S %Z"),
            "finished": self.finished.strftime("%d %b %Y %H:%M:%S %Z") if self.finished else "n/a",
            "target": f"{self.target.label}: {self.target.host} ports {self.target.ports}",
            "scope allow-list": f"{self.target.host}/32",
            "active steps approved / asked": f"{sum(e['approved'] for e in approvals)} / {len(approvals)}",
            "executed": ", ".join(self.summary.get("executed", [])) or "none",
            "skipped (denied/no tool)": ", ".join(self.summary.get("skipped", [])) or "none",
            "tool errors": "; ".join(self.summary.get("errors", [])) or "none",
            "findings": len(self.findings),
            "execution": "dry run: nothing executed" if self.dry_run else "one throwaway Docker sandbox per step",
            "ledger chain": "verified intact" if intact else f"BROKEN at seq {bad}",
            "ledger head hash": head,
        }
        llm = limited(self.llm, MAX_NARRATED_FINDINGS) if self.llm else None
        return to_markdown(self.findings, "ReconLedger sandboxed lab assessment", meta, events, llm=llm)

    def to_dict(self) -> dict:
        return {"id": self.id, "target": self.target.id, "status": self.status,
                "steps": [asdict(s) for s in self.steps], "findings": len(self.findings),
                "summary": self.summary}


def create_app(*, ledger: LedgerLog | None = None, executor: Executor | None = None,
               dry_run: bool = False, targets: tuple[LabTarget, ...] = LAB_TARGETS,
               bind_host: str = "127.0.0.1", approval_timeout: float = APPROVAL_TIMEOUT,
               rules_path: str = DEFAULT_RULES) -> FastAPI:
    user = os.environ.get("WEB_BASIC_AUTH_USER", "")
    password = os.environ.get("WEB_BASIC_AUTH_PASS", "")
    if bool(user) != bool(password):
        raise ValueError("set both WEB_BASIC_AUTH_USER and WEB_BASIC_AUTH_PASS, or neither")
    if not user and not _is_loopback(bind_host):
        raise ValueError(f"refusing to bind {bind_host} without WEB_BASIC_AUTH_USER/WEB_BASIC_AUTH_PASS")

    app = FastAPI(title="ReconLedger", docs_url=None, redoc_url=None, openapi_url=None)
    ledger = ledger if ledger is not None else LedgerLog()
    rules = JsonRulesEngine.from_file(rules_path)
    llm = get_llm()
    by_id = {t.id: t for t in targets}
    assessments: dict[str, Assessment] = {}
    create_lock = threading.Lock()
    llm_label = (os.environ.get("LLM_PROVIDER", "").strip().lower() or "") if llm else ""
    app.state.assessments = assessments
    app.state.ledger = ledger

    def page(name: str, **ctx) -> HTMLResponse:
        intact, bad = ledger.verify()
        return HTMLResponse(_templates.get_template(name).render(
            chain_intact=intact, chain_bad=bad, dry_run=dry_run, llm_label=llm_label, **ctx))

    def get_assessment(aid: str) -> Assessment:
        found = assessments.get(aid)
        if found is None:
            raise HTTPException(404, "no such assessment")
        return found

    async def form(request: Request) -> dict[str, str]:
        body = await request.body()
        if len(body) > MAX_BODY:
            raise HTTPException(413, "form too large")
        return {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace")).items()}

    @app.middleware("http")
    async def guard(request: Request, call_next):
        hdrs = request.headers
        if user:
            ok = False
            scheme, _, value = hdrs.get("authorization", "").partition(" ")
            if scheme.lower() == "basic":
                try:
                    given_user, _, given_pass = base64.b64decode(value).decode().partition(":")
                    ok = (secrets.compare_digest(given_user.encode(), user.encode())
                          & secrets.compare_digest(given_pass.encode(), password.encode()))
                except (binascii.Error, UnicodeDecodeError):
                    ok = False
            if not ok:
                return PlainTextResponse("authentication required", 401,
                                         {"WWW-Authenticate": 'Basic realm="ReconLedger"'})
        elif not _is_loopback(urlparse(f"//{hdrs.get('host', '')}").hostname or ""):
            # Unauthenticated mode serves loopback names only, which stops DNS rebinding.
            return PlainTextResponse("bad host", 400)
        if request.method == "POST":
            # A page on another site must not be able to submit an approval form.
            origin = hdrs.get("origin")
            if hdrs.get("sec-fetch-site") == "cross-site" or (
                    origin is not None and urlparse(origin).netloc != hdrs.get("host")):
                return PlainTextResponse("cross-site request refused", 403)
        request.state.who = f"web:{user}" if user else "web:local-operator"
        return await call_next(request)

    @app.get("/", response_class=HTMLResponse)
    def index():
        return page("index.html", targets=targets, assessments=list(assessments.values()))

    @app.post("/assessments")
    async def start(request: Request):
        target_id = (await form(request)).get("target", "")
        target = by_id.get(target_id)
        if target is None:
            ledger.record("scope_blocked", action="start_assessment", target=target_id[:200],
                          by=request.state.who, error="target is not on the fixed lab list")
            raise HTTPException(400, "target is not on the fixed lab list")
        with create_lock:
            if sum(a.status == "running" for a in assessments.values()) >= MAX_ACTIVE:
                raise HTTPException(429, f"at most {MAX_ACTIVE} assessments may run at once")
            a = Assessment(target, ledger, rules, llm, executor, dry_run, approval_timeout)
            assessments[a.id] = a
        a.audit.record("assessment_start", target=target.host, by=request.state.who,
                       lab_target=target.id)
        a.thread.start()
        return RedirectResponse(f"/assessments/{a.id}", 303)

    @app.get("/assessments/{aid}", response_class=HTMLResponse)
    def show(aid: str):
        a = get_assessment(aid)
        awaiting = any(s.status == "awaiting_approval" for s in a.steps)
        return page("assessment.html", a=a, events=a.audit.events,
                    # No refresh while a form is open: it would wipe a half-typed reason.
                    auto_refresh=a.status == "running" and not awaiting)

    @app.post("/assessments/{aid}/steps/{step_id}/decision")
    async def decision(aid: str, step_id: int, request: Request):
        a = get_assessment(aid)
        data = await form(request)
        choice, reason = data.get("decision"), data.get("reason", "").strip()
        if choice not in {"approve", "reject"}:
            raise HTTPException(400, "decision must be approve or reject")
        if not reason:
            raise HTTPException(400, "a reason is required")
        a.decide(step_id, choice == "approve", reason[:MAX_REASON], request.state.who)
        return RedirectResponse(f"/assessments/{a.id}", 303)

    @app.get("/assessments/{aid}/report.md")
    def report(aid: str):
        a = get_assessment(aid)
        if a.status == "running":
            raise HTTPException(409, "assessment is still running")
        return Response(a.report(), media_type="text/markdown; charset=utf-8", headers={
            "Content-Disposition": f'attachment; filename="reconledger-{a.id}.md"'})

    @app.get("/api/assessments/{aid}")
    def status(aid: str):
        return get_assessment(aid).to_dict()

    @app.get("/ledger", response_class=HTMLResponse)
    def ledger_page():
        return page("ledger.html", events=list(ledger.events))

    return app


def serve(host: str, port: int, dry_run: bool = False) -> int:
    import uvicorn

    path = os.environ.get("RECONLEDGER_WEB_LEDGER") or "out/web-ledger.jsonl"
    try:
        app = create_app(ledger=LedgerLog(path), dry_run=dry_run, bind_host=host)
    except ValueError as exc:
        print(f"refusing to start: {exc}", file=sys.stderr)
        return 2
    uvicorn.run(app, host=host, port=port)
    return 0
