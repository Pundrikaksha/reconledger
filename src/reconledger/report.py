"""VAPT report (Markdown + PDF) with the sections PS1 §7 asks for.

1 Executive summary and scope, 2 Methodology (rules of engagement, assets, tool
execution), 3 Severity distribution and prioritised findings, 4 Detailed findings
(id, asset, description, severity, CWE, evidence, confidence, validation,
explain-why), 5 Impact and remediation, 6 Limitations (assumptions, scan failures,
human approvals, timestamps), Appendix: plan, approval and audit trail.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from typing import Any

from .explain import Explanation, explain
from .integrations import MATRIX
from .kb import SEVERITY_ORDER, lookup, severity_label
from .models import Finding

ACTION_TOOL = {"nmap_scan": "nmap", "header_check": "headers", "nikto_scan": "nikto"}
METHODOLOGY = [
    "Planning (NIST SP 800-115 §3): the analyst request is turned into an auditable plan; every target is checked against a loopback/private-only scope allow-list.",
    "Discovery (§4): nmap TCP connect scan of the in-scope host and ports.",
    "Vulnerability analysis (§4-5): for each open web port the agent plans an HTTP security-header check and a Nikto scan (safe tuning; no injection or DoS classes).",
    "Validation: Nikto file/directory hits are re-fetched and compared with a random-path baseline (soft-404) to weed out false positives. No exploitation is attempted.",
    "Correlation and ranking: duplicates merge across tools; findings on ports nmap confirmed open get context boosts; a JSON rules engine adjusts scores and records every reason.",
    "Human review: every active step needs analyst approval before it runs; the report stays DRAFT until an analyst signs it off.",
]
RULES_OF_ENGAGEMENT = [
    "Targets: only the organiser-authorised / local sandbox lab (loopback or private ranges). Public ranges and hostnames are refused at start-up and again inside each runner.",
    "Every active action (scan, HTTP probe) requires explicit human approval; denials are final for the run.",
    "No exploitation, brute force, injection payloads or denial-of-service checks.",
    "All decisions, approvals, blocks and errors are written to an append-only JSONL audit trail.",
]


def _ts(t: float | None) -> str:
    return datetime.fromtimestamp(t).astimezone().strftime("%d %b %Y %H:%M:%S %Z") if t else "n/a"


def plan_reasons(events: list[dict]) -> dict[tuple[str, str], str]:
    """(tool, host:port) -> why the planner chose the step that produced it."""
    out: dict[tuple[str, str], str] = {}
    for e in events:
        if e.get("event") == "planned":
            tool = ACTION_TOOL.get(e["action"], e["action"])
            tgt = e["target"].split("//")[-1].strip("/")
            out[(tool, tgt)] = e.get("reason", "")
            out.setdefault((tool, tgt.split(":")[0]), e.get("reason", ""))
    return out


def build(findings: list[Finding], meta: dict[str, Any] | None = None,
          events: list[dict] | None = None, llm=None, summary_llm=None) -> dict[str, Any]:
    events = events or []
    reasons = plan_reasons(events)
    rows = []
    for i, f in enumerate(findings, 1):
        src = f.source.split("+")[0]
        host = f.target.split(":")[0]
        why = reasons.get((src, f.target)) or reasons.get((src, host)) or "imported finding (no plan step)"
        rows.append({"n": i, "fid": f"RL-{i:03d}", "f": f, "kb": lookup(f),
                     "x": explain(f, why, llm=llm)})
    dist = Counter(severity_label(f.score) for f in findings)
    approvals = [e for e in events if e.get("event") == "approval"]
    tool_runs = []
    for e in events:
        if e.get("event") in {"executed", "tool_error", "no_tool", "blocked_scope"}:
            tool_runs.append(e)
        if e.get("event") == "approval" and not e.get("approved"):
            tool_runs.append({**e, "event": "denied"})
    return {"rows": rows, "dist": dist, "meta": meta or {}, "events": events,
            "approvals": approvals, "tool_runs": tool_runs, "llm": llm, "summary_llm": summary_llm}


def _exec_summary(ctx: dict) -> str:
    text = _deterministic_summary(ctx)
    summary_llm = ctx["summary_llm"]
    if summary_llm is None or not ctx["rows"]:
        return text
    try:
        rewritten = summary_llm(
            "Rewrite this executive summary for a client VAPT report in at most 3 sentences, "
            "keep every number and fact, add nothing:\n" + text)
        if rewritten and rewritten.strip():
            return rewritten.strip()
    except Exception:  # LLM is optional; deterministic text stays
        pass
    return text


def _deterministic_summary(ctx: dict) -> str:
    rows, dist, meta = ctx["rows"], ctx["dist"], ctx["meta"]
    if not rows:
        return "No findings were produced in this run."
    top = rows[0]
    counts = ", ".join(f"{dist.get(s, 0)} {s}" for s in SEVERITY_ORDER)
    fp = sum(1 for r in rows if "soft-404" in r["f"].tags)
    multi = sum(1 for r in rows if "+" in r["f"].source)
    return (f"ReconLedger assessed {meta.get('target', 'the lab target')} and recorded {len(rows)} findings "
            f"({counts}). The highest-ranked issue is \"{top['f'].title}\" on {top['f'].target} "
            f"({top['x'].severity}, {top['f'].score:.1f}/10). {multi} findings were reported by more than one "
            f"tool and merged; {fp} tool hits were validated as likely false positives and down-ranked "
            f"rather than hidden. No exploitation was performed. {_approval_line(ctx)}")


def _approval_line(ctx: dict) -> str:
    ap = ctx["approvals"]
    if not ap:
        return "No active steps were requested."
    ok = sum(1 for e in ap if e.get("approved"))
    who = sorted({e.get("by", "?") for e in ap})
    return f"{ok} of {len(ap)} active steps passed the human-approval gate ({', '.join(who)})."


# ----------------------------------------------------------------- Markdown
def to_markdown(findings: list[Finding], title: str = "ReconLedger report",
                meta: dict[str, Any] | None = None, events: list[dict] | None = None,
                *, llm=None, summary_llm=None) -> str:
    ctx = build(findings, meta, events, llm=llm, summary_llm=summary_llm)
    L = [f"# {title}", ""]
    status = (meta or {}).get("report status")
    if status:
        L += [f"> **Report status:** {status}", ""]
    L += ["## 1. Executive summary and scope", "", _exec_summary(ctx), ""]
    for k, v in (meta or {}).items():
        L.append(f"- **{k}:** {v}")
    L += ["", "## 2. Assessment methodology", "", "**Method**", ""]
    L += [f"{i}. {m}" for i, m in enumerate(METHODOLOGY, 1)]
    L += ["", "**Rules of engagement**", ""] + [f"- {r}" for r in RULES_OF_ENGAGEMENT]
    L += ["", "**Tool execution summary**", "", "| Time | Tool step | Target | Result |", "|---|---|---|---|"]
    for e in ctx["tool_runs"]:
        L.append(f"| {_ts(e.get('ts'))} | {e.get('action')} | {e.get('target', '')} | {_run_result(e)} |")
    L += ["", "**Tool integration status**", "", "| Tool | Status | Coverage | How |", "|---|---|---|---|"]
    L += [f"| {a} | {b} | {c} | {d} |" for a, b, c, d in MATRIX]
    L += ["", "## 3. Severity distribution and prioritised findings", "",
          "| Severity | Count |", "|---|---|"]
    L += [f"| {s} | {ctx['dist'].get(s, 0)} |" for s in SEVERITY_ORDER]
    L += ["", "| ID | Severity | Score | Asset | Finding | Sources | Confidence |", "|---|---|---|---|---|---|---|"]
    for r in ctx["rows"]:
        f, x = r["f"], r["x"]
        L.append(f"| {r['fid']} | {x.severity} | {f.score:.1f} | {f.target} | {f.title} | {f.source} | {x.confidence.split(' (')[0]} |")
    L += ["", "## 4. Detailed findings (with explain-why)"]
    for r in ctx["rows"]:
        L += _md_detail(r)
    L += ["", "## 5. Impact and remediation", ""]
    for r in ctx["rows"]:
        if "soft-404" in r["f"].tags:
            continue
        L.append(f"- **{r['fid']} {r['f'].title}:** {r['kb'].impact} Fix: {' '.join(r['kb'].steps)}")
    L += ["", "## 6. Assessment limitations", ""] + [f"- {x}" for x in limitations(ctx)]
    L += ["", "## Appendix A. Plan, approvals and audit trail", "",
          "| Time | Event | Action | Target | Detail |", "|---|---|---|---|---|"]
    for e in ctx["events"]:
        L.append(f"| {_ts(e.get('ts'))} | {e['event']} | {e.get('action', '')} | {e.get('target', '')} | {_detail(e)} |")
    return "\n".join(L) + "\n"


def _md_detail(r: dict) -> list[str]:
    f, x, kb = r["f"], r["x"], r["kb"]
    ev = {k: v for k, v in f.evidence.items() if k != "fix"}
    out = [f"\n### {r['fid']}: {f.title}", "",
           f"- **Affected asset:** {f.target}",
           f"- **Severity:** {x.severity} — score {f.score:.1f}/10 (tool base {f.severity:.1f}; CVSS not computed)",
           f"- **CWE / OWASP:** {kb.cwe} / {kb.owasp}" + (f" / {', '.join(f.evidence['cve'])}" if f.evidence.get("cve") else ""),
           f"- **Description:** {kb.description}",
           f"- **Sources:** {f.source}",
           f"- **Confidence:** {x.confidence}",
           f"- **Validation status:** {x.validation}",
           f"- **Evidence:** `{json.dumps(ev, default=str)[:600]}`",
           f"- **Why the agent ran this step:** {x.why_planned}",
           "- **Explain why (score):**",
           f"  - Summary: {x.summary}",
           f"  - Exposure: {x.exposure}",
           f"  - Exploitability: {x.exploitability}",
           f"  - Context: {x.context}",
           "  - Score trail: " + " → ".join(x.score_trail),
           "- **Fix steps:**"] + [f"  {i}. {s}" for i, s in enumerate(kb.steps, 1)]
    if kb.refs:
        out.append("- **References:** " + ", ".join(kb.refs))
    return out


def _run_result(e: dict) -> str:
    ev = e["event"]
    if ev == "executed":
        return f"ran, {e.get('new_findings', 0)} raw findings"
    if ev == "tool_error":
        return f"FAILED: {e.get('error', '')[:120]}"
    if ev == "denied":
        return f"denied by {e.get('by')}"
    if ev == "blocked_scope":
        return "blocked by scope guard"
    return "no tool bound"


def _detail(e: dict) -> str:
    skip = {"ts", "event", "action", "target"}
    return "; ".join(f"{k}={v}" for k, v in e.items() if k not in skip)[:200].replace("|", "/")


def limitations(ctx: dict) -> list[str]:
    meta, ev = ctx["meta"], ctx["events"]
    errs = [e for e in ev if e["event"] == "tool_error"]
    blocked = [e for e in ev if e["event"] == "blocked_scope"]
    appr = ctx["approvals"]
    out = [
        "Testing limitations: unauthenticated, black-box checks only; no exploitation, credentialed scanning, fuzzing or business-logic testing. Nikto ran with safe tuning (0123b) and a time cap.",
        "Severity is a context-adjusted 0-10 score from tool base severity plus explicit rules; it is not a CVSS vector.",
        "Assumptions: the lab app on loopback stands in for the client asset; real exposure depends on how it is deployed.",
        "Integrations disclosed in section 2: Nmap, Nikto and the header check ran live; ZAP, Nessus, OpenVAS, Burp and Metasploit are planned, not implemented.",
        "Scan failures: " + ("; ".join(f"{e['action']}: {e['error'][:150]}" for e in errs) if errs else "none"),
        "Scope blocks: " + ("; ".join(f"{e['action']} -> {e['target']}" for e in blocked) if blocked else "none"),
        "Human approvals: " + (", ".join(f"{e['action']} -> {e['target']}: {'approved' if e['approved'] else 'denied'} by {e['by']}" for e in appr) or "none requested"),
        f"Assessment timestamps: started {meta.get('started', 'n/a')}, finished {meta.get('finished', 'n/a')} ({meta.get('run time', 'n/a')}).",
        _llm_line(ctx),
    ]
    return out


def _llm_line(ctx: dict) -> str:
    """Describes what actually happened, so call this after the LLM text has been produced."""
    llm, summary_llm = ctx["llm"], ctx["summary_llm"]
    if llm is None and summary_llm is None:
        return "No LLM used; all text deterministic."
    used = []
    failed = 0
    for label, hook in (("model", llm), ("summary model", summary_llm)):
        stats = getattr(hook, "stats", None)
        if stats:
            failed += stats.failed
            if stats.models:
                used.append(f"{label} {', '.join(stats.models)}")
        elif hook is not None:  # plain callable: nothing to report beyond its presence
            used.append(f"{label} unspecified")
    if not used:
        return "LLM rewriting was enabled but no call succeeded; all text deterministic."
    gateway = getattr(llm or summary_llm, "gateway", "caller-supplied LLM hook")
    line = (f"Narrative text rewritten via {gateway} ({'; '.join(used)}); scores, evidence and rankings "
            "are deterministic and were not changed by the LLM.")
    if failed:
        line += f" {failed} rewrite(s) failed and kept the deterministic text."
    return line


# ---------------------------------------------------------------------- PDF
def _t(s: Any) -> str:
    s = str(s)
    for a, b in {"—": "-", "–": "-", "→": "->", "“": '"', "”": '"', "’": "'", "‘": "'",
                 "…": "...", "§": "S", "≥": ">=", "≤": "<=", "•": "-"}.items():
        s = s.replace(a, b)
    return s.encode("latin-1", "replace").decode("latin-1")


SEV_COLOURS = {"Critical": (128, 0, 0), "High": (200, 40, 40), "Medium": (230, 140, 0),
               "Low": (60, 120, 200), "Info": (120, 120, 120)}


def to_pdf(findings: list[Finding], path: str, title: str = "ReconLedger VAPT report",
           meta: dict[str, Any] | None = None, events: list[dict] | None = None,
           *, llm=None, summary_llm=None) -> str:
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos

    ctx = build(findings, meta, events, llm=llm, summary_llm=summary_llm)
    meta = meta or {}

    class PDF(FPDF):
        def header(self):
            if self.page_no() > 1:
                self.set_font("Helvetica", "I", 8)
                self.set_text_color(110)
                self.cell(0, 6, _t(f"{title} - {meta.get('report status', 'DRAFT')}"), align="R")
                self.ln(8)
                self.set_text_color(0)

        def footer(self):
            self.set_y(-12)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(110)
            self.cell(0, 6, _t(f"ReconLedger - The Unique Trader Team - page {self.page_no()}/{{nb}}"), align="C")
            self.set_text_color(0)

    pdf = PDF(format="A4")
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(True, margin=16)
    pdf.set_margins(16, 14, 16)
    NL = {"new_x": XPos.LMARGIN, "new_y": YPos.NEXT}

    def h1(s):
        pdf.ln(3); pdf.set_font("Helvetica", "B", 15); pdf.set_text_color(20, 40, 90)
        pdf.multi_cell(0, 8, _t(s), **NL); pdf.set_text_color(0); pdf.ln(1)

    def h2(s):
        pdf.ln(2); pdf.set_font("Helvetica", "B", 11.5); pdf.multi_cell(0, 6, _t(s), **NL)

    def p(s, size=9.5, style=""):
        pdf.set_font("Helvetica", style, size); pdf.multi_cell(0, 5, _t(s), **NL)

    def kv(k, v):
        pdf.set_font("Helvetica", "B", 9); pdf.write(5, _t(f"{k}: "))
        pdf.set_font("Helvetica", "", 9); pdf.write(5, _t(v)); pdf.ln(5.5)

    def table(head, rows, widths, size=8):
        with pdf.table(col_widths=widths, text_align="LEFT", line_height=4.4) as t:
            pdf.set_font("Helvetica", "B", size)
            r = t.row()
            for h in head:
                r.cell(_t(h))
            pdf.set_font("Helvetica", "", size)
            for row in rows:
                r = t.row()
                for c in row:
                    r.cell(_t(c))
        pdf.ln(2)

    # cover
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 22); pdf.set_text_color(20, 40, 90)
    pdf.ln(30); pdf.multi_cell(0, 11, _t(title), **NL)
    pdf.set_font("Helvetica", "", 12); pdf.set_text_color(60)
    pdf.multi_cell(0, 7, _t("Unified VAPT report - AI-assisted, human-approved assessment of the authorised local lab"), **NL)
    pdf.ln(6); pdf.set_text_color(0)
    for k in ("report status", "target", "started", "finished", "run time", "analyst"):
        if k in meta:
            kv(k.capitalize(), meta[k])
    pdf.ln(4)
    p("Prepared with ReconLedger by The Unique Trader Team. Lab-only: no third-party systems were tested.", 9, "I")

    pdf.add_page()
    h1("1. Executive summary and scope")
    p(_exec_summary(ctx))
    pdf.ln(2)
    for k, v in meta.items():
        kv(k, v)

    h1("2. Assessment methodology")
    h2("Method (aligned to NIST SP 800-115)")
    for i, m in enumerate(METHODOLOGY, 1):
        p(f"{i}. {m}")
    h2("Rules of engagement")
    for r in RULES_OF_ENGAGEMENT:
        p(f"- {r}")
    h2("Assets tested")
    p(f"{meta.get('target', 'n/a')}; scope allow-list: {meta.get('scope allow-list', 'n/a')}")
    h2("Tool execution summary")
    table(["Time", "Step", "Target", "Result"],
          [[_ts(e.get("ts")), e.get("action", ""), e.get("target", ""), _run_result(e)] for e in ctx["tool_runs"]],
          (34, 24, 50, 70))
    h2("Tool integration status (disclosed)")
    table(["Tool", "Status", "Coverage", "How"], [list(m) for m in MATRIX], (34, 30, 20, 94), 7.5)

    h1("3. Severity distribution and prioritised findings")
    total = max(1, len(ctx["rows"]))
    for s in SEVERITY_ORDER:
        n = ctx["dist"].get(s, 0)
        pdf.set_font("Helvetica", "B", 9); pdf.cell(22, 6, s)
        pdf.set_fill_color(*SEV_COLOURS[s]); pdf.cell(max(0.5, 120 * n / total), 5, "", fill=True)
        pdf.set_font("Helvetica", "", 9); pdf.cell(10, 6, f" {n}", **NL)
    pdf.ln(2)
    table(["ID", "Severity", "Score", "Asset", "Finding", "Sources", "Conf."],
          [[r["fid"], r["x"].severity, f"{r['f'].score:.1f}", r["f"].target, r["f"].title,
            r["f"].source, r["x"].confidence.split(" (")[0]] for r in ctx["rows"]],
          (14, 16, 11, 24, 69, 26, 18), 7.5)

    h1("4. Detailed vulnerability findings")
    for r in ctx["rows"]:
        f, x, kb = r["f"], r["x"], r["kb"]
        if pdf.get_y() > 230:
            pdf.add_page()
        pdf.set_fill_color(*SEV_COLOURS[x.severity]); pdf.set_text_color(255)
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(0, 6.5, _t(f" {r['fid']}  [{x.severity} {f.score:.1f}]  {f.title}"), fill=True, **NL)
        pdf.set_text_color(0); pdf.ln(1)
        kv("Affected asset", f.target)
        kv("Severity", f"{x.severity}, score {f.score:.1f}/10 (tool base {f.severity:.1f}; CVSS not computed)")
        kv("CWE / OWASP", f"{kb.cwe} / {kb.owasp}" + (f" / {', '.join(f.evidence['cve'])}" if f.evidence.get("cve") else ""))
        kv("Description", kb.description)
        kv("Sources", f.source)
        kv("Confidence", x.confidence)
        kv("Validation status", x.validation)
        ev = {k: v for k, v in f.evidence.items() if k != "fix"}
        kv("Evidence", json.dumps(ev, default=str)[:500])
        kv("Why the agent ran this step", x.why_planned)
        pdf.set_font("Helvetica", "B", 9); pdf.cell(0, 5, "Explain why (score):", **NL)
        for lbl, val in (("Summary", x.summary), ("Exposure", x.exposure),
                         ("Exploitability", x.exploitability), ("Context", x.context),
                         ("Score trail", " -> ".join(x.score_trail))):
            pdf.set_x(20); pdf.set_font("Helvetica", "", 8.5)
            pdf.multi_cell(0, 4.6, _t(f"{lbl}: {val}"), **NL)
        pdf.set_font("Helvetica", "B", 9); pdf.cell(0, 5, "Fix steps:", **NL)
        for i, s in enumerate(kb.steps, 1):
            pdf.set_x(20); pdf.set_font("Helvetica", "", 8.5); pdf.multi_cell(0, 4.6, _t(f"{i}. {s}"), **NL)
        if kb.refs:
            pdf.set_font("Helvetica", "I", 8); pdf.multi_cell(0, 4.5, _t("References: " + ", ".join(kb.refs)), **NL)
        pdf.ln(3)

    h1("5. Impact and remediation")
    table(["ID", "Finding", "Business / technical impact", "Remediation"],
          [[r["fid"], r["f"].title, r["kb"].impact, " ".join(r["kb"].steps)]
           for r in ctx["rows"] if "soft-404" not in r["f"].tags],
          (14, 40, 56, 68), 7.5)
    p("Findings validated as likely false positives (soft-404) are listed in sections 3-4 but excluded here.", 8.5, "I")

    h1("6. Assessment limitations")
    for x in limitations(ctx):
        p(f"- {x}")

    h1("Appendix A. Plan, approval and audit trail")
    p("Every planned step, scope decision, approval, execution and error from the append-only JSONL audit log.", 8.5, "I")
    table(["Time", "Event", "Action", "Target", "Detail"],
          [[_ts(e.get("ts")), e["event"], e.get("action", ""), e.get("target", ""), _detail(e)] for e in ctx["events"]],
          (30, 20, 22, 36, 70), 7)
    h2("Analyst sign-off")
    p(meta.get("report status", "DRAFT - pending analyst review"))
    pdf.output(path)
    return path
