"""Per-finding "explain why": deterministic rationale for each score and each plan step.

The explanation is built only from data the run actually produced (tool sources,
correlation tags, rule hits, validation results), so it needs no API key and is
reproducible. An optional LLM hook can rewrite the text; any failure falls back
to the deterministic version.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .kb import lookup, severity_label
from .models import Finding

LLMHook = Callable[[str], str]


@dataclass
class Explanation:
    severity: str
    exposure: str
    exploitability: str
    context: str
    confidence: str
    validation: str
    score_trail: list[str] = field(default_factory=list)
    why_planned: str = ""
    summary: str = ""


def _sources(f: Finding) -> list[str]:
    return [s for s in f.source.split("+") if s]


def confidence(f: Finding) -> str:
    srcs = _sources(f)
    if "soft-404" in f.tags:
        return "Low (validation shows a catch-all response; likely false positive)"
    if "validated" in f.tags:
        return "High (re-fetched and confirmed distinct content)"
    if len(srcs) > 1:
        return f"High (independently reported by {len(srcs)} tools: {', '.join(srcs)})"
    if srcs and srcs[0] in {"headers", "nmap"}:
        return "High (directly observed in the live response / TCP handshake)"
    if srcs and srcs[0] == "nikto":
        return "Medium (single signature-based scanner, not independently confirmed)"
    return "Medium (imported, not re-observed in this run)"


def validation_status(f: Finding) -> str:
    if f.evidence.get("validation"):
        return str(f.evidence["validation"])
    if "confirmed-open" in f.tags:
        return "observed; port confirmed reachable by nmap; not exploited (no active exploitation performed)"
    return "observed by tool; not exploited (no active exploitation performed)"


def explain(f: Finding, why_planned: str = "", llm: LLMHook | None = None) -> Explanation:
    tags = set(f.tags)
    target = f.target
    if "confirmed-open" in tags or "open-port" in tags:
        exposure = f"{target} accepts TCP connections (confirmed by nmap in this run)."
    else:
        exposure = f"{target} answered the tool over HTTP; reachability not separately port-scanned."
    exposure += " Lab scope: loopback only, so real-world exposure depends on deployment."

    expl_bits = []
    if "known-vuln" in tags or f.evidence.get("cve"):
        expl_bits.append(f"matches a known-vulnerable signature ({', '.join(f.evidence.get('cve', [])) or 'CVE ref'})")
    if "xss-risk" in tags:
        expl_bits.append("removes a browser defence, so any script-injection bug becomes directly exploitable")
    if "cors" in tags:
        expl_bits.append("any website can read responses cross-origin without extra steps")
    if "sensitive-file" in tags:
        expl_bits.append("a plain GET is enough to retrieve it if real")
    if "transport" in tags:
        expl_bits.append("needs a network-position attacker (same Wi-Fi / path)")
    if "info-leak" in tags or "informational" in tags:
        expl_bits.append("not exploitable on its own; aids reconnaissance")
    if "open-port" in tags:
        expl_bits.append(f"the port fronts {f.evidence.get('weaknesses_behind_port', 0)} weaknesses found by other tools")
    if "soft-404" in tags:
        expl_bits.append("validation suggests the file is not really there")
    exploitability = ("; ".join(expl_bits) or "no specific exploitability signal; scored on base severity") + "."

    rule_hits = [r for r in f.reasons if ":" in r and not r.startswith(("base severity", "correlated"))]
    corr = [r for r in f.reasons if r.startswith("correlated")]
    ctx = []
    if corr:
        ctx.append("Correlation: " + "; ".join(c.split(": ", 1)[1] for c in corr))
    if rule_hits:
        ctx.append("Rules applied: " + "; ".join(rule_hits))
    if len(_sources(f)) > 1:
        ctx.append(f"Duplicate merged across {f.source}")
    context = ". ".join(ctx) or "No context rules applied."

    entry = lookup(f)
    sev = severity_label(f.score)
    summary = (f"{f.title} on {target} is rated {sev} ({f.score:.1f}/10): base {f.severity:.1f}"
               f" from the tool, adjusted by {len(rule_hits)} rule(s). {entry.impact}")
    if llm is not None:
        try:
            rewritten = llm(
                "Rewrite for a client VAPT report in 2 sentences, keep every fact, add nothing:\n"
                + summary + "\n" + exposure + "\n" + exploitability)
            if rewritten and rewritten.strip():
                summary = rewritten.strip()
        except Exception:  # LLM is optional; deterministic text stays
            pass
    return Explanation(severity=sev, exposure=exposure, exploitability=exploitability,
                       context=context, confidence=confidence(f),
                       validation=validation_status(f), score_trail=list(f.reasons),
                       why_planned=why_planned, summary=summary)
