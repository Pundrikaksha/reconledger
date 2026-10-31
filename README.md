# ReconLedger

**A human-approved AI triage agent for sandboxed security assessments.** It plans, asks before it acts, runs real tools against a localhost lab, correlates what they find, and explains every ranking.

> Status: working lab loop covering PS1 (Track 1, AI VAPT): 3 live tools (network + web), PDF report, explain-why per finding. Built for the DataOps Innovation Hackathon 2026 by The Unique Trader Team.

## Features
- **Agent loop in rounds:** plan → scope check → human approval (active steps) → run tool → correlate → rank → report. After each round the planner sees all findings and proposes follow-ups (e.g. a header check on every web port nmap found open).
- **Real tool runners:** `nmap` TCP connect scan (`-sT -Pn -oX -`), an HTTP security-header check (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, wildcard CORS, Server / X-Powered-By leaks, cookie flags, plain HTTP) and a `nikto` web scan (`-Format json`, time-boxed). Each has a pure parser into the common `Finding` model.
- **Validation:** Nikto file/directory hits are re-fetched and compared with a random-path baseline (soft-404). Single-page apps answer 200 for everything, so matches are kept but tagged `likely-false-positive` and down-ranked.
- **Scope guard:** only loopback / private lab ranges can be allow-listed (public ranges and hostnames are refused at start-up). Every action is scope-checked before approval is asked, and each runner checks scope again before it touches the network.
- **Human-approval gate:** every active step stops with a reason and a risk note (`approve? [y/N]`). `--non-interactive` denies everything unless an analyst-signed plan file (`--approve-plan`) lists that exact action and target.
- **Correlation:** duplicates merge across tools (e.g. a missing CSP seen by both the header check and Nikto becomes one `headers+nikto` finding with a multi-tool boost); header weaknesses on a port nmap confirmed open get a `confirmed-open` boost, and the open port gets a `has-weaknesses` boost.
- **Config-driven rules engine:** `rules/default.json`; every rule leaves an "explain why" line in the report.
- **Explain why:** every finding gets a deterministic rationale (exposure, exploitability, context, confidence, validation, score trail) plus why the planner chose the step that found it. An optional LLM can rewrite it; it falls back to the deterministic text on any error.
- **Reports:** Markdown and PDF (`--pdf`, pure-Python `fpdf2`) following PS1 §7: executive summary and scope, methodology (NIST SP 800-115), tool execution summary, severity distribution, per-finding detail (asset, CWE / OWASP Top 10 2021, evidence, confidence, validation, explain-why, fix steps, references), limitations, and an appendix with the plan / approval / audit trail. The report stays DRAFT until `--sign-off NAME`.
- **Audit trail:** every round, plan, approval, block, execution and error goes to JSON lines.
- **No API keys needed:** deterministic `LabPlanner`; an LLM planner can plug into the same `Planner` interface.

## Tool integrations
| Tool | Layer | Live run | Import | Notes |
|---|---|---|---|---|
| Nmap | network | yes | `nmap-xml` | TCP connect scan, scope-checked |
| HTTP header check | web | yes (built in) | via `generic-json` | no external binary |
| Nikto | web | yes | `nikto-json` | soft-404 validated |
| Generic JSON | any | n/a | `generic-json` | bring findings from any tool |
| OWASP ZAP | web | planned | planned | baseline scan + JSON import |
| Nessus / OpenVAS | network | planned | planned | report import only |
| Burp Suite | web | planned | planned | XML issue import |
| Metasploit | exploitation | planned | n/a | lab-only, per-module human approval |

## Setup
Requires Python 3.11+, nmap, Perl (for Nikto) and Docker with Compose (for the lab).
```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q                      # unit + loop tests (no Docker, nmap or Nikto needed)
git clone --depth 1 https://github.com/sullo/nikto /opt/nikto   # Nikto (needs Perl + XML::Writer)
export RECONLEDGER_NIKTO=/opt/nikto/program/nikto.pl
```

## Run the lab (localhost only)
```bash
docker compose -f lab/docker-compose.yml up -d                 # OWASP Juice Shop on 127.0.0.1:3000
docker compose -f lab/docker-compose.yml --profile dvwa up -d  # optional DVWA on 127.0.0.1:4280
curl -sI http://127.0.0.1:3000/ | head -1                      # wait for HTTP/1.1 200 OK
```
Every port in the compose file is bound to `127.0.0.1`. Do not change that: these apps are deliberately vulnerable.

## Run an assessment
```bash
reconledger assess --target 127.0.0.1 --ports 3000,4280 \
  --audit out/audit.jsonl --out out/report.md --pdf out/report.pdf
# answer y/N at each [APPROVAL NEEDED] prompt

# unattended, using an analyst-signed plan (anything not listed is denied)
reconledger assess --target 127.0.0.1 --ports 3000,4280 --non-interactive \
  --approve-plan samples/approved-plan.json --out out/report.md --pdf out/report.pdf
```
Options:
- `--non-interactive`: denies every active step, except those listed in `--approve-plan FILE`.
- `--pdf PATH`: also write the PDF report.
- `--sign-off NAME`: mark the report as reviewed by an analyst (otherwise DRAFT).
- `--no-nikto`: skip the Nikto step.
- `RECONLEDGER_NIKTO=/path/nikto.pl`: where Nikto lives (otherwise PATH).
- `--scope 10.10.0.0/16`: add a private lab range. Public ranges are refused.
- `--extra-target URL`: add a header check on another URL. It is useful for showing that the scope guard blocks it.
- `RECONLEDGER_NMAP_DATADIR=/path`: point nmap at its data files, for static nmap builds.

Triage existing findings (passive, no network):
```bash
reconledger triage samples/findings.json --out out/report.md
reconledger triage nikto.json --format nikto-json --out out/report.md --pdf out/report.pdf
```

Sample output from a real run against Juice Shop (31 Oct 2026; 64 s; 3/3 steps approved by plan file; 1 out-of-scope step blocked; 33 raw tool hits → 30 findings: 3 High, 3 Medium, 3 Low, 21 Info, of which 19 are soft-404 likely false positives; 3 multi-tool merges): [`samples/demo-report.md`](samples/demo-report.md), [`samples/demo-report.pdf`](samples/demo-report.pdf), with its audit trail [`samples/demo-audit.jsonl`](samples/demo-audit.jsonl) and terminal transcript [`samples/demo-transcript.txt`](samples/demo-transcript.txt).

Stop the lab: `docker compose -f lab/docker-compose.yml down`.

## Layout
| Path | What |
|---|---|
| `lab/docker-compose.yml` | Juice Shop (+ optional DVWA), 127.0.0.1 only |
| `src/reconledger/agent.py` | round-based agent loop, `Planner` interface, `LabPlanner`, `MockPlanner` |
| `src/reconledger/tools/nmap.py` | nmap runner + XML parser |
| `src/reconledger/tools/headers.py` | HTTP header runner + parser |
| `src/reconledger/tools/nikto.py` | Nikto runner + JSON parser + soft-404 validation |
| `src/reconledger/runners.py` | binds the tools to action names |
| `src/reconledger/correlate.py` | cross-stage correlation |
| `src/reconledger/approval.py` | approval gate (CLI, deny-all, signed plan file) |
| `src/reconledger/scope.py` | lab-only scope allow-list |
| `src/reconledger/rules.py` | `RulesEngine` interface + JSON rules engine |
| `src/reconledger/ingest.py` | parser registry (`generic-json`, `nmap-xml`, `nikto-json`) + dedup |
| `src/reconledger/report.py` | Markdown + PDF report (PS1 §7 sections) |
| `src/reconledger/explain.py` | per-finding explain-why (+ optional LLM hook) |
| `src/reconledger/kb.py` | CWE / OWASP / remediation knowledge base |
| `src/reconledger/integrations.py` | live / import / planned tool matrix |
| `src/reconledger/audit.py` | JSONL audit trail |

## Safety
All security testing runs only against the local sandboxed lab. ReconLedger never targets third-party systems: the scope guard only accepts loopback and private ranges, and both the agent and each runner enforce it.

## Limitations
- Severity is a rules-based 0-10 score, not a computed CVSS vector.
- Nikto signatures are noisy on single-page apps; validation down-ranks but never deletes them.
- ZAP, Nessus/OpenVAS, Burp and Metasploit are planned, not implemented.

## License
MIT. See [LICENSE](LICENSE).
