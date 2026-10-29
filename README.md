# ReconLedger

**A human-approved AI triage agent for sandboxed security assessments.** It plans, asks before it acts, runs real tools against a localhost lab, correlates what they find, and explains every ranking.

> Status: working lab loop (pre-problem-statement). Built for the DataOps Innovation Hackathon 2026 by The Unique Trader Team.

## Features
- **Agent loop in rounds:** plan → scope check → human approval (active steps) → run tool → correlate → rank → report. After each round the planner sees all findings and proposes follow-ups (e.g. a header check on every web port nmap found open).
- **Real tool runners:** `nmap` TCP connect scan (`-sT -Pn -oX -`) and an HTTP security-header check (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, wildcard CORS, Server / X-Powered-By leaks, cookie flags, plain HTTP). Each has a pure parser into the `Finding` model.
- **Scope guard:** only loopback / private lab ranges can be allow-listed (public ranges and hostnames are refused at start-up). Every action is scope-checked before approval is asked, and each runner checks scope again before it touches the network.
- **Human-approval gate:** every active step stops with a reason and a risk note (`approve? [y/N]`). `--non-interactive` denies everything.
- **Correlation:** duplicates merge across stages; header weaknesses on a port nmap confirmed open get a `confirmed-open` boost, and the open port gets a `has-weaknesses` boost.
- **Config-driven rules engine:** `rules/default.json`; every rule leaves an "explain why" line in the report.
- **Audit trail:** every round, plan, approval, block, execution and error goes to JSON lines.
- **No API keys needed:** deterministic `LabPlanner`; an LLM planner can plug into the same `Planner` interface.

## Setup
Requires Python 3.11+, Docker (with Compose) and nmap.
```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q                      # unit + loop tests (no Docker or nmap needed)
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
  --audit out/audit.jsonl --out out/report.md
# answer y/N at each [APPROVAL NEEDED] prompt
```
Options:
- `--non-interactive`: dry run that denies every active step.
- `--scope 10.10.0.0/16`: add a private lab range. Public ranges are refused.
- `--extra-target URL`: add a header check on another URL. It is useful for showing that the scope guard blocks it.
- `RECONLEDGER_NMAP_DATADIR=/path`: point nmap at its data files, for static nmap builds.

Triage existing findings (passive, no network):
```bash
reconledger triage samples/findings.json --out out/report.md
```

Sample output from a real run against Juice Shop: [`samples/demo-report.md`](samples/demo-report.md), with its audit trail [`samples/demo-audit.jsonl`](samples/demo-audit.jsonl) and terminal transcript [`samples/demo-transcript.txt`](samples/demo-transcript.txt).

Stop the lab: `docker compose -f lab/docker-compose.yml down`.

## Layout
| Path | What |
|---|---|
| `lab/docker-compose.yml` | Juice Shop (+ optional DVWA), 127.0.0.1 only |
| `src/reconledger/agent.py` | round-based agent loop, `Planner` interface, `LabPlanner`, `MockPlanner` |
| `src/reconledger/tools/nmap.py` | nmap runner + XML parser |
| `src/reconledger/tools/headers.py` | HTTP header runner + parser |
| `src/reconledger/runners.py` | binds the tools to action names |
| `src/reconledger/correlate.py` | cross-stage correlation |
| `src/reconledger/approval.py` | approval gate (CLI, deny-all) |
| `src/reconledger/scope.py` | lab-only scope allow-list |
| `src/reconledger/rules.py` | `RulesEngine` interface + JSON rules engine |
| `src/reconledger/ingest.py` | parser registry (`generic-json`, `nmap-xml`) + dedup |
| `src/reconledger/report.py` | Markdown report |
| `src/reconledger/audit.py` | JSONL audit trail |

## Safety
All security testing runs only against the local sandboxed lab. ReconLedger never targets third-party systems: the scope guard only accepts loopback and private ranges, and both the agent and each runner enforce it.

## License
MIT. See [LICENSE](LICENSE).
