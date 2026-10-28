# ReconLedger

**A human-approved AI triage agent for sandboxed security assessments.** It reasons, asks before it acts, and explains every finding.

> Status: scaffold (pre-problem-statement). Built for the DataOps Innovation Hackathon 2026 by The Unique Trader Team.

## Features
- **Agent loop:** plan → scope check → human approval (active steps) → act → correlate → rank → report.
- **Scope guard:** only allow-listed lab targets (default `localhost` / `127.0.0.0/8`). Out-of-scope targets are blocked before approval is even asked.
- **Human-approval gate:** passive steps run on their own. Every active step stops with a reason and a risk note. Non-interactive runs deny by default.
- **Config-driven rules engine:** context-aware risk scoring from `rules/default.json` (exposure, exploitability, asset value). Each rule leaves an "explain why" line.
- **Correlation:** duplicate findings from different stages are merged (highest severity kept, sources joined).
- **Audit trail:** every plan, approval, block and execution is written to JSON lines.
- **Offline mock planner:** runs with no API keys. An LLM planner plugs into the same `Planner` interface.

## Setup
```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Run
```bash
reconledger triage samples/findings.json --rules rules/default.json --audit out/audit.jsonl --out out/report.md
pytest -q
```

## Layout
| Path | What |
|---|---|
| `src/reconledger/agent.py` | agent loop + `Planner` interface + mock planner |
| `src/reconledger/approval.py` | approval gate (CLI, deny-all) |
| `src/reconledger/scope.py` | scope allow-list |
| `src/reconledger/rules.py` | `RulesEngine` interface + JSON rules engine |
| `src/reconledger/ingest.py` | parser registry (stub) + dedup |
| `src/reconledger/report.py` | Markdown report |
| `src/reconledger/audit.py` | JSONL audit trail |

## Safety
All security testing must run only against a local sandboxed lab (for example OWASP Juice Shop in Docker on localhost). ReconLedger never targets third-party systems.

## License
MIT. See [LICENSE](LICENSE).
