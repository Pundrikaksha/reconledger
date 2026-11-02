# ReconLedger

**A human-approved AI triage agent for sandboxed security assessments.** It plans, asks before it acts, runs real tools against a localhost lab, correlates what they find, and explains every ranking.

> Status: working lab loop covering PS1 (Track 1, AI VAPT): 3 live tools (network + web), PDF report, explain-why per finding. Built for the DataOps Innovation Hackathon 2026 by The Unique Trader Team.

## Vultr Agent Rush: Blast Radius Zero
This branch adapts the earlier ReconLedger prototype (the CLI loop described below) for the lablab.ai Vultr Agent Rush challenge "Blast Radius Zero": a web-based agent that plans a task, sends each action into an isolated sandbox and returns verifiable output.

```text
browser ──> control layer (FastAPI on a Vultr VM)
              │  planner: deterministic LabPlanner, optionally advised by
              │           Vultr Serverless Inference (menu of allowed steps only)
              │  human approval: Approve / Reject with a required reason
              │  one throwaway Docker container per approved step ──> internal lab network
              └  hash-chained ledger + Markdown report
```

Scores and rankings stay deterministic. The LLM only suggests an order for steps from a fixed menu and rewrites narration; it never touches a score and cannot skip approval.

### The four containment guarantees
| Guarantee | How it is enforced | Code |
|---|---|---|
| Process isolation | Own container per step: `--read-only` with a small `--tmpfs /tmp`, `--cap-drop ALL`, `no-new-privileges`, non-root `--user`, no mounts or published ports. The final argv is checked, and any network Docker doesn't report as internal is refused before the container starts. | `sandbox.py`: `build_argv`, `_assert_contained`, `_check_network`; `lab/docker-compose.yml` |
| No secrets inside | No `-e` or `--env-file` is ever built. The docker CLI itself gets only an allow-listed environment. The LLM key stays in the control layer, and the sandbox has no route to the LLM API. | `sandbox.py`: `_cli_env`; `llm_vultr.py` |
| Resource limits on every run | `--memory` 256m with swap disabled, `--cpus` 0.5, `--pids-limit` 128, a wall-clock timeout, and a cap on captured output. | `sandbox.py`: `SandboxCaps`, `subprocess_executor` |
| Destroyed after each task | `--rm`, then `docker kill` and `docker rm -f` in a `finally`, then a check that the container is gone. The result is logged as `destroyed`. | `sandbox.py`: `SandboxRunner.run`, `_teardown` |

Before any of this, the scope guard blocks out-of-scope targets without calling Docker, and the web UI only offers a fixed list of lab targets. Each `sandbox_run` ledger entry records the caps, image, container, duration, outcome and SHA-256 of the output.

**Verification status:** the unit tests use a fake Docker executor. Run `reconledger demo-containment` on a Docker host to check the guarantees at runtime; `--dry-run` only checks the commands.

### Environment variables
Copy `.env.example` to `.env`. The app reads the process environment and does not load `.env` itself, so export the values first (for example `set -a; . ./.env; set +a`).

| Variable | Purpose |
|---|---|
| `LLM_PROVIDER` | `vultr`, `mock`, or unset for no LLM (fully deterministic) |
| `LLM_BASE_URL` | Default `https://api.vultrinference.com/v1`. Must be https, or http on loopback |
| `LLM_API_KEY` | Required for `vultr` |
| `LLM_MODEL` | Required for `vultr`; no default model |
| `LLM_TIMEOUT` | Seconds, default 20 |
| `WEB_BASIC_AUTH_USER`, `WEB_BASIC_AUTH_PASS` | HTTP basic auth. Required unless bound to loopback |
| `RECONLEDGER_WEB_LEDGER` | Ledger file, default `out/web-ledger.jsonl` |
| `RECONLEDGER_SANDBOX_IMAGE`, `RECONLEDGER_SANDBOX_NETWORK` | Defaults `reconledger-sandbox:latest`, `reconledger-lab` |

### Run it
```bash
pip install -e ".[dev,web]"
docker compose -f lab/docker-compose.yml up -d     # creates the internal reconledger-lab network
docker build -t reconledger-sandbox:latest -f deploy/sandbox/Dockerfile.sandbox deploy/sandbox

reconledger web                       # http://127.0.0.1:8080 (or: python -m reconledger.web)
reconledger web --dry-run             # try the UI without Docker; nothing is executed

reconledger demo-containment          # PASS/FAIL for all four guarantees (or: python scripts/containment_demo.py)
reconledger demo-containment --dry-run
```
Non-loopback binds refuse to start without basic auth. Basic auth sends the password with every request, so put TLS in front of any non-loopback deployment.

### Known limits
- The sandbox image ships `nmap` and `curl`, so Nikto is not part of the sandboxed flow. The CLI `assess` loop still runs it, unsandboxed.
- Juice Shop and DVWA are also on the Compose default network so their `127.0.0.1` ports keep working. A sandbox could only reach the internet through them by exploiting an app, such as an SSRF bug. ReconLedger's tools send no such payloads.
- The ledger detects tampering but cannot prevent a rewrite of the whole file. Keep the head hash, shown in each report, somewhere else if that matters.
- Assessments live in memory and are lost on restart. The ledger file persists.

### Deploy on Vultr
For deploying ReconLedger on a single Vultr Cloud Compute VM (Ubuntu 24.04) with automatic HTTPS (Caddy) and complete lab isolation (Blast Radius Zero), follow the step-by-step instructions in [`deploy/vultr/RUNBOOK.md`](deploy/vultr/RUNBOOK.md).

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

## Track 1 (AI VAPT) fit
How the PS1 mandatory prototype requirements map to the code. "Live" means it runs against the lab today; "planned" means it is not implemented yet.

| PS1 mandatory requirement | Where it is | Status |
|---|---|---|
| Scope validation | `src/reconledger/scope.py` (`ScopeGuard`: loopback/private only, public ranges refused at start-up); checked again in `agent.py` (`Agent._step`) and inside each runner in `tools/` | live |
| Auditable plan | `agent.py` (`Planner` interface, round-based `LabPlanner`, reason + risk note per `PlannedAction` in `models.py`); `audit.py` JSONL trail; Appendix A of the report | live |
| ≥3 working tool integrations covering network + web | Network: Nmap (`tools/nmap.py`). Web: HTTP header check (`tools/headers.py`) and Nikto (`tools/nikto.py`). Imports: `nmap-xml`, `nikto-json`, `generic-json` (`ingest.py`). Bound to actions in `runners.py` | live (3 tools + 3 import formats) |
| Common finding schema | `models.py` (`Finding`: id, source, target, title, severity, tags, evidence, score, reasons); every parser emits it | live |
| Evidence links | `Finding.evidence` (URL, port, header, Nikto item, re-fetch result), printed per finding in the report | live |
| Duplicate handling | `ingest.py` (`dedupe`) + `correlate.py` (cross-tool merges such as `headers+nikto`, multi-tool and `confirmed-open` boosts) | live |
| Risk ranking | `rules.py` + `rules/default.json` (rule-based 0–10 score, **not CVSS**), soft-404 down-ranking in `tools/nikto.py`, explain-why in `explain.py` | live |
| Professional downloadable PDF report (PS1 §7) | `report.py` (`to_pdf`, pure-Python `fpdf2`): executive summary and scope, methodology, severity distribution, detailed findings (CWE/OWASP, evidence, confidence, validation, fix), impact and remediation, limitations, Appendix A plan/approval/audit. DRAFT until `--sign-off` | live |
| Analyst approval gate | `approval.py` (`cli_approver` y/N prompt with reason + risk note, `deny_all`, `plan_file_approver` for `--approve-plan`); every ACTIVE action stops in `Agent._step` | live |
| Conversational request | CLI request (`reconledger assess` / `triage`, `cli.py`) with prompts and plain-language progress; the planner is rule-based today, an LLM planner plugs into the same `Planner` interface | partial (no free-text chat yet) |

Named tools beyond the mandatory three: **OWASP ZAP, Nessus/OpenVAS, Burp Suite and Metasploit are planned, not implemented** (see the table above). Metasploit, if added, stays lab-only behind per-module human approval.

## Demo
- **Video:** `demo/reconledger-demo.mp4` in the HackTheCore entry package (57 s, 1280x720, no audio). **Drive link:** [ReconLedger-HackTheCore-demo.mp4](https://drive.google.com/file/d/1m2FCbeYmuLR_j-11Jb_I5iorajH1WDLw/view) (private until sharing is set to anyone-with-link before submission).
- **What it shows:** one interactive `reconledger assess` against Juice Shop on 127.0.0.1:3000: live `[APPROVAL NEEDED] … approve? [y/N]` prompts for nmap_scan, header_check and nikto_scan; `[SCOPE BLOCKED] header_check -> http://example.com/ … (no request sent)`; per-tool `[RUNNING]`/`[DONE]` lines; then the summary, top findings and report files. Run time 73.8 s (Nikto 63.1 s); 30 findings (3 High, 3 Medium, 3 Low, 21 Info).
- **Honesty note:** the `y` answers at the approval prompts were **typed by a script** (a pexpect driver that answers `y` only for 127.0.0.1 targets), not by a person at the keyboard. The prompts, tool runs and output are real. Idle stretches over 4 s (mostly the Nikto wait) are cut and playback is 0.6x; an on-screen line marks the Nikto cut.

## Setup
Requires Python 3.11+. Live scans also need `nmap` and Perl (for Nikto). The optional lab needs Docker with Compose.

**Option A: pipx (just the CLI)**
```bash
pipx install .                 # from a clone of this repo
reconledger --help
```

**Option B: venv (development, runs the tests)**
```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q                      # unit + loop tests (no Docker, nmap or Nikto needed)
```

**Optional live tools**
```bash
sudo apt-get install -y nmap   # or brew install nmap
git clone --depth 1 https://github.com/sullo/nikto /opt/nikto   # Nikto (needs Perl + XML::Writer)
export RECONLEDGER_NIKTO=/opt/nikto/program/nikto.pl
```

**Optional local lab (127.0.0.1 only):** OWASP Juice Shop (and optionally DVWA) via Docker, see the next section. Without Docker you can run a Juice Shop release locally, but make sure it is reachable only from 127.0.0.1 (host firewall or a loopback-only bind). Never expose these deliberately vulnerable apps on a public interface, and never point ReconLedger at a host you are not authorised to test.

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
| `src/reconledger/audit.py` | JSONL audit trail + hash-chained `LedgerLog` |
| `src/reconledger/sandbox.py` | Docker sandbox runner: caps, teardown, lab target list, sandboxed tool bindings |
| `src/reconledger/llm_vultr.py` | Vultr Serverless Inference / mock LLM, validated plan suggestions |
| `src/reconledger/web/` | FastAPI approve/reject control layer |
| `src/reconledger/containment_demo.py` | Containment demo (`scripts/containment_demo.py` wraps it) |
| `deploy/sandbox/Dockerfile.sandbox` | Minimal sandbox tools image |
| `deploy/vultr/` | Single-VM Vultr deploy: Dockerfile.control, docker-compose.yml, Caddyfile, cloud-init, Makefile, RUNBOOK |

## Safety
All security testing runs only against the local sandboxed lab. ReconLedger never targets third-party systems: the scope guard only accepts loopback and private ranges, and both the agent and each runner enforce it.

## Limitations
- Severity is a rules-based 0-10 score, not a computed CVSS vector.
- Nikto signatures are noisy on single-page apps; validation down-ranks but never deletes them.
- ZAP, Nessus/OpenVAS, Burp and Metasploit are planned, not implemented.
- The planner is rule-based (`LabPlanner`). In the web UI an LLM can suggest an order for steps from a fixed menu; a free-text conversational planner is not built yet.

## License
MIT. See [LICENSE](LICENSE).
