"""Nikto web scanner (lab only): runner, JSON parser and soft-404 validation.

Nikto is a Perl script, so ReconLedger runs it from a checkout:
  git clone --depth 1 https://github.com/sullo/nikto.git
  export RECONLEDGER_NIKTO=/path/to/nikto/program/nikto.pl
Findings are normalised into the common `Finding` schema. Header findings use the
same titles as the built-in header check so `dedupe` merges them (source
"headers+nikto" = two tools agree).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlparse

from ..models import Finding
from ..scope import ScopeGuard
from .headers import REQUIRED

# Nikto tuning: 0 file upload, 1 interesting files/logs, 2 misconfig/default files,
# 3 information disclosure, b software identification. No injection/DoS classes.
SAFE_TUNING = "0123b"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SENSITIVE_HINTS = ("history", "htpasswd", "passwd", "password", "users", "accounts",
                   "master", "conn", "login", "userdata", ".git", ".env", "backup", ".sql")


def find_nikto() -> str | None:
    env = os.environ.get("RECONLEDGER_NIKTO")
    if env and Path(env).is_file():
        return env
    which = shutil.which("nikto") or shutil.which("nikto.pl")
    if which:
        return which
    for cand in ("/tmp/nikto/program/nikto.pl", "/opt/nikto/program/nikto.pl"):
        if Path(cand).is_file():
            return cand
    return None


def build_command(url: str, scope: ScopeGuard, out_path: str, maxtime: int = 180,
                  nikto: str | None = None) -> list[str]:
    scope.check(url)
    if urlparse(url).scheme not in {"http", "https"}:
        raise ValueError("only http(s) URLs")
    nikto = nikto or find_nikto()
    if not nikto:
        raise FileNotFoundError("nikto not found; set RECONLEDGER_NIKTO to program/nikto.pl")
    cmd = ["perl", nikto] if nikto.endswith(".pl") else [nikto]
    return cmd + ["-h", url, "-Format", "json", "-o", out_path, "-maxtime", f"{maxtime}s",
                  "-Tuning", SAFE_TUNING, "-nointeractive", "-ask", "no"]


def run(url: str, scope: ScopeGuard, maxtime: int = 180) -> str:
    with tempfile.TemporaryDirectory() as d:
        out = str(Path(d) / "nikto.json")
        cmd = build_command(url, scope, out, maxtime)
        subprocess.run(cmd, capture_output=True, text=True, timeout=maxtime + 60, check=False)
        if not Path(out).exists():
            raise RuntimeError("nikto produced no JSON output")
        return Path(out).read_text(encoding="utf-8", errors="replace")


def _load(text: str) -> list[dict]:
    data = json.loads(text)
    return data if isinstance(data, list) else [data]


def _classify(msg: str, url: str, refs: str = "") -> tuple[str, float, list[str], str]:
    """Return (title, severity, tags, fix) for one Nikto item."""
    low = msg.lower()
    m = re.search(r"suggested security header missing: ([a-z0-9-]+)", low)
    if m:
        hdr = m.group(1)
        if hdr in REQUIRED:
            title, sev, tags, fix = REQUIRED[hdr]
            return title, sev, ["misconfig", *tags], fix
        name = "-".join(p.capitalize() for p in hdr.split("-"))
        return (f"Missing {name}", 2.0, ["misconfig"],
                f"Add a {name} header that restricts browser features the app does not use.")
    if "access-control-allow-origin" in low and "*" in msg:
        return ("CORS allows any origin (Access-Control-Allow-Origin: *)", 5.0,
                ["misconfig", "cors"], "Restrict Access-Control-Allow-Origin to trusted origins.")
    if "robots.txt" in low:
        return (f"robots.txt reveals path {url}", 2.0, ["info-leak"],
                "Do not rely on robots.txt to hide paths; protect them with authentication.")
    if "uncommon header" in low:
        return (f"Uncommon response header: {msg.split('found')[0].strip()}", 1.0,
                ["info-leak", "informational"], "Remove headers that disclose internal details.")
    if CVE_RE.search(msg + " " + refs):
        name = msg.split(" identified")[0].split(".")[0][:60]
        tags = ["known-vuln"] + (["exposed-path"] if url not in ("", "/") else [])
        return (f"Known-vulnerable component signature: {name} ({url})", 5.0, tags,
                "Confirm the component and version really exist, then patch or remove it.")
    if any(h in url.lower() for h in SENSITIVE_HINTS) or "authorization information" in low:
        return (f"Sensitive file reachable: {url}", 6.0, ["exposed-path", "sensitive-file"],
                "Remove the file from the web root or block it at the server.")
    if len(url) > 1 and url.endswith("/"):
        return (f"Exposed directory {url}", 5.0, ["exposed-path", "sensitive-file"],
                "Disable directory listing and require authentication for this path.")
    return (f"Nikto: {msg[:80]} ({url})", 2.0, ["informational"],
            "Review this item manually.")


def parse_json(text: str) -> list[Finding]:
    out: list[Finding] = []
    for host in _load(text):
        target = f"{host.get('ip') or host.get('host')}:{host.get('port')}"
        for i, v in enumerate(host.get("vulnerabilities", [])):
            url, msg = v.get("url", "/"), v.get("msg", "").replace("\\*", "*")
            refs = [r for r in str(v.get("references", "")).split() if r]
            title, sev, tags, fix = _classify(msg, url, " ".join(refs))
            cves = sorted(set(c.upper() for c in CVE_RE.findall(msg + " " + " ".join(refs))))
            out.append(Finding(
                id=f"nikto-{target}-{v.get('id', i)}-{i}", source="nikto", target=target,
                title=title, severity=sev, tags=["web", *tags],
                evidence={"url": url, "nikto_id": v.get("id"), "method": v.get("method"),
                          "nikto_msg": msg, "references": refs, "cve": cves, "fix": fix},
            ))
    return out


Fetcher = Callable[[str], tuple[int, bytes]]


def _http_get(url: str) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": "ReconLedger-lab/0.3"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 (scope-checked)
            return r.status, r.read(200_000)
    except urllib.error.HTTPError as e:
        return e.code, b""


def validate_soft404(base_url: str, findings: list[Finding], scope: ScopeGuard,
                     fetch: Fetcher = _http_get) -> list[Finding]:
    """Single-page apps answer 200 to every path, so Nikto's "file found" items can be
    false positives. Fetch a random path as a baseline and mark every exposed-path
    finding whose body matches the baseline as a likely false positive."""
    scope.check(base_url)
    probe = urljoin(base_url, f"/rl-soft404-{uuid.uuid4().hex[:8]}")
    status, body = fetch(probe)
    baseline = hashlib.sha256(body).hexdigest() if status == 200 else None
    for f in findings:
        if "exposed-path" not in f.tags:
            continue
        url = urljoin(base_url, f.evidence.get("url", "/"))
        scope.check(url)
        st, b = fetch(url)
        digest = hashlib.sha256(b).hexdigest()
        f.evidence.update({"validated_status": st, "body_sha256": digest[:16],
                           "soft404_baseline": (baseline or "none")[:16]})
        if baseline and digest == baseline:
            f.tags.append("soft-404")
            f.evidence["validation"] = ("likely false positive: response is identical to the "
                                        "app's catch-all page for a random path")
        elif st == 200:
            f.tags.append("validated")
            f.evidence["validation"] = f"confirmed: GET returned {st} with distinct content"
        else:
            f.tags.append("soft-404")
            f.evidence["validation"] = f"not reproduced: GET returned {st}"
    return findings
