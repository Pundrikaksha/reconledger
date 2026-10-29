"""HTTP security-header check (lab only) + parser."""
from __future__ import annotations

import urllib.request
from urllib.parse import urlparse

from ..models import Finding
from ..scope import ScopeGuard

# header -> (title, severity, tags, fix)
REQUIRED = {
    "content-security-policy": ("Missing Content-Security-Policy", 5.0, ["xss-risk"],
                                "Add a restrictive Content-Security-Policy (default-src 'self')."),
    "strict-transport-security": ("Missing Strict-Transport-Security", 3.0, ["transport"],
                                  "Serve over HTTPS and add HSTS (max-age>=15552000)."),
    "x-content-type-options": ("Missing X-Content-Type-Options", 3.0, [],
                               "Add X-Content-Type-Options: nosniff."),
    "x-frame-options": ("Missing X-Frame-Options", 4.0, ["clickjacking"],
                        "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'."),
    "referrer-policy": ("Missing Referrer-Policy", 2.0, [],
                        "Add Referrer-Policy: strict-origin-when-cross-origin."),
}


def fetch(url: str, scope: ScopeGuard, timeout: int = 10) -> tuple[int, dict[str, str]]:
    scope.check(url)
    if urlparse(url).scheme not in {"http", "https"}:
        raise ValueError("only http(s) URLs")
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "ReconLedger-lab/0.2"})
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
    with opener.open(req, timeout=timeout) as resp:  # noqa: S310 (scope-checked)
        hdrs: dict[str, str] = {}
        for k, v in resp.headers.items():
            key = k.lower()
            hdrs[key] = f"{hdrs[key]}\n{v}" if key in hdrs else v
        return resp.status, hdrs


def parse(url: str, headers: dict[str, str]) -> list[Finding]:
    h = {k.lower(): v for k, v in headers.items()}
    u = urlparse(url)
    target = f"{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}"
    out: list[Finding] = []

    def add(fid: str, title: str, sev: float, tags: list[str], fix: str, ev: dict | None = None):
        out.append(Finding(id=f"hdr-{target}-{fid}", source="headers", target=target, title=title,
                           severity=sev, tags=["web", "misconfig", *tags],
                           evidence={"url": url, "fix": fix, **(ev or {})}))

    for name, (title, sev, tags, fix) in REQUIRED.items():
        if name == "strict-transport-security" and u.scheme != "https":
            continue  # HSTS only meaningful over HTTPS; flag plain HTTP separately
        if name not in h:
            add(name, title, sev, tags, fix)
    if u.scheme == "http":
        add("plain-http", "Served over plain HTTP (no TLS)", 4.0, ["transport"],
            "Terminate TLS in front of the app and redirect HTTP to HTTPS.")
    if h.get("access-control-allow-origin", "").strip() == "*":
        add("cors-wildcard", "CORS allows any origin (Access-Control-Allow-Origin: *)", 5.0,
            ["cors"], "Restrict Access-Control-Allow-Origin to trusted origins.",
            {"value": "*"})
    for leak in ("server", "x-powered-by"):
        if leak in h:
            add(f"leak-{leak}", f"Technology disclosed in {leak.title()} header", 2.0,
                ["info-leak"], f"Remove or genericise the {leak} header.", {"value": h[leak]})
    for cookie in h.get("set-cookie", "").split("\n"):
        if not cookie.strip():
            continue
        name = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        missing = [f for f in ("httponly", "secure") if f not in low]
        if missing:
            add(f"cookie-{name}", f"Cookie '{name}' missing {', '.join(missing)}", 4.0,
                ["session"], "Set HttpOnly, Secure and SameSite on session cookies.",
                {"cookie": name, "missing": missing})
    return out
