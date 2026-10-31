"""Small offline knowledge base: CWE / OWASP Top 10 (2021) mapping, impact and fix
steps per finding type. Deterministic, no network, no API keys."""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding


@dataclass(frozen=True)
class Entry:
    cwe: str
    owasp: str
    description: str
    impact: str
    steps: tuple[str, ...]
    refs: tuple[str, ...] = field(default=())


OWASP_A05 = "A05:2021 Security Misconfiguration"
MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"

KB: list[tuple[str, Entry]] = [
    ("missing content-security-policy", Entry(
        "CWE-1021 / CWE-79 (defence in depth)", OWASP_A05,
        "The app sends no Content-Security-Policy, so the browser will run any script that ends up in a page.",
        "Any XSS bug becomes fully exploitable: session theft, account takeover, defacement.",
        ("Start with Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'.",
         "Run it in Content-Security-Policy-Report-Only first and fix violations.",
         "Remove inline scripts or move them behind nonces/hashes, then enforce."),
        (MDN + "Content-Security-Policy", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"))),
    ("cors allows any origin", Entry(
        "CWE-942", OWASP_A05,
        "Access-Control-Allow-Origin: * lets any website read this app's responses from a visitor's browser.",
        "Unauthenticated API data can be read cross-site; combined with token-in-header auth this widens data exposure.",
        ("Replace * with an explicit allow-list of trusted origins.",
         "Return Vary: Origin and never reflect arbitrary Origin values.",
         "Keep credentialed endpoints off the wildcard entirely."),
        (MDN + "Access-Control-Allow-Origin",))),
    ("served over plain http", Entry(
        "CWE-319", "A02:2021 Cryptographic Failures",
        "The app is reachable over unencrypted HTTP.",
        "Credentials and session tokens can be read or modified by anyone on the network path.",
        ("Terminate TLS (reverse proxy or app) with a valid certificate.",
         "Redirect all HTTP requests to HTTPS.", "Then enable HSTS."),
        ("https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",))),
    ("missing strict-transport-security", Entry(
        "CWE-319", "A02:2021 Cryptographic Failures",
        "No HSTS header, so browsers will still try plain HTTP first.",
        "Allows SSL-stripping on first visit once TLS exists.",
        ("After TLS is in place, add Strict-Transport-Security: max-age=31536000; includeSubDomains.",),
        (MDN + "Strict-Transport-Security",))),
    ("missing x-frame-options", Entry(
        "CWE-1021", OWASP_A05, "The app can be framed by other sites.",
        "Clickjacking: users can be tricked into clicking hidden buttons.",
        ("Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",), (MDN + "X-Frame-Options",))),
    ("missing x-content-type-options", Entry(
        "CWE-693", OWASP_A05, "Browsers may MIME-sniff responses.",
        "Uploaded or user-controlled content may be executed as script.",
        ("Add X-Content-Type-Options: nosniff on every response.",), (MDN + "X-Content-Type-Options",))),
    ("missing referrer-policy", Entry(
        "CWE-200", OWASP_A05, "Full URLs may leak to third parties in the Referer header.",
        "Tokens or IDs in URLs can leak to external sites.",
        ("Add Referrer-Policy: strict-origin-when-cross-origin.",), (MDN + "Referrer-Policy",))),
    ("missing permissions-policy", Entry(
        "CWE-693", OWASP_A05, "Browser features (camera, geolocation...) are not restricted.",
        "Low direct impact; widens what injected script could use.",
        ("Add Permissions-Policy disabling unused features, e.g. camera=(), geolocation=().",),
        (MDN + "Permissions-Policy",))),
    ("exposed directory", Entry(
        "CWE-548", "A01:2021 Broken Access Control",
        "A directory path is served without authentication and may list its files.",
        "Backups, documents or config files in it can be downloaded by anyone.",
        ("Disable directory listing.", "Move sensitive files out of the web root.",
         "Require authentication for the path if it must exist."),
        ("https://cwe.mitre.org/data/definitions/548.html",))),
    ("sensitive file reachable", Entry(
        "CWE-538", "A01:2021 Broken Access Control",
        "A file name associated with secrets or history files answered with HTTP 200.",
        "If real, credentials or internal data are exposed to anyone.",
        ("Confirm whether the content is real (see validation status).",
         "Remove the file from the web root or deny the path at the server.",
         "Rotate any secret it contained."),
        ("https://cwe.mitre.org/data/definitions/538.html",))),
    ("known-vulnerable component", Entry(
        "CWE-1104 / CWE-1395", "A06:2021 Vulnerable and Outdated Components",
        "A scanner signature for a component with a published CVE matched this path.",
        "If the component is really present, its published vulnerability (see CVE) applies.",
        ("Check the validation status: on single-page apps this is often a catch-all false positive.",
         "If real, upgrade or remove the component.", "Re-scan to confirm."),
        ("https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",))),
    ("technology disclosed", Entry(
        "CWE-200", OWASP_A05, "A header reveals the server or framework in use.",
        "Helps an attacker pick version-specific exploits.",
        ("Remove or genericise the header at the app or proxy.",), ())),
    ("cookie", Entry(
        "CWE-1004 / CWE-614", OWASP_A05, "A cookie lacks HttpOnly and/or Secure.",
        "Scripts can read it (XSS → session theft) or it can travel over HTTP.",
        ("Set HttpOnly, Secure and SameSite=Lax/Strict on session cookies.",), ())),
    ("open port", Entry(
        "CWE-200 (attack surface)", "n/a (exposure)",
        "A TCP service accepts connections.",
        "Every reachable service is attack surface; its risk depends on what runs behind it.",
        ("Confirm the service is meant to be exposed.",
         "Bind internal services to localhost or firewall them.",
         "Fix the weaknesses found behind this port (see related findings)."),
        ("https://nmap.org/book/man-port-scanning-basics.html",))),
    ("robots.txt", Entry(
        "CWE-200", OWASP_A05, "robots.txt lists a path the owner may not want indexed.",
        "Low: it hints where interesting content lives.",
        ("Protect the path with access control instead of relying on robots.txt.",), ())),
]

DEFAULT = Entry("n/a", "n/a", "Tool-reported observation.", "Review manually.",
                ("Review the evidence and decide whether action is needed.",), ())


def lookup(f: Finding) -> Entry:
    t = f.title.lower()
    for key, entry in KB:
        if key in t:
            return entry
    return DEFAULT


def severity_label(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 1.0:
        return "Low"
    return "Info"


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
