"""Honest integration matrix (PS1 asks teams to disclose live vs import vs planned)."""
from __future__ import annotations

# tool -> (status, coverage, how)
MATRIX: list[tuple[str, str, str, str]] = [
    ("Nmap", "live + import", "network", "runs `nmap -sT -Pn` against the lab; parses XML (`--format nmap-xml`)"),
    ("Nikto", "live + import", "web", "runs nikto.pl (safe tuning 0123b) against lab web ports; parses JSON (`--format nikto-json`); soft-404 validation"),
    ("HTTP header check (built-in)", "live", "web", "one GET per web port; CSP/HSTS/XFO/XCTO/Referrer/CORS/cookies/leaks"),
    ("Generic JSON findings", "import", "any", "`reconledger triage file.json`"),
    ("OWASP ZAP", "planned", "web", "not implemented"),
    ("Nessus", "planned", "network", "not implemented"),
    ("OpenVAS / Greenbone", "planned", "network", "not implemented"),
    ("Burp Suite", "planned", "web", "not implemented"),
    ("Metasploit", "planned (human-approved, lab-only)", "exploitation", "not implemented; ReconLedger performs no exploitation"),
]
