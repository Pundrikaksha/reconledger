"""nmap TCP connect scan (lab only) + XML parser."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

from ..models import Finding
from ..scope import ScopeGuard

PORTS_RE = re.compile(r"^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*$")
WEB_SERVICES = {"http", "https", "http-alt", "http-proxy", "ppp", "hbci", "ssl/http"}


def build_command(host: str, ports: str, scope: ScopeGuard, datadir: str | None = None) -> list[str]:
    scope.check(host)
    if not PORTS_RE.match(ports):
        raise ValueError(f"bad port spec {ports!r}")
    cmd = [shutil.which("nmap") or "nmap"]
    datadir = datadir or os.environ.get("RECONLEDGER_NMAP_DATADIR")
    if datadir:
        cmd += ["--datadir", datadir]
    # -sT: unprivileged connect scan. -Pn: no ping. -oX -: XML to stdout.
    return cmd + ["-sT", "-Pn", "-n", "-p", ports, "-oX", "-", host]


def run(host: str, ports: str, scope: ScopeGuard, timeout: int = 120) -> str:
    cmd = build_command(host, ports, scope)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
    return proc.stdout


def parse_xml(text: str) -> list[Finding]:
    root = ET.fromstring(text)
    out: list[Finding] = []
    for host in root.iter("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "unknown"
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            num, proto = port.get("portid"), port.get("protocol", "tcp")
            svc_el = port.find("service")
            svc = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
            product = (svc_el.get("product", "") if svc_el is not None else "").strip()
            tags = ["open-port", "exposed"]
            if svc in WEB_SERVICES or num in {"80", "443", "3000", "4280", "8000", "8080", "8443"}:
                tags.append("web")
            out.append(Finding(
                id=f"nmap-{addr}-{num}", source="nmap", target=f"{addr}:{num}",
                title=f"Open port {num}/{proto} (service guess: {svc}{' ' + product if product else ''})",
                severity=3.0, tags=tags,
                evidence={"port": int(num), "proto": proto, "service": svc, "product": product},
            ))
    return out
