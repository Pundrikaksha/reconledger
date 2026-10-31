import json
from pathlib import Path

import pytest

from reconledger.ingest import dedupe, load
from reconledger.models import Finding
from reconledger.scope import OutOfScopeError, ScopeGuard
from reconledger.tools import nikto

DATA = Path(__file__).parent / "data" / "nikto-juice.json"


def test_parse_real_juice_shop_output():
    fs = nikto.parse_json(DATA.read_text())
    assert len(fs) == 28  # 28 items reported by the real Nikto 2.6.1 run on Juice Shop
    assert all(f.source == "nikto" and f.target == "127.0.0.1:3000" for f in fs)
    titles = {f.title for f in fs}
    assert "Missing Content-Security-Policy" in titles  # same title as the header check
    assert "CORS allows any origin (Access-Control-Allow-Origin: *)" in titles
    assert any(t.startswith("Exposed directory /ftp") for t in titles)
    jamon = [f for f in fs if f.evidence["cve"]]
    assert jamon and jamon[0].evidence["cve"] == ["CVE-2013-6235"] and "known-vuln" in jamon[0].tags


def test_ingest_registry_has_nikto():
    assert len(load(DATA, "nikto-json")) == 28


def test_nikto_and_header_check_merge_on_dedupe():
    hdr = Finding(id="h", source="headers", target="127.0.0.1:3000",
                  title="Missing Content-Security-Policy", severity=5.0, tags=["web"])
    merged = dedupe([hdr, *nikto.parse_json(DATA.read_text())])
    csp = [f for f in merged if f.title == "Missing Content-Security-Policy"]
    assert len(csp) == 1 and csp[0].source == "headers+nikto"
    assert csp[0].evidence["also_reported_by"][0]["source"] == "nikto"


def test_soft404_marks_spa_catch_all_as_false_positive():
    fs = nikto.parse_json(DATA.read_text())
    spa = b"<html>juice shop index</html>"

    def fetch(url):
        if url.endswith("/ftp/"):
            return 200, b"<html>directory listing</html>"
        return 200, spa  # every other path returns the SPA shell, like Juice Shop

    nikto.validate_soft404("http://127.0.0.1:3000/", fs, ScopeGuard(), fetch)
    ftp = next(f for f in fs if f.evidence["url"] == "/ftp/" and "exposed-path" in f.tags)
    hist = next(f for f in fs if f.evidence["url"] == "/.bash_history")
    assert "validated" in ftp.tags and "soft-404" not in ftp.tags
    assert "soft-404" in hist.tags and "false positive" in hist.evidence["validation"]


def test_soft404_refuses_out_of_scope():
    with pytest.raises(OutOfScopeError):
        nikto.validate_soft404("http://8.8.8.8/", [], ScopeGuard(), lambda u: (200, b""))


def test_build_command_is_scope_checked_and_safe(tmp_path):
    with pytest.raises(OutOfScopeError):
        nikto.build_command("http://example.com/", ScopeGuard(), "o.json", nikto="/x/nikto.pl")
    cmd = nikto.build_command("http://127.0.0.1:3000/", ScopeGuard(), "o.json", nikto="/x/nikto.pl")
    assert cmd[:2] == ["perl", "/x/nikto.pl"]
    assert cmd[cmd.index("-Tuning") + 1] == "0123b"  # no injection / DoS classes
    assert "-nointeractive" in cmd and "json" in cmd
