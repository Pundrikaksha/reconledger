import http.server
import threading
from pathlib import Path

import pytest

from reconledger.ingest import PARSERS
from reconledger.scope import OutOfScopeError, ScopeGuard
from reconledger.tools import headers, nmap

DATA = Path(__file__).parent / "data"


def test_nmap_parser_only_open_ports():
    fs = PARSERS["nmap-xml"]((DATA / "nmap-lab.xml").read_text())
    assert [f.target for f in fs] == ["127.0.0.1:3000"]
    assert "web" in fs[0].tags and fs[0].source == "nmap"


def test_nmap_command_refuses_out_of_scope_and_bad_ports():
    g = ScopeGuard()
    cmd = nmap.build_command("127.0.0.1", "3000,4280", g)
    assert cmd[-1] == "127.0.0.1" and "-sT" in cmd and "-oX" in cmd
    with pytest.raises(OutOfScopeError):
        nmap.build_command("8.8.8.8", "80", g)
    with pytest.raises(OutOfScopeError):
        nmap.build_command("scanme.nmap.org", "80", g)
    with pytest.raises(ValueError):
        nmap.build_command("127.0.0.1", "80; rm -rf /", g)


def _juice_headers():
    lines = (DATA / "juice-headers.txt").read_text().splitlines()[1:]
    return dict(l.split(": ", 1) for l in lines if ": " in l)


def test_header_parser_on_saved_juice_shop_headers():
    fs = headers.parse("http://127.0.0.1:3000/", _juice_headers())
    titles = {f.title for f in fs}
    assert "Missing Content-Security-Policy" in titles
    assert "Missing Referrer-Policy" in titles
    assert any("CORS allows any origin" in t for t in titles)
    assert "Missing X-Frame-Options" not in titles  # Juice Shop sets it
    assert all(f.target == "127.0.0.1:3000" for f in fs)


def test_header_parser_cookie_and_leaks():
    fs = headers.parse("https://127.0.0.1:8443/", {
        "Set-Cookie": "sid=abc; Path=/", "X-Powered-By": "Express",
        "Content-Security-Policy": "default-src 'self'"})
    titles = {f.title for f in fs}
    assert "Missing Strict-Transport-Security" in titles
    assert "Cookie 'sid' missing httponly, secure" in titles
    assert "Technology disclosed in X-Powered-By header" in titles
    assert "Missing Content-Security-Policy" not in titles


class _Stub(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Set-Cookie", "token=x; Path=/")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@pytest.fixture
def stub_server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Stub)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield srv.server_address[1]
    srv.shutdown()


def test_header_fetch_against_local_stub(stub_server):
    status, h = headers.fetch(f"http://127.0.0.1:{stub_server}/", ScopeGuard())
    assert status == 200 and h["access-control-allow-origin"] == "*"
    with pytest.raises(OutOfScopeError):
        headers.fetch("http://example.com/", ScopeGuard())


def test_scope_guard_refuses_public_allow_list():
    with pytest.raises(ValueError):
        ScopeGuard(["0.0.0.0/0"])
    with pytest.raises(ValueError):
        ScopeGuard(["8.8.8.0/24"])
    with pytest.raises(ValueError):
        ScopeGuard(["example.com"])
    assert ScopeGuard(["10.10.0.0/16"]).allowed("10.10.1.5")
