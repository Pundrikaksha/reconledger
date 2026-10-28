import pytest
from reconledger.scope import OutOfScopeError, ScopeGuard


def test_localhost_allowed():
    g = ScopeGuard()
    assert g.allowed("127.0.0.1")
    assert g.allowed("http://localhost:3000/login")
    assert g.allowed("127.0.0.1:8080")


def test_external_blocked():
    g = ScopeGuard()
    assert not g.allowed("8.8.8.8")
    assert not g.allowed("https://example.com")
    with pytest.raises(OutOfScopeError):
        g.check("10.0.0.5")


def test_lab_subnet():
    g = ScopeGuard(["172.28.0.0/16"])
    assert g.allowed("172.28.1.4")
    assert not g.allowed("127.0.0.1")
