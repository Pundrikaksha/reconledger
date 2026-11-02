import pytest

LLM_ENV = ("RECONLEDGER_LLM_PROVIDER", "OTARI_API_KEY", "OTARI_BASE_URL", "OTARI_MODEL",
           "OTARI_FALLBACK_MODEL", "OTARI_SUMMARY_MODEL", "OTARI_GUARDRAILS", "OTARI_TIMEOUT")


@pytest.fixture(autouse=True)
def _no_llm_env(monkeypatch):
    """A developer's shell config must not make the test suite call a real gateway."""
    for name in LLM_ENV:
        monkeypatch.delenv(name, raising=False)
