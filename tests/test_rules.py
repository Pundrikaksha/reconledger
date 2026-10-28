from reconledger.models import Finding
from reconledger.rules import JsonRulesEngine, Rule


def test_rule_adds_and_explains():
    eng = JsonRulesEngine([Rule(id="exp", when={"tag": "exposed"}, add=2, reason="exposed")])
    f = eng.score(Finding(id="a", source="s", target="127.0.0.1", title="t", severity=5, tags=["exposed"]))
    assert f.score == 7
    assert any("exposed" in r for r in f.reasons)


def test_score_clamped():
    eng = JsonRulesEngine([Rule(id="big", when={}, add=50)])
    f = eng.score(Finding(id="a", source="s", target="h", title="t", severity=9))
    assert f.score == 10


def test_default_rules_file_loads():
    from pathlib import Path
    eng = JsonRulesEngine.from_file(Path(__file__).parents[1] / "rules" / "default.json")
    assert len(eng.rules) >= 1
