from pathlib import Path

from reconledger.cli import main

ROOT = Path(__file__).parents[1]


def test_cli_triage(tmp_path):
    out = tmp_path / "r.md"
    rc = main(["triage", str(ROOT / "samples" / "findings.json"), "--out", str(out),
               "--audit", str(tmp_path / "a.jsonl")])
    assert rc == 0
    assert "Outdated web framework" in out.read_text()
