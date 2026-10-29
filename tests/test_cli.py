from pathlib import Path

from reconledger.cli import main

ROOT = Path(__file__).parents[1]


def test_cli_triage(tmp_path):
    out = tmp_path / "r.md"
    rc = main(["triage", str(ROOT / "samples" / "findings.json"), "--out", str(out),
               "--audit", str(tmp_path / "a.jsonl")])
    assert rc == 0
    assert "Outdated web framework" in out.read_text()


def test_assess_refuses_public_target(capsys):
    from reconledger.cli import main
    assert main(["assess", "--target", "8.8.8.8", "--non-interactive"]) == 2


def test_assess_non_interactive_denies_everything(tmp_path):
    from reconledger.cli import main
    out = tmp_path / "r.md"
    assert main(["assess", "--target", "127.0.0.1", "--ports", "3000",
                 "--non-interactive", "--out", str(out)]) == 0
    text = out.read_text()
    assert "active steps approved / asked:** 0 / 1" in text
