import copy
import json

from reconledger.audit import GENESIS, AuditLog, LedgerLog, verify_chain


def _ledger(n=3):
    log = LedgerLog()
    for i in range(n):
        log.record("step", n=i, top=[("a", 1.0)])
    return log


def test_chain_links_entries():
    log = _ledger()
    assert log.events[0]["prev_hash"] == GENESIS
    assert log.events[2]["prev_hash"] == log.events[1]["hash"]
    assert log.verify() == (True, None)


def test_edit_drop_and_reorder_are_detected():
    log = _ledger(4)
    edited = copy.deepcopy(log.events)
    edited[1]["n"] = 99
    assert verify_chain(edited) == (False, 1)
    assert verify_chain(log.events[:1] + log.events[2:]) == (False, 1)
    assert verify_chain([log.events[1], log.events[0]]) == (False, 0)


def test_file_round_trip_and_reopen_continue_the_chain(tmp_path):
    path = tmp_path / "ledger.jsonl"
    first = LedgerLog(path)
    first.record("a", top=[("x", 1.0)])
    second = LedgerLog(path)
    second.record("b")
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert [e["seq"] for e in lines] == [0, 1]
    assert verify_chain(lines) == (True, None)


def test_tampered_file_is_detected_on_reopen(tmp_path):
    path = tmp_path / "ledger.jsonl"
    LedgerLog(path).record("approval", approved=False)
    path.write_text(path.read_text().replace('"approved": false', '"approved": true'))
    assert LedgerLog(path).verify() == (False, 0)


def test_plain_audit_log_is_unchanged():
    assert set(AuditLog().record("x", a=1)) == {"ts", "event", "a"}
