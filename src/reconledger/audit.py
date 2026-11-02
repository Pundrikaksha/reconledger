"""Append-only JSON-lines audit trail of every decision and approval."""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any, Iterable

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.events: list[dict[str, Any]] = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def _seal(self, entry: dict[str, Any]) -> dict[str, Any]:
        return entry

    def record(self, event: str, **data: Any) -> dict[str, Any]:
        entry = self._seal({"ts": round(time.time(), 3), "event": event, **data})
        self.events.append(entry)
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        return entry


def _entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, default=str, sort_keys=True).encode()).hexdigest()


def verify_chain(events: Iterable[dict[str, Any]]) -> tuple[bool, int | None]:
    """Return (intact, seq of the first bad entry). Edits, drops and reorders all break it."""
    prev = GENESIS
    for i, e in enumerate(events):
        if e.get("seq") != i or e.get("prev_hash") != prev or e.get("hash") != _entry_hash(e):
            return False, i
        prev = e["hash"]
    return True, None


class LedgerLog(AuditLog):
    """AuditLog where each entry commits to the one before it (seq, prev_hash, hash).

    Reopening an existing file continues its chain. Note this detects tampering after
    the fact; it cannot stop someone rewriting the whole file from the start, so the
    head hash has to be kept somewhere else if that matters.
    """

    def __init__(self, path: str | Path | None = None):
        super().__init__(path)
        self._lock = threading.Lock()
        if self.path and self.path.exists():
            lines = self.path.read_text(encoding="utf-8").splitlines()
            self.events = [json.loads(line) for line in lines if line.strip()]

    def _seal(self, entry: dict[str, Any]) -> dict[str, Any]:
        entry["seq"] = len(self.events)
        entry["prev_hash"] = self.events[-1]["hash"] if self.events else GENESIS
        entry["hash"] = _entry_hash(entry)
        return entry

    def record(self, event: str, **data: Any) -> dict[str, Any]:
        with self._lock:
            return super().record(event, **data)

    def verify(self) -> tuple[bool, int | None]:
        with self._lock:
            return verify_chain(list(self.events))
