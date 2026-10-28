"""Append-only JSON-lines audit trail of every decision and approval."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.events: list[dict[str, Any]] = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: str, **data: Any) -> dict[str, Any]:
        entry = {"ts": round(time.time(), 3), "event": event, **data}
        self.events.append(entry)
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        return entry
