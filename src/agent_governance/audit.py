"""Step 5: tamper-evident audit log."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .types import now


class AuditLog:
    """Append-only, hash-chained. Altering any past entry breaks verify()."""

    def __init__(self, path: str | None = None):
        self.path = path
        self.entries: list[dict[str, Any]] = []
        self._last_hash = "0" * 64

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        entry = {"ts": now().isoformat(), "event": event, **fields, "prev": self._last_hash}
        payload = json.dumps(entry, sort_keys=True, default=str)
        entry["hash"] = hashlib.sha256(payload.encode()).hexdigest()
        self._last_hash = entry["hash"]
        self.entries.append(entry)
        if self.path:
            with open(self.path, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        return entry

    def verify(self) -> bool:
        prev = "0" * 64
        for e in self.entries:
            body = {k: v for k, v in e.items() if k != "hash"}
            if body["prev"] != prev:
                return False
            if hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest() != e["hash"]:
                return False
            prev = e["hash"]
        return True