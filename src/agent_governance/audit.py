"""Step 5: tamper-evident audit log."""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from .types import now


class AuditIntegrityError(Exception):
    """The on-disk chain failed verification. Further appends are refused."""


class AuditLog:
    """Append-only, hash-chained. Altering any past entry breaks verify().

    When `path` points at an existing file, entries are loaded and the chain is
    checked before anything new is appended. A rewritten file fails `verify()`
    and `record()` refuses to extend it.
    """

    def __init__(self, path: str | None = None):
        self.path = path
        self.entries: list[dict[str, Any]] = []
        self._last_hash = "0" * 64
        self._intact = True
        if path and os.path.isfile(path) and os.path.getsize(path) > 0:
            self.entries = _read_jsonl(path)
            self._intact = self.verify()
            if self._intact and self.entries:
                self._last_hash = self.entries[-1]["hash"]

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        if not self._intact:
            raise AuditIntegrityError("audit log failed verification; refusing to append")
        if self.path and os.path.isfile(self.path) and os.path.getsize(self.path) > 0:
            if not self.verify_disk():
                self._intact = False
                raise AuditIntegrityError("audit log failed verification; refusing to append")
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
        """Check the in-memory chain."""
        return _verify_entries(self.entries)

    def verify_disk(self) -> bool:
        """Re-read `path` and check that chain. Detects a rewrite under a live log."""
        if not self.path:
            return False
        if not os.path.isfile(self.path):
            return not self.entries
        return _verify_entries(_read_jsonl(self.path))


def _read_jsonl(path: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def _verify_entries(entries: list[dict[str, Any]]) -> bool:
    prev = "0" * 64
    for e in entries:
        if "hash" not in e or "prev" not in e:
            return False
        body = {k: v for k, v in e.items() if k != "hash"}
        if body["prev"] != prev:
            return False
        digest = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
        if digest != e["hash"]:
            return False
        prev = e["hash"]
    return True
