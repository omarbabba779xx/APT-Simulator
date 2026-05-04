"""Hash-chained JSONL audit log.

Each entry has a sha256 chain over (prev_hash || canonical_json(entry)).
Tampering with any past line breaks the chain.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any, Callable


GENESIS_HASH = "0" * 64


class AuditLog:
    def __init__(self, path: str | Path, bus: Any | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_hash = self._scan_last_hash()
        self.bus = bus
        self.publishers: list[Callable[[dict[str, Any]], None]] = []
        if bus is not None:
            self.publishers.append(bus.publish)

    def attach_bus(self, bus: Any) -> None:
        self.bus = bus
        self.publishers.append(bus.publish)

    def add_publisher(self, fn: Callable[[dict[str, Any]], None]) -> None:
        self.publishers.append(fn)

    def _scan_last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS_HASH
        last_hash = GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    last_hash = rec.get("hash", last_hash)
                except json.JSONDecodeError:
                    continue
        return last_hash

    def append(self, event: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            entry = {
                "ts": time.time(),
                "event": event,
                "payload": payload,
                "prev": self._last_hash,
            }
            canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            entry["hash"] = digest
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")
            self._last_hash = digest
            for pub in self.publishers:
                try:
                    pub(entry)
                except Exception:  # never let publisher failures break the audit write
                    pass
            return entry

    def verify(self) -> tuple[bool, int | None]:
        """Return (ok, broken_line) where broken_line is 1-indexed."""
        prev = GENESIS_HASH
        if not self.path.exists():
            return True, None
        with self.path.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                stored_hash = rec.pop("hash", None)
                if rec.get("prev") != prev:
                    return False, i
                canonical = json.dumps(rec, sort_keys=True, separators=(",", ":"))
                expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                if expected != stored_hash:
                    return False, i
                prev = stored_hash
        return True, None
