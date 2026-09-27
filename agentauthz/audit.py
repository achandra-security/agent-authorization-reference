"""Structured audit events for every authorization decision (allowed, denied, or pending)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class AuditLog:
    events: list[dict] = field(default_factory=list)

    def record(self, now: float, **fields) -> dict:
        event = {
            "timestamp": datetime.fromtimestamp(now, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
            "event.kind": "event",
            "event.category": "authorization",
            **fields,
        }
        self.events.append(event)
        return event

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(e, sort_keys=True) for e in self.events) + ("\n" if self.events else "")

    def decisions(self) -> list[str]:
        return [e["decision"] for e in self.events]
