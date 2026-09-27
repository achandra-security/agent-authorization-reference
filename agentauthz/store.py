"""In-memory multi-tenant record store and the demo tools that operate on it."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field


@dataclass
class RecordStore:
    records: dict[str, dict] = field(default_factory=dict)

    def add(self, record_id: str, tenant: str, data: dict) -> None:
        self.records[record_id] = {"tenant": tenant, "data": copy.deepcopy(data)}

    def tenant_of(self, record_id) -> str | None:
        """Authoritative ownership lookup. The gateway uses this, never a tenant named by the model."""
        record = self.records.get(record_id) if isinstance(record_id, str) else None
        return record["tenant"] if record else None

    # --- tool implementations (called only after the gateway allows the call) ---

    def read_record(self, record_id: str) -> dict:
        return {"record_id": record_id, **copy.deepcopy(self.records[record_id]["data"])}

    def update_record(self, record_id: str, fields: dict) -> dict:
        allowed = {k: v for k, v in (fields or {}).items() if isinstance(k, str) and k != "tenant"}
        self.records[record_id]["data"].update(allowed)
        return {"record_id": record_id, "updated": sorted(allowed)}

    def delete_record(self, record_id: str) -> dict:
        del self.records[record_id]
        return {"record_id": record_id, "deleted": True}

    def export_record(self, record_id: str, recipient: str) -> dict:
        return {"record_id": record_id, "exported_to": recipient}


TOOL_IMPLEMENTATIONS = {
    "read_record": lambda store, args: store.read_record(args["record_id"]),
    "update_record": lambda store, args: store.update_record(args["record_id"], args.get("fields", {})),
    "delete_record": lambda store, args: store.delete_record(args["record_id"]),
    "export_record": lambda store, args: store.export_record(args["record_id"], str(args.get("recipient"))),
}
