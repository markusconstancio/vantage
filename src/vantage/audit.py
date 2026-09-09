"""Append-only audit logging.

Every consequential action (starting with recon invocations) is recorded as a
JSON line under ``logs/audit.log``. The log is git-ignored — it may reference
real lab targets — but it exists so there is always a record of what ran, when,
and against what.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LOG_DIR = Path(__file__).resolve().parents[2] / "logs"


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        if path is None:
            DEFAULT_LOG_DIR.mkdir(exist_ok=True)
            self.path = DEFAULT_LOG_DIR / "audit.log"
        else:
            self.path = Path(path)
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: str, **fields) -> dict:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry
