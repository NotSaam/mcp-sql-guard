"""Registro de auditoría: una línea JSON por llamada, permitida o denegada."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: str | Path | None) -> None:
        self.path = Path(path) if path else None

    def record(self, **event: Any) -> None:
        if self.path is None:
            return
        event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **event}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
