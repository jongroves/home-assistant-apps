"""Append-only structured audit evidence with defensive redaction."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


SENSITIVE_KEYS = frozenset(
    {"authorization", "content", "credential", "key", "password", "private_key", "secret", "token"}
)
BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")


def redact(value: Any, key: str = "") -> Any:
    if any(part in key.lower() for part in SENSITIVE_KEYS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): redact(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return BEARER_RE.sub("Bearer [REDACTED]", value)
    return value


class AuditLogger:
    def __init__(self, path: Path) -> None:
        self.path = path

    def write(self, record: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = (json.dumps(redact(record), sort_keys=True, separators=(",", ":")) + "\n").encode()
        descriptor = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
