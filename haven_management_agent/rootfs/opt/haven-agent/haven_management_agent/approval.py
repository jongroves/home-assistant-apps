"""Independent signed proof for elevated management operations."""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Mapping
from typing import Protocol


class ApprovalError(ValueError):
    """An elevated approval is absent, expired, or invalid."""


class ApprovalVerifier(Protocol):
    def verify(
        self, request_id: str, operation: str, target: str, approval: dict[str, object] | None
    ) -> str: ...


def approval_message(reference: str, request_id: str, operation: str, target: str, expires_at: int) -> bytes:
    return "\n".join((reference, request_id, operation, target, str(expires_at))).encode()


class HmacApprovalVerifier:
    """Verify approval-service proof with a key separate from request authentication."""

    def __init__(self, keys: Mapping[str, bytes], clock=time.time) -> None:
        if not keys or any(len(value) < 32 for value in keys.values()):
            raise ValueError("approval verification keys must contain at least 32 bytes")
        self._keys = dict(keys)
        self.clock = clock

    def verify(
        self, request_id: str, operation: str, target: str, approval: dict[str, object] | None
    ) -> str:
        if not approval or set(approval) != {"reference", "key_id", "expires_at", "signature"}:
            raise ApprovalError("valid signed approval is required")
        reference = approval["reference"]
        key_id = approval["key_id"]
        expires_at = approval["expires_at"]
        signature = approval["signature"]
        if (
            not isinstance(reference, str) or not reference or len(reference) > 200
            or not isinstance(key_id, str) or not key_id
            or not isinstance(expires_at, int) or expires_at < int(self.clock())
            or expires_at > int(self.clock()) + 3600
            or not isinstance(signature, str)
        ):
            raise ApprovalError("valid signed approval is required")
        secret = self._keys.get(key_id)
        if secret is None:
            raise ApprovalError("valid signed approval is required")
        expected = hmac.new(
            secret, approval_message(reference, request_id, operation, target, expires_at), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ApprovalError("valid signed approval is required")
        return reference


class StaticApprovalVerifier:
    """Test-only approval verifier."""

    def __init__(self, references: set[str] | None = None) -> None:
        self.references = references or set()

    def verify(
        self, _request_id: str, _operation: str, _target: str, approval: dict[str, object] | None
    ) -> str:
        reference = approval.get("reference") if approval else None
        if not isinstance(reference, str) or reference not in self.references:
            raise ApprovalError("valid signed approval is required")
        return reference
