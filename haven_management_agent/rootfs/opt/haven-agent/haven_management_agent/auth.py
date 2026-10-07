"""HMAC request authentication with bounded replay protection."""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
import time
from collections.abc import Mapping


NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class AuthenticationError(ValueError):
    """Authentication failed without leaking credential details."""


class ReplayCache:
    def __init__(self, window_seconds: int = 90) -> None:
        self.window_seconds = window_seconds
        self._seen: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()

    def consume(self, key_id: str, nonce: str, now: int) -> None:
        with self._lock:
            self._seen = {key: expiry for key, expiry in self._seen.items() if expiry >= now}
            key = (key_id, nonce)
            if key in self._seen:
                raise AuthenticationError("request authentication failed")
            self._seen[key] = now + self.window_seconds


def canonical_message(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    digest = hashlib.sha256(body).hexdigest()
    return "\n".join((method.upper(), path, timestamp, nonce, digest)).encode()


class HmacAuthenticator:
    def __init__(
        self,
        keys: Mapping[str, bytes],
        *,
        max_clock_skew_seconds: int = 60,
        replay_cache: ReplayCache | None = None,
        clock=time.time,
    ) -> None:
        if not keys or any(len(secret) < 32 for secret in keys.values()):
            raise ValueError("each authentication key must contain at least 32 bytes")
        self._keys = dict(keys)
        self.max_clock_skew_seconds = max_clock_skew_seconds
        self.replay_cache = replay_cache or ReplayCache(max_clock_skew_seconds + 30)
        self.clock = clock

    def verify(self, method: str, path: str, headers: Mapping[str, str], body: bytes) -> str:
        key_id = headers.get("X-Haven-Key-Id", "")
        timestamp = headers.get("X-Haven-Timestamp", "")
        nonce = headers.get("X-Haven-Nonce", "")
        signature = headers.get("X-Haven-Signature", "")
        if not KEY_ID_RE.fullmatch(key_id) or not NONCE_RE.fullmatch(nonce):
            raise AuthenticationError("request authentication failed")
        try:
            request_time = int(timestamp)
        except ValueError:
            raise AuthenticationError("request authentication failed") from None
        now = int(self.clock())
        if abs(now - request_time) > self.max_clock_skew_seconds:
            raise AuthenticationError("request authentication failed")
        secret = self._keys.get(key_id)
        if secret is None:
            raise AuthenticationError("request authentication failed")
        expected = hmac.new(
            secret, canonical_message(method, path, timestamp, nonce, body), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise AuthenticationError("request authentication failed")
        self.replay_cache.consume(key_id, nonce, now)
        return key_id


def sign_headers(
    key_id: str,
    secret: bytes,
    method: str,
    path: str,
    body: bytes,
    *,
    timestamp: int,
    nonce: str,
) -> dict[str, str]:
    stamp = str(timestamp)
    signature = hmac.new(
        secret, canonical_message(method, path, stamp, nonce, body), hashlib.sha256
    ).hexdigest()
    return {
        "X-Haven-Key-Id": key_id,
        "X-Haven-Timestamp": stamp,
        "X-Haven-Nonce": nonce,
        "X-Haven-Signature": signature,
    }
