"""Constrained, atomic operations within the Home Assistant configuration mount."""

from __future__ import annotations

import hashlib
import os
import tempfile
import threading
from pathlib import Path, PurePosixPath
from typing import Callable


MAX_FILE_BYTES = 8 * 1024 * 1024
DENIED_PARTS = frozenset({".storage", ".ssh", "secrets.yaml"})
WRITABLE_FILES = frozenset({"automations.yaml", "scripts.yaml", "configuration.yaml"})
WRITABLE_PREFIXES = (
    ("www", "haven"),
    ("www", "haven-spike"),
    ("themes", "haven"),
    ("packages", "haven"),
    ("custom_templates", "haven"),
    ("custom_components", "haven_"),
)


class FilesystemError(ValueError):
    """A requested filesystem operation is unsafe or failed validation."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ConfigFilesystem:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self._lock = threading.RLock()

    def _relative(self, value: str) -> PurePosixPath:
        path = PurePosixPath(value)
        if not value or path.is_absolute() or ".." in path.parts or any(part in DENIED_PARTS for part in path.parts):
            raise FilesystemError("path is outside the management allowlist")
        return path

    def _target(self, value: str, *, write: bool) -> Path:
        relative = self._relative(value)
        if write and not self._writable(relative):
            raise FilesystemError("path is outside the write allowlist")
        current = self.root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise FilesystemError("managed paths may not contain symlinks")
        target = (self.root / Path(*relative.parts)).resolve()
        try:
            target.relative_to(self.root)
        except ValueError:
            raise FilesystemError("path escapes the configuration root") from None
        return target

    @staticmethod
    def _writable(path: PurePosixPath) -> bool:
        if str(path) in WRITABLE_FILES:
            return True
        parts = path.parts
        for parent, stem in WRITABLE_PREFIXES:
            if len(parts) >= 2 and parts[0] == parent and parts[1].startswith(stem):
                return True
        return False

    def inspect(self, path: str, include_content: bool = False) -> dict[str, object]:
        target = self._target(path, write=False)
        if not target.is_file() or target.is_symlink():
            raise FilesystemError("managed file does not exist")
        content = target.read_bytes()
        result: dict[str, object] = {"path": path, "size": len(content), "sha256": sha256(content)}
        if include_content:
            result["content"] = content.decode("utf-8")
        return result

    def plan_deploy(self, path: str, content: bytes, expected_sha256: str | None) -> dict[str, object]:
        with self._lock:
            if len(content) > MAX_FILE_BYTES:
                raise FilesystemError("file exceeds the maximum managed size")
            target = self._target(path, write=True)
            old = target.read_bytes() if target.is_file() and not target.is_symlink() else None
            if target.exists() and old is None:
                raise FilesystemError("target is not a regular file")
            old_hash = sha256(old) if old is not None else None
            if old is None and expected_sha256 is not None:
                raise FilesystemError("pre-change hash asserts a file that does not exist")
            if old is not None and expected_sha256 is None:
                raise FilesystemError("null pre-change hash is valid only for a new file")
            if expected_sha256 is not None and old_hash != expected_sha256:
                raise FilesystemError("pre-change hash does not match")
            return {
                "path": path,
                "before_sha256": old_hash,
                "after_sha256": sha256(content),
                "changed": old != content,
                "rollback": "restore previous bytes" if old is not None else "remove newly created file",
            }

    def deploy(
        self,
        path: str,
        content: bytes,
        expected_sha256: str | None,
        validate: Callable[[], dict[str, object]] | None = None,
    ) -> dict[str, object]:
        with self._lock:
            plan = self.plan_deploy(path, content, expected_sha256)
            if not plan["changed"]:
                return {**plan, "validation": {"valid": True, "result": "unchanged"}}
            target = self._target(path, write=True)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            previous = target.read_bytes() if target.exists() else None
            previous_mode = target.stat().st_mode & 0o777 if target.exists() else 0o640
            self._atomic_replace(target, content, previous_mode)
            try:
                validation = validate() if validate else {"valid": True, "result": "not-required"}
                if not validation.get("valid", False):
                    raise FilesystemError("post-write validation failed")
            except Exception:
                if previous is None:
                    target.unlink(missing_ok=True)
                else:
                    self._atomic_replace(target, previous, previous_mode)
                raise
            return {**plan, "validation": validation}

    @staticmethod
    def _atomic_replace(target: Path, content: bytes, mode: int) -> None:
        descriptor, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        temp = Path(temp_name)
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, target)
            directory = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temp.unlink(missing_ok=True)
