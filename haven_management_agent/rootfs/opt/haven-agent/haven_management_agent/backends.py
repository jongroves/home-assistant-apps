"""Supported Core/Supervisor API adapters and deterministic local fixtures."""

from __future__ import annotations

import http.client
import json
from dataclasses import dataclass, field
from typing import Any, Protocol


class BackendError(RuntimeError):
    """A supported Home Assistant API operation failed."""


class CoreBackend(Protocol):
    def reload(self, target: str) -> dict[str, object]: ...


class SupervisorBackend(Protocol):
    def status(self) -> dict[str, object]: ...
    def validate_config(self) -> dict[str, object]: ...
    def create_backup(self, name: str, full: bool) -> dict[str, object]: ...
    def list_apps(self) -> dict[str, object]: ...
    def app_action(self, action: str, slug: str, options: dict[str, object]) -> dict[str, object]: ...
    def restart_core(self) -> dict[str, object]: ...


class SupervisorHttpBackend:
    """Calls only explicitly mapped documented APIs from inside the HA app."""

    def __init__(self, token: str, host: str = "supervisor", port: int = 80) -> None:
        if not token:
            raise ValueError("SUPERVISOR_TOKEN is required inside the app")
        self._token = token
        self._host = host
        self._port = port

    def _request(self, method: str, path: str, payload: dict[str, object] | None = None) -> Any:
        body = json.dumps(payload).encode() if payload is not None else None
        connection = http.client.HTTPConnection(self._host, self._port, timeout=30)
        try:
            connection.request(
                method,
                path,
                body=body,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024 or response.status >= 400:
                raise BackendError("Home Assistant management API request failed")
            parsed = json.loads(raw or b"{}")
            if not isinstance(parsed, (dict, list)):
                raise BackendError("Home Assistant management API returned an invalid response")
            return parsed
        except (OSError, ValueError, json.JSONDecodeError) as error:
            raise BackendError("Home Assistant management API request failed") from error
        finally:
            connection.close()

    def status(self) -> dict[str, object]:
        safe_fields = {
            "state", "version", "version_latest", "update_available", "healthy",
            "supported", "arch", "machine", "channel",
        }
        result: dict[str, object] = {}
        for name, path in (("supervisor", "/info"), ("core", "/core/info")):
            raw = self._request("GET", path)
            data = self._data(raw)
            if not isinstance(data, dict):
                raise BackendError("Home Assistant status response is invalid")
            result[name] = {key: value for key, value in data.items() if key in safe_fields}
        return result

    def validate_config(self) -> dict[str, object]:
        result = self._request("POST", "/core/check", {})
        data = self._data(result)
        if not isinstance(data, dict):
            raise BackendError("Home Assistant validation response is invalid")
        return {"valid": data.get("result") == "valid", "errors": data.get("errors")}

    def create_backup(self, name: str, full: bool) -> dict[str, object]:
        if full:
            raw = self._request("POST", "/backups/new/full", {"name": name, "background": True})
        else:
            raw = self._request(
                "POST", "/backups/new/partial", {"name": name, "homeassistant": True, "background": True}
            )
        data = self._data(raw)
        if not isinstance(data, dict):
            raise BackendError("Home Assistant backup response is invalid")
        return {key: data[key] for key in ("job_id", "slug") if key in data}

    def list_apps(self) -> dict[str, object]:
        response = self._request("GET", "/addons")
        payload = self._data(response)
        addons = payload.get("addons", []) if isinstance(payload, dict) else []
        safe_fields = {
            "slug", "name", "state", "version", "version_latest", "update_available",
            "installed", "repository", "protected",
        }
        return {
            "addons": [
                {key: value for key, value in addon.items() if key in safe_fields}
                for addon in addons
                if isinstance(addon, dict)
            ]
        }

    def app_action(self, action: str, slug: str, options: dict[str, object]) -> dict[str, object]:
        if not slug or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for character in slug):
            raise BackendError("invalid app slug")
        if action == "install":
            self._request("POST", f"/store/addons/{slug}/install", {})
        if action == "update":
            self._request("POST", f"/store/addons/{slug}/update", {})
        if action == "configure":
            self._request("POST", f"/addons/{slug}/options", {"options": options})
        if action == "restart":
            self._request("POST", f"/addons/{slug}/restart", {})
        if action not in {"install", "update", "configure", "restart"}:
            raise BackendError("unsupported app action")
        return {"result": "accepted"}

    def restart_core(self) -> dict[str, object]:
        self._request("POST", "/core/restart", {})
        return {"result": "accepted"}

    @staticmethod
    def _data(response: Any) -> Any:
        if isinstance(response, dict) and response.get("result") == "ok" and "data" in response:
            return response["data"]
        return response


class CoreHttpBackend:
    ALLOWED_RELOADS = {
        "automations": ("automation", "reload"),
        "scripts": ("script", "reload"),
        "themes": ("frontend", "reload_themes"),
        "templates": ("homeassistant", "reload_custom_templates"),
        "lovelace_resources": ("lovelace", "reload_resources"),
    }

    def __init__(self, supervisor: SupervisorHttpBackend) -> None:
        self._supervisor = supervisor

    def reload(self, target: str) -> dict[str, object]:
        if target not in self.ALLOWED_RELOADS:
            raise BackendError("reload target is not allowlisted")
        domain, action = self.ALLOWED_RELOADS[target]
        self._supervisor._request("POST", f"/core/api/services/{domain}/{action}", {})
        return {"result": "accepted", "target": target}


@dataclass
class FixtureSupervisorBackend:
    config_valid: bool = True
    calls: list[tuple[str, object]] = field(default_factory=list)

    def status(self) -> dict[str, object]:
        self.calls.append(("status", None))
        return {"supervisor": {"state": "running"}, "core": {"state": "running"}}

    def validate_config(self) -> dict[str, object]:
        self.calls.append(("validate_config", None))
        return {"valid": self.config_valid, "result": "valid" if self.config_valid else "invalid"}

    def create_backup(self, name: str, full: bool) -> dict[str, object]:
        self.calls.append(("create_backup", {"name": name, "full": full}))
        return {"job_id": "fixture-job", "slug": "fixture-backup"}

    def list_apps(self) -> dict[str, object]:
        self.calls.append(("list_apps", None))
        return {"addons": [{"slug": "fixture", "state": "started"}]}

    def app_action(self, action: str, slug: str, options: dict[str, object]) -> dict[str, object]:
        self.calls.append(("app_action", {"action": action, "slug": slug, "options": options}))
        return {"result": "ok"}

    def restart_core(self) -> dict[str, object]:
        self.calls.append(("restart_core", None))
        return {"result": "ok"}


@dataclass
class FixtureCoreBackend:
    calls: list[tuple[str, object]] = field(default_factory=list)

    def reload(self, target: str) -> dict[str, object]:
        if target not in CoreHttpBackend.ALLOWED_RELOADS:
            raise BackendError("reload target is not allowlisted")
        self.calls.append(("reload", target))
        return {"result": "ok", "target": target}
