"""Structured operation dispatcher for the Haven management agent."""

from __future__ import annotations

import base64
import binascii
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .approval import ApprovalVerifier
from .audit import AuditLogger
from .backends import CoreBackend, SupervisorBackend
from .filesystem import ConfigFilesystem, FilesystemError
from .policy import PolicyClass, PolicyError, authorize


class ProtocolError(ValueError):
    """A request is malformed or unsupported."""


@dataclass(frozen=True)
class OperationRequest:
    request_id: str
    project: str
    task: str
    operation: str
    mode: str
    target: str
    parameters: dict[str, Any]
    approval: dict[str, object] | None

    @property
    def approval_reference(self) -> str | None:
        reference = self.approval.get("reference") if self.approval else None
        return reference if isinstance(reference, str) else None

    @classmethod
    def parse(cls, body: bytes) -> "OperationRequest":
        if len(body) > 10 * 1024 * 1024:
            raise ProtocolError("request exceeds maximum size")
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProtocolError("request is not valid JSON") from None
        allowed = {"request_id", "project", "task", "operation", "mode", "target", "parameters", "approval"}
        if not isinstance(value, dict) or set(value) - allowed:
            raise ProtocolError("request contains unknown fields")
        required = {"request_id", "project", "task", "operation", "mode", "target", "parameters"}
        if not required.issubset(value) or not isinstance(value["parameters"], dict):
            raise ProtocolError("request is missing required fields")
        for key in ("request_id", "project", "task", "operation", "mode", "target"):
            if not isinstance(value[key], str) or not value[key] or len(value[key]) > 200:
                raise ProtocolError(f"{key} is invalid")
        try:
            uuid.UUID(value["request_id"])
        except ValueError:
            raise ProtocolError("request_id must be a UUID") from None
        approval = value.get("approval")
        if approval is not None and not isinstance(approval, dict):
            raise ProtocolError("approval is invalid")
        return cls(
            request_id=value["request_id"],
            project=value["project"],
            task=value["task"],
            operation=value["operation"].upper(),
            mode=value["mode"],
            target=value["target"],
            parameters=value["parameters"],
            approval=approval,
        )


class ManagementAgent:
    def __init__(
        self,
        filesystem: ConfigFilesystem,
        core: CoreBackend,
        supervisor: SupervisorBackend,
        audit: AuditLogger,
        approval_verifier: ApprovalVerifier,
        bootstrap_mode: bool = True,
        clock=time.time,
    ) -> None:
        self.filesystem = filesystem
        self.core = core
        self.supervisor = supervisor
        self.audit = audit
        self.approval_verifier = approval_verifier
        self.bootstrap_mode = bootstrap_mode
        self.clock = clock

    def execute(self, request: OperationRequest, actor: str) -> dict[str, object]:
        started = self.clock()
        policy: PolicyClass | None = None
        result: dict[str, object] | None = None
        error: str | None = None
        rollback: str | None = None
        try:
            policy = authorize(
                request.operation, request.parameters, request.mode, request.approval_reference
            )
            if (
                self.bootstrap_mode
                and request.mode == "apply"
                and request.operation not in {"STATUS", "FILE_READ", "APP_LIST", "CONFIG_VALIDATE"}
            ):
                raise PolicyError("operation is unavailable while bootstrap mode is enabled")
            if request.mode == "apply" and policy is PolicyClass.ELEVATED:
                self.approval_verifier.verify(
                    request.request_id, request.operation, request.target, request.approval
                )
            result = self._dispatch(request)
            return {
                "request_id": request.request_id,
                "operation": request.operation,
                "mode": request.mode,
                "policy_class": policy.value,
                "result": result,
            }
        except (PolicyError, ProtocolError, FilesystemError, ValueError) as exception:
            error = str(exception)
            if request.operation == "FILE_DEPLOY":
                rollback = "automatic file rollback attempted when apply had begun"
            raise
        except Exception:
            error = "operation failed"
            raise
        finally:
            self.audit.write(
                {
                    "timestamp": int(self.clock()),
                    "request_id": request.request_id,
                    "actor": actor,
                    "project": request.project,
                    "task": request.task,
                    "operation": request.operation,
                    "target": request.target,
                    "mode": request.mode,
                    "policy_class": policy.value if policy else None,
                    "approval_reference": request.approval_reference,
                    "pre_change": result.get("before_sha256") if result else None,
                    "backup_reference": result.get("slug") if result else None,
                    "result": "failed" if error else "succeeded",
                    "validation_result": result.get("validation") if result else None,
                    "rollback_result": rollback,
                    "error": error,
                    "duration_ms": int((self.clock() - started) * 1000),
                }
            )

    def _dispatch(self, request: OperationRequest) -> dict[str, object]:
        op, params = request.operation, request.parameters
        if op == "STATUS":
            if request.mode == "plan":
                return {"planned": True, "bootstrap_mode": self.bootstrap_mode}
            return {
                "agent": {"bootstrap_mode": self.bootstrap_mode},
                "home_assistant": self.supervisor.status(),
            }
        if op == "FILE_READ":
            return self.filesystem.inspect(str(params.get("path", "")), bool(params.get("include_content", False)))
        if op == "FILE_DEPLOY":
            path = str(params.get("path", ""))
            content = self._decode_content(params)
            if "expected_sha256" not in params:
                raise ProtocolError("expected_sha256 is required; use null only for a new file")
            expected = params["expected_sha256"]
            if expected is not None and not isinstance(expected, str):
                raise ProtocolError("expected_sha256 must be a string")
            plan = self.filesystem.plan_deploy(path, content, expected)
            if request.mode == "plan":
                return {**plan, "backup_recommendation": self._backup_recommendation(path)}
            validator = self.supervisor.validate_config if self._requires_config_validation(path) else None
            return self.filesystem.deploy(path, content, expected, validator)
        if op == "CONFIG_VALIDATE":
            return {"would_call": "Supervisor /core/check"} if request.mode == "plan" else self.supervisor.validate_config()
        if op == "BACKUP_CREATE":
            full = bool(params.get("full", False))
            name = str(params.get("name", "Haven management checkpoint"))[:120]
            return {"type": "full" if full else "partial", "would_create": True} if request.mode == "plan" else self.supervisor.create_backup(name, full)
        if op == "APP_LIST":
            return {"would_call": "Supervisor /addons"} if request.mode == "plan" else self.supervisor.list_apps()
        if op in {"APP_INSTALL", "APP_UPDATE", "APP_CONFIGURE", "APP_RESTART"}:
            action = op.removeprefix("APP_").lower()
            slug = str(params.get("slug", ""))
            options = params.get("options", {})
            if not isinstance(options, dict):
                raise ProtocolError("app options must be an object")
            if request.mode == "plan":
                return {"app": slug, "action": action, "backup_recommendation": "partial before configuration or uninstall-class changes"}
            return self.supervisor.app_action(action, slug, options)
        if op == "HA_RELOAD":
            target = str(params.get("target", ""))
            allowed_reload_targets = {
                "automations", "scripts", "themes", "templates", "lovelace_resources"
            }
            if target not in allowed_reload_targets:
                raise ProtocolError("reload target is not allowlisted")
            if request.mode == "plan":
                return {"reload_target": target, "restart_required": False}
            return self.core.reload(target)
        if op == "HA_RESTART":
            return {"restart_required": True, "backup_recommendation": "configuration snapshot or partial backup"} if request.mode == "plan" else self.supervisor.restart_core()
        if op == "HAVEN_DEPLOY_PLAN":
            return self._haven_plan()
        raise PolicyError("operation is not allowlisted")

    @staticmethod
    def _decode_content(params: dict[str, Any]) -> bytes:
        if set(params) - {"path", "content_base64", "expected_sha256", "include_content"}:
            raise ProtocolError("file deployment contains unknown parameters")
        encoded = params.get("content_base64")
        if not isinstance(encoded, str):
            raise ProtocolError("content_base64 is required")
        try:
            return base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise ProtocolError("content_base64 is invalid") from None

    @staticmethod
    def _requires_config_validation(path: str) -> bool:
        return path == "configuration.yaml" or path.endswith((".yaml", ".yml")) and not path.startswith("www/")

    @staticmethod
    def _backup_recommendation(path: str) -> str:
        if path.startswith("www/haven"):
            return "configuration snapshot is sufficient"
        if path in {"automations.yaml", "scripts.yaml"} or path.startswith(("themes/", "packages/")):
            return "configuration snapshot"
        return "partial Home Assistant backup"

    @staticmethod
    def _haven_plan() -> dict[str, object]:
        return {
            "automated_files": [
                "www/haven-spike/shared/entity-map.js",
                "www/haven-spike/shared/model.js",
                "www/haven-spike/shared/haven-network-slice.js",
                "www/haven-spike/lovelace/haven-network-card.js",
            ],
            "resource_registration": {
                "status": "interactive_or_deferred",
                "reason": "storage-mode resource mutation has no documented public API",
            },
            "dashboard_creation": {
                "status": "interactive_or_yaml",
                "reason": "storage-mode dashboard mutation has no documented public API; YAML dashboard is supported but changes file-owned configuration",
            },
            "existing_dashboards": "must remain untouched",
            "rollback": "remove isolated dashboard/resource, remove four files, hard-refresh clients",
        }
