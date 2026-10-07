"""Security and transaction tests for the Haven Management Agent."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "haven_management_agent/rootfs/opt/haven-agent"
sys.path.insert(0, str(SOURCE))

from haven_management_agent.agent import ManagementAgent, OperationRequest, ProtocolError
from haven_management_agent.approval import (
    ApprovalError, HmacApprovalVerifier, StaticApprovalVerifier, approval_message,
)
from haven_management_agent.audit import AuditLogger, redact
from haven_management_agent.auth import AuthenticationError, HmacAuthenticator, sign_headers
from haven_management_agent.backends import FixtureCoreBackend, FixtureSupervisorBackend
from haven_management_agent.backends import SupervisorHttpBackend
from haven_management_agent.filesystem import ConfigFilesystem, FilesystemError, sha256
from haven_management_agent.policy import PolicyClass, PolicyError, authorize, classify
from haven_management_agent.server import load_bootstrap_mode


class AuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = b"a" * 32
        self.body = b'{"safe":true}'
        self.headers = sign_headers(
            "controller-v1", self.secret, "POST", "/v1/operations", self.body,
            timestamp=1_000, nonce="n" * 24,
        )

    def test_valid_signature(self) -> None:
        auth = HmacAuthenticator({"controller-v1": self.secret}, clock=lambda: 1_000)
        self.assertEqual("controller-v1", auth.verify("POST", "/v1/operations", self.headers, self.body))

    def test_wrong_secret_rejected(self) -> None:
        auth = HmacAuthenticator({"controller-v1": b"b" * 32}, clock=lambda: 1_000)
        with self.assertRaises(AuthenticationError):
            auth.verify("POST", "/v1/operations", self.headers, self.body)

    def test_tampered_body_rejected(self) -> None:
        auth = HmacAuthenticator({"controller-v1": self.secret}, clock=lambda: 1_000)
        with self.assertRaises(AuthenticationError):
            auth.verify("POST", "/v1/operations", self.headers, b'{"safe":false}')

    def test_expired_request_rejected(self) -> None:
        auth = HmacAuthenticator({"controller-v1": self.secret}, clock=lambda: 2_000)
        with self.assertRaises(AuthenticationError):
            auth.verify("POST", "/v1/operations", self.headers, self.body)

    def test_replay_rejected(self) -> None:
        auth = HmacAuthenticator({"controller-v1": self.secret}, clock=lambda: 1_000)
        auth.verify("POST", "/v1/operations", self.headers, self.body)
        with self.assertRaises(AuthenticationError):
            auth.verify("POST", "/v1/operations", self.headers, self.body)

    def test_short_key_rejected(self) -> None:
        with self.assertRaises(ValueError):
            HmacAuthenticator({"bad": b"short"})


class PolicyTests(unittest.TestCase):
    def test_routine_operation(self) -> None:
        self.assertEqual(PolicyClass.ROUTINE, authorize("STATUS", {}, "apply", None))

    def test_elevated_requires_approval_on_apply(self) -> None:
        with self.assertRaises(PolicyError):
            authorize("HA_RESTART", {}, "apply", None)
        self.assertEqual(
            PolicyClass.ELEVATED, authorize("HA_RESTART", {}, "apply", "approval-123")
        )

    def test_elevated_dry_run_needs_no_approval(self) -> None:
        self.assertEqual(PolicyClass.ELEVATED, authorize("APP_INSTALL", {}, "plan", None))

    def test_sensitive_file_is_elevated(self) -> None:
        self.assertEqual(
            PolicyClass.ELEVATED, classify("FILE_DEPLOY", {"path": "configuration.yaml"})
        )
        self.assertEqual(
            PolicyClass.ELEVATED, classify("FILE_READ", {"path": "automations.yaml", "include_content": True})
        )

    def test_restricted_and_unknown_rejected(self) -> None:
        with self.assertRaises(PolicyError):
            authorize("EXEC", {}, "apply", "anything")
        with self.assertRaises(PolicyError):
            authorize("MADE_UP", {}, "plan", None)


class ApprovalTests(unittest.TestCase):
    def test_bound_unexpired_approval(self) -> None:
        secret = b"p" * 32
        expires = 1_200
        signature = hmac.new(
            secret, approval_message("approval-1", "request-1", "HA_RESTART", "fixture-ha", expires),
            hashlib.sha256,
        ).hexdigest()
        verifier = HmacApprovalVerifier({"approver-v1": secret}, clock=lambda: 1_000)
        approval = {
            "reference": "approval-1", "key_id": "approver-v1", "expires_at": expires,
            "signature": signature,
        }
        self.assertEqual(
            "approval-1", verifier.verify("request-1", "HA_RESTART", "fixture-ha", approval)
        )

    def test_approval_cannot_be_rebound_or_expired(self) -> None:
        secret = b"p" * 32
        expires = 1_001
        signature = hmac.new(
            secret, approval_message("approval-1", "request-1", "HA_RESTART", "fixture-ha", expires),
            hashlib.sha256,
        ).hexdigest()
        approval = {
            "reference": "approval-1", "key_id": "approver-v1", "expires_at": expires,
            "signature": signature,
        }
        verifier = HmacApprovalVerifier({"approver-v1": secret}, clock=lambda: 1_000)
        with self.assertRaises(ApprovalError):
            verifier.verify("request-1", "APP_INSTALL", "fixture-ha", approval)
        expired = HmacApprovalVerifier({"approver-v1": secret}, clock=lambda: 1_002)
        with self.assertRaises(ApprovalError):
            expired.verify("request-1", "HA_RESTART", "fixture-ha", approval)


class FilesystemTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fs = ConfigFilesystem(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_allowed_frontend_atomic_deploy(self) -> None:
        result = self.fs.deploy("www/haven-spike/card.js", b"safe", None)
        self.assertTrue(result["changed"])
        self.assertEqual(b"safe", (self.root / "www/haven-spike/card.js").read_bytes())

    def test_hash_precondition(self) -> None:
        target = self.root / "automations.yaml"
        target.write_text("old")
        with self.assertRaises(FilesystemError):
            self.fs.deploy("automations.yaml", b"new", "0" * 64)
        self.assertEqual("old", target.read_text())

    def test_validation_failure_rolls_back_existing_file(self) -> None:
        target = self.root / "configuration.yaml"
        target.write_text("old")
        with self.assertRaises(FilesystemError):
            self.fs.deploy(
                "configuration.yaml", b"invalid", sha256(b"old"), lambda: {"valid": False}
            )
        self.assertEqual(b"old", target.read_bytes())

    def test_validation_failure_removes_new_file(self) -> None:
        target = self.root / "themes/haven/theme.yaml"
        with self.assertRaises(FilesystemError):
            self.fs.deploy(str(target.relative_to(self.root)), b"invalid", None, lambda: {"valid": False})
        self.assertFalse(target.exists())

    def test_path_traversal_and_storage_rejected(self) -> None:
        for path in ("../configuration.yaml", "/etc/passwd", ".storage/lovelace", "secrets.yaml"):
            with self.subTest(path=path), self.assertRaises(FilesystemError):
                self.fs.inspect(path)

    def test_non_allowlisted_write_rejected(self) -> None:
        with self.assertRaises(FilesystemError):
            self.fs.deploy("random.txt", b"no", None)

    def test_symlink_escape_rejected(self) -> None:
        outside = self.root.parent / "outside-ha-management-test"
        outside.mkdir(exist_ok=True)
        (self.root / "www").symlink_to(outside, target_is_directory=True)
        try:
            with self.assertRaises(FilesystemError):
                self.fs.deploy("www/haven-spike/card.js", b"no", None)
        finally:
            outside.rmdir()

    def test_internal_symlink_alias_rejected(self) -> None:
        sensitive = self.root / "configuration.yaml"
        sensitive.write_text("safe")
        (self.root / "www").mkdir()
        (self.root / "www/haven-spike").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(FilesystemError):
            self.fs.deploy("www/haven-spike/configuration.yaml", b"unsafe", None)
        self.assertEqual("safe", sensitive.read_text())


def request(operation: str, *, mode: str = "plan", parameters: dict | None = None, approval: str | None = None) -> OperationRequest:
    payload = {
        "request_id": str(uuid.uuid4()),
        "project": "home-assistant",
        "task": "test",
        "operation": operation,
        "mode": mode,
        "target": "fixture-ha",
        "parameters": parameters or {},
    }
    if approval:
        payload["approval"] = {"reference": approval}
    return OperationRequest.parse(json.dumps(payload).encode())


class AgentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.supervisor = FixtureSupervisorBackend()
        self.core = FixtureCoreBackend()
        self.audit_path = root / "audit/events.jsonl"
        self.agent = ManagementAgent(
            ConfigFilesystem(root / "config"), self.core, self.supervisor, AuditLogger(self.audit_path),
            StaticApprovalVerifier({"approval-1"}),
            bootstrap_mode=False,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_malformed_request(self) -> None:
        with self.assertRaises(ProtocolError):
            OperationRequest.parse(b"[]")
        with self.assertRaises(ProtocolError):
            OperationRequest.parse(b"not-json")

    def test_dry_run_has_no_backend_side_effect(self) -> None:
        result = self.agent.execute(request("HA_RESTART"), "controller-v1")
        self.assertTrue(result["result"]["restart_required"])
        self.assertEqual([], self.supervisor.calls)

    def test_routine_backup_fixture(self) -> None:
        result = self.agent.execute(
            request("BACKUP_CREATE", mode="apply", parameters={"name": "checkpoint"}),
            "controller-v1",
        )
        self.assertEqual("fixture-backup", result["result"]["slug"])

    def test_elevated_app_action(self) -> None:
        result = self.agent.execute(
            request("APP_INSTALL", mode="apply", parameters={"slug": "example"}, approval="approval-1"),
            "controller-v1",
        )
        self.assertEqual("ok", result["result"]["result"])

    def test_reload_allowlist(self) -> None:
        self.agent.execute(
            request("HA_RELOAD", mode="apply", parameters={"target": "automations"}),
            "controller-v1",
        )
        with self.assertRaises(ValueError):
            self.agent.execute(
                request("HA_RELOAD", mode="apply", parameters={"target": "everything"}),
                "controller-v1",
            )

    def test_file_deploy_rolls_back_on_config_failure(self) -> None:
        config = Path(self.temp.name) / "config/automations.yaml"
        config.parent.mkdir(parents=True)
        config.write_bytes(b"old")
        self.supervisor.config_valid = False
        encoded = base64.b64encode(b"new").decode()
        with self.assertRaises(FilesystemError):
            self.agent.execute(
                request(
                    "FILE_DEPLOY", mode="apply",
                    parameters={"path": "automations.yaml", "content_base64": encoded, "expected_sha256": sha256(b"old")},
                ),
                "controller-v1",
            )
        self.assertEqual(b"old", config.read_bytes())

    def test_haven_plan_marks_storage_operations_unautomated(self) -> None:
        result = self.agent.execute(request("HAVEN_DEPLOY_PLAN"), "controller-v1")["result"]
        self.assertEqual(4, len(result["automated_files"]))
        self.assertEqual("interactive_or_deferred", result["resource_registration"]["status"])

    def test_bootstrap_mode_allows_reads_and_plans_but_denies_mutations(self) -> None:
        root = Path(self.temp.name)
        agent = ManagementAgent(
            ConfigFilesystem(root / "bootstrap-config"), self.core, self.supervisor,
            AuditLogger(root / "bootstrap-audit.jsonl"), StaticApprovalVerifier({"approval-1"}),
        )
        status = agent.execute(request("STATUS", mode="apply"), "controller-v1")
        self.assertTrue(status["result"]["agent"]["bootstrap_mode"])
        agent.execute(request("HAVEN_DEPLOY_PLAN", mode="plan"), "controller-v1")
        with self.assertRaises(PolicyError):
            agent.execute(request("BACKUP_CREATE", mode="apply"), "controller-v1")
        with self.assertRaises(PolicyError):
            agent.execute(
                request("HA_RESTART", mode="apply", approval="approval-1"), "controller-v1"
            )

    def test_file_deploy_requires_explicit_precondition(self) -> None:
        encoded = base64.b64encode(b"canary").decode()
        with self.assertRaises(ProtocolError):
            self.agent.execute(
                request(
                    "FILE_DEPLOY", mode="plan",
                    parameters={"path": "www/haven-management-test/canary.txt", "content_base64": encoded},
                ),
                "controller-v1",
            )

    def test_audit_record_contains_evidence_not_content(self) -> None:
        self.agent.execute(request("STATUS", mode="apply"), "controller-v1")
        record = json.loads(self.audit_path.read_text())
        self.assertEqual("STATUS", record["operation"])
        self.assertEqual("succeeded", record["result"])
        self.assertNotIn("SUPERVISOR_TOKEN", self.audit_path.read_text())


class AuditAndPackagingTests(unittest.TestCase):
    def test_secret_redaction(self) -> None:
        value = redact({"token": "abc", "nested": {"password": "def"}, "message": "Bearer xyz"})
        self.assertEqual("[REDACTED]", value["token"])
        self.assertEqual("[REDACTED]", value["nested"]["password"])
        self.assertEqual("Bearer [REDACTED]", value["message"])

    def test_app_requests_no_host_or_docker_privilege(self) -> None:
        config = (ROOT / "haven_management_agent/config.yaml").read_text()
        self.assertIn("homeassistant_api: true", config)
        self.assertIn("hassio_api: true", config)
        self.assertIn("hassio_role: manager", config)
        self.assertIn("host_network: false", config)
        self.assertNotIn("docker_api: true", config)
        self.assertNotIn("full_access: true", config)
        self.assertNotIn("privileged:", config)
        self.assertIn("bootstrap_mode: true", config)
        self.assertIn("  - amd64", config)
        self.assertNotIn("aarch64", config)

    def test_base_image_is_immutable(self) -> None:
        dockerfile = (ROOT / "haven_management_agent/Dockerfile").read_text()
        self.assertIn(
            "ghcr.io/home-assistant/base:latest@sha256:59c99f645cd5bc2e20ca8acac0a6a6163749720e1a1fcdd49bcb5702b5db9688",
            dockerfile,
        )

    def test_bootstrap_options_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "options.json"
            self.assertTrue(load_bootstrap_mode(path))
            path.write_text('{"bootstrap_mode": true}')
            self.assertTrue(load_bootstrap_mode(path))
            path.write_text('{"bootstrap_mode": false}')
            self.assertFalse(load_bootstrap_mode(path))
            path.write_text("not-json")
            self.assertTrue(load_bootstrap_mode(path))

    def test_no_arbitrary_shell_operation(self) -> None:
        source = "\n".join(
            path.read_text()
            for path in (ROOT / "haven_management_agent/rootfs/opt/haven-agent/haven_management_agent").glob("*.py")
        )
        self.assertNotIn("subprocess", source)
        self.assertNotIn("os.system", source)
        with self.assertRaises(PolicyError):
            authorize("EXEC", {}, "apply", "approved")

    def test_app_listing_projects_away_options(self) -> None:
        backend = SupervisorHttpBackend("fixture-token")
        backend._request = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
            "result": "ok",
            "data": {"addons": [{"slug": "safe", "state": "started", "options": {"password": "no"}}]},
        }
        result = backend.list_apps()
        self.assertEqual([{"slug": "safe", "state": "started"}], result["addons"])


if __name__ == "__main__":
    unittest.main()
