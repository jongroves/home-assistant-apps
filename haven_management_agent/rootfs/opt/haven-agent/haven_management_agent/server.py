"""TLS HTTP entrypoint for the structured management protocol."""

from __future__ import annotations

import base64
import json
import os
import ssl
import stat
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .agent import ManagementAgent, OperationRequest, ProtocolError
from .approval import ApprovalError, HmacApprovalVerifier
from .audit import AuditLogger
from .auth import AuthenticationError, HmacAuthenticator
from .backends import CoreHttpBackend, SupervisorHttpBackend
from .filesystem import ConfigFilesystem
from .policy import PolicyError


MAX_REQUEST_BYTES = 10 * 1024 * 1024


def load_secret_keys(path: Path) -> dict[str, bytes]:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise RuntimeError("authentication key file permissions are unsafe")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            payload = json.load(handle)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        raw_keys = payload["keys"]
        keys = {key_id: base64.b64decode(secret, validate=True) for key_id, secret in raw_keys.items()}
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise RuntimeError("authentication key file is invalid") from error
    return keys


def load_bootstrap_mode(path: Path = Path("/data/options.json")) -> bool:
    """Fail closed unless Supervisor options explicitly disable bootstrap mode."""
    try:
        payload = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return True
    value = payload.get("bootstrap_mode") if isinstance(payload, dict) else None
    return False if value is False else True


class ManagementRequestHandler(BaseHTTPRequestHandler):
    server_version = "HavenManagementAgent/0.1"

    def do_POST(self) -> None:  # noqa: N802 - HTTP handler contract
        if self.path != "/v1/operations":
            self._reply(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._reply(400, {"error": "malformed_request"})
            return
        if length < 2 or length > MAX_REQUEST_BYTES:
            self._reply(413, {"error": "invalid_request_size"})
            return
        body = self.rfile.read(length)
        try:
            actor = self.server.authenticator.verify("POST", self.path, self.headers, body)  # type: ignore[attr-defined]
            request = OperationRequest.parse(body)
            result = self.server.agent.execute(request, actor)  # type: ignore[attr-defined]
        except AuthenticationError:
            self._reply(401, {"error": "authentication_failed"})
            return
        except (ApprovalError, ProtocolError, PolicyError, ValueError):
            self._reply(400, {"error": "request_rejected"})
            return
        except Exception:
            self._reply(502, {"error": "operation_failed"})
            return
        self._reply(200, result)

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _reply(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


class AgentServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], authenticator: HmacAuthenticator, agent: ManagementAgent):
        super().__init__(address, ManagementRequestHandler)
        self.authenticator = authenticator
        self.agent = agent


def main() -> None:
    token = os.environ.get("SUPERVISOR_TOKEN", "")
    supervisor = SupervisorHttpBackend(token)
    agent = ManagementAgent(
        ConfigFilesystem(Path(os.environ.get("HAVEN_HA_CONFIG", "/homeassistant"))),
        CoreHttpBackend(supervisor),
        supervisor,
        AuditLogger(Path(os.environ.get("HAVEN_AUDIT_LOG", "/data/audit/events.jsonl"))),
        HmacApprovalVerifier(
            load_secret_keys(Path(os.environ.get("HAVEN_APPROVAL_KEYS", "/agent-config/auth/approvals.json")))
        ),
        bootstrap_mode=load_bootstrap_mode(),
    )
    authenticator = HmacAuthenticator(
        load_secret_keys(Path(os.environ.get("HAVEN_CLIENT_KEYS", "/agent-config/auth/clients.json")))
    )
    server = AgentServer(("0.0.0.0", 8443), authenticator, agent)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        os.environ.get("HAVEN_TLS_CERT", "/agent-config/tls/server.crt"),
        os.environ.get("HAVEN_TLS_KEY", "/agent-config/tls/server.key"),
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
