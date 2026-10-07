"""Operation allowlist and policy classification."""

from __future__ import annotations

from enum import StrEnum
from pathlib import PurePosixPath


class PolicyClass(StrEnum):
    ROUTINE = "routine"
    ELEVATED = "elevated"
    RESTRICTED = "restricted"


BASE_POLICY = {
    "STATUS": PolicyClass.ROUTINE,
    "FILE_READ": PolicyClass.ROUTINE,
    "FILE_DEPLOY": PolicyClass.ROUTINE,
    "CONFIG_VALIDATE": PolicyClass.ROUTINE,
    "BACKUP_CREATE": PolicyClass.ROUTINE,
    "APP_LIST": PolicyClass.ROUTINE,
    "APP_INSTALL": PolicyClass.ELEVATED,
    "APP_UPDATE": PolicyClass.ELEVATED,
    "APP_CONFIGURE": PolicyClass.ELEVATED,
    "APP_RESTART": PolicyClass.ELEVATED,
    "HA_RELOAD": PolicyClass.ROUTINE,
    "HA_RESTART": PolicyClass.ELEVATED,
    "HAVEN_DEPLOY_PLAN": PolicyClass.ROUTINE,
}

RESTRICTED_OPERATIONS = frozenset(
    {
        "EXEC",
        "SHELL",
        "DOCKER",
        "HOST_NETWORK_CONFIGURE",
        "FIREWALL_CONFIGURE",
        "BACKUP_RESTORE",
        "MASS_DELETE",
        "CREDENTIAL_EXPORT",
    }
)


class PolicyError(ValueError):
    """A request violates the management policy."""


def classify(operation: str, parameters: dict[str, object]) -> PolicyClass:
    operation = operation.upper()
    if operation in RESTRICTED_OPERATIONS:
        return PolicyClass.RESTRICTED
    if operation not in BASE_POLICY:
        raise PolicyError("operation is not allowlisted")
    if operation in {"FILE_READ", "FILE_DEPLOY"}:
        path = PurePosixPath(str(parameters.get("path", "")))
        if path == PurePosixPath("configuration.yaml") or (
            path.parts and path.parts[0] == "custom_components"
        ):
            return PolicyClass.ELEVATED
        if parameters.get("include_content") is True:
            return PolicyClass.ELEVATED
    return BASE_POLICY[operation]


def authorize(
    operation: str,
    parameters: dict[str, object],
    mode: str,
    approval_reference: str | None,
) -> PolicyClass:
    policy = classify(operation, parameters)
    if policy is PolicyClass.RESTRICTED:
        raise PolicyError("restricted operation is not exposed")
    if mode not in {"plan", "apply"}:
        raise PolicyError("mode must be plan or apply")
    if mode == "apply" and policy is PolicyClass.ELEVATED and not approval_reference:
        raise PolicyError("elevated apply requires an approval reference")
    return policy
