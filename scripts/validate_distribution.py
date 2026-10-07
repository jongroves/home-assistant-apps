#!/usr/bin/env python3
"""Fail-closed validation for the public Home Assistant App distribution."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "haven_management_agent"
SOURCE = APP / "rootfs/opt/haven-agent/haven_management_agent"
EXPECTED_FILES = {
    ".gitignore",
    "README.md",
    "repository.yaml",
    "haven_management_agent/DOCS.md",
    "haven_management_agent/Dockerfile",
    "haven_management_agent/config.yaml",
    "haven_management_agent/run.sh",
    "scripts/validate_distribution.py",
    "tests/test_agent.py",
    *{
        f"haven_management_agent/rootfs/opt/haven-agent/haven_management_agent/{name}.py"
        for name in (
            "__init__",
            "agent",
            "approval",
            "audit",
            "auth",
            "backends",
            "filesystem",
            "policy",
            "server",
        )
    },
}
PINNED_BASE = (
    "ghcr.io/home-assistant/base:latest@sha256:"
    "59c99f645cd5bc2e20ca8acac0a6a6163749720e1a1fcdd49bcb5702b5db9688"
)


def fail(message: str) -> None:
    raise SystemExit(f"validation failed: {message}")


def repository_files() -> set[str]:
    return {
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if path.is_file()
        and ".git" not in path.relative_to(ROOT).parts
        and "__pycache__" not in path.relative_to(ROOT).parts
        and path.suffix != ".pyc"
    }


def validate_file_boundary() -> None:
    actual = repository_files()
    if actual != EXPECTED_FILES:
        fail(f"public file boundary differs: unexpected={sorted(actual - EXPECTED_FILES)}, missing={sorted(EXPECTED_FILES - actual)}")
    for path in ROOT.rglob("*"):
        if (
            ".git" not in path.relative_to(ROOT).parts
            and "__pycache__" not in path.relative_to(ROOT).parts
            and path.is_symlink()
        ):
            fail(f"symbolic links are not permitted: {path.relative_to(ROOT)}")


def validate_secret_boundary() -> None:
    private_ipv4 = re.compile(r"(?<![0-9])(?:10|192\.168|172\.(?:1[6-9]|2[0-9]|3[01]))(?:\.[0-9]{1,3}){2}(?![0-9])")
    key_block = re.compile("BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY")
    token_prefix = re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,})")
    home_path = re.compile(r"/home/[A-Za-z0-9._-]+/")
    forbidden_text = (
        "tail" + "scale",
        "ts" + ".net",
        "dev" + "-control",
        "lab" + "-infra",
    )
    forbidden_names = {".env", "secrets.yaml", "credentials.json", "id_rsa", "id_ed25519"}
    forbidden_suffixes = {".key", ".pem", ".p12", ".pfx", ".crt", ".sqlite", ".db"}
    for relative in sorted(repository_files()):
        path = ROOT / relative
        if path.name in forbidden_names or path.suffix.lower() in forbidden_suffixes:
            fail(f"secret-bearing filename is not publishable: {relative}")
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            fail(f"binary content is not permitted: {relative}")
        lowered = text.lower()
        if any(value in lowered for value in forbidden_text):
            fail(f"private environment reference found: {relative}")
        if private_ipv4.search(text) or home_path.search(text):
            fail(f"private address or home path found: {relative}")
        if key_block.search(text) or token_prefix.search(text):
            fail(f"credential material found: {relative}")


def validate_app_descriptor() -> None:
    config = (APP / "config.yaml").read_text()
    required = {
        'name: "Haven Management Agent"',
        'slug: "haven_management_agent"',
        'version: "0.1.0"',
        "  - amd64",
        "homeassistant_api: true",
        "hassio_api: true",
        "hassio_role: manager",
        "apparmor: true",
        "host_network: false",
        "bootstrap_mode: true",
        "  8443/tcp: 9443",
    }
    missing = sorted(value for value in required if value not in config)
    if missing:
        fail(f"app descriptor is missing required settings: {missing}")
    for forbidden in ("docker_api: true", "full_access: true", "privileged:", "host_network: true"):
        if forbidden in config:
            fail(f"app descriptor requests forbidden privilege: {forbidden}")

    repository = (ROOT / "repository.yaml").read_text()
    for required_line in (
        'name: "Haven Home Assistant Apps"',
        'url: "https://github.com/jongroves/home-assistant-apps"',
        'maintainer: "jongroves"',
    ):
        if required_line not in repository:
            fail(f"repository descriptor is missing {required_line}")


def validate_runtime_boundary() -> None:
    dockerfile = (APP / "Dockerfile").read_text()
    first = dockerfile.splitlines()[0]
    if first != f"FROM {PINNED_BASE}":
        fail("base image is not pinned to the reviewed immutable digest")
    run_script = (APP / "run.sh").read_text()
    if "python3 -B -m haven_management_agent.server" not in run_script:
        fail("run script does not launch the reviewed server module")
    source = "\n".join(path.read_text() for path in sorted(SOURCE.glob("*.py")))
    for forbidden in ("sub" + "process", "os." + "system", "os." + "popen", "docker.sock", "shell=True"):
        if forbidden in source:
            fail(f"runtime contains a forbidden execution path: {forbidden}")
    if "bootstrap_mode: bool" not in (APP / "config.yaml").read_text():
        fail("bootstrap mode schema is missing")


def run_checks() -> None:
    commands = (
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        ["sh", "-n", "haven_management_agent/run.sh"],
    )
    for command in commands:
        completed = subprocess.run(command, cwd=ROOT, check=False)
        if completed.returncode:
            fail(f"check failed: {' '.join(command)}")


def main() -> None:
    validate_file_boundary()
    validate_secret_boundary()
    validate_app_descriptor()
    validate_runtime_boundary()
    run_checks()
    print("distribution validation passed")


if __name__ == "__main__":
    main()
