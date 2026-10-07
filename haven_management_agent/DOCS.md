# Haven Management Agent

The Haven Management Agent is a purpose-built Home Assistant App for structured administration from a trusted automation controller. It exposes one TLS endpoint, `POST /v1/operations`, and deliberately provides no general shell, Docker socket, host-network access, privileged Linux capabilities, ingress page, or unauthenticated API.

## Installation posture

The app uses manual boot and defaults to `bootstrap_mode: true`. In bootstrap mode, mutation operations are unavailable. Only status and explicitly safe read/validation operations can be applied; planning remains available for allowlisted operations.

Before starting the app, its private app configuration directory must contain:

- `auth/clients.json`: request-authentication keys.
- `auth/approvals.json`: independent elevated-approval verification keys.
- `tls/server.crt`: server certificate.
- `tls/server.key`: matching private key.

Secret files must be owner-only, must never be committed, and must be provisioned through an approved administrative workflow. The app refuses authentication key files with group or world permissions.

## Declared capabilities

The app intentionally requests Home Assistant Core API access, Supervisor API access with the `manager` role, a writable Home Assistant configuration mapping, and a private writable app configuration mapping. AppArmor and protection remain enabled; host networking is disabled.

These permissions are broad inside Home Assistant but do not grant unrelated host administration. The application protocol further constrains operations by allowlist, policy class, bootstrap mode, path rules, expected hashes, and signed approvals.

## Network

The container listens on TCP 8443, mapped by default to host TCP 9443. Limit network access to the single trusted controller address at the surrounding firewall. Certificate validation must remain enabled.

## Removal

Stop and uninstall the app, remove its repository from the App store if no longer needed, revoke the controller credential, and remove any firewall rule created solely for this service. Removing the app does not remove files it previously deployed under the Home Assistant configuration directory.
