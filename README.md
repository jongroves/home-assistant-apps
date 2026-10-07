# Haven Home Assistant Apps

Public Home Assistant App distribution repository for the Haven Management Agent.

The agent provides a structured, authenticated, audited management protocol for a trusted automation controller. It is not a general-purpose shell and does not expose Docker, host networking, or unrestricted host access.

The current release is an installation candidate. It starts in bootstrap mode, where mutation operations are disabled until connectivity, authentication, policy enforcement, and audit behavior have been validated.

## Add this repository

In Home Assistant, open **Settings → Apps → App store → ⋮ → Repositories**, then add:

```text
https://github.com/jongroves/home-assistant-apps
```

Installing the app does not provision its TLS or authentication material. Do not start it until those files have been supplied through its private app configuration directory as described in the app documentation.

## Security posture

- TLS is mandatory.
- Requests require timestamped HMAC authentication and replay protection.
- Elevated operations require a separate signed approval proof.
- Restricted operations are not exposed.
- File writes use an explicit path allowlist, expected-content hashes, atomic replacement, validation, and rollback.
- App protection and AppArmor remain enabled.
- No credentials, keys, certificates, endpoints, or deployment-specific configuration are included in this repository.

Run `python3 scripts/validate_distribution.py` before publishing a change.
