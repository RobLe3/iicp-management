# Domain-local management authority

The management controller is a headless, domain-local authorization boundary.
It accepts JCS-canonicalized, Ed25519-signed requests through owner-restricted
local IPC, evaluates the configured audience, domain, action, time, generation,
nonce and revocation checkpoint, and persists bounded decisions in SQLite.

```bash
iicp-management-controller serve \
  /run/user/$(id -u)/iicp-management.sock \
  ~/.local/state/iicp-management/controller.db \
  ~/.config/iicp-management/controller.pub \
  controller:example domain:example
```

The public-key file contains exactly 32 raw Ed25519 verification-key bytes. The
controller does not load a signing key, provider credential or task content.
The socket is created with owner-only permissions on Unix systems. Other local
IPC transports must provide the same current-user boundary before being enabled.

`ed25519-jcs-v1` is the initial signature profile, not a permanent management
semantic. Requests expire within five minutes. Nonces are single use, and the
expected generation is changed transactionally with the recorded decision.
High-impact operations fail when the configured revocation checkpoint is stale.

Managed adapters expose only bounded capabilities. The initial contract permits
observation, dry-run, apply, verification and rollback; it does not include an
arbitrary shell. The synthetic adapter provides deterministic lifecycle tests.
The runtime-configuration adapter validates a versioned configuration object,
rejects inline secrets, writes an owner-only same-filesystem stage, replaces the
target atomically, verifies the read-back and retains rollback material in the
controller process. It changes configuration files only; it does not start,
stop or restart services.

This foundation is for disposable and local evidence. It is not a remote
administration endpoint or production deployment authorization.
