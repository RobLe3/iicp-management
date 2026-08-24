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
On Windows, use a named-pipe path such as
`\\.\pipe\iicp-management-controller`. The controller creates a protected DACL
that grants access only to the current Windows user and LocalSystem. It does not
fall back to TCP or to the default named-pipe DACL.

`ed25519-jcs-v1` is the initial signature profile, not a permanent management
semantic. Requests expire within five minutes. Nonces are single use, and the
expected generation is changed transactionally with the recorded decision.
High-impact operations fail when the configured revocation checkpoint is stale.

The versioned local plan-submission envelope carries a pre-signed request and
the exact semantic plan, but not the desired-state values. The controller
accepts it only when the request's plan digest, bundle digest, resource set and
generation match the submitted plan. The dedicated `accept_plan` action advances
accepted controller state; it is not an adapter `apply` operation. Its receipt
therefore states that no target effect was attempted and convergence was not
evaluated. Signing, interactive confirmation and target execution remain
separate authority layers.

Managed adapters expose only bounded capabilities. The initial contract permits
observation, dry-run, apply, verification and rollback; it does not include an
arbitrary shell. Each host registration binds one exact target and capability.
Operations bind the target, action, plan, desired state, expected generation,
expiry and any referenced rollback operation. Unknown combinations fail closed.
The adapter host is outbound-only and receives an already authorized operation;
it has no policy-administration credential.

The synthetic adapter provides deterministic lifecycle tests, including drift,
partial convergence and irrecoverable failure. The runtime-configuration
adapter depends on the released Rust SDK's exact `RuntimeConfigV1` type. It
rejects invalid configurations and inline secrets while preserving typed secret
references, writes owner-only same-filesystem stages, replaces the target
atomically and verifies the read-back. Generation, operation bindings, receipts
and rollback material are persisted in an owner-only sidecar so duplicate
delivery and rollback remain deterministic after restart. The adapter does not
resolve secret references; a future adapter that needs a secret must declare
that permission and resolve it only at the narrow target boundary. It changes
configuration files only; it does not start, stop or restart services.

This foundation is for disposable and local evidence. It is not a remote
administration endpoint or production deployment authorization.

## Read-only inspection

The controller database inspection path uses SQLite read-only mode and reports
accepted generation plus bounded decision history. Adapter capability and
target evidence remain adapter-owned. An adapter host may produce the
`adapter-inspection-v1` artifact, which contains descriptor and observation
digests rather than raw configuration. A completed adapter receipt is required
before the combined view reports convergence.

The CLI validates freshness, identifiers, unique target/capability bindings,
digest shape and required extensions before combining the two evidence sources.
A missing or failed observation remains explicit. The combined snapshot is a
local diagnostic artifact with `authorizes_mutation: false`; it is not an
approval, execution receipt or remote-management credential.
