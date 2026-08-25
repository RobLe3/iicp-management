# IICP Management Foundation 0.7.0

This developer-preview candidate adds read-only local runtime observation.

- Consume the Rust SDK's implementation-level runtime-health v1 snapshot without
  turning it into an IICP wire requirement.
- Project content-minimized, freshness-bounded, non-authorizing runtime evidence.
- Add `show runtime-health <snapshot.json|-> --target <resource-id> [--brief]`,
  deterministic JSON output and shell completion.
- Reject unsupported versions, future timestamps, secret-like fields, malformed
  input and inputs over 1 MiB.
- Add Rust/schema tests and a portable Python classification fixture.

This release does not add a management service, node discovery, process control,
remote administration, Directory changes or a production deployment.
