# IICP Management Foundation 0.2.0

This developer preview adds portable diagnostic evidence to the public IICP
management foundation. An operator can create, verify and inspect a
content-minimized bundle from explicit local bootstrap, controller, adapter,
management-profile and rollout evidence.

The bundle records bounded status, freshness, reason codes, counts and source
digests. It deliberately excludes raw policy and desired state, prompts,
responses, credentials, request and target identifiers, and private topology.
Missing optional evidence remains visible. Supplied invalid or stale evidence
and later modification fail validation.

Install the exact published dependency graph:

```bash
cargo install iicp-management-core --version 0.2.0 --locked
```

The package includes the operator CLI, domain-local controller and conformance
runner. It does not install a network service, grant remote authority, modify a
Directory or authorize a production deployment. Its diagnostic digest detects
modification; it does not authenticate who created the bundle.

The release assets include the packaged crate, a vendored offline source bundle
and an integrity manifest. Publication and installation remain separate from
deployment and representative administrator adoption.
