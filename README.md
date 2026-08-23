# IICP Management Foundation

This repository contains implementation-neutral management contracts, a
deterministic Rust evaluator and planner, and project-owned conformance
fixtures for IICP domains. It is Apache-2.0 software and is separate from the
IICP wire protocol and from optional management clients and operator interfaces.

The foundation is an early development surface. It includes a headless
domain-local controller and bounded synthetic and runtime-configuration
adapters. It does not include a remote administration service, service restart
authority or production deployment.

## State model

The contracts keep four states distinct:

- **desired state** is a portable proposal;
- **accepted state** is the generation authorized by the domain-local authority;
- **observed state** is what a target reports or a verifier measures;
- **effective state** is the evidence-backed convergence result.

Plans are deterministic functions of a validated desired-state bundle and an
accepted-state snapshot. Digests use RFC 8785 JSON Canonicalization Scheme
bytes. Approval binds the exact bundle digest, plan digest, audience and
expected generation. Portable artifacts contain secret references rather than
secret values.

## Typed policy evaluator

The `typed-v0` evaluator has no dependency on Cedar, CEL, OPA or another policy
engine. It keeps eligibility separate from ranking, applies explicit deny
precedence and returns stable reason codes. Unknown or stale evidence, adapter
failures and missing apply authority fail closed.

The profile bounds serialized policy and context sizes, rule and syntax-tree
size, expression and named-reference depth, collection size, deterministic
fuel and host execution time. An implementation may advertise lower local
limits but cannot silently raise the profile maximum. Named rules are resolved
with cycle detection before evaluation.

## Test and conformance commands

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo run --locked --bin iicp-management-conformance
python3 tools/run_management_conformance.py fixtures/management-portable-conformance-v1.json
```

The conformance runner accepts an optional fixture path:

```bash
cargo run --locked --bin iicp-management-conformance -- path/to/fixture.json
```

It writes a deterministic JSON report. Exit status `0` means every case passed,
`1` means at least one result differed and `2` means the input or invocation was
invalid. The built-in report is project evidence. It is not independent
interoperability evidence.

See [CONFORMANCE.md](CONFORMANCE.md) for the language-neutral EM-1 fixture pack,
clean-room instructions and result-bundle requirements.

The next foundation layer provides a headless domain-local controller and
capability-scoped adapters. See [LOCAL_AUTHORITY.md](LOCAL_AUTHORITY.md) for its
authority, IPC, persistence and deployment boundaries.

## Authority boundary

The contracts do not grant management authority. A future domain-local
controller must authenticate and authorize an exact plan before any adapter can
apply it. IICP membership, discovery, dispatch tickets and provider reputation
do not substitute for management authorization.

Other services may consume these contracts but cannot widen domain-local policy
or become undeclared IICP protocol authority. Product workflows, analytics, IAM
integrations, managed operations and product-specific interfaces remain outside
this repository.
