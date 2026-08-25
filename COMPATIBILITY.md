# Compatibility policy

The Rust package version and the management contract generations are separate
axes. A package update does not silently change a released contract's meaning.

## Developer-preview guarantees

- Patch releases preserve accepted v1 serialized artifacts unless a documented
  security defect requires rejection.
- Unknown required or security-critical extensions fail closed.
- Optional extensions do not widen authority.
- Persisted controller state and receipts are never discarded merely to permit
  a binary downgrade.
- A downgrade is supported only when the older binary understands every
  persisted schema generation in use.

The pre-1.0 lines are developer previews. Rust source APIs may evolve between
minor releases, but serialized contract changes require a new explicit schema
or profile generation plus positive and negative fixtures.

Publication, installation, deployment and adoption are independent facts. A
crate or GitHub release does not make the controller production-ready and does
not authorize it to manage a target.

## Friction evidence

`iicp.management-friction-evidence.v1` remains valid as historical project
rehearsal evidence and is not reinterpreted. Version 2 adds typed trial
qualification, environment, outcome and aggregation fields under new schema
identifiers. Consumers must select the schema they understand; an unknown v2
artifact must not be silently treated as v1 or as release authorization.
