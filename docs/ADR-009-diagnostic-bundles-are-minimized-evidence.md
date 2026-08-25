# ADR-009: Diagnostic bundles are content-minimized evidence

## Status

Accepted for the public management foundation.

## Context

Operators need one portable record that explains whether a local management environment is healthy, degraded, incompatible or missing evidence. Copying controller databases, policy files or raw adapter output into a support archive would disclose more information than diagnosis requires. A diagnostic record could also be mistaken for configuration truth, authorization or proof that a target converged.

## Decision

The management foundation provides a typed diagnostic projection built only from locally supplied, validated evidence. It records source digests, freshness, check states, bounded counts, stable reason codes and safe next actions. It does not include prompts, responses, credentials, policy contents, raw desired state, decision identifiers, target identifiers or private topology.

A bundle is non-authorizing and performs no network or target operation. Its canonical digest detects modification of the projection. The digest does not authenticate its creator and does not replace signatures or receipts already carried by source evidence. Missing optional evidence remains visible; supplied invalid or stale evidence stops bundle creation.

## Consequences

- Administrators can inspect or share a small diagnostic record without exporting the underlying management state.
- Support tooling can rely on stable typed reason codes instead of parsing logs.
- A valid bundle proves only that its content is internally consistent and fresh at validation time.
- Product interfaces may present the bundle differently but cannot add hidden authority or silently collect broader telemetry.
