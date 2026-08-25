# ADR-013: Runtime-aware diagnostics preserve version 1

**Status:** Accepted for the 0.8 developer-preview candidate

## Context

Runtime-health observation became available after the original diagnostic-bundle contract was published. Adding runtime fields to that strict contract would make historical bundles ambiguous and break consumers that correctly reject unknown fields.

## Decision

Keep `iicp.management-diagnostic-bundle.v1` unchanged. Runtime-aware creation emits `iicp.management-diagnostic-bundle.v2` only when an operator supplies both a runtime-health snapshot and an explicit projection target. Version 2 adds a required minimized runtime summary and a sixth integrity-bound artifact. It does not retain the target identifier or raw runtime snapshot. Verification dispatches by `schema_version` and rejects unknown generations.

Runtime evidence informs diagnostics only. It grants no lifecycle, routing, execution or mutation authority and does not become an IICP wire requirement.

## Consequences

Historical version 1 fixtures and consumers remain valid. Consumers that need runtime evidence opt into version 2 explicitly. Supporting two generations adds small validation and presentation branches, but avoids silently changing released semantics.
