# ADR-012: Runtime health is evidence, not lifecycle authority

**Status:** accepted  
**Date:** 2026-08-25

## Context

Operators need one compact answer to whether a local IICP node currently reports
itself live and ready. The Rust node already emits a versioned implementation-level
runtime-health snapshot. That snapshot contains useful operational evidence, but
it is not an IICP wire contract and does not authorize management actions.

Copying the complete source would also expose process identifiers that are not
needed for ordinary inspection. Treating a fresh report as authority to restart,
replace or reconfigure a node would collapse observation and lifecycle control.

## Decision

The Management Foundation consumes `iicp.runtime-health.v1` only as explicit
local input and projects it into the content-minimized
`iicp.management-runtime-observation.v1` contract. The projection includes its
source digest, target, evidence timestamps, reported lifecycle/liveness/readiness,
effective state, reason codes and bounded subsystem summaries. It omits PID and
process epoch and always sets `authorizes_mutation=false`.

Unsupported schema generations, future timestamps, secret-like fields, malformed
input and input over 1 MiB fail closed. Expired evidence remains visible as
`unknown`; it never becomes an inferred healthy state. This command performs no
network access, process discovery, service control, Directory mutation or node
configuration.

## Consequences

- CLI, API and future graphical clients can consume one typed observation.
- The node runtime remains the source of the reported state; the local controller
  remains the authority for an exact authorized lifecycle operation.
- A new runtime-health generation requires explicit compatibility work.
- The contract does not make runtime health part of the IICP wire protocol and
  does not prove that a target is trustworthy or reachable.
