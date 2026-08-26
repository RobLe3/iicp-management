# ADR-003: Bootstrap discovery produces candidates, not authority

**Status:** accepted  
**Date:** 2026-08-25

## Context

First-run tools can inspect local runtimes, configuration projections,
directories and management evidence. Treating those observations as trusted
configuration would collapse discovery, identity, trust and activation into one
unsafe step.

## Decision

The Environment Bootstrap and Adoption context owns non-authorizing assessments,
recommendations, unresolved decisions, proposals and friction evidence. Every
assessment states `authorizes_mutation=false`. Verified claims require bounded,
fresh evidence; candidates remain candidates.

Bootstrap proposals use the existing desired-state contract and follow the
normal plan, authorization, apply, verification and recovery lifecycle. Import
validates but never activates. Private, federated-private and local-only modes
cannot silently fall back to the public Directory.

An existing canonical `RuntimeConfigV1` may be converted into a bootstrap
assessment. The configuration is an explicit operator-supplied source, not an
automatically trusted discovery result. Optional runtime-health input is reduced
to the existing content-minimized observation before it enters the assessment.
The conversion reads only supplied input: it does not execute `iicp-node`, open
node identity files, contact a Directory or infer trust from local presence.

## Consequences

- A wizard, CLI or automation client can share one typed assessment.
- Missing evidence remains visible rather than being replaced by a default.
- Platform-specific collectors may be added later without redefining trust.
- A legacy node can use `iicp-node config migrate-node` to produce the canonical,
  secret-free configuration input without giving this component access to its
  identity or credential store.
- No IICP wire change, package release or deployment follows from this decision.
