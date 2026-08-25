# ADR-004: Policy templates compile to canonical state

**Status:** accepted  
**Date:** 2026-08-25

## Context

Administrators should not have to author every policy from an empty document.
Templates reduce that friction, but a template catalog must not become a second
policy language, hidden product state or an activation authority.

## Decision

A policy template is a versioned, provenance-bearing input to the existing
policy lifecycle. Rendering resolves typed parameters and emits ordinary policy
revisions and an application binding. The rendered canonical objects remain
reviewable, simulatable and subject to the normal authorization lifecycle.

Reference templates are deliberately bounded. Unknown parameters and values
outside an explicit allowlist fail before rendering. Template rendering and
impact preview never activate policy or mutate a target.

Impact reports compare current and proposed policy against supplied candidate
facts. Cost, latency, quality and capacity remain `NOT_AVAILABLE` unless fresh,
integrity-bound evidence is supplied. A preview is not a convergence claim.

## Consequences

- CLI, automation and future graphical clients can share one template result.
- Wizards cannot hide proprietary policy state behind their generated output.
- Template versions remain separate from policy revision identity and authority.
- Catalog signing, distribution and third-party templates remain later work.
- No IICP wire change, release or deployment follows from this decision.
