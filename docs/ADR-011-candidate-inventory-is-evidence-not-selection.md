# ADR-011: Candidate inventory is evidence, not selection authority

**Status:** accepted  
**Date:** 2026-08-25

## Context

Operators need to see which candidate intelligence resources satisfy an
application's effective policy. A list obtained from a Directory, adapter,
configuration import or test fixture is only an evidence snapshot. It does not
establish identity, trust, authorization, availability or a fixed route.

## Decision

The Management Foundation accepts content-minimized, time-bounded candidate
evidence and evaluates every candidate through the existing effective-policy
contract. The resulting inspection distinguishes eligible, ineligible and
unresolved candidates. Compatibility and evidence freshness can narrow
eligibility; preferences cannot create it.

Resolution inspection is read-only and always reports
`authorizes_mutation=false` and `ranking_applied=false`. It neither ranks nor
selects a provider and never writes to a Directory or target. Discovery,
identity, trust, policy eligibility, ranking, selection and execution remain
separate decisions owned by their existing contexts.

## Consequences

- CLI, API and graphical clients can use one deterministic inspection result.
- Expired evidence remains visible as unresolved rather than becoming allow.
- Empty candidate evidence is a truthful zero-result inspection.
- Future ranking can consume eligible candidates through established IICP
  selection semantics without moving ranking into the management evaluator.
- No IICP wire change, service deployment or remote management authority is
  introduced.
