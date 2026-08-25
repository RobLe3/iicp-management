# ADR-010: Administrator trial evidence is non-authorizing

**Status:** Accepted  
**Date:** 2026-08-25

## Context

IICP has explicit usability targets for common administrator workflows. Project
rehearsals can test a harness, but they cannot establish that an administrator
unfamiliar with IICP can complete the same work. Timing alone also cannot prove
participant independence, consent, a correct technical result, or permission to
change a release gate.

The evidence must remain usable across a CLI, graphical interface or automation
client without making any of those interfaces the source of management truth.

## Decision

The management foundation provides a content-minimized trial recorder and
aggregator. It records one declared workflow, a bounded participant
qualification, build and disposable environment classes, counted interactions,
assistance, outcome and a machine-result digest. It does not record names,
credentials, payloads, raw policy, raw configuration or private topology.

`project_rehearsal`, `representative_observation` and
`independent_reproduction` remain distinct evidence classes. Every v2 record is
labelled `observer_declared`. The validator can reject a contributor presented
as a representative or independent participant, but it cannot prove that the
declaration is true.

Aggregation may report whether the documented numerical threshold—five
representative observations across three roles for one workflow—has been met.
It always reports `release_gate_authorized=false`. A separate reviewed decision
is required before a time budget becomes a release gate.

The trial lifecycle is non-authorizing. It never runs a management command,
contacts a Directory, establishes trust, activates policy or changes a target.

## Consequences

- Failed, abandoned and assisted attempts remain visible instead of being
  filtered from the result.
- The same evidence shape can be produced around different user interfaces.
- Trial files can be inspected and exported without exposing ordinary secrets
  or workload content.
- Participant qualification and independence still require human review.
- Version 1 friction evidence remains valid and is not reclassified.
